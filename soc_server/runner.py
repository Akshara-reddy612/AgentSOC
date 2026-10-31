"""
soc_server/runner.py

Live runner (M4.2, 2026-10-18; DEMO_BACKEND_DESIGN.md): the SOC loop as a
long-running process fed by a replay source at an adjustable speed, with
checkpoints and restart recovery.

  - One thread owns the Knowledge Store and the loop (single writer, I6).  The
    API thread(s) only write the case store (thread-safe) and read.
  - Time: the loop's clock is the stream's event time.  `now()` is the time the
    review API must stamp analysts' actions with, so a verdict given while the
    replay shows January 2025 applies to that stream.  While paused, the runner
    keeps applying analysts' commands at the paused time (`SocLoop.tick`).
  - Pacing: an event at stream time t is processed at wall time
    wall0 + (t - t0) / speed (speed = stream seconds per wall second).
    `run_until(t)` fast-forwards without pacing (training, demo start).
    Following live logs (soc_server/follow.py, `paced=False`), events are
    processed as they arrive; a source with nothing new yields WAIT, and the
    runner ticks the loop and waits (moving the clock to `idle_clock()` if
    one is given, e.g. the wall clock for real-time logs).
  - Checkpoints (every `checkpoint_every` wall seconds, on pause and on stop):
    consistent copies of the Knowledge Store and the case store (SQLite backup
    API) plus a pickle of the loop's in-memory state (open cases, gate queue,
    watches, awaiting verdicts, decision cache) and the stream position.
    Database connections are not pickled: they are re-attached on restore.
    On start, the latest checkpoint is restored and the stream resumes after
    its position, so a crash loses at most one checkpoint interval (stream
    work and analysts' actions alike).
  - Checkpoint integrity (2026-10-31, review item 8).  A pickle can run code
    when it is loaded, so:
      * loading resolves only the classes and functions the loop's state is
        made of (`_ALLOWED`), and bound methods only from `_ALLOWED_METHODS`;
        anything else is refused before it runs;
      * each checkpoint carries `manifest.json`: the SHA-256 of its three files
        and an HMAC over them with a per-user key kept outside the home
        (`AGENTSOC_CHECKPOINT_KEY`, default ~/.agentsoc/checkpoint.key).  A
        checkpoint changed after it was written is refused before any live file
        is touched.  Checkpoints written before this change have no manifest:
        they load (under the allowlist) and the next checkpoint is signed;
      * a crash between checkpoint()'s two renames leaves only
        `checkpoint.old`, which is then restored.
    This protects checkpoints at rest.  The live databases of a running server
    are protected only by the home directory's permissions.
"""
from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import os
import pickle
import secrets
import shutil
import threading
import time
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from perception.case_store import CaseStore
from perception.environment import EnvironmentProfile
from perception.knowledge_db import KnowledgeDB
from perception.outcome_monitor import OutcomeMonitor
from perception.soc_loop import SocLoop

BATCH_EVENTS = 500
IDLE_WAIT = 0.5                                       # wall seconds between polls of a waiting source


class _Wait:
    def __repr__(self) -> str:
        return "WAIT"


WAIT = _Wait()                                        # a live source has no new event yet


class Source(Protocol):
    def events(self, after: Any | None) -> Iterator[tuple[Any, datetime, dict]]:
        """(position, event time, event) in time order, starting after `after` (None: from the start)."""


class _Pickler(pickle.Pickler):
    def __init__(self, f, externals: dict[int, str]):
        super().__init__(f)
        self.externals = externals

    def persistent_id(self, obj):
        return self.externals.get(id(obj))

    def reducer_override(self, obj):
        if type(obj) is itertools.count:        # itertools pickling is deprecated (removed in 3.14)
            return itertools.count, (int(repr(obj)[6:-1].split(",")[0]),)
        return NotImplemented


# What the loop's pickled state is made of (module, name).  A new class in the loop's state must be added here,
# or restoring a checkpoint fails with "checkpoint refers to ..." (tests/test_live_runner.py restores each source).
_ALLOWED = frozenset({
    ("builtins", "set"), ("builtins", "frozenset"),
    ("collections", "Counter"), ("collections", "OrderedDict"), ("collections", "defaultdict"), ("collections", "deque"),
    ("datetime", "date"), ("datetime", "datetime"), ("datetime", "timedelta"), ("datetime", "timezone"),
    ("itertools", "count"),
    ("perception.case_builder", "Case"), ("perception.case_builder", "CaseBuilder"),
    ("perception.case_builder", "alert_case_key"), ("perception.case_builder", "network_case_key"),
    ("perception.knowledge_updater", "KnowledgeUpdater"),
    ("perception.outcome_monitor", "OutcomeMonitor"), ("perception.outcome_monitor", "ProposedResponse"),
    ("perception.outcome_monitor", "Watch"),
    ("perception.soc_loop", "SocLoop"),
    ("perception.triage_gate", "DailyBudget"), ("perception.triage_gate", "Decision"),
    ("perception.triage_gate", "TriageGate"),
})
# Bound methods in the state (pickled as getattr(obj, name)): the gate's watch hook.
_ALLOWED_METHODS = frozenset({(OutcomeMonitor, "reasons")})
CHECKPOINT_FILES = ("ks.sqlite", "cases.sqlite", "state.pkl")


def _bound_method(obj, name):
    if (type(obj), name) not in _ALLOWED_METHODS:
        raise pickle.UnpicklingError(f"checkpoint refers to {type(obj).__qualname__}.{name}")
    return getattr(obj, name)


class _Unpickler(pickle.Unpickler):
    def __init__(self, f, externals: dict[str, Any]):
        super().__init__(f)
        self.externals = externals

    def persistent_load(self, pid):
        return self.externals[pid]

    def find_class(self, module, name):
        if (module, name) == ("builtins", "getattr"):
            return _bound_method
        if (module, name) not in _ALLOWED:
            raise pickle.UnpicklingError(f"checkpoint refers to {module}.{name}, which a checkpoint never holds")
        return super().find_class(module, name)


def _key() -> bytes:
    """The per-user checkpoint key, created on first use (outside the home: whoever can write a home cannot sign)."""
    path = Path(os.environ.get("AGENTSOC_CHECKPOINT_KEY") or Path.home() / ".agentsoc" / "checkpoint.key")
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(secrets.token_bytes(32))
    return path.read_bytes()


def _digests(d: Path) -> tuple[dict[str, str], str]:
    files = {}
    for name in CHECKPOINT_FILES:
        with open(d / name, "rb") as f:
            files[name] = hashlib.file_digest(f, "sha256").hexdigest()
    mac = hmac.new(_key(), json.dumps(files, sort_keys=True).encode("utf-8"), "sha256").hexdigest()
    return files, mac


def _sign(d: Path) -> None:
    files, mac = _digests(d)
    (d / "manifest.json").write_text(json.dumps({"files": files, "hmac": mac}, indent=1), encoding="utf-8")


def _verify(d: Path) -> bool:
    """True if `d` matches its manifest, False if it has none (written before 2026-10-31); raises if it was changed."""
    if not (d / "manifest.json").exists():
        return False
    stored = json.loads((d / "manifest.json").read_text(encoding="utf-8"))
    files, mac = _digests(d)
    if not hmac.compare_digest(mac, str(stored.get("hmac"))) or files != stored.get("files"):
        raise ValueError(f"{d} does not match its manifest (changed after it was written, or signed with another "
                         f"key): refusing to load it. Use another home directory, or remove that checkpoint.")
    return True


class LiveRunner:
    """See module docstring.  `make_loop(db, case_store)` builds the loop on first start."""

    def __init__(self, home: str | Path, source: Source, *, profile: EnvironmentProfile, start: datetime,
                 make_loop: Callable[[KnowledgeDB, CaseStore], SocLoop],
                 handle: Callable[[SocLoop, dict, datetime], None],
                 seed: Callable[[KnowledgeDB], None] | None = None, externals: dict[str, Any] | None = None,
                 speed: float = 60.0, checkpoint_every: float = 30.0, source_id: str = "default",
                 paced: bool = True, idle_clock: Callable[[], datetime] | None = None) -> None:
        self.home = Path(home)
        self.home.mkdir(parents=True, exist_ok=True)
        self.source, self.handle, self.source_id = source, handle, source_id
        self.paced, self.idle_clock = paced, idle_clock
        self.speed, self.checkpoint_every = speed, checkpoint_every
        self.extra = externals or {}                      # e.g. {"nce": LiveNCE(...)}: not pickled
        self._cond = threading.Condition()
        self._state = "paused"                           # paused | running | finished | stopped
        self._thread: threading.Thread | None = None
        self.events_processed = 0
        self.last_checkpoint: datetime | None = None
        self._dirty = False                               # events processed since the last checkpoint
        self._profile, self._start, self._make_loop, self._seed = profile, start, make_loop, seed
        self.quarantined: set[str] = set()                # repr(position) of events that failed (2026-10-31)
        self.events_failed = 0
        self._current: tuple | None = None                # (position, time, event) being handled
        self._checkpoint_soon = False                     # after a recovery: checkpoint once past the bad event
        self.unsigned_checkpoint = False
        self.db: KnowledgeDB | None = None
        self.cases: CaseStore | None = None
        cp = self._latest_checkpoint()
        if cp is not None:                                # restart: restore the latest checkpoint
            self._restore(cp)
        else:
            self._fresh()
        self.restored = cp is not None
        self._iter: Iterator | None = None
        self._pending = None

    def _latest_checkpoint(self) -> Path | None:
        cp, old = self.home / "checkpoint", self.home / "checkpoint.old"
        if (cp / "state.pkl").exists():
            return cp
        return old if (old / "state.pkl").exists() else None    # a crash between checkpoint()'s two renames

    def _replace_live_files(self, cp: Path | None) -> None:
        """The live stores' files become the checkpoint's copies (None: no files, a fresh start)."""
        for name in ("ks.sqlite", "cases.sqlite"):
            for suffix in ("", "-wal", "-shm"):
                (self.home / f"{name}{suffix}").unlink(missing_ok=True)
            if cp is not None:
                shutil.copyfile(cp / name, self.home / name)

    def _open_cases(self, created_at: datetime | None = None) -> None:
        if self.cases is None:
            self.cases = CaseStore(self.home / "cases.sqlite", created_at=created_at)
        else:                                             # same object: the review API holds it
            self.cases.reconnect(created_at=created_at)

    def _restore(self, cp: Path) -> None:
        self.unsigned_checkpoint = not _verify(cp)        # before any live file is touched
        self._replace_live_files(cp)
        self.db = KnowledgeDB(self.home / "ks.sqlite")
        self._open_cases()
        try:
            with open(cp / "state.pkl", "rb") as f:
                st = _Unpickler(f, {"ks": self.db, "cases": self.cases, **self.extra}).load()
        except pickle.UnpicklingError:
            self.db.close()
            self.cases.close()
            raise
        if st.get("source_id", "default") != self.source_id:
            self.db.close()
            self.cases.close()
            raise ValueError(f"{self.home} was built from sources {st.get('source_id', 'default')!r}, not "
                             f"{self.source_id!r}: use another home directory")
        self.loop, self.pos, self.clock = st["loop"], st["pos"], st["clock"]
        self.cases._alert_cap.update(st["alert_cap"])
        self.events_processed = st["events_processed"]
        self.quarantined |= set(st.get("quarantined", ()))
        self.events_failed = max(self.events_failed, st.get("events_failed", 0))

    def _fresh(self) -> None:
        self._replace_live_files(None)                    # no checkpoint: nothing consistent to keep
        self.db = KnowledgeDB(self.home / "ks.sqlite", self._profile, created_at=self._start)
        if self._seed is not None:
            self._seed(self.db)
        self._open_cases(created_at=self._start)
        self.loop = self._make_loop(self.db, self.cases)
        self.pos, self.clock = None, self._start
        self.events_processed = 0

    # -- what the API sees ------------------------------------------------------

    def now(self) -> datetime:
        """The stream's current time (stamp analysts' actions with this)."""
        return self.clock

    def status(self) -> dict:
        return {"state": self._state, "mode": "replay" if self.paced else "follow",
                "stream_time": self.clock.isoformat(), "speed": self.speed,
                "events_processed": self.events_processed, "counts": dict(self.loop.counts),
                "alerts_test": self.cases.alert_total(),       # loop.counts["alerts"] includes training
                "last_checkpoint": self.last_checkpoint.isoformat() if self.last_checkpoint else None,
                "restored_from_checkpoint": self.restored,
                "events_failed": self.events_failed,                       # quarantined (2026-10-31)
                "events_rejected": int(self.loop.counts.get("events_rejected", 0))}

    # -- control (any thread) -----------------------------------------------------

    def start(self, paused: bool = False) -> None:
        """
        Start (or resume) paced replay in the background.  `paused=True` starts the thread
        without replaying, so analysts' commands are applied from the moment the server is up.
        """
        with self._cond:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="soc-runner", daemon=True)
                self._state = "paused" if paused else "running"
                self._thread.start()
            elif self._state == "paused":
                self._state = "running"
            self._cond.notify_all()

    def pause(self) -> None:
        with self._cond:
            if self._state == "running":
                self._state = "paused"
                self._cond.notify_all()

    def set_speed(self, speed: float) -> None:
        if not 0 < speed <= 86_400:
            raise ValueError("speed is stream seconds per wall second, 0 < speed <= 86400")
        with self._cond:
            self.speed = speed
            self._cond.notify_all()

    def stop(self) -> None:
        """Stop the thread (a final checkpoint is taken) and close the stores."""
        with self._cond:
            self._state = "stopped"
            self._cond.notify_all()
        if self._thread is not None:
            self._thread.join()
        else:
            self.checkpoint()
        self.db.close()
        self.cases.close()

    # -- processing (runner thread, or the caller before start) ----------------------

    def _next(self):
        if self._pending is None:
            if self._iter is None:
                self._iter = self.source.events(self.pos)
            self._pending = next(self._iter, None)
        return self._pending

    def _process(self, until_wall: float | None, limit: int, until_time: datetime | None = None) -> int:
        """Process due events (one transaction); returns how many."""
        n = 0
        with self.db.batch(), self.cases.batch():
            while n < limit:
                item = self._next()
                if item is WAIT:
                    self._pending = None
                    break
                if item is None:
                    break
                pos, at, event = item
                if until_time is not None and at >= until_time:
                    break
                if until_wall is not None and self._due(at) > until_wall:
                    break
                self.clock = max(self.clock, at)
                if repr(pos) not in self.quarantined:          # an event that failed before is skipped
                    self._current = (pos, at, event)
                    self.handle(self.loop, event, self.clock)
                    self._current = None
                self.pos, self._pending = pos, None
                n += 1
        self.events_processed += n
        self._dirty = self._dirty or n > 0
        self._write_rejected()
        return n

    def _process_guarded(self, until_wall: float | None, limit: int, until_time: datetime | None = None, *,
                         source: Source | None = None) -> int:
        """
        _process, except that an event the pipeline fails on does not stop the SOC (2026-10-31).  Its chunk's
        transaction is rolled back (batch), the event is quarantined (quarantine.jsonl, status), the stores and
        the loop are restored from the latest checkpoint -- a consistent state, unlike the loop's memory after a
        half-handled event -- and the stream resumes from there without that event.  `source`: the one being
        read (run_until's training replay), if not the runner's own.
        """
        try:
            return self._process(until_wall, limit, until_time)
        except Exception as e:  # noqa: BLE001 -- any failure on one event; others propagate from _process
            if self._current is None:
                raise
            self._quarantine(e)
            self._recover(source)
            return 1                                       # the stream moved on (past the quarantined event)

    def _quarantine(self, e: Exception) -> None:
        pos, at, event = self._current
        self._current = None
        self.quarantined.add(repr(pos))
        self.events_failed += 1
        rec = {"kind": "failed", "position": repr(pos), "event_time": at.isoformat(),
               "error": f"{type(e).__name__}: {e}"[:500], "traceback": traceback.format_exc(limit=12)[-6000:],
               "event": event}
        with open(self.home / "quarantine.jsonl", "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        print(f"an event failed in the pipeline and was quarantined ({type(e).__name__}); the runner restores its "
              f"latest checkpoint and continues without it: {self.home / 'quarantine.jsonl'}", flush=True)

    def _write_rejected(self) -> None:
        """Events the loop refused as malformed (SocLoop.rejected) go to the quarantine file too."""
        rejected = getattr(self.loop, "rejected", None)
        if not rejected:
            return
        with open(self.home / "quarantine.jsonl", "a", encoding="utf-8") as f:
            for at, problem, event in rejected:
                f.write(json.dumps({"kind": "rejected", "event_time": at.isoformat(), "error": problem,
                                    "event": event}, default=str) + "\n")
        rejected.clear()

    def _recover(self, source: Source | None) -> None:
        with self.cases._lock:                            # the review API waits instead of meeting a closed store
            self.db.close()
            self.cases.close()
            cp = self._latest_checkpoint()
            if cp is not None:
                self._restore(cp)
            else:
                self._fresh()
        self._iter = source.events(self.pos) if source is not None else None
        self._pending, self._current = None, None
        self._dirty = self._checkpoint_soon = True        # past the bad event, checkpoint: a repeat costs less

    def run_until(self, t: datetime, source: Source | None = None) -> int:
        """
        Fast-forward (no pacing) through every event before `t`; returns the number processed.
        With `source` (before start): learn from that source instead, e.g. a replay of the benign
        weeks before following live logs; the runner's own source then starts from its beginning.
        """
        if source is not None:
            self._iter, self._pending = source.events(None), None
        total = 0
        while n := self._process_guarded(None, BATCH_EVENTS * 20, until_time=t, source=source):
            total += n
        if source is not None:
            self._iter, self._pending, self.pos = None, None, None
        with self.db.batch(), self.cases.batch():
            self.clock = max(self.clock, t)
            self.loop.tick(self.clock)
        self.checkpoint()
        return total

    def _due(self, at: datetime) -> float:
        return self._wall0 + (at - self._t0).total_seconds() / self.speed

    def _rebase(self) -> None:
        self._t0, self._wall0 = self.clock, time.monotonic()

    def _run(self) -> None:
        self._rebase()
        speed, last_cp = self.speed, time.monotonic()
        while True:
            with self._cond:
                state = self._state
                if self.speed != speed:
                    speed = self.speed
                    self._rebase()
            if state == "stopped":
                break
            if state == "paused":
                with self.db.batch(), self.cases.batch():
                    self.loop.tick(self.clock)            # analysts' commands apply while paused
                if self._dirty or time.monotonic() - last_cp > self.checkpoint_every:
                    self.checkpoint()                     # pausing checkpoints right away
                    last_cp = time.monotonic()
                with self._cond:
                    self._cond.wait(0.5)
                    if self._state == "running":
                        self._rebase()
                continue
            item = self._next()
            if item is WAIT:
                self._pending = None
                with self.db.batch(), self.cases.batch():
                    if self.idle_clock is not None:
                        self.clock = max(self.clock, self.idle_clock())
                    self.loop.tick(self.clock)
                if time.monotonic() - last_cp > self.checkpoint_every:
                    self.checkpoint()
                    last_cp = time.monotonic()
                with self._cond:
                    self._cond.wait(IDLE_WAIT)
                continue
            if item is None:
                with self.db.batch(), self.cases.batch():
                    self.loop.tick(self.clock)
                with self._cond:
                    self._state = "finished"
                    self._cond.wait(0.5)
                    if self._state == "finished":
                        continue
                continue
            now = time.monotonic()
            if self.paced and self._due(item[1]) > now:
                with self.db.batch(), self.cases.batch():
                    self.loop.tick(self.clock)
                with self._cond:
                    self._cond.wait(min(self._due(item[1]) - now, 0.25))
                continue
            self._process_guarded(now if self.paced else None, BATCH_EVENTS)
            if self._checkpoint_soon or time.monotonic() - last_cp > self.checkpoint_every:
                self.checkpoint()
                last_cp = time.monotonic()
        self.checkpoint()

    def checkpoint(self) -> None:
        """Consistent copy of both stores + the loop's state (runner thread, outside batches)."""
        tmp, cp, old = self.home / "checkpoint.tmp", self.home / "checkpoint", self.home / "checkpoint.old"
        shutil.rmtree(tmp, ignore_errors=True)
        tmp.mkdir()
        self.db.backup_to(tmp / "ks.sqlite")
        self.cases.backup_to(tmp / "cases.sqlite")
        externals = {id(self.db): "ks", id(self.cases): "cases", **{id(v): k for k, v in self.extra.items()}}
        with open(tmp / "state.pkl", "wb") as f:
            _Pickler(f, externals).dump({"loop": self.loop, "pos": self.pos, "clock": self.clock,
                                         "source_id": self.source_id,
                                         "alert_cap": dict(self.cases._alert_cap),
                                         "events_processed": self.events_processed,
                                         "quarantined": sorted(self.quarantined),
                                         "events_failed": self.events_failed})
        _sign(tmp)
        shutil.rmtree(old, ignore_errors=True)
        if cp.exists():
            cp.rename(old)
        tmp.rename(cp)
        shutil.rmtree(old, ignore_errors=True)
        self.last_checkpoint, self._dirty, self._checkpoint_soon = self.clock, False, False


def stream_after(events: list[tuple[datetime, dict]], after: int | None) -> Iterator[tuple[int, datetime, dict]]:
    """A list as a Source: positions are indices."""
    start = 0 if after is None else after + 1
    for i in range(start, len(events)):
        yield i, events[i][0], events[i][1]


__all__ = ["LiveRunner", "Source", "WAIT", "stream_after"]
