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
"""
from __future__ import annotations

import itertools
import pickle
import shutil
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Iterator, Protocol

from perception.case_store import CaseStore
from perception.environment import EnvironmentProfile
from perception.knowledge_db import KnowledgeDB
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


class _Unpickler(pickle.Unpickler):
    def __init__(self, f, externals: dict[str, Any]):
        super().__init__(f)
        self.externals = externals

    def persistent_load(self, pid):
        return self.externals[pid]


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
        ks, cs = self.home / "ks.sqlite", self.home / "cases.sqlite"
        cp = self.home / "checkpoint"
        if (cp / "state.pkl").exists():                   # restart: restore the latest checkpoint
            for name in ("ks.sqlite", "cases.sqlite"):
                for suffix in ("", "-wal", "-shm"):
                    (self.home / f"{name}{suffix}").unlink(missing_ok=True)
                shutil.copyfile(cp / name, self.home / name)
            self.db, self.cases = KnowledgeDB(ks), CaseStore(cs)
            with open(cp / "state.pkl", "rb") as f:
                st = _Unpickler(f, {"ks": self.db, "cases": self.cases, **self.extra}).load()
            if st.get("source_id", "default") != source_id:
                self.db.close()
                self.cases.close()
                raise ValueError(f"{self.home} was built from sources {st.get('source_id', 'default')!r}, not "
                                 f"{source_id!r}: use another home directory")
            self.loop, self.pos, self.clock = st["loop"], st["pos"], st["clock"]
            self.cases._alert_cap.update(st["alert_cap"])
            self.events_processed = st["events_processed"]
            self.restored = True
        else:
            self.db = KnowledgeDB(ks, profile, created_at=start)
            if seed is not None:
                seed(self.db)
            self.cases = CaseStore(cs, created_at=start)
            self.loop = make_loop(self.db, self.cases)
            self.pos, self.clock = None, start
            self.restored = False
        self._iter: Iterator | None = None
        self._pending = None

    # -- what the API sees ------------------------------------------------------

    def now(self) -> datetime:
        """The stream's current time (stamp analysts' actions with this)."""
        return self.clock

    def status(self) -> dict:
        return {"state": self._state, "mode": "replay" if self.paced else "follow",
                "stream_time": self.clock.isoformat(), "speed": self.speed,
                "events_processed": self.events_processed, "counts": dict(self.loop.counts),
                "last_checkpoint": self.last_checkpoint.isoformat() if self.last_checkpoint else None,
                "restored_from_checkpoint": self.restored}

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
                self.handle(self.loop, event, self.clock)
                self.pos, self._pending = pos, None
                n += 1
        self.events_processed += n
        self._dirty = self._dirty or n > 0
        return n

    def run_until(self, t: datetime, source: Source | None = None) -> int:
        """
        Fast-forward (no pacing) through every event before `t`; returns the number processed.
        With `source` (before start): learn from that source instead, e.g. a replay of the benign
        weeks before following live logs; the runner's own source then starts from its beginning.
        """
        if source is not None:
            self._iter, self._pending = source.events(None), None
        total = 0
        while n := self._process(None, BATCH_EVENTS * 20, until_time=t):
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
            self._process(now if self.paced else None, BATCH_EVENTS)
            if time.monotonic() - last_cp > self.checkpoint_every:
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
                                         "events_processed": self.events_processed})
        shutil.rmtree(old, ignore_errors=True)
        if cp.exists():
            cp.rename(old)
        tmp.rename(cp)
        shutil.rmtree(old, ignore_errors=True)
        self.last_checkpoint, self._dirty = self.clock, False


def stream_after(events: list[tuple[datetime, dict]], after: int | None) -> Iterator[tuple[int, datetime, dict]]:
    """A list as a Source: positions are indices."""
    start = 0 if after is None else after + 1
    for i in range(start, len(events)):
        yield i, events[i][0], events[i][1]


__all__ = ["LiveRunner", "Source", "WAIT", "stream_after"]
