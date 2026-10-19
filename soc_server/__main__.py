"""
Run the demo server (M4.4):

    python -m soc_server [--home <dir>] [--speed 600] [--demo-start 2025-01-06T08:00] [--port 8000]

- On first start it learns DEDALE's two benign weeks and fast-forwards to
  --demo-start (a few minutes), then checkpoints.
- Later starts resume from the latest checkpoint.
- The replay starts paused; a lead or admin starts it (POST /live/start or the frontend).
- NCE uses the recorded hypotheses (cache only, no API calls).
- Accounts live in <home>/auth.sqlite. Create the first admin with:
      python -m review_api.accounts --db <home>/auth.sqlite create-user <name> --role admin
- Binds 127.0.0.1 by default. The API reference is at /docs.

Live logs instead of the replay (soc_server/follow.py):

    python -m soc_server --home <new dir> --follow host=<winlogbeat.ndjson>,network=<eve.json>

- On first start it learns DEDALE's benign weeks (the replay), then follows the
  files from their start, as they grow; it runs without pressing Start.
- --follow-clock wall moves the clock to the wall time while the files are
  quiet (real-time logs); the default, events, keeps the time of the last event
  (logs with past timestamps, e.g. DEDALE lines appended for a test).
- The environment is still DEDALE's (inventory, zones): the logs must come
  from its hosts.

Contamination scenario (PROJECT_PLAN section 5, item 7):

    python -m soc_server --home <new dir> --inject steer      # or suppress, fake_approval

- The attacker's own command lines carry text written for the LLM (E1's
  payloads, experiments/dedale_inject.py); with --nce cache, the LLM answers
  are E1's recorded ones for that text (no API calls).
- Look for CLIENT2 / CLIENT1 cases whose command line ends in the payload: the
  trace shows the LLM following it, entity binding flagging the steered
  host, and no containment against it.
"""
from __future__ import annotations

import argparse
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path


def nce_cache(recorded: Path, home: Path, *, live: bool) -> Path:
    """
    The NCE cache file to use.  Cache mode reads the recorded answers.  Live mode works on a copy
    in the home: a live call appends its answer to the cache, and the recorded caches must stay as
    the frozen results used them (found 2026-10-19, before any live demo run).
    """
    if not live:
        return recorded
    own = home / recorded.name
    if not own.exists():
        home.mkdir(parents=True, exist_ok=True)
        if recorded.exists():
            shutil.copyfile(recorded, own)
    return own


def main() -> None:
    from dedale import data_dir

    ap = argparse.ArgumentParser(description="AgentSOC demo server")
    ap.add_argument("--home", default=str(data_dir().parent / "live"), help="server state (stores, checkpoints)")
    ap.add_argument("--speed", type=float, default=600.0, help="stream seconds per wall second")
    ap.add_argument("--demo-start", default="2025-01-06T08:00", help="UTC stream time the demo starts at")
    ap.add_argument("--sources", default="host,network", help="host, network or both (DEDALE replay)")
    ap.add_argument("--nce", default="cache", choices=["cache", "live", "off"],
                    help="cache: recorded LLM answers only (no API calls); live: Gemini, limited by --nce-per-day")
    ap.add_argument("--nce-per-day", type=int, default=200, help="live NCE: at most this many calls per stream day")
    ap.add_argument("--follow", default="", help="follow live log files: host=<path>,network=<path> (either or both)")
    ap.add_argument("--inject", default=None, choices=["suppress", "fake_approval", "steer"],
                    help="contamination scenario: the attacker's command lines carry this E1 payload family")
    ap.add_argument("--follow-clock", default="events", choices=["events", "wall"],
                    help="with --follow: does the clock move with the wall time while the files are quiet?")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()

    import uvicorn

    from dedale.environment import DEDALE_PROFILE, seed_store
    from experiments.dedale_host_replay import EVENTS, TRAINING_END, TRAINING_START
    from experiments.dedale_nce import LiveNCE
    from perception.soc_loop import SocLoop
    from review_api.accounts import AccountStore
    from soc_server.app import build_app, with_frontend
    from soc_server.runner import LiveRunner
    from perception.triage_gate import DailyBudget
    from soc_server.sources import DedaleHostSource, DedaleNetSource, MergedSource, handle_merged

    follow = {}
    for part in filter(None, (p.strip() for p in args.follow.split(","))):
        kind, _, path = part.partition("=")
        if kind not in ("host", "network") or not path or kind in follow:
            sys.exit("--follow takes host=<path>,network=<path> (either or both)")
        follow[kind] = str(Path(path).resolve())
    kinds = sorted(follow) or sorted({k.strip() for k in args.sources.split(",") if k.strip()})
    if not kinds or set(kinds) - {"host", "network"}:
        sys.exit("--sources takes host, network or host,network")
    if args.inject and (follow or "host" not in kinds):
        sys.exit("--inject needs the host replay (not --follow)")
    host_source = DedaleHostSource(EVENTS)
    if args.inject:                    # the attacker simulation reads labels; the pipeline does not
        from experiments.dedale_host_novelty import load_host_labels
        from experiments.dedale_inject import Injector
        from soc_server.sources import InjectedSource

        host_source = InjectedSource(host_source, Injector(args.inject, load_host_labels()))
    replay = MergedSource({k: host_source if k == "host" else DedaleNetSource() for k in kinds})
    if follow:
        from soc_server.follow import PARSERS, FollowSource, TailSource

        source = FollowSource({k: TailSource(p, PARSERS[k]) for k, p in sorted(follow.items())})
        source_id = "follow:" + ",".join(f"{k}={p}" for k, p in sorted(follow.items()))
    else:
        source, source_id = replay, ",".join(kinds) + (f"+inject={args.inject}" if args.inject else "")
    externals, gate_options = {}, {}
    if args.nce != "off":
        from experiments.dedale_nce import CACHE, CallCap

        cap = None if args.nce == "cache" else CallCap(10**9)

        def cache(name: str) -> Path:
            return nce_cache(CACHE.with_name(name), Path(args.home), live=cap is not None)

        nce = LiveNCE(cap, cache_only=cap is None, cache_path=cache(CACHE.name))
        if args.inject:                # E1's recorded answers for the injected text (its own cache)
            from experiments.dedale_inject import InjectedRouter

            nce = InjectedRouter(args.inject, nce, LiveNCE(cap, cache_only=cap is None,
                                                           cache_path=cache(f"nce_cache_host_{args.inject}.jsonl")))
        externals["nce"] = nce
        gate_options["nce"] = nce
        if args.nce == "live":
            gate_options["budget"] = DailyBudget(args.nce_per_day)

    def make_loop(db, cases):
        return SocLoop(db, mode="gated", training_end=TRAINING_END, case_store=cases, gate_options=gate_options)

    try:
        runner = LiveRunner(args.home, source, profile=DEDALE_PROFILE, start=TRAINING_START, make_loop=make_loop,
                            handle=handle_merged, seed=lambda db: seed_store(db, TRAINING_START),
                            externals=externals, speed=args.speed, source_id=source_id, paced=not follow,
                            idle_clock=(lambda: datetime.now(timezone.utc)) if args.follow_clock == "wall" else None)
    except ValueError as e:
        sys.exit(str(e))
    if not runner.restored and follow:
        print("first start: learning the benign weeks, then following " + ", ".join(follow.values()), flush=True)
        n = runner.run_until(TRAINING_END, source=replay)
        print(f"  {n:,} events processed; checkpoint written", flush=True)
    elif not runner.restored:
        target = datetime.fromisoformat(args.demo_start).replace(tzinfo=timezone.utc)
        print(f"first start: learning the benign weeks and fast-forwarding to {target:%Y-%m-%d %H:%M} ...",
              flush=True)
        n = runner.run_until(target)
        print(f"  {n:,} events processed; checkpoint written", flush=True)
    runner.start(paused=not follow)           # paused replay still applies analysts' commands
    accounts = AccountStore(runner.home / "auth.sqlite")
    if not accounts.has_users():
        print(f"no accounts yet: open http://{args.host}:{args.port}/ to create the first admin "
              f"(or: python -m review_api.accounts --db {runner.home / 'auth.sqlite'} create-user <name> --role admin)",
              file=sys.stderr, flush=True)
    try:
        app = build_app(runner, accounts=accounts)
        dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
        if dist.joinpath("index.html").exists():          # built frontend: one origin, API under /api
            app = with_frontend(app, dist)
            print(f"frontend: http://{args.host}:{args.port}/  (API under /api)", flush=True)
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
