"""
Run the demo server (M4.4):

    python -m soc_server [--dataset dedale] [--home <dir>] [--speed 600] [--demo-start 2025-01-06T08:00] [--port 8000]

- The dataset (environment model, replay sources, recorded LLM answers, training
  window) comes from soc_server/datasets.py; DEDALE is the default and the only
  one registered so far (docs/ADDING_A_DATASET.md adds another).
- On first start it learns the dataset's benign training window and fast-forwards
  to --demo-start (a few minutes for DEDALE), then checkpoints.
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
    from soc_server.datasets import DATASETS, load

    ap = argparse.ArgumentParser(description="AgentSOC demo server")
    ap.add_argument("--dataset", default="dedale", choices=sorted(DATASETS), help="which dataset to replay")
    ap.add_argument("--home", default=None, help="server state (stores, checkpoints); default <data>/live (DEDALE) "
                                                  "or <data>/live_<dataset>")
    ap.add_argument("--speed", type=float, default=600.0, help="stream seconds per wall second")
    ap.add_argument("--demo-start", default=None, help="UTC stream time the demo starts at (default: the dataset's)")
    ap.add_argument("--sources", default="host,network", help="host, network or both (the dataset's replay sources)")
    ap.add_argument("--nce", default="cache", choices=["cache", "live", "off"],
                    help="cache: recorded LLM answers only (no API calls); live: Gemini, limited by --nce-per-day")
    ap.add_argument("--nce-per-day", type=int, default=200, help="live NCE: at most this many calls per stream day")
    ap.add_argument("--follow", default="", help="follow live log files: host=<path>,network=<path> (either or both)")
    ap.add_argument("--inject", default=None,
                    help="contamination scenario: the attacker's command lines carry this payload family "
                         "(DEDALE: suppress, fake_approval, steer)")
    ap.add_argument("--follow-clock", default="events", choices=["events", "wall"],
                    help="with --follow: does the clock move with the wall time while the files are quiet?")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args()
    ds = load(args.dataset)
    if args.home is None:
        args.home = str(data_dir().parent / ("live" if ds.name == "dedale" else f"live_{ds.name}"))

    import uvicorn

    from experiments.dedale_nce import LiveNCE
    from perception.soc_loop import SocLoop
    from perception.triage_gate import DailyBudget
    from review_api.accounts import AccountStore
    from soc_server.app import build_app, with_frontend
    from soc_server.runner import LiveRunner
    from soc_server.sources import MergedSource, handle_merged

    follow = {}
    for part in filter(None, (p.strip() for p in args.follow.split(","))):
        kind, _, path = part.partition("=")
        if kind not in ("host", "network") or not path or kind in follow:
            sys.exit("--follow takes host=<path>,network=<path> (either or both)")
        follow[kind] = str(Path(path).resolve())
    kinds = sorted(follow) or sorted({k.strip() for k in args.sources.split(",") if k.strip()})
    if not kinds or set(kinds) - set(ds.sources):
        sys.exit(f"--sources takes {' / '.join(sorted(ds.sources))} (comma-separated) for {ds.label}")
    if args.inject and (follow or "host" not in kinds or args.inject not in ds.injections):
        sys.exit(f"--inject needs the host replay (not --follow) and one of: {', '.join(ds.injections) or 'none for ' + ds.label}")
    replay_sources = {k: ds.sources[k]() for k in kinds}
    if args.inject:                    # the attacker simulation may read labels; the pipeline does not (I4)
        from soc_server.sources import InjectedSource

        replay_sources["host"] = InjectedSource(replay_sources["host"], ds.injector(args.inject))
    replay = MergedSource(replay_sources)
    if follow:
        from soc_server.follow import PARSERS, FollowSource, TailSource

        source = FollowSource({k: TailSource(p, PARSERS[k]) for k, p in sorted(follow.items())})
        source_id = "follow:" + ",".join(f"{k}={p}" for k, p in sorted(follow.items()))
    else:
        source, source_id = replay, ",".join(kinds) + (f"+inject={args.inject}" if args.inject else "")
        if ds.name != "dedale":                      # DEDALE homes keep their original source ids
            source_id = f"{ds.name}:{source_id}"
    externals, gate_options = {}, {}
    if args.nce != "off":
        from experiments.dedale_nce import CallCap

        cap = None if args.nce == "cache" else CallCap(10**9)

        def cache(recorded: Path) -> Path:
            return nce_cache(recorded, Path(args.home), live=cap is not None)

        recorded = ds.nce_cache or Path(args.home) / f"nce_cache_{ds.name}.jsonl"
        nce = LiveNCE(cap, cache_only=cap is None, cache_path=cache(recorded))
        if args.inject:                # the recorded answers for the injected text (their own cache)
            from experiments.dedale_inject import InjectedRouter

            nce = InjectedRouter(args.inject, nce, LiveNCE(cap, cache_only=cap is None,
                                                           cache_path=cache(ds.injection_cache(args.inject))))
        externals["nce"] = nce
        gate_options["nce"] = nce
        if args.nce == "live":
            gate_options["budget"] = DailyBudget(args.nce_per_day)

    def make_loop(db, cases):
        return SocLoop(db, mode="gated", training_end=ds.training_end, case_store=cases, gate_options=gate_options)

    try:
        runner = LiveRunner(args.home, source, profile=ds.profile, start=ds.training_start, make_loop=make_loop,
                            handle=handle_merged, seed=ds.seed,
                            externals=externals, speed=args.speed, source_id=source_id, paced=not follow,
                            idle_clock=(lambda: datetime.now(timezone.utc)) if args.follow_clock == "wall" else None)
    except ValueError as e:
        sys.exit(str(e))
    if not runner.restored and follow:
        print("first start: learning the benign training window, then following " + ", ".join(follow.values()), flush=True)
        n = runner.run_until(ds.training_end, source=replay)
        print(f"  {n:,} events processed; checkpoint written", flush=True)
    elif not runner.restored:
        target = datetime.fromisoformat(args.demo_start).replace(tzinfo=timezone.utc) if args.demo_start else ds.demo_start
        print(f"first start ({ds.label}): learning the benign training window and fast-forwarding to {target:%Y-%m-%d %H:%M} ...",
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
        app = build_app(runner, accounts=accounts, dataset=ds)
        dist = Path(__file__).resolve().parent.parent / "frontend" / "dist"
        if dist.joinpath("index.html").exists():          # built frontend: one origin, API under /api
            app = with_frontend(app, dist)
            print(f"frontend: http://{args.host}:{args.port}/  (API under /api)", flush=True)
        uvicorn.run(app, host=args.host, port=args.port)
    finally:
        runner.stop()


if __name__ == "__main__":
    main()
