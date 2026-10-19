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
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


def main() -> None:
    from dedale import data_dir

    ap = argparse.ArgumentParser(description="AgentSOC demo server")
    ap.add_argument("--home", default=str(data_dir().parent / "live"), help="server state (stores, checkpoints)")
    ap.add_argument("--speed", type=float, default=600.0, help="stream seconds per wall second")
    ap.add_argument("--demo-start", default="2025-01-06T08:00", help="UTC stream time the demo starts at")
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
    from soc_server.sources import DedaleHostSource

    nce = LiveNCE(None, cache_only=True)

    def make_loop(db, cases):
        return SocLoop(db, mode="gated", training_end=TRAINING_END, case_store=cases,
                       gate_options={"nce": nce})

    runner = LiveRunner(args.home, DedaleHostSource(EVENTS), profile=DEDALE_PROFILE, start=TRAINING_START,
                        make_loop=make_loop, handle=lambda loop, ev, at: loop.process_host_event(ev, at),
                        seed=lambda db: seed_store(db, TRAINING_START), externals={"nce": nce}, speed=args.speed)
    if not runner.restored:
        target = datetime.fromisoformat(args.demo_start).replace(tzinfo=timezone.utc)
        print(f"first start: learning the benign weeks and fast-forwarding to {target:%Y-%m-%d %H:%M} ...",
              flush=True)
        n = runner.run_until(target)
        print(f"  {n:,} events processed; checkpoint written", flush=True)
    accounts = AccountStore(runner.home / "auth.sqlite")
    if not accounts.users():
        print(f"no accounts yet: python -m review_api.accounts --db {runner.home / 'auth.sqlite'} "
              "create-user <name> --role admin", file=sys.stderr)
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
