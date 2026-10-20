"""
tools/e2e_check.py

The one-command end-to-end check of a running console (handover, 2026-10-20):
sign in, open every page as a user would -- the overview, the top case in the
queue, its host's timeline, the Knowledge Store, Metrics, the Contamination
Lab and one of its pairs, My account, Accounts (admins) -- and check that each
shows what it should and logs no JavaScript error.  Read-only: it changes
nothing in the server.

    python tools/e2e_check.py --url http://127.0.0.1:8000 --user <name> --password-file pw.txt
                              [--browser <edge/chrome exe>] [--screenshots <dir>]

Exit code 0 when every check passes.  Run it after any change to the server or
the frontend (with `python -m soc_server` running and the frontend built).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from browser import Browser  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description="End-to-end check of a running AgentSOC console (read-only)")
    ap.add_argument("--url", default="http://127.0.0.1:8000")
    ap.add_argument("--user", required=True)
    ap.add_argument("--password-file", required=True, help="a file holding the password (it is never printed)")
    ap.add_argument("--browser", default=None, help="path to Edge / Chrome / Chromium (default: found automatically)")
    ap.add_argument("--screenshots", default=None, help="save a screenshot of every page here")
    args = ap.parse_args()
    password = Path(args.password_file).read_text().strip()
    shots = Path(args.screenshots) if args.screenshots else None
    if shots:
        shots.mkdir(parents=True, exist_ok=True)

    results: list[tuple[str, bool, str]] = []
    with Browser(args.url, args.browser) as b:
        if not b.sign_in(args.user, password):
            print("FAIL  sign in: wrong user or password (or the server is not running)")
            return 1
        me = b.api("/me") or {}
        queue = b.api("/queue?limit=1") or []
        runs = b.api("/lab/runs") or []
        pair = None
        if runs:
            page = b.api(f"/lab/{runs[0]['id']}/pairs?limit=1") or {}
            pair = (page.get("items") or [None])[0]
        checks = [("overview", "/", ["SOC overview", "Review queue", "Triage, last 24 hours"])]
        if queue:
            case, host = queue[0]["case_id"], queue[0]["host"]
            checks += [("case", f"/cases/{case}", ["Pipeline", "Sensor alert", "Analyst decision", "Entities"])]
            if host:
                checks += [("host timeline", f"/hosts/{host}", ["Chronology", "Activity over stream time"])]
        checks += [
            ("knowledge store", "/knowledge", ["Knowledge Store", "Where the learning came from"]),
            ("metrics", "/metrics", ["Metrics", "Reviews per day by learning mode"]),
            ("contamination lab", "/lab", ["Contamination Lab", "By payload family", "Pairs"]),
        ]
        if pair:
            checks += [("lab pair", f"/lab/{runs[0]['id']}/{pair['pair_id']}", ["Clean alert", "Contaminated alert", "Defended pipeline"])]
        checks += [("my account", "/account", ["My account", "Change password"])]
        if me.get("role") == "admin":
            checks += [("accounts", "/admin", ["Accounts", "New account"])]

        for name, path, expected in checks:
            b.goto(path)
            text = b.text()
            missing = [e for e in expected if e not in text]
            errors = list(b.errors)
            ok = not missing and not errors
            detail = ("missing: " + ", ".join(missing) if missing else "") + (f" js errors: {errors[:2]}" if errors else "")
            results.append((name, ok, detail or path))
            if shots:
                b.screenshot(shots / ((path.strip("/").replace("/", "_") or "overview") + ".png"))
        if not queue:
            results.append(("case", True, "skipped: the review queue is empty (start the replay)"))

    width = max(len(n) for n, _, _ in results)
    for name, ok, detail in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name:<{width}}  {detail}")
    failed = sum(not ok for _, ok, _ in results)
    print(f"\n{len(results) - failed} / {len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
