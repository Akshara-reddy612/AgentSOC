"""
agent/run_guard.py

Overwrite guard for evaluation runners that rewrite their result file
wholesale.  Committed result files back reported numbers, so a stray
`python -m agent.run_*` must not silently replace them (and spend API quota).

A runner calls confirm_overwrite(path) at the top of main().  If the file
already exists, the run stops unless the caller passes --allow-overwrite on
the command line or sets AGENTSOC_ALLOW_OVERWRITE=1.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ALLOW_FLAG = "--allow-overwrite"
ALLOW_ENV = "AGENTSOC_ALLOW_OVERWRITE"


def confirm_overwrite(*paths: Path) -> None:
    """Exit with code 2 if any existing result file would be overwritten without explicit permission."""
    if ALLOW_FLAG in sys.argv or os.environ.get(ALLOW_ENV) == "1":
        return
    existing = [Path(p) for p in paths if Path(p).exists()]
    if not existing:
        return
    print("REFUSING TO RUN: this script overwrites existing result file(s):", flush=True)
    for p in existing:
        print(f"  {p}", flush=True)
    print(
        f"These files back reported numbers. Re-run with {ALLOW_FLAG} "
        f"(or set {ALLOW_ENV}=1) if you really intend to replace them.",
        flush=True,
    )
    sys.exit(2)
