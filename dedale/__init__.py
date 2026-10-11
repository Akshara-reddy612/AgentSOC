"""
dedale/

Reading the DEDALE dataset (DOI 10.57745/Y5JLDG, CC BY 4.0) into AgentSOC:
the documented environment (environment.py) and the Suricata alerts
(suricata.py).  Design step S3 of experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md;
what the files contain is in experiments/DEDALE_DATA_NOTES.md.

The data lives outside the repo: $AGENTSOC_DATA_DIR/dedale, by default
<repo>/../agentsoc_data/dedale.  Nothing in this package reads DEDALE's labels
or the published attack timeline; they are for the scorer only (design
invariant I4).
"""
from __future__ import annotations

import os
from pathlib import Path


def data_dir() -> Path:
    base = os.environ.get("AGENTSOC_DATA_DIR")
    root = Path(base) if base else Path(__file__).resolve().parents[1].parent / "agentsoc_data"
    return root / "dedale"
