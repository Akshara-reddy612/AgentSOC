"""
soc_server/datasets.py

Everything the demo server needs to know about a dataset, in one place
(handover, 2026-10-20): its environment model, where its benign training
window ends and the demo starts, its replay sources (host events and / or
network alerts), its recorded LLM answers, the frozen comparison runs for the
Metrics page and, optionally, a contamination scenario.

    python -m soc_server --dataset dedale        (the default)

A third dataset (AIT-LDS, E3) is added by writing its readers and
environment model the way dedale/ does and registering a factory below; see
docs/ADDING_A_DATASET.md.  Factories import their modules lazily, so listing
the datasets loads nothing.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from perception.environment import EnvironmentProfile
from perception.knowledge_db import KnowledgeDB


@dataclass(frozen=True)
class Dataset:
    name: str
    label: str                                         # shown in the console header ("DEDALE replay")
    profile: EnvironmentProfile                        # what the operator knows: networks, zones, policy
    seed: Callable[[KnowledgeDB], None]                # writes the inventory / zones into a new store
    training_start: datetime
    training_end: datetime                             # benign window: learned without the gate
    demo_start: datetime                               # where a first start fast-forwards to
    sources: dict[str, Callable[[], object]]           # "host" / "network" -> replay source factory
    nce_cache: Path | None = None                      # recorded LLM answers (--nce cache)
    comparison: Path | None = None                     # frozen *_scores.json for the Metrics page
    comparison_runs: dict[str, str] = field(default_factory=dict)
    # contamination scenario (optional): family -> event rewriter, and the recorded answers for that text
    injections: tuple[str, ...] = ()
    injector: Callable[[str], Callable[[dict], dict]] | None = None
    injection_cache: Callable[[str], Path] | None = None


def _utc(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)


def dedale() -> Dataset:
    from dedale.environment import DEDALE_PROFILE, seed_store
    from experiments.dedale_host_replay import EVENTS, TRAINING_END, TRAINING_START
    from experiments.dedale_nce import CACHE
    from soc_server.sources import DedaleHostSource, DedaleNetSource

    def injector(family: str):
        from experiments.dedale_host_novelty import load_host_labels   # the attacker simulation reads labels;
        from experiments.dedale_inject import Injector                 # the pipeline never does (I4)
        return Injector(family, load_host_labels())

    return Dataset(
        name="dedale", label="DEDALE",
        profile=DEDALE_PROFILE, seed=lambda db: seed_store(db, TRAINING_START),
        training_start=TRAINING_START, training_end=TRAINING_END, demo_start=_utc("2025-01-06T08:00"),
        sources={"host": lambda: DedaleHostSource(EVENTS), "network": lambda: DedaleNetSource()},
        nce_cache=CACHE,
        comparison=Path(__file__).resolve().parent.parent / "experiments" / "dedale_results" / "final_host_scores.json",
        comparison_runs={"no learning (static)": "static_F_static", "learning behind the gate": "gated_F_gated",
                         "learning without the gate": "ungated_F_ungated", "gate + analyst (4 h)": "gated_analyst_F_d4"},
        injections=("suppress", "fake_approval", "steer"), injector=injector,
        injection_cache=lambda family: CACHE.with_name(f"nce_cache_host_{family}.jsonl"),
    )


DATASETS: dict[str, Callable[[], Dataset]] = {"dedale": dedale}


def load(name: str) -> Dataset:
    if name not in DATASETS:
        raise SystemExit(f"unknown dataset {name!r}; registered: {', '.join(DATASETS)}")
    return DATASETS[name]()
