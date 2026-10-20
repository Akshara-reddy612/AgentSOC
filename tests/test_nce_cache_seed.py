"""
Handover (2026-10-20): the recorded DEDALE NCE answers ship in the repository; a data folder without a
cache starts from a copy of them, and live answers never touch the tracked copy.
"""
from __future__ import annotations

from experiments.dedale_nce import RECORDED, LiveNCE


def test_a_fresh_data_folder_starts_from_the_recorded_answers(tmp_path):
    for name in ("nce_cache_host.jsonl", "nce_cache_host_steer.jsonl"):
        target = tmp_path / "runs" / name
        recorded = (RECORDED / name).read_bytes()
        nce = LiveNCE(None, cache_only=True, cache_path=target)
        assert target.read_bytes() == recorded                   # copied into the data folder
        assert len(nce.cache) == len(recorded.splitlines()) > 0
    assert (RECORDED / "nce_cache_host.jsonl").exists()          # the tracked copy stays where it is


def test_an_existing_cache_is_left_alone(tmp_path):
    target = tmp_path / "nce_cache_host.jsonl"
    target.write_text("")
    nce = LiveNCE(None, cache_only=True, cache_path=target)
    assert nce.cache == {} and target.read_text() == ""
