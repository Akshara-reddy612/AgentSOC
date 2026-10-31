"""
Shared test setup.  Checkpoints are signed with a per-user key (soc_server/runner.py, 2026-10-31); the tests use
their own key, so running them never creates one in the user's profile.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True, scope="session")
def _checkpoint_key(tmp_path_factory):
    old = os.environ.get("AGENTSOC_CHECKPOINT_KEY")
    os.environ["AGENTSOC_CHECKPOINT_KEY"] = str(tmp_path_factory.mktemp("key") / "checkpoint.key")
    yield
    if old is None:
        os.environ.pop("AGENTSOC_CHECKPOINT_KEY", None)
    else:
        os.environ["AGENTSOC_CHECKPOINT_KEY"] = old
