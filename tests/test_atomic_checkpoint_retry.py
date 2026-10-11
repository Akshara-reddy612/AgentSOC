"""
2026-10-11: _atomic_checkpoint_write must survive another process/handle
briefly holding the checkpoint open (Windows refuses os.replace then); a v2
held-out run crashed this way when a progress monitor read the file.
"""
from __future__ import annotations

import json
import threading
import time

from experiments.run_paired_clean_eval_B_parallel import _atomic_checkpoint_write


def test_replace_retries_while_target_is_open(tmp_path):
    target = tmp_path / "results.json"
    target.write_text("[]", encoding="utf-8")
    handle = open(target, encoding="utf-8")          # reader holds the file, as the monitor did
    threading.Timer(0.6, handle.close).start()
    t0 = time.time()
    _atomic_checkpoint_write({"a": {"alert_id": "a"}}, target)
    assert json.loads(target.read_text(encoding="utf-8")) == [{"alert_id": "a"}]
    assert not list(tmp_path.glob("ckpt_*.tmp"))      # temp file consumed
    assert time.time() - t0 < 10
