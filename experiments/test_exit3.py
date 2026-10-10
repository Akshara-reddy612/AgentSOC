import os, subprocess, sys, time
from pathlib import Path
wd_path = Path('experiments/run_with_watchdog_B_parallel.py')
orig_wd = wd_path.read_text(encoding='utf-8')
patched_wd = orig_wd.replace('cmd = [python, "-m", "experiments.run_paired_clean_eval_B_parallel"]', 'cmd = [python, "-m", "experiments.fake_harness"]')
wd_path.write_text(patched_wd, encoding='utf-8')
try:
    env = {**os.environ, 'FAKE_HARNESS_MODE': 'exit_3', 'STALL_TIMEOUT_S': '5', 'POLL_INTERVAL_S': '2'}
    proc = subprocess.run([sys.executable, str(wd_path)], env=env, capture_output=True, text=True)
    print(proc.stdout)
finally:
    wd_path.write_text(orig_wd, encoding='utf-8')
