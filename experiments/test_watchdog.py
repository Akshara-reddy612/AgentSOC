import os
import subprocess
import time
from pathlib import Path

def run_test(name, env):
    print(f"\n=== TEST: {name} ===")
    
    # We patch run_with_watchdog_B_parallel.py temporarily so it uses fake_harness
    wd_path = Path("experiments/run_with_watchdog_B_parallel.py")
    orig_wd = wd_path.read_text(encoding="utf-8")
    
    patched_wd = orig_wd.replace(
        'cmd = [python, "-m", "experiments.run_paired_clean_eval_B_parallel"]',
        'cmd = [python, "-m", "experiments.fake_harness"]'
    )
    wd_path.write_text(patched_wd, encoding="utf-8")
    
    try:
        proc = subprocess.Popen(
            [sys.executable, str(wd_path)],
            env={**os.environ, **env},
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        
        # for hanging tests we wait and see what happens, we also print processes
        out = ""
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            print(line, end='')
            out += line
            
            if "Killing tree PID" in line or "taskkill stdout" in line:
                # check processes
                print("Checking processes...")
                try:
                    p = subprocess.run(["powershell", "-Command", "Get-Process python* | Select-Object Id, ProcessName"], capture_output=True, text=True)
                    print(p.stdout)
                except Exception as e:
                    print("Error getting processes", e)
        proc.wait()
    finally:
        wd_path.write_text(orig_wd, encoding="utf-8")

import sys
if __name__ == '__main__':
    # Test (a) and (b) combined if we fake an old mtime.
    # We can fake old mtime by just ensuring RESULTS_JSON is touched long ago.
    # Actually wait, test (a): a checkpoint older than the timeout at launch does NOT trigger a kill during the first part of the run.
    results_json = Path("experiments/paired_clean_results_B.json")
    if results_json.exists():
        t = time.time() - 1000 # very old
        os.utime(results_json, (t, t))
    
    # Test (a) and (b): hung harness with child
    run_test("hung_with_child", {
        "FAKE_HARNESS_MODE": "hang_with_child",
        "STALL_TIMEOUT_S": "5",
        "POLL_INTERVAL_S": "2"
    })
    
    # Test (c): exit code 3
    run_test("exit_3", {
        "FAKE_HARNESS_MODE": "exit_3",
        "STALL_TIMEOUT_S": "5",
        "POLL_INTERVAL_S": "2"
    })
