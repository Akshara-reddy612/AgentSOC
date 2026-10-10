import sys
import time
import os
import multiprocessing

def child_worker():
    # hang forever
    while True:
        time.sleep(1)

if __name__ == '__main__':
    mode = os.environ.get("FAKE_HARNESS_MODE", "normal")
    if mode == "exit_3":
        print("Fake harness exiting with 3", flush=True)
        sys.exit(3)
    elif mode == "hang_with_child":
        print("Fake harness spawning child and hanging", flush=True)
        p = multiprocessing.Process(target=child_worker)
        p.start()
        # hang forever
        while True:
            time.sleep(1)
    elif mode == "normal":
        # just exit after 2s
        time.sleep(2)
        sys.exit(0)
