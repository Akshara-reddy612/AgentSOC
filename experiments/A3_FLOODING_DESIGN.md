# A3: escalation flooding (design, 2026-11-23)

Reviewer checklist A3 (flooding); paper limitation (6) "escalation flooding was not evaluated". Offline replays of
DEDALE host logs, NCE off, no API call. Experiment code only (`experiments/dedale_flood.py`, `--flood` in
`experiments/dedale_host_replay.py`, `experiments/flood_eval.py`); no pipeline module changes.

## Attacker

While it controls a host, the attacker launches harmless programs the store has never seen, `rate` per hour, each
from a new path (`explorer.exe -> C:\Users\Public\Tools\updater_<i>.exe`). Each has a new process-lineage key, so each
opens its own case (the case key is the detector key) and goes to review. Footholds: CLIENT2 from initial access
(2025-01-06 10:00), CLIENT1 from lateral movement (2025-01-08 15:00), both until 2025-01-12. Rates 5 and 50 per hour
(about 120 and 1,200 junk cases per host per day). Junk events carry record ids no label carries.

## What is measured

The flood cannot hide an alert: every new key still reaches review. What it can do is bury the attack in the queue.
Each day's review cases are ordered as `experiments/dedale_queue_eval.py` orders them at the end of the day:

- **v2:** `review_service.priority` with all factors. With NCE off, the factors are host tier, other cases on the
  same host in 24 h (capped at +25), alert count and waiting time. The flood also raises the peer factor of the attack
  cases, because they are on the same host.
- **fifo:** oldest first.

An analyst team that reviews K cases a day (K = 25, 50, 100, 200; the unflooded queue averages 65 a day) reviews the
day's top K. Reported: attack cases within the top K, the median rank, and for each of the four attack steps whether
one of its cases is within the top K of its day.

Runs: `gated --case-store` with no flood (baseline, the frozen F_gated condition plus a case store), 5 and 50 per hour.

## Expected, before running

The flood and the attack are on the same hosts and look alike to the priority function without NCE, so the attack's
cases should sink in proportion to the flood. Whatever the result, it is reported as a result or a limitation; the
pipeline is not changed before submission (user, 2026-11-22).
