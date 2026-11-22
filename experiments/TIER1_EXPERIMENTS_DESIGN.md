# Paper revision, Tier 1: the remaining offline experiments (design, 2026-11-22; FOR APPROVAL, nothing run yet)

Decision P10 (`PROJECT_PLAN.md`). Same rules as A10 (`experiments/PERSUADED_ANALYST_DESIGN.md`):
- recorded LLM answers only, no API call;
- no change to `perception/`, `soc_server/`, `review_api/` or `frontend/`;
- new replay options default to today's behaviour;
- runs go to `<data>/runs/` under new tags.

A9 (detection metrics) needs no replay. It is built from the frozen `final_host_scores.json` by `experiments/detection_metrics.py`, done 2026-11-22.

## A7: a simple memory baseline (review: "empty store is a straw man")

**What already answers it:** the *frozen* condition is exactly "an allowlist of every pattern seen in the two clean weeks". It gives the same 65.2 reviews/day as the gated store (`RESULTS.md` C2). So the paper must compare against frozen, not against the empty store; that is a writing fix.

**New baseline:** a frequency threshold, the usual stricter allowlist. A pattern counts as normal only if it was seen at least *k* times in the clean weeks.
- **How:** a replay option `--min-train-count K`. At the end of training, the replay retracts training-learned edges whose recorded `count` is below *K*, so they alert again. This is experiment code, using `KnowledgeDB.retract_edge`, which the store already allows for non-config edges.
- **Conditions:** host logs, NCE off, no analyst, *K* = 2, 5, 10, each as frozen and as gated. That is 6 replays.
- **Measures:** reviews per day; attack cases raised; labelled events alerted; precision (as A9).
- **Prediction:** higher *K* gives more reviews and no better attack coverage, so the clean-weeks allowlist is the stronger simple baseline.

## A8: exercising the learning gate (review: "the gate admitted 0 edges")

**Why the gate looks idle:** under asymmetric trust and with D7 on, nothing is dismissed without an analyst, so the gate has nothing to learn. It works only where cases are dismissed. So the delay is swept where it does work:
- host gated + NCE, acting rule: `F_nce` learned 13 lineage keys through the gate;
- network gated with D7 off: `F_noact` learned 67 + 549 edges.

**Delay sweep:**
- **How:** a replay option `--gate-delay HOURS` on both replay scripts. `SocLoop` already takes `gate_delay`; the default 24 h stays.
- **Conditions:** 1 h, 72 h, 168 h (24 h is the frozen run). That is 6 replays.
- **Measures:**
  - edges learned through the gate (`closed_benign`);
  - gate drops;
  - attack patterns learned;
  - for the network run, whether the dropper download (`sid 2027262 client2 → 172.19.1.1`) is learned;
  - reviews per day.

**Unlearning-lookback sweep (review B, "make unlearning realistic"):**
- **How:** a replay option `--unlearn-lookback DAYS`. It sets `perception.soc_loop.UNLEARN_LOOKBACK` for that run only; the module constant itself is not edited.
- **Conditions:** host gated + analyst missing 20% (the C3 condition), B5 on, lookback 1, 3 and 14 days (7 is frozen), 10 seeds each. That is 30 replays.
- **Measures:** attack patterns learned at the end; labelled events alerted; reviews per day; the false-alarm cost (also on the 5% false-alarm analyst, seed 0).

## A11: analyst mistakes over many draws (review: "one apparent run")

- **What:** the C3 conditions repeated over 10 seeds: misses 5% and 20%, false alarms 5%, each with B5 on and off. The replay already has `--analyst-seed`; seed 0 is the frozen run. That is 6 conditions × 9 new seeds = 54 replays.
- **Report:** mean ± sd and min / max for attack patterns learned, labelled events alerted and reviews per day, next to the frozen seed-0 values.

## Size and order

- **Total:** about 96 replays. At 6 workers (memory is the limit, about 450 MB per replay) that is **about 2 h of compute**, after the A10 grid.
- **Order:** A7 and the gate sweep first (12 replays, about 20 min), then A11, then the lookback sweep.
- **Checks:** with every new option at its default, a replay equals its frozen run byte for byte (one check per option); plus the full test suite.
- **Results:** `experiments/dedale_results/tier1_scores.json`, and new tables in `experiments/build_results.py` (`RESULTS.md`). Existing tables stay unchanged.

## Not in Tier 1

These need their own decision (`PROJECT_STATUS.md`, next steps):
- low-and-slow poisoning (a new attacker simulation);
- escalation flooding;
- second dataset;
- hardened-prompt baselines (API budget);
- adaptive attacker.
