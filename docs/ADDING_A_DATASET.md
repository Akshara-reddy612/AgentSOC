# Adding a dataset (E3: AIT-LDS)

How to bring a third dataset into AgentSOC: the readers, the environment model, the experiments that test claims C2–C3 on it, and the demo. DEDALE went through every step below, so each step points at its DEDALE file to copy from.

The plan (`PROJECT_PLAN.md`, section 4) scopes this as optional milestone M6: AIT-LDS v2, 2 of its 8 networks, about a week of work. Its main new piece is host detection for Linux logs.

## Rules that do not change

These invariants (`experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`) hold for every dataset. Each one has a test somewhere; keep it that way.

| | Rule | In practice |
|:--|:--|:--|
| I1 | The store learns structured fields only, never free text | Detector keys use hosts, accounts, program paths, ports and ids. Never command lines or messages. |
| I2 | No look-ahead | Replays are single-threaded on the events' own clock. |
| I3 | The learning gate | After the training window, only cases closed benign are learned, after a delay, and only if nothing near them was escalated. |
| I4 | Labels never enter the pipeline | Labels are read by scorers (and an attacker simulation) only. The environment model holds what a real operator would know: the inventory and network plan, never the attacker's machines. |
| I5 | Actions are simulated | Containment never touches real systems. |
| I6 | Single writer, append-only audit | Only the loop writes the Knowledge Store, and every write is logged. |

## Steps

### 1. Get the data

- **Ask first.** Report the size, licence and disk space. Downloads need explicit approval, and "yes" to a plan is not approval to download.
  - AIT-LDS v2 is CC BY-NC-SA 4.0. Check what non-commercial means for the paper and the demo.
- **Store it outside the repository:** `<data>/aitlds/`. `<data>` is `AGENTSOC_DATA_DIR`, or `../agentsoc_data` by default.
- **Write data notes** like `experiments/DEDALE_DATA_NOTES.md`:
  - what each file holds and its time range;
  - which hosts it covers;
  - where the labels are, and what was verified by reading the files rather than the documentation.

### 2. A package for the dataset

Create `aitlds/`, shaped like `dedale/`.

| File | Like | Holds |
|:--|:--|:--|
| `aitlds/__init__.py` | `dedale/__init__.py` | `data_dir()` |
| `aitlds/<logs>.py` | `dedale/winlogbeat.py`, `dedale/suricata.py` | Readers that stream the raw files into **host events** and / or **network alerts** (shapes below) |
| `aitlds/environment.py` | `dedale/environment.py` | `AITLDS_PROFILE` (an `EnvironmentProfile`), `INVENTORY` (hosts, tiers, zones, addresses) and `seed_store(db, at)` |

**The environment profile** (`perception/environment.py`) needs:
- the internal networks and domain suffixes;
- the hostname pattern;
- each zone's egress policy;
- `observed_hosts`: the hosts whose logs you ingest. SSE treats the rest as unknown, not impossible (the open-world rule; C4 shows why it matters).
- `four_eyes_min_tier`.

Write down every assumption, as DEDALE's module docstring does.

**Network alerts** (`dedale/suricata.py:to_alert`) are dicts with:
- `alert_id`, `timestamp`, `event_type`, `source_system`, `sensor`;
- `generator_id`, `signature_id`, `signature_rev`, `signature`, `classification`, `priority`, `severity`;
- `protocol`, `src_ip`, `src_port`, `dst_ip`, `dst_port`;
- `raw_log_line`, the only free text.

If the dataset has IDS alerts, convert them to this shape and the network path works unchanged: case building, learning, NCE, SSE, containment, the demo.

**Host events** (`dedale/winlogbeat.py:compact`) are small dicts:
- `t`, `host`, `rid`, plus a channel and code (`ch`, `code`);
- the structured fields a detector needs (for example `image`, `parent_image`, `user`);
- free-text fields kept apart (`cmd`, `script`, ...).

### 3. Host detection for Linux logs

`perception/host_detection.py` has the Windows detectors in `DETECTORS`: `lineage`, `pipe`, `exec_file_write`, `powershell`, `logon` and `lsass_access`.

A detector is a `HostDetector(name, key, edge)`:
- `key(event)` returns the structured key of a host event, or `None` if the detector does not apply.
- `edge(key)` returns the Knowledge Store edge that learning it creates.

An event whose key the store has not learned becomes an alert.

For AIT-LDS, add Linux detectors, for example:
- process start from auditd `execve` (parent → program);
- logins from `auth.log` (user, source address, method);
- `sudo` (user → command path);
- new listening ports.

Put them in their own module and register them in `DETECTORS`. Test each one with small events, as `tests/test_host_detection.py` does.

### 4. Labels, for scoring only

- Write a label loader like `experiments/dedale_host_novelty.py:load_host_labels`. AIT-LDS labels lines.
- Write a scorer like `experiments/dedale_host_score.py`.
- Only scorers import them (I4).

### 5. The replays

Copy `experiments/dedale_host_replay.py` (and `experiments/dedale_replay.py` for network alerts) to `experiments/aitlds_*`:

- **Training window:** the dataset's benign period (DEDALE: `TRAINING_START`, `TRAINING_END`). Choose it from the data notes, not from the labels' attack times.
- **Conditions:** keep the same options:
  - `--mode static|frozen|gated|ungated`;
  - `--analyst oracle` with `--analyst-delay`, `--analyst-miss` and `--analyst-false-alarm`;
  - `--nce off|cache|live`, `--no-unlearn`, `--case-store`.
- **Outputs:** each run writes `summary.json`, its alerts and its case store under `<data>/runs/`.

### 6. Freeze and score

- Copy `experiments/freeze_dedale.py`: it runs every condition behind a claim on the final code and writes `experiments/aitlds_results/final_*_scores.json`.
  - Keep the score keys DEDALE uses (`reviews_per_day.mean` / `.by_day`, `labelled_events_alerted`, `cases_by_ground_truth`, `attack_keys_learned_as_routine`, ...), so the table and figure code can be reused.
- Add an AIT-LDS section to `experiments/build_results.py`, the generality check of C2–C3, and to `experiments/build_figures.py` if the paper gets a figure for it.
- Update `REPRODUCE.md`.

### 7. LLM answers

- Running NCE live on the new alerts costs API calls. **Estimate the calls and get the budget approved before any live run.**
- Record the answers in a cache with `experiments/dedale_nce.py:LiveNCE(cap, cache_path=<data>/runs/nce_cache_aitlds.jsonl)`. The frozen runs then replay that cache with no further calls.

### 8. The demo

- Register the dataset in `soc_server/datasets.py`: a `Dataset` with profile, seed, training window, demo start, source factories, NCE cache and comparison scores file.
- Then `python -m soc_server --dataset aitlds` replays it. The console follows: header label, host lists and Metrics comparison all come from the dataset.
- Check it with `python tools/e2e_check.py --url http://127.0.0.1:8000 --user <you> --password-file <file>`.

### 9. Paper and tracking

- **Paper:** add the generality check to Results (C2–C3 on a second real dataset), its limits to the Discussion, and the dataset to the references.
- **Tracking docs:** update `PROJECT_STATUS.md` in place, append to `RESEARCH_LOG.md`, and add what may and may not be claimed to `experiments/PAPER_CLAIMS_TO_REVISE.md`.

## Checklist

- [ ] Download approved; data notes written
- [ ] Readers and environment model, with tests
- [ ] Linux detectors, with tests
- [ ] Label loader and scorer (scorer side only)
- [ ] Replays for every condition; frozen scores
- [ ] LLM budget approved; answers recorded in a cache
- [ ] `build_results` / `build_figures` / `REPRODUCE.md` updated
- [ ] Registered in `soc_server/datasets.py`; e2e check passes
- [ ] Paper section; tracking docs
