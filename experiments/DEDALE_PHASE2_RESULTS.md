# DEDALE Phase 2 results — host logs, Knowledge-Store detection (2026-10-11)

**Question:** can the learning Knowledge Store detect DEDALE's attack on the Windows clients themselves, from their own logs, and at what analyst cost?

- Ground truth is **exact**: DEDALE labels individual malicious host events (class 1 = malicious, class 2 = malicious-related).
- NCE (the LLM) was off, so **no API calls**.
- Design: `experiments/PHASE2_HOST_LOGS_DESIGN.md`. Phase 1 (network alerts): `experiments/DEDALE_PHASE1_RESULTS.md`.

## Setup

- **Data:** all 672 hours of winlogbeat (30 Windows clients, 188,115,925 records). A one-time extraction kept 13,548,274 events (7.2%): process creation, named pipes, executable / script / macro / archive file writes, PowerShell, logons, LSASS access, DNS.
- **How detection works:** each detector turns an event into a structured key. The training weeks (2024-12-23 .. 2025-01-05, benign) teach the store every key it sees. In the test weeks (2025-01-06 .. 2025-01-19) **an event whose key the store has not learned becomes a host alert**, and alerts go through the same case builder, triage gate, outcome monitor and gated learning as in Phase 1.
- **Detectors** were chosen *before* the replay, from a measurement of benign novelty vs labelled attack events (`experiments/dedale_results/phase2_novelty.json`):

  | Detector | Key | Benign new keys / test day | Labelled class-1 events on a new key |
  |:--|:--|--:|--:|
  | lineage | host, parent program, program | 22.8 | 70 / 84 |
  | named pipe | host, program, pipe name | 0.6 | 229 / 245 |
  | executable file write | host, program, file type | 1.0 | 67 / 68 |
  | PowerShell | host, SHA-256 of normalised script text | 0.1 | 34 / 76 |
  | logon | host, account, logon type, source | 0.1 | no labelled logons |
  | LSASS reader | host, program | 0.1 | no labelled LSASS access |
  | *not used:* command-line shape | | 2,467 | 84 / 84 |
  | *not used:* DNS domain | | 396 | 3 / 12 |

- **Learned in the training weeks:** 4,397 lineage keys, 929 pipe keys, 557 file-write keys, 150 script fingerprints, 359 logon keys (240 first logons -> `HAS_PRIOR_ACCESS`), 92 LSASS readers.
- **What is never learned:** command lines and script text (invariant I1). The store keeps only a fingerprint of PowerShell scripts.
- **Runtime:** ~2 min per replay.
- **Reproduce:**
  - `python -m experiments.dedale_extract_winlogbeat` (once, ~1 h)
  - `python -m experiments.dedale_host_novelty`
  - `python -m experiments.dedale_host_replay --mode <mode> [--analyst oracle] --overwrite`
  - `python -m experiments.dedale_host_score`

## Results (test weeks, 14 days)

| Run | Host cases | Reviews / day (week 1 -> week 2) | Attack cases surfaced | Labelled attack events alerted | Attack keys learned as routine |
|:--|--:|:--|:--|--:|--:|
| static (nothing learned) | 85,336 | 6,095.4 (6,119.6 -> 6,071.3) | 80 / 80 | 473 (+ 37 class 2) | 0 |
| frozen (training only) | 913 | 65.2 (42.3 -> 88.1) | 72 / 72 | 400 | 0 |
| gated | 913 | 65.2 (42.3 -> 88.1) | 72 / 72 | 400 | 0 |
| ungated | 384 | 27.4 (20.3 -> 34.4) | 38 | **99** | **38** |
| **gated + analyst** | **432** | **30.9 (25.0 -> 36.7)** | **72 / 72** | **400** | **0** |

All test-week host cases go to REVIEW (NCE off: nothing reasons about them). "Attack cases" = cases containing at least one labelled class-1 event.

**Attack steps** on the clients (gated and gated + analyst; step times from the published timeline):

| Step | First case after | What surfaced it |
|:--|--:|:--|
| Initial access, client 2 (01-06 10:00) | 1.2 min | PowerShell writing the dropper archive (new file-write key) |
| Lateral movement to client 1 (01-08 15:00) | 28.5 min | `taskhostw.exe -> ...\AppData\Local\Temp\svcmon.exe --fetch-command-url ...` (new lineage) |
| Collection window, client 1 (01-10 11:00) | 30 min | a new named pipe of `svcmon.exe` |
| Exfiltration window, client 1 (01-11 11:00) | 21 h | a later relaunch of `svcmon.exe` (new lineage) |

## What this shows

0. **Without learned knowledge, host telemetry is unusable.** The static run raises 3,142,395 host alerts in 85,336 cases (~6,095 reviews/day). Every labelled attack event alerts, but it is buried. Learning the benign weeks cuts this ~94x (65/day), and ~197x with analyst feedback (31/day).
1. **Knowledge-Store novelty detects this APT on the hosts.**
   - Every case that contains labelled malicious activity reaches an analyst: 72 of 72 in frozen / gated / analyst.
   - The first step surfaced within ~1 minute.
   - 400 labelled class-1 events raised alerts; that is 85% of the 473 labelled class-1 events of the detected event types.
   - The same attack was almost invisible to Suricata (Phase 1: 1 of 84 labelled flows alerted).
2. **Without feedback the review load grows.** Gated learning without an analyst = frozen = 65 reviews/day, rising from week 1 to week 2: benign new process lineages recur and nothing vouches for them (lineage causes 853 of the 913 cases).
3. **Analyst feedback halves the load and stays safe.** With verdicts (360 benign, 72 malicious) the load drops to 30.9/day. Benign new keys are learned, and nothing malicious is: all 72 attack cases still surface and 0 attack keys are learned.
4. **Ungated learning is unsafe, now measured exactly.** Its load is similar (27.4/day), but it learned 38 attack keys as routine after their first occurrence and silenced **301 of the 400** attack event alerts. The exfiltration-window step disappeared completely. This is the Knowledge-Store poisoning risk the learning gate exists for.

## Limitations

- **NCE was off.** Every novel case goes to an analyst; nothing reasons about it yet (Phase 3).
- **Labelled-event coverage of the kept types:** only 590 of the 10,593 labelled client events are of the kept types (most are DLL loads and ordinary file writes, which were dropped as too voluminous). Registry events are not logged in DEDALE at all, so registry persistence is invisible.
- **Only the Windows clients:** the internal server (Linux, auditbeat) and router 2's internal network traffic are not covered.
- **Step matching is by time window.** The "exfiltration" first case is the next relaunch of the malware, not the exfiltration transfer itself.
- **The simulated analyst is perfect** (it reads the labels) and answers after exactly 4 h.
- **One attack scenario, 30 hosts.**

## Next

**Phase 3:** live NCE on the review cases, ~30-65 per day — well inside the Gemini quota, but it needs an API budget approval. NCE uses the extended technique vocabulary (decision D6) and sees the real command lines and scripts. The question: does reasoning separate the benign new lineages from the attack, and does contamination of the evidence change that?
