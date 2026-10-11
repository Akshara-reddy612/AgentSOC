# Phase 2 — host logs (Windows clients) — design (draft 2026-10-11)

**Status:** P2-1 running; the rest is a proposal. Builds on the learning Knowledge Store (`experiments/LEARNING_KNOWLEDGE_STORE_DESIGN.md`, steps S1-S9, Phase 1 results in `experiments/DEDALE_PHASE1_RESULTS.md`).

**Goal:** evaluate the store-backed pipeline where DEDALE's attack is actually visible: the Windows clients' own logs. Ground truth here is exact, because DEDALE labels individual host events. This also prepares Phase 3, where NCE reasons over real attacker-influenced text (command lines, PowerShell).

## Data (verified 2026-10-11)

- **File:** `system_logs_winlogbeat.zip` (27.1 GB, MD5-verified): 672 hourly `.jsonl.bz2` members, ECS records from the **30 Windows clients only**. The domain controller / internal server is Linux (auditbeat, 10.9 GB, not downloaded).
- **Volume:** a weekday hour holds ~650,000 records (~1.7 GB uncompressed, ~1 TB for the four weeks), 99.8% Sysmon:
  - file creation 28%, DLL loads 26%, file deletions 22%, process access 17%;
  - DNS 3.7%;
  - process creation ~0.5% (~3,100 / hour);
  - Security logons ~400 / hour;
  - a few PowerShell events.
- **Absent in the inspected hour:** Sysmon registry (12/13), network connections (3), Security 4688 and service installs (7045). DEDALE's labels contain no registry events either, so registry-key persistence may not be visible at all.
- **Labels:** per event, for CLIENT1 (2,153) and CLIENT2 (8,440). Class 1 = malicious, class 2 = malicious-related. They can be joined by (host, channel, record id).

## Steps

1. **P2-1 Extraction (running).** `experiments/dedale_extract_winlogbeat.py`, `dedale/winlogbeat.py`. A parallel one-time pass keeps only the event types detection and the store need:
   - process creation;
   - LSASS access;
   - executable / script / macro-document / archive file creation;
   - named pipes;
   - DNS;
   - logons and special privileges;
   - PowerShell;
   - service installs.

   Output: compact hourly gzip JSONL (~1 MB per hour) plus per-hour counts of every event type. Labels are not read.
2. **P2-2 Label join (scorer side).** An index (host, channel, record id) -> class 1 / 2, kept out of the extracted files (invariant I4).
3. **P2-3 Host knowledge in the store, and novelty rates.** Learned from the training weeks:
   - **identity:** accounts and account -> host logons from 4624. This gives the real `HAS_PRIOR_ACCESS` edges that SSE and the expected-activity rule (`perception/baseline.py`) use;
   - **process lineage:** parent image -> child image, per host;
   - **PowerShell:** commands / script blocks seen.

   Before building any alerting on these, **measure** for each candidate novelty detector in the test weeks: how many benign novelties per day, and what share of labelled malicious events it catches. Phase 1 showed that a plausible detector can be unusable: first-contact network pairs gave 4,400-9,300 per day.
4. **P2-4 Host alert source(s):**
   - **(a) Knowledge Store novelty** (no download): the detectors from P2-3 that pass the measurement, as alerts with structured fields (host, account, images) and free text (command line, script).
   - **(b) Community detection rules (SigmaHQ, DRL 1.1)** evaluated over the extracted events. This is closer to a real SOC's alert stream and not written by us, but **it needs a download (rule set, tens of MB) — ask the user first.** Writing our own rules after looking at the labelled attack would bias the result, so we do not do that.
5. **P2-5 SOC loop for host alerts.** Generalise the loop's case key and entity fields (host, account, image) beyond network alerts; same gate, updater, monitor and analyst condition.
6. **P2-6 Technique vocabulary (decision D6).** Extend `sse.TECHNIQUE_TABLE` / NCE's vocabulary to the techniques host logs show:

   | Technique | Structural check |
   |:--|:--|
   | T1105 ingress tool transfer, T1041 exfiltration over C2 | egress route, like T1071 |
   | T1210 exploitation of remote services | network path to the target's zone |
   | T1021.004 SSH | account access + port 22 |
   | T1003 credential dumping | ADMIN on the host |
   | T1039 data from network share | READ on the share host |

   For techniques with **no structural precondition** (T1566 phishing, T1059 scripting, T1547 autostart, T1005 local data), SSE gets a defined result "not structurally constrained" -> the case goes to review, never auto-approved and never silently dropped. Verified like S1: 0 changes on stored runs.
7. **P2-7 Replay and scoring with exact labels:**
   - alert and case precision / recall against labelled malicious events;
   - coverage per attack step on the clients;
   - benign review load per day;
   - learning safety (no labelled-malicious pattern learned in the gated runs).

## Open decisions (Phase 2)

- **E1 Sigma rules:** download SigmaHQ rules (+ evaluator) as a second alert source? Size / licence to be reported before downloading.
- **E2 Auditbeat** (10.9 GB): the internal server's logs (collection step, SSH from client 1). Download later if the server side is needed.
- **E3 Router 2 Zeek** (green_internal 3.54 GB / orange_servers 3.41 GB): exact labels for internal network traffic (lateral movement). Later.
