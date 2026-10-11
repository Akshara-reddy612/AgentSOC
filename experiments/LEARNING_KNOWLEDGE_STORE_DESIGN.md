# Learning Knowledge Store and monitoring feedback loop — design (draft 2026-10-11)

**Status:** proposal for team review. Nothing below is implemented yet. Decisions marked **[OPEN]** need an answer before the step that depends on them.

**Goal:** build the two parts of the base paper (AgentSOC, ICAIC 2026, arXiv 2604.20134) that the project does not have yet. The first is the Internal Knowledge Store's *dynamic behavioural knowledge*. The second is the *Real-Time Monitoring* feedback loop (§III-D; workflow steps 7-8 in §III-E). We then evaluate them on real telemetry (DEDALE) replayed in time order. The same store becomes the persistent store for the analyst review loop (plan item B).

## 1. Paper vs. today vs. this design

| Paper element | Today (verified in code, 2026-10-11) | This design |
|:--|:--|:--|
| Knowledge Store, static context (CMDB, IAM, topology) | `KnowledgeStoreGraph` is rebuilt on every run from synthetic seeds (`enterprise_model.py`, `network_model.py`, toy store) | Built from a per-environment **profile** (the dataset's documented hosts, zones, address ranges, roles) |
| Knowledge Store, dynamic knowledge ("historical traces, telemetry deltas, derived indicators, post-execution state") | None. The pipeline never writes to the store, and nothing is saved between runs (RSEM writes only to dry-run copies) | Learned from the telemetry stream and from decisions; saved to disk; every fact versioned (`KnowledgeFact` already has version / source / timestamp / audit_history) |
| Noise Reduction (§III-A) | `perception/noise_reducer.py` clusters one batch on trusted fields; no memory across batches | **Case builder with memory**: later alerts attach to an open case instead of re-running the pipeline |
| Real-Time Monitoring (§III-D) | `monitoring/` = alert stream runner (queue -> one worker -> pipeline -> in-memory deque of 500 -> dashboard); NCE from old cache files; the dashboard asserts "graph immutability" | Keep the runner; add the **outcome monitor**: correlate new alerts with earlier decisions, record (simulated) containment effect, feed results back into the store |
| Step 8 "Knowledge Store is updated for subsequent cycles" | Not done | `KnowledgeUpdater` (single writer, gated, audited) |

**Gap found while designing:** `network_model.is_internal_address()` hard-codes RFC 1918. DEDALE's simulated internet, including the attacker (172.19.1.1, 172.19.2.1, 172.19.0.2), lies inside 172.16.0.0/12. Today's pipeline would therefore treat the attacker as *internal*, so the known-bad escalation and the T1071 destination checks would never fire. Internal ranges must come from the environment profile (step S1).

## 2. Invariants

These are the safety properties the implementation must keep, and each one gets a test.

- **I1 Trusted-only writes.** The store learns only from structured telemetry fields: addresses, ports, protocol, host and account identifiers, signature / event ids, timestamps. It also stores pipeline decisions and analyst actions *as records*. It never learns from NCE output or free text (command lines, messages, signature prose). Otherwise a prompt injection could write itself into long-term memory (memory poisoning). This carries the project's existing trust split (STRUCTURED vs FREE_TEXT) over to memory.
- **I2 No look-ahead.** An alert at time *t* is triaged against the store as it was after all events before *t*. Replay is single-threaded on a virtual clock.
- **I3 Learning gate (anti-poisoning).** "Normal" (baseline patterns, prior-access and communication edges) is learned only from:
  - (a) the training window;
  - (b) cases that ended LOW_PRIORITY / NO_ACTIONABLE, after a quarantine delay *D* with no escalation on the same entities in the meantime;
  - (c) analyst closure as benign.

  A case that went to REVIEW never becomes "normal" unless an analyst closes it as benign. Without this gate the store would learn the attacker's own traffic as normal during the attack weeks.
- **I4 Labels never enter the store.** Dataset labels, the published attack timeline and the attacker IPs are used only by the scorer. The environment profile contains only what a real enterprise would know (its own CMDB / network plan), not attacker infrastructure.
- **I5 Actions stay dry-run.** Simulated action effects (e.g. "destination blocked") live in a separate simulated layer. They never overwrite observed facts.
- **I6 Single writer, append-only audit.** Only `KnowledgeUpdater` writes. Every write is an append-only log entry. Facts keep their version history, so any store state can be rebuilt or rolled back.

## 3. Components

```
source adapters (DEDALE Suricata, later DEDALE winlogbeat / Zeek, corpus v2)
        |  time-ordered observations + alerts (common dict format)
        v
case builder (noise reduction with memory) ----> attach to open case (no pipeline run)
        |  new or materially changed case
        v
triage gate (store lookups, no LLM) -----------> LOW_PRIORITY / cached decision / escalation
        |  needs reasoning
        v
NCE budget queue (daily call budget, priority, evidence-hash cache)
        v
existing pipeline: grounding -> alert context -> SSE -> RSEM -> guardrails -> outcome
        v
outcome monitor (watches on decided entities)  --> KnowledgeUpdater (gated, audited) --> store
```

- **Environment profile** (static, one per dataset): internal address ranges, zones, host table (address -> host name, role, criticality tier, zone), known accounts and groups if documented. Loaded into the store as `source = config`.
- **Source adapters** turn raw records into (i) *observations*, which only update the store, and (ii) *alerts*, which go to triage. For DEDALE Suricata every alert is also an observation. Later, Zeek conn.log / Sysmon events become observations that teach the store, and Sigma-style hits become alerts.
- **Case builder.** Key = (signature id, source address, destination address). A case stays open until idle for a window *W* **[OPEN D3]**. Later alerts update count / last_seen. The case is re-triaged only on a material change: a new escalation on one of its entities, a jump in volume, or a change of priority.
- **Triage gate** (before any LLM call), in order:
  1. escalation rules on trusted fields (known-bad indicator, ERA, contact with an entity under watch);
  2. pattern is learned baseline and no escalation -> LOW_PRIORITY, no NCE call;
  3. decision cache hit (same pattern, same store version of its entities) -> reuse;
  4. otherwise -> NCE queue.
- **NCE budget queue.** Holds a daily call budget (current free tier: 5 Gemini keys × 500 requests per day). Cases are ordered by escalations first, then target criticality, then novelty. Results are cached by evidence hash. Cases left over at the end of the day are counted as **backlog**, which is a reported metric.
- **Outcome monitor** (the paper's Real-Time Monitoring). Every decision with an action registers a *watch* on the targeted entity for a period. Later alerts and observations that touch a watched entity are linked to the decision. That gives: would the action have blocked them (simulated, I5)? Did activity continue (deviation flag)? Results are written back as decision-outcome facts.
- **Persistent store.** SQLite file per run **[OPEN D4: location]**. The NetworkX graph that SSE / baseline / RSEM read is a *projection* of the store, built at load time and kept in sync by the updater. SSE, RSEM and baseline need no interface change.

## 4. Store schema (SQLite, first version)

| Table | Columns (main) | Notes |
|:--|:--|:--|
| `entities` | id, kind (host / account / address / domain / zone / group / service), attrs, first_seen, last_seen | |
| `facts` | entity_id, key, value, version, confidence, source, ts | one row per `KnowledgeFact` version (history kept) |
| `relations` | src, dst, kind (COMMUNICATES_WITH, HAS_PRIOR_ACCESS, MEMBER_OF, GRANTS, HOSTED_IN, EGRESS), port, proto, count, first_seen, last_seen, learned_from (config / training / closed_benign / analyst) | `learned_from` makes I3 auditable |
| `patterns` | signature_id, src, dst, count, first_seen, last_seen, status (baseline / candidate / escalated) | |
| `indicators` | address, reputation, confidence, source (config_threat_intel / analyst_confirmed), ts | |
| `cases` | case_id, key, opened, last_seen, alert_count, status, outcome, nce_used, store_version_at_decision | |
| `decisions` | case_id, ts, actions, playbook statuses, guardrail reasons | |
| `watches` | decision_id, entity, until, hits | |
| `analyst_actions` | case_id, analyst, action (approve / reject / close_benign / close_malicious), ts, note | plan item B |
| `ks_log` | seq, ts, writer, op, payload | append-only audit (I6) |

## 5. What is learned, from what

| Knowledge | Learned from | Phase available |
|:--|:--|:--|
| Who talks to whom (COMMUNICATES_WITH, port, proto) | Suricata src/dst now; Zeek conn.log later | Suricata phase |
| Routine detection patterns (signature, src, dst) | training window + gate (I3) | Suricata phase |
| Account -> host prior access (HAS_PRIOR_ACCESS) | Windows logon events (4624 etc.) | winlogbeat phase |
| Host roles, zones, criticality | profile only, never learned (traffic must not be able to make a host look like a server) | profile |
| Known-bad indicators | config threat intel; analyst confirmation **[OPEN D1]** | both |

## 6. Replay and evaluation protocol

- **Data:** DEDALE. Training window = 2024-12-23 .. 2025-01-05 (benign by design; the dataset authors recommend weeks 1-2 for training/calibration). Test window = 2025-01-06 .. 2025-01-19.
- **Conditions (ablation):**
  - C0 static store (today's behaviour);
  - C1 baseline learned in training, then frozen;
  - C2 learning continues during test with the gate;
  - C3 learning continues without the gate (shows the poisoning risk).
- **Metrics:**
  - alerts -> cases reduction;
  - analyst review load (cases per day);
  - NCE calls per day and backlog;
  - per attack step from the published timeline (infection 01-06, lateral movement 01-08, collection 01-10, exfiltration 01-11): first escalation and time to it;
  - review load on benign cases;
  - handling of the 3 confirmed false positives;
  - simulated containment: attack-related events after the first decision on the entity.
- **LLM:** first run fully offline (deterministic layers, NCE disabled or mocked). Live NCE only through the budget queue, and only after the user approves the call budget.
- **Ground truth (scorer only):** published timeline + attacker / victim addresses for the Suricata phase; host labels (class 1 / 1+2) and Zeek flow labels in later phases.

## 7. Implementation steps

Each step is a commit with tests and tracking-doc updates.

1. **S1 Environment profile + configurable internal ranges.** The default profile reproduces today's behaviour (re-score of stored runs must show 0 changes).
2. **S2 Persistent store** (SQLite, `KnowledgeFact` mapping, graph projection, audit log).
3. **S3 DEDALE Suricata adapter + DEDALE profile.** The profile is built from DEDALE's documented architecture; the architecture page still has to be read.
4. **S4 Case builder with memory.** Extends `NoiseReducer` rather than replacing it.
5. **S5 KnowledgeUpdater + learning gate (I1, I3).**
6. **S6 Triage gate, decision cache, NCE budget queue.**
7. **S7 Outcome monitor (watches).**
8. **S8 Replay runner** (synchronous, virtual clock). It reuses the pipeline adapter; the threaded `monitoring/` worker can later consume the same components for live mode.
9. **S9 Scorer + report** (conditions C0-C3).
10. **B** analyst API on `analyst_actions` / `decisions` (separate plan).

## 8. Open decisions

- **D1 Indicators without an analyst during replay.** (a) Indicators only from config, so nothing is confirmed during replay. (b) A simulated analyst that closes REVIEW cases using the labels, reported as a separate "with analyst feedback" condition. This is realistic, because analysts establish ground truth, but it must be kept apart from C0-C3.
- **D2 Replace the monitoring invariant** "graph immutability" with "single writer, trusted-only, audited" (I1, I6). The invariant is enforced today by `test_graph_immutability_during_monitoring`. That test would be kept for the pipeline stages (SSE / RSEM / guardrails must still never write), and new tests would cover the updater. The dashboard text changes when the frontend is rebuilt.
- **D3 Case window *W*** and learning-gate delay *D*: tune on the training window only.
- **D4 Store location:** `D:\agentsoc_data\ks\` (outside the repo, next to the data) vs `logs/` (git-ignored).
- **D5 Second dataset for generalization** (see §9). Needs download approval.

## 9. Dataset choice

DEDALE is the development dataset. It is the only verified candidate that has all of: multi-host Windows + Linux + network telemetry, a two-week benign period to learn from, per-event labels and a published attack timeline (details: `experiments/DEDALE_DATA_NOTES.md`).

Its limits:
- one attack execution, so few positives and results from a single scenario;
- host labels for only 3 hosts;
- Suricata nearly blind to this attack;
- benign activity generated by a user simulator (AURA), not real people.

The design is dataset-agnostic (source adapters + environment profile), so a second dataset can be added without redesign. Candidates (from web search 2026-10-11, **not verified by download**):
- **AIT Alert Data Set (AIT-ADS):** alerts from Suricata, Wazuh and AMiner over 8 executions of a multi-step attack, with attack-phase labels. It gives more attack instances and already-labelled alerts, but it is Linux / web-centric.
- **LANL comprehensive cyber-security events:** the base paper's dataset. Real (de-identified) enterprise, 58 days, ~12 GB compressed, red-team events. It is ideal for learning an identity graph at real scale and allows a direct comparison with the base paper, but it has no free text, so it cannot test NCE or contamination.
