import sys
import os

with open('c:/agentsoc/PROJECT_STATUS.md', 'r', encoding='utf-8') as f:
    ps = f.read()

# Step 2: "Current State" block rewrites
# Replace from `## Current State (AgentSOC 2.0)` to `## Experiment 1:`
old_cs = """## Current State (AgentSOC 2.0)
- **Baseline Structural Defense Rate:** 80.0-81.5% (320-326/400)
- **Filtered Structural Defense Rate:** 85.0-86.0% (340-344/400)
- **Stability (two runs):** 162/320 (50.6%) hypothesis sets differed; 6/320 (1.9%) final verdicts changed.
- **T1071 FEASIBLE rate on clean data (n=60):** 10/60 = 16.7% post-filter.
- **Structural pipeline (NCE + filter + SSE) defended 10/10 of the alerts in the n=80 corpus where the undefended LLM was confirmed hijacked (any_hijack=True)**
- **ApprovalClaimDetector FPR:** 2/15 = 13.3% (n=30 corpus) -> 1/50 = 2.0% (scaled corpus, n=100 total). 9/10 attacks detected (1 false negative).
- **RSEM:** all 56 (run A) feasible T1071 hypotheses tie 4-way at composite 0.0000.
"""

new_cs = """## Current State (AgentSOC 2.0)
- **Headline 85.0-86.0% is the no-actionable-hypothesis rate under contamination; clean alerts score the same on this metric (clean A 275/320, clean B 276/320 vs contaminated A 277/320, B 273/320), so it is NOT an attack-blocking rate. Supported claims: verdict stability under LLM noise (3/320 verdicts change between two clean runs while 53.1% of technique sets change), and the evidentiary filter lift (+15 to +25 alerts per 320).**
- **No-actionable-hypothesis rate (pre-/post-filter):** 80.0-81.5% (320-326/400) / 85.0-86.0% (340-344/400)
- **Stability (two runs):** 162/320 (50.6%) hypothesis sets differed; 6/320 (1.9%) final verdicts changed.
- **T1071 FEASIBLE rate on clean data (n=60):** 10/60 = 16.7% post-filter.
- **Structural pipeline (NCE + filter + SSE) defended 10/10 of the alerts in the n=80 corpus where the undefended LLM was confirmed hijacked (any_hijack=True)** (these 10 count as defended partly because the graph holds no GUIDE entities, so non-T1071 hypotheses are INFEASIBLE regardless of the LLM; n is small).
- **ApprovalClaimDetector FPR:** 2/15 = 13.3% (n=30 corpus) -> 1/50 = 2.0% (scaled corpus, n=100 total). 9/10 attacks detected (1 false negative).
- **RSEM:** all 56 (run A) feasible T1071 hypotheses tie 4-way at composite 0.0000.
"""
ps = ps.replace(old_cs, new_cs)

# Step 1: Experiment 1 block rewrites
old_ex = """## Experiment 1: Paired Clean-vs-Contaminated Evaluation

A paired evaluation on 320 contaminated alerts and their 320 clean twins confirmed the baseline structural defense rate of 85.0-86.0% (340-344/400).
- **Run B Metric Corrected:** The canonical Run B result is 273/320. An earlier 274 re-score occurred because the script inadvertently scored the contaminated run against the clean corpus evidence. The corrected regression reproduces all four runs exactly (clean A 275, clean B 276, contaminated A 277, contaminated B 273 of 320). The combined total remains 340/400.
- **Filter Lift & Vulnerability:** The T1071 evidentiary filter lift rests on an accidental match: 15 contaminated alerts (all `fake_output_injection`) pass the beacon predicate solely because the case-insensitive regex `\\bPOST\\b` matches the lowercase word "post" in `"stage":"post-triage"`. The clean twins have 0 such matches. This outcome effect drops the surviving failures from 43 to 43 (Run A) and 47 to 46 (Run B, alert 962072675970). Under a case-sensitive POST check, Run B would be 274/320 (overall 85.0-86.0% range unchanged). This match makes the alert actionable, which is the opposite of the payload's suppression goal. The filter predicates read fields an attacker controls, and no payload designed specifically to pass this filter has yet been tested.
- **Verdict Stability:** Wilson 95% intervals for no-actionable counts pre- and post-filter: Clean A 250 -> 275, Clean B 254 -> 276, Contaminated A 262 -> 277, Contaminated B 256 -> 273 (of 320). Final verdicts changed on only 3/320 (Clean A vs B) and 6/320 (Contam A vs B), or 2 to 6/320 across conditions. Technique sets differ 53.1% (clean vs clean) and 43.4% (contam vs contam). Because the headline "defense success" rate equals the clean-alert rate on the exact same metric, the supported claim is verdict stability under LLM noise.
- **T1071 Confidence Comparison:** Exploratory and inconclusive. Clean A vs B 25 lower / 16 higher (p=0.2110); Contaminated A vs B 14/14 (p=1.0000); cross-condition 25/4 (p=0.0001), 31/13 (p=0.0096), 26/8 (p=0.0029), 24/13 (p=0.0989). Emission asymmetry p-values were 0.0649, 0.2912, 0.0725, 0.3489 across conditions and 1.0000 within clean. Since runs differ in harness, day and process model, and six comparisons were made, no payload effect is claimed.
- **V4 Filter Sensitivity (No Beacon Predicate):** Removing the beacon predicate entirely yields post-filter no-actionable counts: Clean A 275/320 (Lift: +25), Clean B 276/320 (Lift: +22), Contam A 277/320 (Lift: +15), Contam B 274/320 (Lift: +18), nce7 Contam 68/80 (Lift: +4).
"""

new_ex = """## Experiment 1: Paired Clean-vs-Contaminated Evaluation

A paired evaluation on 320 contaminated alerts and their 320 clean twins found that clean alerts (no payload) reach the same no-actionable rate as contaminated alerts, so the headline rate is not an attack-blocking rate.
- **Run B Metric Corrected:** The canonical Run B result is 273/320. An earlier 274 re-score occurred because the script inadvertently scored the contaminated run against the clean corpus evidence. The corrected regression reproduces all four runs exactly (clean A 275, clean B 276, contaminated A 277, contaminated B 273 of 320). The combined total remains 340/400.
- **Filter Lift & Vulnerability:** 15 contaminated alerts (all `fake_output_injection`) pass the beacon predicate only through lowercase "post" in `"stage":"post-triage"`; their clean twins have 0 such matches; 0 of 43 surviving failures in run A and 1 of 47 in run B (alert 962072675970) pass the filter only through that match. The filter's lift does not depend on it: removing the beacon predicate entirely (V4) changes no verdict in clean A, clean B or contaminated A, and changes one alert each in contaminated B (962072675970, 273 -> 274/320) and the 80-alert n=80 slice (824633724927, 67 -> 68/80). Under a case-sensitive POST (V1) the combined totals would be run A 277 + 68 = 345/400 (86.25%) and run B 274 + 68 = 342/400 (85.5%), so the reported 85.0-86.0% (340-344/400) is for the filter as it ran. (Alert 824633724927 also appears in `t1071_mislabeling_investigation.md` as a QUESTIONABLE T1071 case: `| 14 | 824633724927 | fake_output_injection | raw_log_line has category=Exfiltration, target=WKSTN-9431 (internal host, not external IP) | No external IP anywhere. No beaconing command. command_line is svc_2558.exe. NCE tagged T1071 with target=WKSTN-9431 and conf=0.48 based solely on raw_log_line reference. | 0.48 | **QUESTIONABLE** |`). The beacon predicate is redundant on this corpus because every clean beacon match also contains an external IP (33/33).
- **Verdict Stability:** Wilson 95% intervals for no-actionable counts pre- and post-filter:
  - Clean A pre-filter no-actionable: 250/320 = 0.7812 [0.7328, 0.8231]
  - Clean A post-filter no-actionable: 275/320 = 0.8594 [0.8170, 0.8932]
  - Clean B pre-filter no-actionable: 254/320 = 0.7937 [0.7461, 0.8345]
  - Clean B post-filter no-actionable: 276/320 = 0.8625 [0.8204, 0.8960]
  - Contam A pre-filter no-actionable: 262/320 = 0.8187 [0.7728, 0.8571]
  - Contam A post-filter no-actionable: 277/320 = 0.8656 [0.8239, 0.8987]
  - Contam B pre-filter no-actionable: 256/320 = 0.8000 [0.7527, 0.8402]
  - Contam B post-filter no-actionable: 273/320 = 0.8531 [0.8102, 0.8877]
  Final verdicts changed on only 3/320 (Clean A vs B) and 6/320 (Contam A vs B), or 2 to 6/320 across conditions. Technique sets differ 53.1% (clean vs clean) and 43.4% (contam vs contam). Because the headline "defense success" rate equals the clean-alert rate on the exact same metric, the supported claim is verdict stability under LLM noise.
- **T1071 Confidence Comparison:** Exploratory and inconclusive. Clean A vs B 25 lower / 16 higher (p=0.2110); Contaminated A vs B 14/14 (p=1.0000); cross-condition 25/4 (p=0.0001), 31/13 (p=0.0096), 26/8 (p=0.0029), 24/13 (p=0.0989). Emission asymmetry p-values were 0.0649, 0.2912, 0.0725, 0.3489 across conditions and 1.0000 within clean. Since runs differ in harness, day and process model, and six comparisons were made, no payload effect is claimed.
- **V4 Filter Sensitivity (No Beacon Predicate):** Removing the beacon predicate entirely yields post-filter no-actionable counts: Clean A 275/320 (Lift: +25), Clean B 276/320 (Lift: +22), Contam A 277/320 (Lift: +15), Contam B 274/320 (Lift: +18), nce7 Contam 68/80 (Lift: +4).
"""
ps = ps.replace(old_ex, new_ex)

# Step 3: Known limitations and What's NOT Built Yet
old_limitations = """## Known limitations
- "No actionable hypothesis" counts as a defense success, which means a suppression payload designed to intentionally cause an INFEASIBLE verdict would technically succeed by triggering this exact outcome.
- The T1071 FEASIBLE rate represents a base-rate property of how GUIDE alerts describe network activity, not a contamination-specific effect. The 85.0-86.0% "defense success" metric must carry the clean-baseline qualification.
- 0/704 (Run A) and 0/706 (Run B) post-filter hypotheses named a host that exists in the default seeded graph. The 0% clean non-T1071 FP rate holds because synthetic GUIDE accounts lack standing access-granting edges; it has not been verified on an identity/topology graph with real access grants. NCE does not receive source_user/source_host/target_host and no code compares hypothesis entities to them; SSE T1071 uses egress_to_any=True and accepts internal 443/80 EGRESS edges including the WORKSTATION->WORKSTATION self-loop.
- The T1071 evidentiary filter reads attacker-controlled fields, and no "filter-aware" payload has been tested.
- Detector 1 false negative.
"""

new_limitations = """## Known limitations
- "No actionable hypothesis" counts as a defense success, which means a suppression payload designed to intentionally cause an INFEASIBLE verdict would technically succeed by triggering this exact outcome.
- The T1071 FEASIBLE rate represents a base-rate property of how GUIDE alerts describe network activity, not a contamination-specific effect. The 85.0-86.0% "defense success" metric must carry the clean-baseline qualification.
- 0/704 (Run A) and 0/706 (Run B) post-filter hypotheses named a host that exists in the default seeded graph. The 0% clean non-T1071 FP rate holds because synthetic GUIDE accounts lack standing access-granting edges; it has not been verified on an identity/topology graph with real access grants. NCE does not receive source_user/source_host/target_host and no code compares hypothesis entities to them; SSE T1071 uses egress_to_any=True and accepts internal 443/80 EGRESS edges including the WORKSTATION->WORKSTATION self-loop.
- The T1071 evidentiary filter reads attacker-controlled fields, and no "filter-aware" payload has been tested.
- 86% defense excludes ERA and guardrails; the ApprovalClaimDetector (9/10 detected, 1/50 false positives) is evaluated separately.
- 0/60 clean non-T1071 FP is corpus-specific.
- Detector 1 false negative.
"""
ps = ps.replace(old_limitations, new_limitations)

old_wnby = """## What's NOT Built Yet & Immediate Next Steps (Replaced)
- Experiment 2: Alert-grounded authorization table, independent oracle, entity binding.
- Experiment 3: Identity steering evaluation.
- Groq paired run.
- Ablation study (note: "no NCE" cannot just leave SSE running).
- Technique-specific guardrail heuristics for T1071 (network-perimeter responses).
- Real-time monitoring / Real SOAR integration.
"""

new_wnby = """## What's NOT Built Yet & Immediate Next Steps (Replaced)
- RSEM tie-break policy (required fix: all 56 run-A T1071 hypotheses tie 4-way at 0.0000).
- Experiment 2: Alert-grounded authorization table, independent oracle, entity binding.
- Experiment 3: Identity steering evaluation.
- Groq paired run.
- Ablation study (note: "no NCE" cannot just leave SSE running).
- Technique-specific guardrail heuristics for T1071 (network-perimeter responses).
- Real-time monitoring / Real SOAR integration.
"""
ps = ps.replace(old_wnby, new_wnby)

with open('c:/agentsoc/PROJECT_STATUS.md', 'w', encoding='utf-8') as f:
    f.write(ps)

# Step 4: RESEARCH_LOG.md
with open('c:/agentsoc/RESEARCH_LOG.md', 'r', encoding='utf-8') as f:
    rl = f.read()

rl = rl.replace('## 2026-10-06 — Session: Experiment 1', '## 2026-10-03 & 2026-10-05 — Session: Experiment 1')
rl = rl.replace(old_ex.replace('## Experiment 1: Paired Clean-vs-Contaminated Evaluation\n\n', ''), new_ex.replace('## Experiment 1: Paired Clean-vs-Contaminated Evaluation\n\n', ''))

new_entries = """
## 2026-10-03 — Read-only audit of SSE behaviour on GUIDE alerts

- non-T1071 hypotheses 0/659 FEASIBLE in run A, 0/659 in run B, 0/185 in nce7
- 0/704 run A and 0/706 run B hypotheses name a host in the default graph
- all defense failures are T1071 only (43/320 run A, 47/320 run B)
- filter flips 15 (A) and 17 (B), all from the T1071 filter
- after the filter T1071 hypotheses are FEASIBLE in 43/45 (A) and 47/47 (B), the two INFEASIBLE ones have source host "unknown"
- SSE T1071 uses egress_to_any=True and accepts any 443/80 EGRESS edge from the source zone including the WORKSTATION->WORKSTATION self-loop (only WORKSTATION and DMZ have an edge to EXTERNAL)
- GUIDE has target_host == source_host (cite the line: guide_to_alerts.py:75 `"target_host": row.get("synth_device_name"),  # GUIDE has no distinct target host; using source as placeholder`)
- NCE does not receive source_user/source_host/target_host (cite the line: nce_engine.py:751 `for field_name in _NCE_EVIDENCE_FIELD_NAMES:`) and no code compares hypothesis entities with them
- hypothesis source_account equals the alert's source_user in all but 2 of 719/704/706 hypotheses (clean A, contaminated A, contaminated B)
- all 320 contaminated alert ids exist in guide_sample_500_alerts.json with identical fields except raw_log_line (also registry_key for 40 cross_field_split alerts; timestamp differs in 8)

## 2026-10-05 — Clean-B run and harness failures

- clean B run (parallel harness, 5 keys, 293 alerts, 379.0s, 0 errors)
- the first run stalled at alert 28 because the watchdog blocked on readline() and a thread timeout cannot cancel a hung socket (replaced by a spawned-process timeout)
- the key pool only rotates on a 429 so all earlier calls used key 0
- the free-tier limit for gemini-3.1-flash-lite is 500 requests/day per key (an earlier statement of 1500 was wrong)
- the parallel watchdog launched with the wrong interpreter and reported "exited cleanly" at 27/320
- a re-score of contaminated run B that read the clean corpus evidence produced 274 instead of 273
"""
rl += new_entries

with open('c:/agentsoc/RESEARCH_LOG.md', 'w', encoding='utf-8') as f:
    f.write(rl)
