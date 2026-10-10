import sys

with open('c:/agentsoc/PROJECT_STATUS.md', 'r', encoding='utf-8') as f:
    content = f.read()

new_section = """
## Experiment 1: Paired Clean-vs-Contaminated Evaluation

A paired evaluation on 320 contaminated alerts and their 320 clean twins confirmed the baseline structural defense rate of 85.0-86.0% (340-344/400).
- **Run B Metric Corrected:** The canonical Run B result is 273/320. An earlier 274 re-score occurred because the script inadvertently scored the contaminated run against the clean corpus evidence. The corrected regression reproduces all four runs exactly (clean A 275, clean B 276, contaminated A 277, contaminated B 273 of 320). The combined total remains 340/400.
- **Filter Lift & Vulnerability:** The T1071 evidentiary filter lift rests on an accidental match: 15 contaminated alerts (all `fake_output_injection`) pass the beacon predicate solely because the case-insensitive regex `\\bPOST\\b` matches the lowercase word "post" in `"stage":"post-triage"`. The clean twins have 0 such matches. This outcome effect drops the surviving failures from 43 to 43 (Run A) and 47 to 46 (Run B, alert 962072675970). Under a case-sensitive POST check, Run B would be 274/320 (overall 85.0-86.0% range unchanged). This match makes the alert actionable, which is the opposite of the payload's suppression goal. The filter predicates read fields an attacker controls, and no payload designed specifically to pass this filter has yet been tested.
- **Verdict Stability:** Wilson 95% intervals for no-actionable counts pre- and post-filter: Clean A 250 -> 275, Clean B 254 -> 276, Contaminated A 262 -> 277, Contaminated B 256 -> 273 (of 320). Final verdicts changed on only 3/320 (Clean A vs B) and 6/320 (Contam A vs B), or 2 to 6/320 across conditions. Technique sets differ 53.1% (clean vs clean) and 43.4% (contam vs contam). Because the headline "defense success" rate equals the clean-alert rate on the exact same metric, the supported claim is verdict stability under LLM noise.
- **T1071 Confidence Comparison:** Exploratory and inconclusive. Clean A vs B 25 lower / 16 higher (p=0.2110); Contaminated A vs B 14/14 (p=1.0000); cross-condition 25/4 (p=0.0001), 31/13 (p=0.0096), 26/8 (p=0.0029), 24/13 (p=0.0989). Emission asymmetry p-values were 0.0649, 0.2912, 0.0725, 0.3489 across conditions and 1.0000 within clean. Since runs differ in harness, day and process model, and six comparisons were made, no payload effect is claimed.
- **V4 Filter Sensitivity (No Beacon Predicate):** Removing the beacon predicate entirely yields post-filter no-actionable counts: Clean A 275/320 (Lift: +25), Clean B 276/320 (Lift: +22), Contam A 277/320 (Lift: +15), Contam B 274/320 (Lift: +18), nce7 Contam 68/80 (Lift: +4).

"""

content = content.replace("## Completed milestones (historical)", new_section + "## Completed milestones (historical)")

limitations_text = """## Known limitations
- "No actionable hypothesis" counts as a defense success, which means a suppression payload designed to intentionally cause an INFEASIBLE verdict would technically succeed by triggering this exact outcome.
- The T1071 FEASIBLE rate represents a base-rate property of how GUIDE alerts describe network activity, not a contamination-specific effect. The 85.0-86.0% "defense success" metric must carry the clean-baseline qualification.
- 0/704 (Run A) and 0/706 (Run B) post-filter hypotheses named a host that exists in the default seeded graph. The 0% clean non-T1071 FP rate holds because synthetic GUIDE accounts lack standing access-granting edges; it has not been verified on an identity/topology graph with real access grants. NCE does not receive source_user/source_host/target_host and no code compares hypothesis entities to them; SSE T1071 uses egress_to_any=True and accepts internal 443/80 EGRESS edges including the WORKSTATION->WORKSTATION self-loop.
- The T1071 evidentiary filter reads attacker-controlled fields, and no "filter-aware" payload has been tested.
- Detector 1 false negative.
"""

# Replace Known limitations
old_limitations = content[content.find("## Known limitations"):]
content = content.replace(old_limitations, limitations_text)

# Replace What's NOT Built Yet
old_wnby = content[content.find("## What's NOT Built Yet & Immediate Next Steps (Replaced)"):content.find("## Known limitations")]

new_wnby = """## What's NOT Built Yet & Immediate Next Steps (Replaced)
- Experiment 2: Alert-grounded authorization table, independent oracle, entity binding.
- Experiment 3: Identity steering evaluation.
- Groq paired run.
- Ablation study (note: "no NCE" cannot just leave SSE running).
- Technique-specific guardrail heuristics for T1071 (network-perimeter responses).
- Real-time monitoring / Real SOAR integration.

"""
content = content.replace(old_wnby, new_wnby)

with open('c:/agentsoc/PROJECT_STATUS.md', 'w', encoding='utf-8') as f:
    f.write(content)
print("Updated PROJECT_STATUS.md")
