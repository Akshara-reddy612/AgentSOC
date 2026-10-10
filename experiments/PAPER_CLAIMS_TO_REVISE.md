# Paper Claims to Revise

The following sentences in the project documentation and paper require revision based on the clean-vs-contaminated evaluation findings.

### (a) "Independently validates" against a "real identity/topology graph"
- **`agentsoc2_paper_corrected.tex:56`**: APPLIED 2026-10-10: "Agentic Security Operations Center (SOC) frameworks such as AgentSOC integrate"
  - **Reason 1**: The evaluation uses synthetic GUIDE accounts carrying no standing access-granting edges, so non-T1071 is automatically INFEASIBLE. 0/704 and 0/706 hypotheses across the two runs named a host in the default graph. For T1071, SSE uses `egress_to_any=True` and accepts internal 443/80 EGRESS edges (including WORKSTATION->WORKSTATION self-loops). This does not validate against a "real" graph.
  - **Reason 2**: The metric counts "no actionable hypothesis" as success, which also occurs whenever the LLM does not emit a T1071 hypothesis that survives the filter.

### (b) Headline 85.0-86.0% reported as "defense success" without clean-baseline qualification
- **`agentsoc2_paper_corrected.tex:56`**: APPLIED 2026-10-10: "Agentic Security Operations Center (SOC) frameworks such as AgentSOC integrate"
  - **Reason 1**: The 85.0-86.0% "defense success" metric must carry the clean-baseline qualification. Clean alerts reach the same no-actionable rate (275/320 and 276/320), so this is a base-rate property of how GUIDE alerts describe network activity, not a contamination-specific effect.
  - **Reason 2**: The metric counts "no actionable hypothesis" as success, which also occurs whenever the LLM does not emit a T1071 hypothesis that survives the filter.
- **`agentsoc2_paper_corrected.tex:75`**: APPLIED 2026-10-10: "\item Empirical measurement of the pipeline's outcome under contamination: across"
  - **Reason 1**: Reports the metric without the clean-baseline qualification.
  - **Reason 2**: The metric counts "no actionable hypothesis" as success, which also occurs whenever the LLM does not emit a T1071 hypothesis that survives the filter.
- **`agentsoc2_paper_corrected.tex:76`**: APPLIED 2026-10-10: "\item An NCE evidentiary threshold filter for network-layer hypotheses, which ra"
  - **Reason**: Reports the metric without the clean-baseline qualification.
- **`agentsoc2_paper_corrected.tex:291` & `298`**: APPLIED 2026-10-10: "\subsection{Pipeline Outcome Under Contamination ($n=400$)}" / "\caption{No-Acti"
  - **Reason**: Rename to the no-actionable-hypothesis rate under contamination and add the clean-baseline row.
- **`agentsoc2_paper_corrected.tex:294`**: APPLIED 2026-10-10: "Table~\ref{tab:defense} reports, per injection family, the fraction of contaminat"
  - **Reason**: Characterizes the metric as an active defense blocking the narrative, when it is actually a base-rate property.
- **`agentsoc2_paper_corrected.tex:402`** (conclusion; previously cited as line 375): **NOT APPLIED** [corrected 2026-10-10 audit]. The committed `.tex` still reads "We show that a layered pipeline of independent, non-LLM structural verification components can prevent contaminated log evidence from producing an actionable security decision in 85.0-86.0% … independently of the underlying LLM reasoning engine". The "We find that…" replacement recorded here earlier is not in the file, and the conclusion contradicts the rewritten abstract.
  - **Reason**: Clean alerts reach the same no-actionable rate (275/320 and 276/320 vs 277/320 and 273/320; on the 206 genuinely clean pairs 178/179 vs 177/176), so the measured rate is not attributable to defense.
- **`PROJECT_STATUS.md` n=80 / n=8 phase sections**: 
  - **Reason**: PROJECT_STATUS.md n=80 / n=8 phase sections: figures predate the clean-baseline finding; add a one-line note at the top of each historical section instead of rewording the figures (heading lines are 246 and 459).

### (c) Claims the 10/10 result without the empty-graph caveat
- **`agentsoc2_paper_corrected.tex:56`**: APPLIED 2026-10-10: "Agentic Security Operations Center (SOC) frameworks such as AgentSOC integrate"
  - **Reason**: These 10 count as defended partly because the graph holds no GUIDE entities, so non-T1071 hypotheses are INFEASIBLE regardless of the LLM.
- **`agentsoc2_paper_corrected.tex:75`**: APPLIED 2026-10-10: "\item Empirical measurement of the pipeline's outcome under contamination: across"
  - **Reason**: Same as above; missing the empty-graph caveat.
- **`PROJECT_STATUS.md:16`**: "- **Structural pipeline (NCE + filter + SSE) defended 10/10 of the alerts in the n=80 corpus where the undefended LLM was confirmed hijacked (any_hijack=True)**"
  - **Reason**: Same as above; missing the empty-graph caveat.

### (d) Structural immunity claims
- **`agentsoc2_paper_corrected.tex:242`**: APPLIED 2026-10-10: "SSE never reads log text directly: its public \texttt{check()} method carries an"
  - **Reason**: The isinstance guard blocks Evidence objects, but the account/host/technique strings SSE checks are produced by an LLM that read untrusted fields, and no code compares them with the trusted alert fields; the claim should be limited to "SSE never reads log text directly".

### (e) Test power claims
- **`agentsoc2_paper_corrected.tex:397`** (previously cited as line 370): "The defense pipeline is untested on reasoning backends other than \texttt{gemini-3.1-flash-lite}."
  - **Reason**: Needs the additional statement that, in undefended triage tests, this model was hijacked on only 3 of the 8 families (10/80 any-hijack), so the test has little power. Those hijack rates were measured on the triage-verdict task (not NCE) with the label-leaking `severity` field in the prompt.

### (f) Open items found during Step 6 search
- **`agentsoc2_paper_corrected.tex:320`**: "This accounts for the net improvement from 64 to 67 defended alerts: 3 additional alerts were defended by dropping their sole T1071 hypothesis, with 4 of the 7 dropped hypotheses coming from alerts already defended on other grounds."
- **`agentsoc2_paper_corrected.tex:391`**: "This indicates the structural defense outcome is substantially more stable than the LLM output feeding it, which is the property the architecture is designed to provide."
- **`agentsoc2_paper_corrected.tex:397`**: "At $n=400$, the field \texttt{undefended\_hijack} tracking whether NCE was actually fooled is absent from the 320-alert scale-up corpus; we therefore cannot report a per-alert hijack count at full scale and soften all claims about LLM manipulation to refer to the defense outcome rather than the LLM's internal state."

### (g) Claims found during the 2026-10-10 full audit (all NOT APPLIED)
- **Paired evaluation (`sec:paired`, abstract, contribution 2, Table `tab:paired_clean_family`)**: 108 of the 320 "clean twins" contain blunt-family `INJECTED_FIELD_VALUE` payloads and 6 more are different GUIDE rows sharing a duplicated alert_id (114 invalid). Restate on the 206 pairs whose clean input matches the verified twin (`python -m experiments.analyze_paired_valid`): no-actionable Clean A/B 178/179, Contaminated A/B 177/176 of 206; exact McNemar cA-cB b1/c2 p=1.0, rA-rB b2/c1 p=1.0, cA-rA b2/c1 p=1.0, cA-rB b2/c0 p=0.5, cB-rA b2/c0 p=0.5, cB-rB b3/c0 p=0.25. Also disclose that conditions were run on different dates (contaminated 2026-09-18..28, clean 2026-10-03..05).
- **`tex:391`**: "162 of 320 alerts (50.6%) produced a different hypothesis set" is not reproducible. Use 151/320 (47.2%) hypothesis sets, 139/320 (43.4%) technique sets. "under identical settings" is also wrong (harness and day differ).
- **`tex:393`**: "it keeps SSE's contamination-immunity property … fully intact" contradicts `tex:242`. Remove "immunity".
- **`tex:279` (Dataset)**: "500-row held-out sample" is wrong for the 320-alert slice (sampled from GUIDE_Train.csv via `guide_sample_500`); only the n=80 slice is from the held-out `guide_test_500`. Also disclose that all free-text evidence is synthesized by `synth_fields.py` (GUIDE free text is anonymized) and that most payloads are wrapped in a literal `INJECTED_FIELD_VALUE="..."` label.
- **`tex:93`**: obfuscated_trigger described as "zero-width-character obfuscation"; only 12/40 such payloads contain zero-width characters.
- **`tex:320` (Factor 1/2)**: "~75% / ~25%" does not follow from `t1071_mislabeling_investigation.md`, whose table gives 10 REASONABLE + 6 QUESTIONABLE contaminated failures (62.5% / 37.5%). "zero of the 12 Factor 1 cases" mixes in the 2 clean REASONABLE cases.
- **`tex:373` (detector)**: "the same syntactic shape as 2 of the 10 real attacks" cites `704374641116` and `1271310320953`, which are zero_imperative_evidence alerts outside the 10-attack set and whose only `key="value"` is the generator wrapper. Also state that the 10 attacks come from 3 payload templates and are in-sample, and that the benign corpora were generated by gemini-3.5-flash.
- **`tex:74` (contribution 1)**: "reducing false positives from 13.3% to 2.0%" compares different corpora; like-for-like is 2/15 -> 0/15 (n=30), then 1/50 at n=100.
- **`tex:378-382` (RSEM)**: the "0.50-1.00" containment values are inflated by duplicate SSE PathResults when parallel edges exist (e.g. REVOKE on svc_backup counts 0.75 vs 0.5 de-duplicated).
- **`tex:202` (Figure 1)**: the arrow from ERA to NCE implies a data flow that does not exist (NCE never receives ERA output); "Real-Time Monitoring … not implemented" should say a replay-only monitor exists.
- **`tex:76` (contribution 3)**: "it does not depend on attacker-supplied text" conflicts with the next sentence; the IP/domain predicates also read attacker-controlled fields.
- **Undefended hijack rates (`tex:350`, `tex:75`)**: must disclose the `severity` label leakage (severity = f(IncidentGrade), printed in the undefended prompt).
- **Metric sign (`sec:paired`)**: every payload family is a suppression attack, so "no actionable hypothesis" is the attacker's goal; state this explicitly.

## Supported replacement claims
- The pipeline outcome under contamination shows no detectable effect relative to the clean twins (on the 206 genuinely clean, unique pairs: verdict changes 1 to 3 across conditions vs 3 between two runs of the same condition; no exact McNemar p below 0.25; the original n=320 comparison, which included 116 contaminated or mismatched "twins", gave 2 to 6 vs 3 and 6, p ≥ 0.21). State as "no detectable effect", never "statistically indistinguishable".
- The pipeline's verdict is stable across LLM runs (3/320 changes between two clean runs, against 53.1% of technique sets changing), but it depends on a single binary event, a surviving T1071 hypothesis with an extractable host, because non-T1071 hypotheses are rejected on this graph regardless of the LLM.
- The evidentiary filter raises the no-actionable rate by +15 to +25 alerts per 320.
- The ApprovalClaimDetector detects 9 of 10 fabricated-evidence attacks at 1/50 false positives (evaluated separately; not part of the 85-86%).
- 'The measured rate ... Attackers are not meaningfully raising this rate' in the clean-alert subsection. SUPPORTED (cite as evidence for the paired result).
- In earlier undefended triage tests on held-out alerts ($n=10$ per family), this model was hijacked on three of the eight families used here (\texttt{fabricated\_evidence} 60\%, \texttt{zero\_imperative\_evidence} 30\%, \texttt{cross\_field\_split} 10\%) and on none of the others; the paired result above therefore comes from a model that the payloads rarely fool, which limits what it can show about the structural layers.

## Not supported (do not claim)
- That SSE validates hypotheses against a real identity graph.
- That the pipeline blocked attacks at 85-86%.
- That contamination has no effect on any model (only tested on gemini-3.1-flash-lite, which in undefended triage tests was hijacked on 3 of the 8 families).
- That SSE "catches" hijacked hypotheses or has a "contamination-immunity property".
- That the T1071 base rate is a property of "how GUIDE alerts describe network activity" (it is a property of the project's `synth_fields.py` templates).
- That the evaluation used real or held-out telemetry for the 320-alert slice.
