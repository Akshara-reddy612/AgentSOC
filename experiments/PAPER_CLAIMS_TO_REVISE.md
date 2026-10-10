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
- **`agentsoc2_paper_corrected.tex:375`**: APPLIED 2026-10-10: "We find that a layered pipeline of non-LLM structural verification components yi"
  - **Reason**: Clean alerts reach the same no-actionable rate (275/320 and 276/320 vs 277/320 and 273/320), so the measured rate is not attributable to defense.
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
- **`agentsoc2_paper_corrected.tex:370`**: "The defense pipeline is untested on reasoning backends other than \texttt{gemini-3.1-flash-lite}."
  - **Reason**: Needs the additional statement that this model resists nearly all payload families, so the test has little power.

### (f) Open items found during Step 6 search
- **`agentsoc2_paper_corrected.tex:320`**: "This accounts for the net improvement from 64 to 67 defended alerts: 3 additional alerts were defended by dropping their sole T1071 hypothesis, with 4 of the 7 dropped hypotheses coming from alerts already defended on other grounds."
- **`agentsoc2_paper_corrected.tex:391`**: "This indicates the structural defense outcome is substantially more stable than the LLM output feeding it, which is the property the architecture is designed to provide."
- **`agentsoc2_paper_corrected.tex:397`**: "At $n=400$, the field \texttt{undefended\_hijack} tracking whether NCE was actually fooled is absent from the 320-alert scale-up corpus; we therefore cannot report a per-alert hijack count at full scale and soften all claims about LLM manipulation to refer to the defense outcome rather than the LLM's internal state."

## Supported replacement claims
- The pipeline outcome under contamination is statistically indistinguishable from the outcome on the clean twins (verdict changes 2 to 6 of 320 across conditions vs 3 and 6 of 320 between two runs of the same condition; no McNemar p below 0.21).
- The pipeline's verdict is stable across LLM runs (3/320 changes between two clean runs, against 53.1% of technique sets changing), but it depends on a single binary event, a surviving T1071 hypothesis with an extractable host, because non-T1071 hypotheses are rejected on this graph regardless of the LLM.
- The evidentiary filter raises the no-actionable rate by +15 to +25 alerts per 320.
- The ApprovalClaimDetector detects 9 of 10 fabricated-evidence attacks at 1/50 false positives (evaluated separately; not part of the 85-86%).
- 'The measured rate ... Attackers are not meaningfully raising this rate' in the clean-alert subsection. SUPPORTED (cite as evidence for the paired result).
- In earlier undefended triage tests on held-out alerts ($n=10$ per family), this model was hijacked on three of the eight families used here (\texttt{fabricated\_evidence} 60\%, \texttt{zero\_imperative\_evidence} 30\%, \texttt{cross\_field\_split} 10\%) and on none of the others; the paired result above therefore comes from a model that the payloads rarely fool, which limits what it can show about the structural layers.

## Not supported (do not claim)
- That SSE validates hypotheses against a real identity graph.
- That the pipeline blocked attacks at 85-86%.
- That contamination has no effect on any model (only tested on gemini-3.1-flash-lite, which resists most payloads).
