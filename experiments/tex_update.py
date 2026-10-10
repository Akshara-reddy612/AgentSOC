import sys
import re

with open('agentsoc2_paper_corrected.tex', 'r', encoding='utf-8') as f:
    text = f.read()

# 2.1 Abstract
abs_start = "Agentic Security Operations Center (SOC) frameworks such as AgentSOC integrate LLM-based reasoning"
abs_end = "verification structurally cannot help."
p_abs = re.compile(re.escape(abs_start) + r'.*?' + re.escape(abs_end), re.DOTALL)
new_abs = r"""Agentic Security Operations Center (SOC) frameworks such as AgentSOC integrate LLM-based reasoning directly into the incident triage loop, using a Narrative Counterfactual Engine (NCE) to generate attack hypotheses from raw telemetry fields. This design implicitly trusts log content -- process names, command lines, registry keys -- as safe evidence for LLM reasoning, creating an unaddressed attack surface: an adversary who can influence log fields can embed natural-language directives that hijack the NCE's hypothesis generation, a threat we term Data-to-Prompt Log Contamination. We extend the AgentSOC architecture with (1) an Evidence Risk Assessment layer including a structural ApprovalClaimDetector, (2) a Structural Simulation Engine (SSE) that checks NCE hypotheses against an identity/topology graph without reading log text, (3) an NCE evidentiary threshold filter for network-layer hypotheses, and (4) policy guardrails governing autonomous response execution. We evaluate on 400 contaminated alerts across 8 injection families from the Microsoft GUIDE dataset (50 per family) and on paired clean twins of 320 of them. With \texttt{gemini-3.1-flash-lite}, the pipeline yields no actionable hypothesis for 85.0--86.0\% (340--344/400) of contaminated alerts across two NCE runs. Clean alerts reach the same rate (275/320 and 276/320, versus 277/320 and 273/320 contaminated), and the verdict changed for only 2 to 6 of 320 alerts between conditions, no more than between two runs of the same condition. We therefore report invariance of the pipeline's outcome to contamination on this model, not an attack-blocking rate: the model resists most of our payload families, and the evaluation graph holds none of the GUIDE entities, so non-network-layer hypotheses are rejected regardless of the LLM. The ApprovalClaimDetector, evaluated separately, detects 9 of 10 fabricated-evidence attacks, with a false-positive rate of 2.0\% (1/50) on a larger dual-signal corpus (13.3\%, 2/15, on a smaller one). We document a network-egress validation ceiling affecting one MITRE ATT\&CK technique and a residual detector ambiguity, and we specify the experiments needed to test the structural layers against a model that the payloads do fool."""
text = p_abs.sub(lambda m: new_abs, text)

# 2.2 Contribution item 2
c2_start = r"\item Empirical validation of SSE as a contamination-agnostic backstop"
c2_end = "not as a claim about live deployments."
p_c2 = re.compile(re.escape(c2_start) + r'.*?' + re.escape(c2_end), re.DOTALL)
new_c2 = r"""\item Empirical measurement of the pipeline's outcome under contamination: across 400 contaminated alerts spanning 8 injection families (50 per family), the NCE+filter+SSE pipeline yields no actionable hypothesis for 85.0--86.0\% (340--344/400) of cases across two NCE runs. A paired evaluation on 320 alerts and their clean twins shows the same outcome rate without any payload (275/320 and 276/320 clean versus 277/320 and 273/320 contaminated) and 2 to 6 changed verdicts per 320 across conditions, versus 3 and 6 between two runs of the same condition (no exact McNemar $p$ below 0.21). The measured rate is therefore not an attack-blocking rate. Among the 10 alerts within the $n=80$ subset where the undefended agent was confirmed hijacked (\texttt{any\_hijack=True}), the pipeline produced no actionable hypothesis for all 10; because the evaluation graph holds no GUIDE entities, non-network-layer hypotheses are rejected regardless of the LLM, so this small-sample result is not evidence that SSE catches hijacked hypotheses."""
text = p_c2.sub(lambda m: new_c2, text)

# 2.3 Contribution item 3
c3_start = r"\item An NCE evidentiary threshold filter that closes part of the gap"
c3_end = r"not individually re-reviewed at scale (Section~\ref{sec:results-defense})."
p_c3 = re.compile(re.escape(c3_start) + r'.*?' + re.escape(c3_end), re.DOTALL)
new_c3 = r"""\item An NCE evidentiary threshold filter for network-layer hypotheses, which raises the no-actionable rate from 80.0--81.5\% (320--326/400) to 85.0--86.0\% (340--344/400) by dropping T1071 hypotheses that lack an external IP, a public domain, or a beaconing command. The lift is +15 to +25 alerts per 320 across clean and contaminated runs, and it does not depend on attacker-supplied text: removing the beacon predicate changes at most one alert per run. The filter reads fields an attacker controls, and no payload designed to pass it has been tested. Zero genuine-evidence drops were confirmed by exhaustive review at $n=80$; at $n=400$ only post-filter survivors were spot-checked (15/43 T1071 FEASIBLE cases), and dropped hypotheses were not individually re-reviewed at scale (Section~\ref{sec:results-defense})."""
text = p_c3.sub(lambda m: new_c3, text)

# 2.4 Headers
text = text.replace(r"\subsection{Structural Defense Against Log Contamination ($n=400$)}", r"\subsection{Pipeline Outcome Under Contamination ($n=400$)}")
text = text.replace(r"\caption{Structural Defense Success Rate by Injection Family ($n=50$ each)}", r"\caption{No-Actionable-Hypothesis Rate by Injection Family ($n=50$ each)}")

# 2.5 Table paragraph
tab_start = r"Table~\ref{tab:defense} reports per-family structural defense success -- the fraction of contaminated alerts for which the NCE+filter+SSE pipeline correctly rejects all attacker-influenced hypotheses as structurally infeasible, preventing the contaminated narrative from reaching an actionable decision."
tab_new = r"Table~\ref{tab:defense} reports, per injection family, the fraction of contaminated alerts for which the NCE+filter+SSE pipeline yields no actionable hypothesis, meaning every hypothesis is either dropped by the evidentiary filter or judged structurally infeasible by SSE. This is the rate at which contamination fails to produce an actionable decision; it is not an attack-blocking rate, because clean twins of the same alerts reach the same rate (Section~\ref{sec:paired})."
text = text.replace(tab_start, tab_new)

# 2.6 SSE never reads log text directly
sse_start = r"SSE is structurally immune to injected \textit{instructions}"
sse_new = r"SSE never reads log text directly"
text = text.replace(sse_start, sse_new)

sse_par_start = r"SSE never reads log text directly: its public \texttt{check()} method carries"
sse_par_end = r"accept a confidence-bearing field from NCE at all."

# find the whole paragraph to append to
match = re.search(re.escape(sse_par_start) + r'.*?' + re.escape(sse_par_end), text, re.DOTALL)
if match:
    old_par = match.group(0)
    new_par = old_par + r" The account, host, and technique strings it checks are produced by an LLM that read untrusted fields, and no check currently compares them with the trusted alert metadata; the guarantee is that SSE's verdict cannot be altered by injected text it never receives."
    text = text.replace(old_par, new_par)

# 2.7 Conclusion paragraph
concl_start = "We show that a layered pipeline of independent, non-LLM structural verification components"
concl_end = "verification structurally cannot help."
p_concl = re.compile(re.escape(concl_start) + r'.*?' + re.escape(concl_end), re.DOTALL)
new_concl = r"""We find that a layered pipeline of non-LLM structural verification components yields an outcome on contaminated alerts that is statistically indistinguishable from its outcome on clean twins of the same alerts (85.0--86.0\% no actionable hypothesis across two runs on 400 alerts; 2 to 6 of 320 verdicts changing between conditions, comparable to run-to-run variation), while the LLM's own output varies far more (53.1\% of technique sets differ between two clean runs, against 0.9\% of verdicts). The verdict depends almost entirely on whether a network-layer hypothesis survives the evidentiary filter, because non-network-layer hypotheses are never feasible on our evaluation graph. These results therefore establish invariance on a single model that resists most of our payloads; they do not show that SSE blocks hijacked hypotheses. The residual 14.0--15.0\% is entirely T1071 (egress-only) and is a base-rate property of how GUIDE alerts describe network activity. Future work includes evaluation on a backend that the payloads fool; an alert-grounded authorization graph with an independent oracle and an entity-binding check between hypotheses and trusted alert fields; a defined RSEM tie-breaking policy for egress-only techniques where containment is architecturally zero for multiple candidate actions (Section~\ref{sec:tie-blindness}); technique-specific guardrail heuristics for external-target techniques lacking internal graph representation; exhaustive Factor 1/2/3 reclassification of the full $n=400$ corpus; and integration with live SOAR/EDR execution to validate the Action/Playbook Layer beyond dry-run simulation."""
text = p_concl.sub(lambda m: new_concl, text)

with open('agentsoc2_paper_corrected.tex', 'w', encoding='utf-8') as f:
    f.write(text)
