import re

with open('agentsoc2_paper_corrected.tex', 'r', encoding='utf-8') as f:
    text = f.read()

new_section = r"""
\subsection{Paired Clean-Versus-Contaminated Evaluation ($n=320$)}
\label{sec:paired}

To isolate the effect of log contamination from the base rate of structural feasibility, we conducted a paired evaluation on 320 alerts and their clean (uncontaminated) twins across two independent NCE runs (Run A and Run B). Table~\ref{tab:paired_clean_family} details the post-filter no-actionable counts per injection family, showing near-identical distributions. The overall no-actionable counts with Wilson 95\% intervals confirm this: pre-filter, Clean A scored 250/320 [0.7328, 0.8231] and Clean B 254/320 [0.7461, 0.8345], compared to Contaminated A 262/320 [0.7728, 0.8571] and Contaminated B 256/320 [0.7527, 0.8402]. Post-filter, the counts converged further: Clean A 275/320 [0.8170, 0.8932], Clean B 276/320 [0.8204, 0.8960], Contaminated A 277/320 [0.8239, 0.8987], and Contaminated B 273/320 [0.8102, 0.8877]. Because the metric counts "no actionable hypothesis" as success, a suppression payload would succeed by producing this outcome, so the metric must be read by attacker goal per family. However, the evaluation graph holds none of the GUIDE hosts or accounts (0/704 and 0/706 hypotheses name a host in the default graph; 0 of 1,503 non-T1071 hypotheses were FEASIBLE), so non-T1071 verdicts do not reflect SSE judgement.

\begin{table}[h]
\centering
\caption{No-Actionable-Hypothesis Count by Injection Family ($n=40$ each)}
\label{tab:paired_clean_family}
\begin{tabular}{@{}lcccc@{}}
\toprule
\textbf{Injection Family} & \textbf{Clean A} & \textbf{Clean B} & \textbf{Contam A} & \textbf{Contam B} \\
\midrule
\texttt{authority\_escalation} & 38 & 38 & 38 & 38 \\
\texttt{cross\_field\_split} & 33 & 34 & 35 & 33 \\
\texttt{direct\_override} & 35 & 35 & 35 & 35 \\
\texttt{fabricated\_evidence} & 33 & 34 & 34 & 33 \\
\texttt{fake\_output\_injection} & 34 & 33 & 34 & 32 \\
\texttt{native\_format\_mimicry} & 36 & 36 & 35 & 36 \\
\texttt{obfuscated\_trigger} & 33 & 33 & 33 & 33 \\
\texttt{zero\_imperative\_evidence} & 33 & 33 & 33 & 33 \\
\bottomrule
\end{tabular}
\end{table}

A pairwise analysis of verdict changes reveals that the pipeline's outcome under contamination is statistically indistinguishable from its outcome on clean data. The noise floor between two runs of the same condition shows 3/320 verdict changes for Clean A vs Clean B (exact McNemar $b=1, c=2, p=1.0000$) and 6/320 for Contaminated A vs B ($b=5, c=1, p=0.2187$). Across conditions, verdict changes remain at this floor: 6/320 for Clean A vs Contam A ($b=2, c=4, p=0.6875$), 2/320 for Clean A vs Contam B ($b=2, c=0, p=0.5000$), 5/320 for Clean B vs Contam A ($b=2, c=3, p=1.0000$), and 3/320 for Clean B vs Contam B ($b=3, c=0, p=0.2500$). Because a non-significant McNemar test does not prove equality, we state this as no detectable effect, bounded within a few percentage points. This stability contrasts sharply with the LLM's own hypothesis generation, where technique sets differ in 53.1\% of alerts (170/320) between the two clean runs and 43.4\% (139/320) between the two contaminated runs. An exploratory T1071 confidence comparison (Clean A vs B: 25 lower / 16 higher, sign test $p=0.2110$; Contam A vs B: 14/14, $p=1.0000$; Clean vs Contam: 25/4 $p=0.0001$, 31/13 $p=0.0096$, 26/8 $p=0.0029$, 24/13 $p=0.0989$) was inconclusive, as runs differ in harness, day, and process model, pairs share alerts, and six comparisons were made. Ultimately, this model resists most payload families (NOT FOUND IN REPO), rendering the overall test insensitive to the structural layers' active defense capabilities.
"""

text = text.replace(r"\subsection{Clean-Alert False-Positive Assessment ($n=60$)}", new_section + r"\subsection{Clean-Alert False-Positive Assessment ($n=60$)}")

with open('agentsoc2_paper_corrected.tex', 'w', encoding='utf-8') as f:
    f.write(text)
