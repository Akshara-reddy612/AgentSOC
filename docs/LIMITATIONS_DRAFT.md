# Limitations — draft for the paper (2026-10-31)

A plain-language draft of the paper's Limitations section, for the team to revise. Every number comes from
`experiments/RESULTS.md` or a file named in the "Source" column at the end. The DEDALE numbers were checked
against the full re-freeze of 2026-10-31 (all three score files byte-identical to the committed ones).

## Draft text

**One testbed dataset, with two attacked hosts.** The real-telemetry evidence comes from DEDALE: four weeks of
logs from a testbed that emulates a small company, with one attack scenario. Exact labels exist for the two
Windows clients the attacker used. Results from one scenario on two hosts are a case study, not a measurement of
how the pipeline behaves across organisations or attacks. The network results rest on very few attack cases:
Suricata alerted on 1 of the 84 labelled attack flows. The GUIDE corpus, which tests contamination at scale, uses
synthetic entities, evidence and payloads.

**A simulated analyst.** The analyst in our experiments is an oracle that answers from the labels after a fixed
delay, with random, independent mistakes. Real analysts are slower on some cases than others, and their mistakes
are probably not random: an attacker who blends in well is more likely to be cleared. Our analyst results are
bounds under these assumptions, not field data.

**One language model on DEDALE.** All DEDALE runs use one model (gemini-3.1-flash-lite). A second model
(gpt-oss-20b) was run on the GUIDE development set only. Each model condition was run once; replaying the recorded
answers makes every number reproducible, but it does not measure how much a model's answers vary from run to run.

**The analyst channel.** Asymmetric trust limits what the language model's output can cause. It does not limit the
analyst. Analysts must read the evidence, including text the attacker wrote, and a benign verdict teaches the store
by design, which is how analyst feedback lowers the workload. A misled analyst can therefore still teach the store
something it should not learn. Unlearning on confirmed compromise undoes this for a host once some analyst confirms
that host as compromised; it does not help before that.

**The model sees part of each field.** The model is shown the first 512 characters of each evidence field. On
DEDALE the command line is almost always fully visible: 1 of 797 command lines is longer than 512 characters. The
raw log line, which records the whole event, is cut in 718 of 856 cases, so attacker text late in the raw line is
not seen by the model. Under asymmetric trust this only costs a missed escalation: text the model never sees
cannot cause a dismissal or an action either.

**Where the model is the only detector, contamination still suppresses.** On GUIDE each alert goes through the
single-alert pipeline, with no learned store, so the model's hypotheses are what raises a response. Injected text
still suppressed the response in 4 of 428 development pairs (3 of 437 held-out; 10 of 437 with gpt-oss-20b), with
or without asymmetric trust: a rule about what the model's output may cause cannot make the model notice what the
text hid. In the DEDALE loop, detection comes from the learned store and the model only adds, which is why no attack
case was dismissed there under the rule.

**Activity that looks routine stays silent.** The store learns what normal activity looks like and alerts on what
it has not seen. Attack activity whose structured pattern also occurs in normal activity does not alert: 73 of the
473 labelled attack events that alert when nothing is learned stay silent after the benign weeks are learned.
Many labelled attack events are also of kinds our detectors do not cover at all (DLL loads, ordinary
file writes). Every step of the attack still reached an analyst, but no novelty detector can see activity that is
truly indistinguishable from routine.

**No prompt-level baseline.** No prompt-level defence was evaluated as a baseline: the pipeline is compared only
with an undefended triage agent. Prompt-level defences, such as marking untrusted input in the prompt or training
the model to follow a trusted channel, reduce how often a model follows injected text; our results concern what
happens when it does. A comparison with a hardened prompt, in which the untrusted fields are delimited and declared
to be data, was prepared on DEDALE but could not be completed, because the model's API returned only overload
errors (HTTP 503) during the attempts. No result from it is reported.

**Also (one line each, already in the paper):** tampering with structured sensor fields is outside the defences;
all containment is simulated; the host detectors, the open-world rule and the review-queue order were chosen on
DEDALE itself.

## LaTeX version (for `paper/agentsoc_combined.tex`, Limitations list)

```latex
\item One labelled dataset, from a testbed: one attack scenario, with labels for two attacked Windows clients.
Suricata alerted on 1 of the 84 labelled attack flows, so the network results rest on very few attack cases.
GUIDE v2's entities, evidence and payloads are synthetic.
\item A simulated analyst: an oracle with random, per-case mistakes. Real analysts' mistakes are likely correlated
with how well the attacker blends in.
\item One model on DEDALE (\texttt{gemini-3.1-flash-lite}); \texttt{gpt-oss-20b} on the GUIDE development set only.
Each model condition was run once.
\item The analyst channel: asymmetric trust limits what the model's output can cause, not what an analyst decides.
A misled analyst can still teach the store; unlearning helps only after a host is confirmed compromised.
\item The model sees the first 512 characters of each evidence field. The command line is almost always fully
visible (1 of 797 is longer); the raw log line is cut in 718 of 856 cases, so attacker text late in it is not seen.
Under asymmetric trust this only costs a missed escalation.
\item Where the model is the only detector (GUIDE), injected text still suppressed 4 of 428 responses, with or
without asymmetric trust.
\item Activity whose structured pattern also occurs in normal activity stays silent (73 of the 473 labelled attack
events that alert when nothing is learned); many labelled events are of kinds the detectors do not cover.
\item No prompt-level defence~\cite{spotlighting,struq} was evaluated as a baseline: the pipeline is compared only
with an undefended triage agent. A comparison with a hardened prompt, in which the untrusted fields are delimited
and declared to be data, was prepared on DEDALE but could not be completed, because the model's API returned only
overload errors (HTTP 503) during the attempts.
```

## Sources

| Number | Source |
|:--|:--|
| 1 of 84 labelled attack flows alerted | `experiments/DEDALE_PHASE1_RESULTS.md:74` ("83 of the 84 labelled attack flows raised no Suricata alert") and `:95`; `experiments/DEDALE_DATA_NOTES.md:112`. Not in `RESULTS.md`: it is a data finding of Phase 1, not a scored condition |
| 4 of 428, 3 of 437, 10 of 437 | `experiments/RESULTS.md`, C1 table; recomputed 2026-10-31 from `agent/v2_results/*_rescored.json` |
| 512 characters | `risk_assessment/config.py:115` (`MAX_PROMPT_FIELD_LENGTH`), applied in `prompt_construction/nce_prompt_builder.py:148-149`; unchanged since 2026-08-03 |
| 73 of 473 | `experiments/RESULTS.md`, C2 table: static 473, frozen 400 (`final_host_scores.json`, confirmed by the 2026-10-31 re-freeze) |
| 1 of 797 command lines, 718 of 856 raw log lines over 512 characters | `experiments/RESULTS.md`, C4, "What NCE is shown" (since 2026-11-01; `experiments/build_results.py` counts them, read-only, from the first alert of each test case in the case store of `gated_nce_F_nce`, `<data>/runs/dedale_host_gated_nce_F_nce/cases.sqlite`) |
| Hardened-prompt comparison prepared, not completed (HTTP 503) | `RESEARCH_LOG.md` on main, 2026-11-01 (paper limitation entry): only overload errors (HTTP 503) in the two pilot attempts. The counts (6 calls, 24 requests, 0 answers) are in the log and the answers file of the unmerged branch `baseline-prompt`, with the design (`experiments/BASELINE_PROMPT_DESIGN.md`). No result is claimed |
