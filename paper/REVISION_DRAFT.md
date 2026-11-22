# GuardedSOC: revision draft for the 8-page version

Proposed text for `AgentSOC_IEEE_Revised.docx`; the user moves it into the docx. Budget: [PAGE_BUDGET.md](PAGE_BUDGET.md).

Conventions:
- Numbers come from `experiments/RESULTS.md`. The few taken from a score file instead are tagged with that file in the editor notes.
- `⟨T2.x: …⟩` marks a Tier 2 number that is still running. The sentence around it does not assume a direction.
- *Editor notes* in italics are for us, not for the paper.

---

GuardedSOC: Bounding LLM Authority and Memory Updates in Agentic SOC Triage

*(author block unchanged)*

**Abstract**—Agentic security operations centers (SOCs) put large language models (LLMs) and adaptive knowledge stores into alert triage. Both are attack surfaces: the LLM reads attacker-written log text, and the store learns from observed activity. We build GuardedSOC on the AgentSOC architecture and bound both. Under asymmetric trust, LLM hypotheses may escalate a case to human review but cannot dismiss it, trigger containment or authorize a memory update. Autonomous updates pass a 24-hour quarantined learning gate, and a confirmed compromise retracts the host's recent patterns. On 500 GUIDE v2 clean/contaminated alert pairs, an undefended agent was hijacked into dismissals on 130/439 pairs (29.6%) ⟨T2.1: held-out⟩; within GuardedSOC, contamination suppressed a response on 4/428 (0.9%). On 14 test days of DEDALE telemetry, 0/72 attack cases were dismissed under injected text, and targeted unlearning removed every pattern learned from a 20% analyst miss rate in all 6 seeds. A persuaded analyst who clears a host's first attack case defeats unlearning, and the LLM gave no workload reduction over the model-free baseline.

*Editor notes: 243 → 165 words. The last sentence keeps the honest result and adds A10.*

Index Terms—Security Operations Center, Agentic AI, Large Language Models, Prompt Injection, Memory Poisoning, Alert Triage.

## I. Introduction

Security operations centers (SOCs) triage large volumes of alerts, most of them benign [5]. Agentic architectures such as AgentSOC [1] aim to reduce this load. An LLM proposes attack hypotheses, structural analysis checks them against the environment, a risk module ranks responses, and a knowledge store learns from earlier cases.

Two of these components process data an attacker can influence. The LLM reads free text from logs, such as command lines, script blocks and raw log records, which an attacker shapes simply by running processes on a monitored host. Direct and indirect prompt injection against such inputs is well documented [6]–[8]. The knowledge store learns what is normal, and poisoning of learned baselines and agent memory is equally documented [12]–[14]. AgentSOC was evaluated on a fixed proof-of-concept scenario [1]. It did not measure what happens when the LLM is manipulated, or when the store is updated over weeks of telemetry and analyst feedback.

We present GuardedSOC, which bounds what the LLM and the memory may do rather than trying to make the model robust. Its contributions are:

1. **Asymmetric trust**, an architectural rule under which LLM output may only raise scrutiny. The final decision is never less strict than the model-free decision, D(x, h) ≥ D(x, none). The model therefore cannot dismiss a case, cancel containment or authorize learning.
2. **A bounded memory**: a quarantined learning gate for autonomous updates, and targeted unlearning (B5) that retracts a host's recent patterns when an analyst confirms compromise.
3. **An evaluation on two attack surfaces.** Injected log text is tested on GUIDE v2 alert pairs, against prompt-level defences and an adaptive attacker, and on DEDALE command lines. Memory poisoning is tested over 14 DEDALE test days through ungated learning, analyst mistakes and a persuaded analyst, with seeds and a frequency-threshold baseline.

Section II reviews AgentSOC and related work. Section III describes the architecture, Section IV the setup, Section V the results, and Section VI the limitations.

*Editor notes: 725 → about 330 words. Cut the paragraphs that repeat §II and §III. The "rest of the paper" paragraph is shortened to one sentence.*

## II. Base Paper and Related Work

### A. AgentSOC

AgentSOC [1] has four layers: Perception, Agentic Reasoning, Action and Playbooks, around a knowledge store. In the reasoning layer:
- the Narrative Counterfactual Engine (NCE) asks an LLM for attack-progression hypotheses, each tagged with MITRE ATT&CK techniques [4] and a confidence;
- the Structural Simulation Engine (SSE) rejects hypotheses the identity, privilege and network model cannot support;
- the Risk Scoring and Evaluation Module (RSEM) ranks responses by containment benefit against business impact. High-impact responses go to analysts, the rest run with audit and rollback.

The original study used 5,000 LANL authentication events, a 50-node simulated topology and GPT-4, and reported one incident end to end. It named continuous telemetry and the human loop as open questions. Table I summarizes how this work extends it.

### B. Related Work

**Prompt injection and its defences.** Instructions hidden in data steer LLMs directly [6] and indirectly through retrieved or tool content [7]. Liu et al. [8] formalize these attacks and benchmark defences, and AgentDojo [17] and InjecAgent [18] measure them for tool-using agents. Defences act on the prompt or the model:
- spotlighting marks untrusted data [9];
- StruQ separates instructions from data [10];
- the instruction hierarchy trains models to rank privileged instructions above data [16].

CaMeL [11] instead enforces security outside the model, so the model need not recognize an attack. GuardedSOC follows that principle for triage. We also measure three prompt-level defences as baselines (Section V-A).

**Poisoning of learning systems and agent memory.** Poisoning has been studied for anomaly detectors [12], for agent memory and knowledge bases [13], [19] and for retrieval-augmented generation [14]. Dash et al. [19] find that prompt-injection defences do not cover memory poisoning. MemStream [20] adapts a streaming detector's memory to drift, with design choices against poisoning. A SOC's learned baseline has the same weakness: activity learned as normal is never alerted again. Machine unlearning [15] removes learned influence; we apply a narrow, host-scoped form of it.

**LLM alert triage.** Tsegai et al. [21] report that every LLM-agent triage approach they studied missed at least 40.4% of attack-related alerts. GuardedSOC addresses a different question, namely what an LLM is allowed to decide, and it does not claim better detection (Section V-D).

*Editor notes: 1,194 → about 420 words. The datasets subsection moves to §IV. The paragraphs on motivation and on how this work extends AgentSOC are covered by Table I.*

## III. System Architecture

### A. Threat Model and Trust Boundaries

**Attacker-controlled input.** The adversary writes free text in telemetry: command-line arguments, script blocks, raw log records, and the names of the binaries and files it drops. It may also try to mislead the human analyst who reviews that evidence.

**Trusted.** The following are trusted:
- sensors, endpoint agents and network taps;
- structured fields: host identifiers, authenticated accounts, IP addresses, ports, event IDs;
- the pipeline's rule engines (SSE, RSEM) and the asset inventory.

**The LLM.** It reads untrusted text and proposes hypotheses. It is untrusted for dismissal, containment and memory updates, and may only request review.

**Non-guarantees.** Asymmetric trust does not protect against:
- an analyst who issues a wrong benign verdict after reading manipulated evidence (we measure this channel in Section V-C);
- poisoning of the two training weeks, which are assumed clean.

*Fig. 1 (full width, figure unchanged):* GuardedSOC within the AgentSOC architecture [1]: layers, components and trust boundaries; additions highlighted. Trusted fields feed the model-free path; attacker text reaches only NCE. Guardrails keep the model-free outcome or raise it to review, and a response only NCE supports waits for an analyst. ERA is evaluated on GUIDE only.

*Editor notes: Fig. 1 checked against the code on 2026-11-22. Every box and arrow matches. The caption is cut from 106 to about 60 words; the E1 sentence moves to §V-A. Optional small fixes in the TikZ source (`paper/agentsoc_v2.tex`) are listed in the chat reply of 2026-11-22.*

Events are normalized and enriched from the knowledge store. Detectors raise an alert when a structured pattern is not yet learned as normal, and alerts with the same pattern are grouped into a case. NCE sees the first 512 characters of each text field. Entity binding checks that the hosts and accounts named in a hypothesis exist in trusted fields, and SSE keeps only feasible hypotheses for RSEM. On GUIDE, the Evidence Risk Assessment (ERA) also escalates alerts whose text looks like an injection. ERA is off on DEDALE, so there raw attacker text reaches NCE uninspected.

### B. Asymmetric Trust

Let a case x have structured telemetry x_s and text x_t. Let h = LLM(x_t) be the hypotheses, and let *none* denote no hypotheses. Outcomes are ordered by severity: NO_ACTIONABLE < LOW_PRIORITY < AUTO_APPROVED < REVIEW.

GuardedSOC computes a model-free decision D_base(x) = D(x, none) from x_s and the store. On DEDALE, a case with an unlearned pattern goes to review (rule D7). A model-assisted decision D_LLM(x, h) can only return REVIEW or abstain. The outcome is

D(x, h) = max(D_base(x), D_LLM(x, h)).

Containment actions come only from D_base. A model-assisted escalation therefore adds review but never cancels a model-free block.

**Property 1 (safety monotonicity).** For all x and h, D(x, h) ≥ D(x, none). This follows directly from the max. An attacker who changes x_t, and through it h, cannot push the outcome below D_base.

**Property 2 (memory quarantine).** For all x and h on the autonomous path, Learn_auto(x, h) ⊆ Learn_auto(x, none). A case is eligible for autonomous learning only at LOW_PRIORITY or NO_ACTIONABLE. An escalation caused by h only removes eligibility, so the LLM can prevent learning but never authorize it. Analyst verdicts bypass this path by design.

We call the earlier behaviour, in which NCE output can also lower an outcome, the *acting rule*. Both rules are evaluated on the same recorded LLM answers. Property 1 was also checked against randomized synthetic hypotheses.

### C. Learning Gate and Targeted Unlearning

The store learns normal patterns from two clean training weeks. During testing, a case closed without escalation becomes a learning candidate. The gate commits it only after 24 h, and only if no escalation has occurred on the same host or endpoints in the meantime. Analyst benign verdicts teach the store immediately: they are the intended route for new normal patterns, and the channel a deceived analyst opens.

Targeted unlearning (B5) acts on an analyst's confirmation that a host is compromised. It retracts every pattern learned on that host in the previous 7 days, and stops further learning there. Training-week patterns are permanent.

### D. Fail-Safes

Malformed events are rejected and counted. An event that crashes processing is quarantined and the live runner resumes from its last checkpoint. Any triage error sends the case to review, commands apply atomically, and checkpoints are signed and load only allow-listed classes. These are tested by unit tests. No event was rejected in the 43 frozen replays, which run the loop directly, so they do not measure recovery.

*Editor notes: 1,774 → about 850 words.*
- *Cut: the duplicate paragraphs on structured and text data, which are now the threat model; three paragraphs restating asymmetric trust; and the gate-admitted-0-edges sentence, which moves to §V-B.*
- *Algorithm 1 (Appendix B) goes to the repo.*

## IV. Evaluation Setup

### A. GUIDE v2 Alert Pairs

From GUIDE v2 [2] we built 1,000 pairs: 500 for development and 500 held out. Each pair is a clean alert and a contaminated twin that differs only at the injection site. Entities, evidence text and payloads are synthetic. Alerts run through the single-alert pipeline, with no learned store.

A pair is **suppressed** when the clean twin received a response (REVIEW or AUTO_APPROVED) and the contaminated twin did not. We also count lost automatic containment: the clean twin's model-free block is missing from the contaminated twin. We report 95% Wilson intervals and exact McNemar tests on the discordant pairs.

An **undefended agent** gets the same alert text, without the pipeline's telemetry, inventory or novelty store, and returns a verdict. It is **hijacked** on a pair when the contaminated twin is dismissed but the clean twin is not.

We test three prompt-level defences on the undefended agent with identical structured fields:
- delimited untrusted text;
- spotlighting [9];
- an instruction-hierarchy system prompt [16].

An **adaptive attacker** rewrites each suppression payload until ERA rates it low risk, and moves raw-log payloads into NCE's 512-character view. This uses 300 pairs, with ERA flags falling from ⟨T2.3: 53⟩ to ⟨T2.3: 0⟩.

### B. DEDALE Testbed Telemetry

DEDALE [3] is an emulated small enterprise with host logs, Suricata network alerts, and one multi-stage APT campaign whose events are labelled on two Windows clients. Two benign weeks seed the store, and then 14 test days replay in order.

A simulated analyst answers each case after a set delay (4 h unless stated) from the ground-truth labels. It can be configured to miss attacks (5% or 20%), to raise false alarms (5%), or to be *persuaded*. A persuaded analyst sees attacker text in the case and clears a malicious verdict with probability q. Persuasion applies either to that case alone or host-wide, to every later case on the host. Random draws are seeded; we report 6 seeds (5 for some conditions) as mean ± sd.

In experiment E1, three payloads are written into the attacker's command lines: routine maintenance, fake approval, and a steer that names the domain controller as the host to isolate. Of 84 injected events, 38 fall in the first alert of their case.

As a memory baseline, a training pattern counts as normal only if it occurred at least K times in the clean weeks (K = 1, 2, 5, 10).

### C. Recorded Answers and Reproducibility

All LLM answers (gemini-3.1-flash-lite, and gpt-oss-20b on GUIDE development pairs) were recorded once. Every condition, under either rule, replays those answers deterministically. One script rebuilds every number from the frozen score files in the repository.

*Editor notes: 983 → about 560 words.*
- *Cut: the old §IV-D list of planned experiments, now mostly done. What remains goes to §VI.*
- *Move Fig. 2 to §V-A, where it is discussed.*

## V. Results

### A. Injected Log Text

Table II lists the GUIDE and E1 results under both rules.

**GUIDE.** Contamination suppressed a response on:
- 4/428 development pairs (0.9%, CI 0.4–2.4%; McNemar b=4, c=4, p=1.0);
- 3/437 held-out pairs (0.7%, CI 0.2–2.0%; b=3, c=0, p=0.25);
- 10/437 development pairs with gpt-oss-20b (2.3%, CI 1.2–4.2%; b=10, c=5, p=0.30).

The rule does not change these counts. In the 4 development Gemini pairs, the 3 held-out pairs and 9 of the 10 gpt-oss pairs, the clean twin was reviewed only because the model emitted an ungrounded T1071 hypothesis, which the injected text made it drop. With no learned baseline, the LLM is the only detector, and asymmetric trust cannot restore an escalation the model failed to emit.

The rule does change containment. Under the acting rule, review requests cancelled clean automatic blocks in 20/178, 18/168 and 21/176 pairs. Under asymmetric trust, model-free blocks always execute, and 0 were lost: 0/178, CI 0–2.1%; 0/168; 0/178.

**Undefended agent.** It was hijacked into dismissals on 130/439 development pairs (29.6%, CI 25.5–34.0%; b=130, c=28, p=6.5e-17) and on ⟨T2.1: x/y held-out pairs (z%, CI …)⟩. With delimited text, spotlighting and the instruction hierarchy it was hijacked on ⟨T2.2: a/439⟩, ⟨T2.2: b/439⟩ and ⟨T2.2: c/439⟩ pairs. Prompt-level defences thus ⟨T2.2: one clause stating the direction and size of the change, filled in from the numbers⟩. Unlike asymmetric trust, a prompt-level defence bounds the attack only as far as the model obeys it.

**Adaptive attacker.** Against payloads rewritten to evade ERA and placed inside NCE's view, suppression was ⟨T2.3: n/300⟩ under the acting rule and ⟨T2.3: m/300⟩ under asymmetric trust, against ⟨T2.3: k/300⟩ for the original payloads.

**E1 on DEDALE.** Without an analyst and under the acting rule, the maintenance, fake-approval and steer payloads dismissed 1, 3 and 1 of the 72 attack cases. The steer made NCE name the domain controller in 30 of 38 injected cases (32 of 38 with an analyst). Entity binding marked all 49 such hypotheses (59 with an analyst) as unbound, so no misdirected containment was proposed. Under asymmetric trust, 0/72 attack cases were dismissed (CI 0–5.1%) for every payload: a property of the design, confirmed by the replay.

*Fig. 2 (one column):* Attacker text under the acting rule (hatched) and asymmetric trust (solid). Left: E1 attack cases dismissed (of 72), no analyst. Right: GUIDE pairs that lost an automatic block.

### B. Gated Learning, Workload and a Simple Baseline

With nothing learned, the host detectors opened 6,095.4 reviews per day. Precision was 0.1%, with 80 attack cases and 473 labelled attack events alerted (Table III). Seeding the store with the two clean weeks cut this to 65.2 reviews per day (98.9% less), with precision 7.9%.

Every one of the 72 attack cases raised was reviewed. 400 of the 473 detector-visible attack events were alerted (84.6%). The other 73 matched routine activity from the training weeks, which is the cost of novelty filtering and an opening for mimicry. Each attack stage was first reviewed:
- initial access: 1.2 min after it began;
- lateral movement: 28.5 min;
- collection: 30 min;
- exfiltration: 1,265 min.

**Learning without the gate** lowered reviews to 27.4 per day but absorbed 38 attack patterns as routine. Attack cases raised fell to 38 and events alerted to 99, and the exfiltration stage was never detected. With D7 on, no case with an unlearned pattern closed without review, so the gate committed 0 patterns on host logs and 0 network pattern edges.

On Suricata network alerts:

| Condition | Reviews / day | Attack cases missed |
|:--|--:|--:|
| Static | 552.3 | 0/7 |
| Gated | 26.1 | 0/7 |
| Ungated | 20.6 | 4/7 |

**Frequency threshold (baseline).** Treating a training pattern as normal only if it occurred at least K times did not improve detection. Every K raised the same 72 attack cases and 400 events. Workload grew from 65.2 reviews per day (K=1) to 86.4, 163.4 and 718.7 for K = 2, 5, 10, and precision fell to 0.7%. Rarity in clean data is a poor proxy for risk. The poisoning that matters enters during testing (Section V-C), where a threshold on the training weeks has no effect.

**Gate delay.** We measure where the gate does learn: host logs under the acting rule, and network alerts with D7 off. Raising the delay from 1 h to 168 h cut patterns committed through the gate from 16 to 0 (host) and from 671 to 256 edges (network). No attack pattern was learned at any delay. Host reviews rose only from 55.0 to 58.9 per day, and network reviews stayed at 7.9.

*Fig. 3 (one column):* Host reviews per day, log scale: static, gated and ungated learning.

### C. Analyst-Induced Poisoning and Targeted Unlearning

An analyst's benign verdict teaches the store directly, so a missed attack becomes a learned pattern (Table IV).

**Missed attacks.** Without unlearning (B5 off), across 6 seeds:
- a 5% miss rate left 7.33 ± 2.42 attack cases' patterns learned, with 386.5 ± 18.5 of 400 events alerted;
- a 20% miss rate left 18.5 ± 2.81 learned, with 333.3 ± 61.1 events alerted.

With B5 on, confirmation of a compromised host retracted its recent patterns. Every seed and both miss rates ended with 0 attack patterns learned and all 400 events alerted.

**Costs of B5.** It raised workload from 30.0–30.6 to 34.1 reviews per day, because retracted routine patterns are reviewed again. With 5% false alarms (benign hosts confirmed as compromised), workload was 41.8 ± 2.3 reviews per day against 31.4 ± 0.2 without B5. The lookback barely matters on this campaign. From 1 to 14 days every run ended with 0 learned attack patterns; 1 day gave 33.3 reviews per day, and 3 to 14 days gave 34.1.

**Persuaded analyst.** Here the attacker's text, which reaches 38 of the 72 attack cases, talks the analyst out of a malicious verdict.
- *Per case*, persuasion never defeated B5 (q = 1 and q = 0.5; 0 learned and 400 events alerted in every seed), because the host's other attack cases still led to a confirmation. Without B5, 21 patterns were learned at q = 1.
- *Host-wide* persuasion did defeat B5 whenever the first attack case on CLIENT1 carried the text and was cleared: 10 of 10 runs at q = 1, and 2 of 5 at q = 0.5. CLIENT1 was then never confirmed, 13 attack cases' patterns stayed learned for up to 268.5 h, and only 262 of 400 events were alerted. Across the 5 runs at q = 0.5, 5.2 patterns were learned on average.

B5 bounds poisoning by an analyst who errs independently, but not by one who is deceived about a whole host. That channel lies outside asymmetric trust by our threat model, and the result quantifies the gap.

*Fig. 4 (one column):* Patterns learned as benign (left) and attack events alerted (right) for 5% and 20% analyst misses, without (hatched) and with (solid) targeted unlearning; bars = mean over 6 seeds, whiskers = min–max.

*Editor note: Fig. 4 needs redrawing with the seed means and ranges.*

### D. What the LLM Contributes

Under the acting rule with a closed-world feasibility check, NCE cut host reviews to 54.6 per day. It also dismissed 2 attack cases, both on a server with no telemetry in the store. An open-world check, which treats unmonitored hosts as unknown, kept the workload at 54.8 per day with 0 attack dismissals. Both variants dismissed 89 benign cases, and with an analyst the workload was 33.2 per day.

That reduction comes entirely from dismissals, the path injected text attacks. Under asymmetric trust, workload was 65.2 reviews per day without an analyst and 34.1 with one, identical to turning NCE off. The LLM generated no escalation on clean traffic. Under the tested thresholds it therefore gave neither a workload reduction nor a detection gain.

Network containment of the attacker's command server followed the analyst delay exactly (60 to 4,320 minutes for 1 to 72 h), because containment waited for approval. Host workload rose with delay, from 33.1 reviews per day at 1 h to 51.5 at 72 h, with all 72 attack cases still raised.

*Editor notes: old §V-D and §V-E merged; Figs. 5 and 6 cut. The NCE-off rows stay in Table III.*

### E. Enforcement Summary

On the same recorded answers, asymmetric trust:
- left GUIDE suppression unchanged (4/428, 3/437, 10/437);
- removed every lost containment;
- held E1 at 0/72 dismissals.

It raised clean workload from 54.8 to 65.2 reviews per day without an analyst, and from 33.2 to 34.1 with one, because the model could no longer dismiss. The gpt-oss containment denominator moved from 176 to 178 for the same reason: two clean pairs whose review request had cancelled a block under the acting rule.

*Editor notes: old §V-F, 342 → about 90 words. Most of it is now in §V-A.*

## VI. Discussion and Limitations

Injected text does steer the model. It hijacked the undefended agent on 29.6% of pairs, and the steer payload made NCE name the attacker's chosen host in 30 of 38 cases. What the text achieves depends on the authority the output carries. With asymmetric trust, the same answers dismissed no attack and cancelled no containment, without the model having to recognize the attack, as in CaMeL [11]. The price is that the LLM, on this data, adds no measurable value to triage. Asymmetric trust also cannot restore an escalation the model fails to emit when the model is the only detector (the GUIDE residual).

For memory, the clean-weeks store does most of the work (98.9% fewer reviews). The gate and D7 kept autonomous learning from absorbing attacks, but they also kept it from learning anything on host logs: new normal patterns came only from analysts. The analyst is therefore the remaining poisoning channel. Targeted unlearning closes it for independent mistakes, but not for host-wide deception.

Limitations:
1. **One testbed.** There is one testbed campaign, with labels on two Windows hosts, and the GUIDE pairs are synthetic.
2. **Simulated analysts.** The analyst and its mistakes are simulated from labels. Real fatigue and deception may differ from our error models, including the persuasion model.
3. **Models and stochasticity.** DEDALE uses one model (gpt-oss-20b only on GUIDE development pairs). Seeds vary the simulated analyst, not the LLM, whose answers were recorded once.
4. **Clean training weeks.** Patterns learned in the training weeks are permanent, and poisoning during training is out of scope.
5. **Truncation.** NCE sees 512 characters per field; raw log lines were longer in 718 of 856 cases. The adaptive attacker moves its payload into view; a naive attacker's late payloads never reach the model.
6. **Mimicry and flooding.** 73 of 473 attack events matched learned routine activity. Deliberate mimicry, and escalation flooding against the review queue, were not evaluated.
7. **Untested costs and ablations.** Statistical power is low for the small discordant counts; ERA was not ablated on DEDALE; latency and token cost were not measured.

*Editor notes: 934 → about 390 words.*
- *Limitation 9 (prompt defences not evaluated) is removed: Tier 2 does it. Limitation 3 now says what the seeds cover.*
- *Limitation 5 (lookback) is removed: the sweep shows it does not matter here.*
- *Remove limitation 5 (truncation) from the list if the T2.3 numbers make the point in §V-A.*

## VII. Conclusion

GuardedSOC bounds what an LLM and an adaptive store may do in SOC triage. Asymmetric trust made injected log text unable to dismiss attack cases (0/72) or cancel containment. The quarantined gate kept autonomous learning from absorbing attacks, and targeted unlearning removed every pattern learned from independent analyst misses. Two results mark the boundary. Under these rules, the LLM gave no workload reduction over the model-free baseline. An analyst persuaded host-wide defeats unlearning. Future work: models that escalate usefully under asymmetric trust, and defences for the analyst channel.

*Editor notes: 253 → about 105 words.*

**Data & Code.** https://github.com/Akshara-reddy612/AgentSOC: the recorded LLM answers, the scripts that rebuild every number, the full algorithm, count glossary, pair identifiers and prompts (former Appendices A–D).

---

## Tables

**TABLE I. AgentSOC [1] and this work** (5 rows; Fail-Safes, Data detail and Evaluation merged)

| Aspect | AgentSOC [1] | This work |
|:--|:--|:--|
| Attack model | Stolen credentials, lateral movement, privilege escalation | Text injected into logs the LLM reads; poisoning of learned memory (V-A, V-C) |
| LLM authority | Infeasible hypotheses filtered by SSE | Asymmetric trust: output may add review, never dismiss, contain or teach (V-A, V-E) |
| Memory | Enterprise context and learned knowledge | Learning gate; analyst verdicts; targeted unlearning on confirmed compromise (V-B, V-C) |
| Data and models | 5,000 LANL events, 50-node topology; GPT-4 | GUIDE v2 (500 + 500 pairs), DEDALE (2 + 14 days); gemini-3.1-flash-lite, gpt-oss-20b |
| Evaluation | One proof-of-concept incident | Paired contamination tests with prompt-defence and adaptive baselines; seeded replays; Wilson intervals, exact McNemar |

**TABLE II. Attacker-written text, acting rule vs asymmetric trust** (rows added for Tier 2)

| Setting | Measure | Acting rule | Asym. trust |
|:--|:--|--:|--:|
| GUIDE dev, Gemini | Suppressed | 4/428 | 4/428 |
| | Containment removed | 20/178 | 0/178 |
| GUIDE held-out, Gemini | Suppressed | 3/437 | 3/437 |
| | Containment removed | 18/168 | 0/168 |
| GUIDE dev, gpt-oss-20b | Suppressed | 10/437 | 10/437 |
| | Containment removed | 21/176 | 0/178 |
| GUIDE dev, adaptive attacker | Suppressed | ⟨T2.3⟩/300 | ⟨T2.3⟩/300 |
| E1 DEDALE, no analyst | Attack cases dismissed (maint. / appr. / steer) | 1 / 3 / 1 of 72 | 0 / 0 / 0 of 72 |
| | Clean reviews per day | 54.8 | 65.2 |
| E1 DEDALE, analyst | Attack cases dismissed (all) | 0/72 | 0/72 |
| | Clean reviews per day | 33.2 | 34.1 |
| Undefended agent | Hijacked, dev / held-out | 130/439 / ⟨T2.1⟩ | n/a |
| | + delimited / spotlighting / hierarchy (dev) | ⟨T2.2⟩ / ⟨T2.2⟩ / ⟨T2.2⟩ of 439 | n/a |

**TABLE III. DEDALE host logs, 14 test days: memory and LLM conditions** (old Tables III and IV merged, plus precision and the K baseline)

| Condition | Reviews/day | Attack cases raised | Events alerted | Attack patterns learned | Precision | Benign dismissed |
|:--|--:|--:|--:|--:|--:|--:|
| No learning | 6095.4 | 80 | 473 | 0 | 0.1% | 0 |
| Clean weeks + gate | 65.2 | 72 | 400 | 0 | 7.9% | 0 |
| Frequency threshold K=2 / 5 / 10 | 86.4 / 163.4 / 718.7 | 72 | 400 | 0 | 5.9 / 3.1 / 0.7% | 0 |
| No gate | 27.4 | 38 | 99 | 38 | 9.9% | 1 |
| NCE, acting rule (open world) | 54.8 | 72 | 400 | 0 | 9.4% | 89 |
| NCE, asymmetric trust (= NCE off) | 65.2 | 72 | 400 | 0 | 7.9% | 0 |
| NCE + analyst, asymmetric trust | 34.1 | 72 | 400 | 0 | 15.1% | 0 |

*Editor notes on Table III:*
- *"Attack patterns learned" for the K rows is 0 from `tier1_scores.json` (`attack_cases_learned`); RESULTS.md states it as "same as frozen at every K". I'll add the column to RESULTS.md before this goes in.*
- *Precision and "benign dismissed" come from the detection-metrics table. Its acting-rule row is run `gated_nce_F_nce`, the 54.8/day open-world run (checked in `experiments/detection_metrics.py`).*

**TABLE IV. Analyst-induced poisoning, asymmetric trust, analyst after 4 h** (mean over seeds)

| Analyst | B5 | Seeds | Attack patterns learned | Events alerted (of 400) | Reviews/day |
|:--|:--|--:|--:|--:|--:|
| Misses 5% | off / on | 6 | 7.33 / 0 | 386.5 / 400 | 30.6 / 34.1 |
| Misses 20% | off / on | 6 | 18.5 / 0 | 333.3 / 400 | 30.0 / 34.1 |
| 5% false alarms | off / on | 6 | 0 / 0 | 400 / 400 | 31.4 / 41.8 |
| Persuaded per case, q=1 | off / on | 1 | 21 / 0 | 351 / 400 | 29.6 / 34.1 |
| Persuaded host-wide, q=1 | off / on | 1 | 32 / 13 | 99 / 262 | 28.4 / 30.0 |
| Persuaded host-wide, q=0.5 | off / on | 5 | 33.2 / 5.2 | 174.2 / 344.8 | 28.6 / 31.7 |

*Editor notes on Table IV:*
- *Host-wide, q = 1: the 10-seed runs with an added 20% miss rate give the same B5-on numbers (13 / 262 / 30), so the table could cite 10 seeds instead.*
- *The persuaded rows assume E1's command-line text reaches the analyst. RESULTS.md runs these with NCE from E1's recorded answers, not the clean run.*
