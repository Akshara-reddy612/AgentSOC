# Viva preparation — questions and short answers (draft, 2026-10-31)

Simple answers to questions an examiner is likely to ask. Numbers come from `experiments/RESULTS.md`; those marked
**(verify)** depend on the DEDALE re-freeze running when this was written.

---

**1. What does your work add to the base paper (AgentSOC)?**

The base paper proposed three engines (an LLM that suggests attack hypotheses, a structural checker, and a response
ranker) and evaluated them conceptually, with a proof of concept on authentication data, with no attacker, no
memory and no analyst. We built the full pipeline plus the loop around it (a store that learns what is normal, a
learning gate, an outcome monitor and an analyst review loop) and evaluated two attack surfaces: the log text the
LLM reads, and the memory that learns. We tested on 1,000 clean/contaminated GUIDE alert pairs and four weeks of
DEDALE testbed telemetry, and added a design rule, asymmetric trust, that removes the attacker's remaining route
through the LLM.

**2. What is asymmetric trust, in one sentence?**

The LLM's output may raise scrutiny but never lower it: it can send a case to an analyst, but it cannot dismiss a
case, trigger an action, or make anything learnable.

**3. Why does asymmetric trust hold "by construction"?**

Because of how the decision is computed, not because the LLM behaves well. For every case the pipeline decides
twice: once without the LLM's hypotheses (the *text-free decision*) and once with them. The final outcome is the
text-free decision, unless the LLM asks for review, in which case it is review. Nothing in between can be lower.
Only actions of the text-free decision are allowed to run without an analyst; an action only the LLM supports
becomes a proposal. The learning gate only learns cases that were dismissed, and only the text-free decision can
dismiss. So whatever the LLM says (right, wrong or hijacked), it can only add review. We still test it: the rule
held on all 2,000 recorded LLM answers from two models and on 300 random adversarial inputs.

**4. What exactly does "what the attacker can't write" cover?**

The structured fields that sensors record (host name, account, parent process, the program path as recorded,
IP addresses and ports, event ids), the company's asset inventory and network plan, and the patterns the store has
learned behind the gate. It does not cover free text: command lines, script text, raw log lines, file and tool
names. Those the attacker controls, so only the LLM and the text-risk check (ERA) read them, and both can only
escalate. Tampering with the structured fields at the sensor itself is outside our threat model.

**5. If the rule is so strong, why does GUIDE still show 4 of 428 suppressed?**

On GUIDE there is no learned store, so the LLM is the only thing that notices a problem. In those 4 pairs the clean
alert's response came from the LLM reading the clean text, and the injected text kept it from noticing. The rule
stops the LLM from lowering a decision; it cannot make the LLM notice something. That is why our loop on DEDALE
lets the learned store do the detecting and lets the LLM only add, and there no attack case was dismissed.

**6. Why is the analyst channel a known gap?**

The rule limits the LLM, not the person. Analysts have to read the evidence, including the attacker's text, and a
benign verdict teaches the store; that is deliberate, because it is how analyst feedback cuts the workload (65 to
31-34 reviews per day). So a misled analyst can still teach the store something it should not learn. Our
mitigations: the learning gate, two analysts for containing critical hosts, and unlearning what was learned on a
host once it is confirmed compromised. Testing with real analysts is future work.

**7. Why do the detectors miss some labelled attack events?**

Two reasons. Coverage: the six detectors look at process launches, named pipes, executable file writes, PowerShell
scripts, logons and access to the credential process (LSASS); most labelled events are DLL loads and ordinary file
writes, which happen too often to learn reliably and were left out. Novelty: after learning the benign weeks, an
event whose pattern also appears in normal activity is treated as routine; 73 of the 473 labelled attack events
that alert with nothing learned stay silent **(verify)**. Every step of the attack still reached an analyst.

**8. What does asymmetric trust cost?**

Very little with an analyst: 0.9 more reviews per day on DEDALE (33.2 to 34.1). Without an analyst it costs 10.4
per day (54.8 to 65.2), because all the LLM's workload savings came from dismissing cases, the same thing the
attacker used it for. On GUIDE it cost nothing: the same 532 cases went to review and 336 were contained
automatically.

**9. What was the "containment removed by contamination" finding?**

Under the old rule, any review held back the alert's automatic block. Injected text that caused a review, mostly
because our own ERA detector flagged it, therefore delayed containment: 20 of 178, 18 of 168 and 21 of 176 GUIDE
pairs (11%). The usual suppression measure counted these as handled. Under asymmetric trust the block the trusted
telemetry supports runs anyway and the review is added: 0 removed.

**10. How do you know your numbers are reproducible, and what if bad input crashes the system?**

The LLM's answers were recorded once and are replayed, so no model call is needed: `freeze_dedale` re-runs all 43
DEDALE replays and `build_results` writes `RESULTS.md`, the source of every number in the paper. For bad input:
a pipeline error sends the case to an analyst, an event the pipeline fails on is quarantined while the server
recovers from its last checkpoint, malformed events are refused and counted, and a check that long crafted text
could slow down now reads only the part the LLM saw.
