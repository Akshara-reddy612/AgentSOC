# Paper outline (M3, 2026-10-18)

- **Thesis** (`PROJECT_PLAN.md` P1): an LLM-driven SOC has two attack surfaces, the LLM reading log text an attacker can write and the memory that learns from what it sees, and the full pipeline defends both while keeping the workload benefit of automation.
- **Format:** IEEE conference, about 8 pages (the venue is chosen after the draft, P2).
- **Source of every number:** `experiments/RESULTS.md`.
- **Old draft:** `agentsoc2_paper_corrected.tex` (contamination only). Its architecture sections are reused. Its results sections (n = 400, n = 320, n = 60, ApprovalClaimDetector, RSEM tie-blindness) are replaced; see `experiments/PAPER_CLAIMS_TO_REVISE.md`.

**Working title:** *Securing Autonomous Defense: Contamination and Memory Poisoning in a Learning Agentic SOC.*

## Sections

| # | Section | Content | Evidence | Writer |
|:--|:--|:--|:--|:--|
| 1 | Introduction | Agentic SOCs reason over attacker-writable logs and learn from them. Two attack surfaces; why both matter together; contributions C1-C5 | — | Claude draft (P6, 2026-10-19); team revises |
| 2 | Background and related work | Agentic SOCs (AgentSOC base paper), prompt injection / log contamination, memory poisoning in learning systems, alert triage and fatigue, datasets (GUIDE, DEDALE) | — | Claude draft (P6, 2026-10-19); team revises |
| 3 | Threat model | Attacker controls free text in their own telemetry (command lines, raw logs), not structured sensor fields, the inventory, the gate or the analyst. Goals: suppress (dismissal / learning as routine), misdirect (wrong containment). Out of scope: tampering at the sensor (discussed via the GUIDE structured-field test) | — | Claude |
| 4 | System | One pipeline: NCE -> SSE + entity binding (open world) -> RSEM -> guardrails -> triage gate -> learning Knowledge Store (trusted-only writes, learning gate) -> outcome monitor -> analyst review loop (inbox, four-eyes, unlearning). One figure. Invariants I1-I6 | architecture docs | Claude (reuse old section 4) |
| 5 | Evaluation setup | GUIDE corpus v2 (clean / contaminated twins, 10 payload families, dev / held-out); DEDALE (4 weeks, 2 benign training weeks, exact host labels); learning modes; simulated analyst; models; metrics; reproducibility (`REPRODUCE.md`) | — | Claude |
| 6.1 | Results: contamination (C1) | GUIDE dev / held-out suppression vs induced; undefended agent vs defended pipeline (29.6% vs 0.9%); E1 on real telemetry | RESULTS C1 tables | Claude |
| 6.2 | Results: the learning store (C2) | Static / frozen / gated / ungated on host and network | RESULTS C2 | Claude |
| 6.3 | Results: poisoning (C3) | Ungated learns the attacker; analyst mistakes; unlearning on confirmation | RESULTS C3 | Claude |
| 6.4 | Results: the LLM's contribution (C4) | Modest reduction; closed-world failure and the open-world fix | RESULTS C4 | Claude |
| 6.5 | Results: operating the loop (C5) | Analyst delay, containment time, false alarms | RESULTS C5 | Claude |
| 7 | Discussion and limitations | One real dataset (2 attacked hosts), simulated analyst, one LLM on DEDALE (second model on GUIDE), synthetic GUIDE evidence; what a deployment would need | RESULTS "Limits" | Claude draft (2026-10-19); team revises |
| 8 | Conclusion | — | — | Claude draft (P6, 2026-10-19); team revises |

## Figures and tables (draft)

- **Fig. 1** — pipeline and loop (sections 4, 6).
- **Table 1** — C1: GUIDE suppression, undefended vs defended.
- **Table 2** — E1.
- **Table 3** — C2 host + network.
- **Table 4** — C3 analyst mistakes, B5 on / off.
- **Fig. 2** — reviews / day over the 14 test days per learning mode (data in `final_host_scores.json`, `by_day`).
- **Table 5** — C4.
- **Fig. 3** — analyst delay vs reviews / day and containment time (C5).

## Open before the draft is final

- Authors and the repository link (team).
- Fig. 2 and Fig. 3 are not drawn yet: the frozen score files have no per-day series, so Fig. 2 needs a small extraction from the run stores.

- The gpt-oss-20b GUIDE dev run (590 / 1,000; resumes daily).
- **Optional E3 (AIT-LDS):** decided after this draft (plan section 4).
