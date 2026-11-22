# Paper page budget: 8 pages, IEEE conference format (approved 2026-11-22)

Approved by the user on 2026-11-22, with 8 pages instead of the 7 first proposed. Source draft: `AgentSOC_IEEE_Revised.docx` (2026-11-22 10:26). Agents propose text; the user edits the docx.

## Measured starting point

- Word (repair mode, read-only copy): **9 pages, 10,510 words** at the draft's own format: 8.5 pt body, margins about 0.35 in.
- IEEE conference format (10 pt body; margins 0.75 in top, 1 in bottom, 0.625 in sides) fits about 0.63 of that per page. The same text would be **about 14 pages**.
- Assumption: the 8-page limit is in IEEE format and includes the references. Appendices count toward it, so they leave the paper.

## Space for everything that is not body text (8 pages)

| Item | Now | Proposed | Pages |
|:--|:--|:--|--:|
| Title, authors, keywords | as is | as is | 0.25 |
| Abstract | 243 words | 160 words | (in text) |
| Fig. 1 architecture | full page width | redraw to one column | 0.25 |
| Fig. 2 injection, two rules | 1 column | keep | 0.2 |
| Fig. 3 reviews per day, log scale | 1 column | keep | 0.2 |
| Fig. 4 analyst misses 5%/20% | 1 column | keep (poisoning is the paper's second claim) | 0.2 |
| Fig. 5 LLM contribution | 1 column | cut; 1 sentence plus Table III row | 0 |
| Fig. 6 analyst latency | 1 column | cut; 1 sentence | 0 |
| Table I AgentSOC vs this work | 9 rows | 5 rows | 0.2 |
| Table II main results, both rules | 13 rows | keep and add Tier 2 rows: held-out, 3 prompt defences, adaptive attacker | 0.3 |
| Tables III and IV, DEDALE conditions | 2 tables | merge into one Table III, with precision and recall columns (detection metrics) | 0.25 |
| New Table IV: poisoning and memory | none | A7 rarity baseline, gate delay, A10 persuaded analyst, A11 seeds, analyst miss rate | 0.3 |
| Appendices A–D | about 2/3 page | cut; to the repo (cited in Data & Code) | 0 |
| References | 21 entries | keep about 20 (8 pt) | 0.7 |
| Headings and spacing | | | 0.25 |
| **Total** | | | **about 3.3** |

That leaves **about 4.7 pages, about 4,700 words of body text**: 45% of today's 10,510.

## Words per section

| Section | Now | Target | What goes in, what goes out |
|:--|--:|--:|:--|
| Abstract | 243 | 160 | Problem, two mechanisms, 3 headline numbers, including one Tier 2 number |
| I. Introduction | 725 | 450 | Keep the motivation and contributions list (3 bullets). Cut the background that §II repeats |
| II. Base paper and related work | 1,194 | 520 | AgentSOC 150. Related work 370: injection with defences (incl. the T2.2 baselines [9][10][16]), memory poisoning, unlearning. The datasets subsection moves to §IV |
| III. Architecture | 1,774 | 1,000 | Threat model 300 (with Fig. 1). Asymmetric trust 360 (properties stated, proofs to the repo). Gate and unlearning 250 (incl. B5 rule). Fail-safes 90 |
| IV. Evaluation setup | 983 | 550 | GUIDE v2 170; DEDALE 170; protocol 210 (recorded answers, both rules, seeds, baselines; held-out set) |
| V. Results | 2,471 | 1,500 | A. Injection 380: Table II, Fig. 2, T2.1 held-out, T2.2 defences, T2.3 adaptive. B. Gated learning 350: Fig. 3, A7 baseline, gate delay, lookback. C. Poisoning and unlearning 400: Fig. 4, Table IV, A10, A11 seeds. D. LLM contribution and latency 220 (old D and E merged). E. Asymmetric trust enforcement 150 |
| VI. Discussion and limitations | 934 | 420 | Limitations kept, incl. those A10 shows: a persuaded analyst at host level beats B5. Discussion cut to its main point |
| VII. Conclusion | 253 | 120 | |
| Data & Code | 12 | 30 | Repo link; appendices and proofs live there |
| **Total** | **8,589** | **4,750** | |

## The new results the reviewer asked for, and where each lands

| Result | Status | Lands in |
|:--|:--|:--|
| Detection metrics (precision, recall) | scored | Table III columns |
| A7 rarity baseline (K = 1, 2, 5, 10) | scored (fix not yet committed) | §V-B, Table IV |
| Gate delay; lookback sweep | scored | §V-B, 1 sentence each; Table IV |
| A10 persuaded analyst | scored | §V-C, Table IV; §VI limitation |
| A11 seed variation | scored | Table IV (mean ± sd) |
| T2.1 undefended, held-out set | running | Table II |
| T2.2 delimited, spotlighting, instruction hierarchy | queued | Table II, §II citations |
| T2.3 adaptive attacker (ERA evaded) | queued | Table II, §V-A |

## Order of work

1. Budget approved (8 pages).
2. Rewrite §I–IV, §V-B to §V-E, §VI and §VII now. All numbers come from `experiments/RESULTS.md`.
3. When Tier 2 finishes: §V-A, Table II rows, abstract number.
4. A length check: put the text into an IEEE-format copy and count the pages in Word.
