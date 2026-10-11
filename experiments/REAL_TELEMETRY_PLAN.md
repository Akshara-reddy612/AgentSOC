# Real-telemetry evaluation — scoping (2026-10-11)

## Why

Corpus v2 measures **robustness to contamination** (clean vs contaminated twins), but it cannot measure **detection accuracy**: its evidence is synthetic and deliberately carries no ground-truth signal (see PROJECT_STATUS, step 4.4). Measuring whether the pipeline responds to real attacks and stays quiet on real benign activity needs real raw logs with known ground truth.

## Candidate datasets

Availability, licence and format below come from web search on 2026-10-11 and have **not been verified by downloading**.

| Dataset | What it is | Ground truth | Fit | Effort |
|:--|:--|:--|:--|:--|
| **DEDALE** (2025) | 8-day APT in a simulated corporate network (55 VMs), with benign user activity; Windows event logs, Linux syslog, network logs | Sigma-rule alerts with labels corrected by hand; each alert is a JSON Lines record with the original log, labelled true (attack) or false (benign) | **Best fit**: real alerts + raw log + labels + benign baseline period | Medium |
| **OTRF Security-Datasets (Mordor)** | Recorded host/network logs of simulated ATT&CK techniques (JSON, some PCAP); includes the benign events around each attack | Each dataset mapped to ATT&CK techniques; attack window known | Good for realistic evidence per technique; short captures, alerts must be generated (e.g. Sigma) | Low-medium |
| **SecOps Elasticsearch benchmark** (Hugging Face) | Real host telemetry (Elastic Endpoint, Zeek, nginx, Suricata) with scripted attacks on top of a live host's benign noise | By construction (attacks are scripted) | Good second source; Elastic schema | Medium |
| **Splunk BOTS v3** | CTF dataset, CC0, ~320 MB, pre-indexed for Splunk | Q&A-style, not per-event labels | Realistic but needs Splunk Enterprise and manual labelling | High |
| **Precinct6 (WitFoo)** | 1.96 M sanitized events from real enterprise monitoring | Malicious/benign labelling intended | Sanitized text may remove the free-text evidence NCE needs | Unknown |

## How real data would enter the pipeline (no leakage by design)

1. **Alerts**: run Sigma rules over the raw logs (DEDALE ships these); one alert = rule hit + the original event(s).
2. **Structured fields** (trusted): user, host, destination IP/domain, process id — parsed from the event's own fields, never from text.
3. **Free text** (NCE input): command line, process/parent image, script block, raw event — real attacker-influenced text instead of behaviour labels.
4. **Identity graph and baseline**: built from the dataset itself — users, hosts and group memberships seen in AD/logon events; HAS_PRIOR_ACCESS edges learned from a **benign-only training window** (e.g. the first days), evaluation on the later days. This replaces the synthetic inventory and gives a real "expected activity" baseline.
5. **Network context**: destinations observed in the logs; reputation only from information available at alert time (no ground-truth labels) — otherwise treat as unknown.
6. **Metrics**: per alert, response (REVIEW/AUTO_APPROVED) vs ground truth -> recall on attack alerts, response rate on benign alerts, analyst-review load; plus the existing contamination test by injecting payloads into the real free-text fields (paired, as in v2).

## Recommended first step

Download DEDALE (or, if unavailable, one OTRF compound dataset), write a converter to the alert schema with the field split above, and check on ~100 alerts that structured fields parse cleanly and NCE gets meaningful evidence — before any large API run.

## Sources

- MSTICPy docs, OTRF/Mordor data provider: https://msticpy.readthedocs.io/en/stable/data_acquisition/MordorData.html
- DEDALE / alert-dataset paper (PAR NSF): https://par.nsf.gov//servlets/purl/10530815
- Agentic alert investigation (AIT Log Data Set usage): https://arxiv.org/pdf/2604.25846
- SecOps Elasticsearch benchmark: https://huggingface.co/datasets/TocharianOU/secops-es-benchmark
- Precinct6 (WitFoo): https://huggingface.co/datasets/witfoo/precinct6-cybersecurity/blob/main/README.md
- Splunk BOTS v3 release: https://www.splunk.com/en_us/blog/security/botsv3-dataset-released.html
