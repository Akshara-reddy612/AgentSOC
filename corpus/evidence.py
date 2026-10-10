"""
corpus/evidence.py

Structured entities and free-text evidence for corpus v2 (Phase 3, 2026-10-11).

Differences from GUIDE_Dataset/processed/synth_fields.py (v1):
  - entities come from the synthetic enterprise inventory
    (perception/enterprise_model.py), so the identity graph knows them;
  - evidence is written as EDR-style behaviour labels
    (`[edr_behavior=execution.encoded_script_block]`) with arguments redacted,
    not as literal command lines.  v1's literal templates contained exactly
    the strings the T1071 grounding check matches, so the check's "lift" was
    a property of the generator; in v2 a network indicator appears only when
    the alert has trusted destination telemetry;
  - destinations come from the synthetic network model or are unlisted
    addresses in the same reserved ranges (RFC 5737 IPs, `.example` names);
    reputation is drawn from the row's seed, independently of IncidentGrade;
  - every bucket mixes suspicious and routine behaviours;
  - parent_process and registry_key are always populated (in v1 a non-null
    parent_process appeared only on contaminated alerts).
Template choice depends on Category/EntityType only, never on the grade.
"""
from __future__ import annotations

import hashlib
import random

from perception.enterprise_model import INVENTORY
from perception.network_model import KNOWN_BAD, SANCTIONED, SYNTHETIC_DESTINATIONS

CATEGORY_TO_EVENT_TYPE = {
    "SuspiciousActivity": "process_create", "Exfiltration": "data_exfiltration",
    "Malware": "process_create", "InitialAccess": "logon", "DefenseEvasion": "process_create",
    "CommandAndControl": "network_connect", "Impact": "process_create",
    "LateralMovement": "lateral_movement", "Execution": "process_create",
    "Collection": "process_create", "Discovery": "process_create",
    "Persistence": "registry_write", "UnwantedSoftware": "process_create",
    "CredentialAccess": "process_create", "PrivilegeEscalation": "privilege_escalation",
}

# Severity from the detection category (what a SIEM rule would assign), never from IncidentGrade.
CATEGORY_TO_SEVERITY = {
    "CommandAndControl": "high", "Exfiltration": "high", "CredentialAccess": "high",
    "LateralMovement": "high", "PrivilegeEscalation": "high", "Impact": "high", "Malware": "high",
    "InitialAccess": "medium", "Execution": "medium", "DefenseEvasion": "medium",
    "Persistence": "medium", "SuspiciousActivity": "medium",
    "Discovery": "low", "Collection": "low", "UnwantedSoftware": "low",
}

NETWORK_BUCKETS = {"c2", "exfiltration", "initial_access"}
REPUTATIONS = (KNOWN_BAD, SANCTIONED, "unknown")
REPUTATION_WEIGHTS = (0.3, 0.3, 0.4)

# (process image, behaviour label) per bucket — suspicious and routine mixed.
BEHAVIOURS = {
    "credential_access": [
        ("unknown_tool.exe", "credential_access.auth_process_memory_read"),
        ("taskmgr.exe", "process.memory_snapshot.user_initiated"),
        ("powershell.exe", "credential_access.credential_store_query"),
        ("lsaiso.exe", "auth.routine_token_refresh"),
    ],
    "defense_evasion": [
        ("rundll32.exe", "defense_evasion.signed_binary_proxy_load"),
        ("msiexec.exe", "software.install.signed_vendor"),
        ("powershell.exe", "defense_evasion.security_tool_config_change"),
        ("certutil.exe", "certificate.routine_store_update"),
    ],
    "execution": [
        ("powershell.exe", "execution.encoded_script_block"),
        ("powershell.exe", "execution.scheduled_inventory_script"),
        ("wscript.exe", "execution.script_from_downloads"),
        ("cmd.exe", "execution.admin_batch_job"),
    ],
    "c2": [
        ("curl.exe", "network.periodic_outbound_http"),
        ("powershell.exe", "network.scripted_outbound_http"),
        ("OneDrive.exe", "network.cloud_sync"),
        ("svchost.exe", "network.service_update_check"),
    ],
    "exfiltration": [
        ("7z.exe", "collection.archive_user_documents"),
        ("robocopy.exe", "file.bulk_copy"),
        ("chrome.exe", "network.large_upload"),
        ("OneDrive.exe", "network.cloud_sync"),
    ],
    "initial_access": [
        ("outlook.exe", "email.attachment_opened"),
        ("chrome.exe", "network.credential_page_visit"),
        ("winword.exe", "document.macro_prompt"),
        ("outlook.exe", "email.link_clicked"),
    ],
    "malware": [
        ("unknown_binary.exe", "malware.av_detection_quarantined"),
        ("setup.exe", "software.install.unsigned"),
        ("svchost.exe", "malware.av_detection_blocked"),
    ],
    "default": [
        ("explorer.exe", "process.routine_activity"),
        ("svchost.exe", "service.routine_activity"),
        ("powershell.exe", "execution.admin_script"),
        ("teams.exe", "application.routine_activity"),
    ],
}

PARENTS = {
    "execution": ["explorer.exe", "winword.exe", "outlook.exe", "cmd.exe"],
    "initial_access": ["explorer.exe", "outlook.exe", "chrome.exe"],
    "default": ["explorer.exe", "services.exe", "svchost.exe", "userinit.exe"],
}

FILE_PATHS = [
    "C:\\Users\\{user}\\Documents\\report_{rand}.xlsx",
    "C:\\Users\\{user}\\Downloads\\invoice_{rand}.pdf",
    "C:\\Users\\{user}\\AppData\\Local\\Temp\\tmp{rand}.dat",
    "C:\\ProgramData\\Vendor{rand}\\cache.db",
]
REGISTRY_KEYS = [
    "HKCU\\Software\\Microsoft\\Office\\16.0\\Common\\Roaming",
    "HKLM\\Software\\Vendor{rand}\\Settings",
    "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs",
    "HKLM\\System\\CurrentControlSet\\Services\\svc{rand}\\Parameters",
]

_LISTED_IPS = {d["address"] for d in SYNTHETIC_DESTINATIONS if d["kind"] == "ip"}
_RFC5737 = ("192.0.2", "198.51.100", "203.0.113")
_UNLISTED_WORDS = ["cdn", "files", "static", "api", "sync", "media", "portal", "edge"]


def row_rng(key: str, salt: str = "") -> random.Random:
    h = hashlib.sha256(f"{key}|{salt}".encode()).hexdigest()
    return random.Random(int(h[:12], 16))


def bucket(category, mitre) -> str:
    cat = str(category or "").lower()
    if "T1003" in str(mitre or "") or cat == "credentialaccess":
        return "credential_access"
    return {"defenseevasion": "defense_evasion", "execution": "execution", "commandandcontrol": "c2",
            "exfiltration": "exfiltration", "malware": "malware", "initialaccess": "initial_access"}.get(cat, "default")


def _unlisted_ip(rng: random.Random) -> str:
    while True:
        ip = f"{rng.choice(_RFC5737)}.{rng.randint(1, 254)}"
        if ip not in _LISTED_IPS:
            return ip


def pick_destination(rng: random.Random) -> dict:
    """Trusted network telemetry for one alert; reputation independent of the label."""
    rep = rng.choices(REPUTATIONS, REPUTATION_WEIGHTS)[0]
    as_domain = rng.random() < 0.5
    if rep == "unknown":
        domain = f"{rng.choice(_UNLISTED_WORDS)}{rng.randint(100, 999)}.example" if as_domain else None
        ip = _unlisted_ip(rng)
    else:
        pool = [d for d in SYNTHETIC_DESTINATIONS if d["reputation"] == rep
                and d["kind"] == ("domain" if as_domain else "ip")]
        chosen = rng.choice(pool)["address"]
        domain, ip = (chosen, _unlisted_ip(rng)) if as_domain else (None, chosen)
    return {"destination_ip": ip, "destination_domain": domain, "reputation": rep}


def pick_entities(rng: random.Random, category: str) -> dict:
    """source_user / source_host / target_host from the inventory."""
    privileged_mix = category in ("CredentialAccess", "LateralMovement", "PrivilegeEscalation")
    roll = rng.random()
    if privileged_mix and roll < 0.3:
        acct = rng.choice([a for a in INVENTORY.accounts if a.role in ("helpdesk_admin", "server_admin", "service")])
    elif roll < 0.05:
        acct = rng.choice(INVENTORY.by_role("helpdesk_admin"))
    else:
        acct = rng.choice(INVENTORY.by_role("standard_user"))
    endpoints = [h.host_id for h in INVENTORY.hosts if h.zone == "WORKSTATION"]
    source = acct.home_host or rng.choice(endpoints)
    target = source
    if category == "LateralMovement":
        target = rng.choice([h.host_id for h in INVENTORY.hosts if h.host_class == "FILE_SERVER"])
    return {"source_user": acct.account_id, "source_host": source, "target_host": target}


def synthesize(key: str, category: str, mitre, entity_type: str, timestamp, last_verdict) -> dict:
    """All clean v2 fields for one GUIDE row (deterministic in `key`)."""
    rng = row_rng(key, "evidence")
    b = bucket(category, mitre)
    ents = pick_entities(row_rng(key, "entities"), category)
    network = b in NETWORK_BUCKETS or entity_type in ("Ip", "Url")
    dest = pick_destination(row_rng(key, "destination")) if network else None
    proc, behaviour = rng.choice(BEHAVIOURS.get(b, BEHAVIOURS["default"]))
    fill = {"user": ents["source_user"], "rand": rng.randint(1000, 9999)}
    dst_text = (dest["destination_domain"] or dest["destination_ip"]) if dest else None
    cmd = f"{proc} <arguments redacted> [edr_behavior={behaviour}]" + (f" dst={dst_text}" if dst_text else "")
    file_path = rng.choice(FILE_PATHS).format(**fill)
    reg_key = rng.choice(REGISTRY_KEYS).format(**fill)
    parent = rng.choice(PARENTS.get(b, PARENTS["default"]))
    verdict = f" verdict={last_verdict}" if last_verdict else ""
    raw = (f"[{timestamp}] category={category} entity={entity_type}{verdict} | "
           f"user={ents['source_user']} device={ents['source_host']} process={proc} parent={parent} "
           f"behavior={behaviour}")
    if dst_text:
        raw += f" dst={dst_text}"
    if entity_type == "File":
        raw += f' file_path="{file_path}"'
    elif str(entity_type).startswith("Registry"):
        raw += f' registry_key="{reg_key}"'
    return {
        **ents,
        "event_type": CATEGORY_TO_EVENT_TYPE.get(category, "process_create"),
        "severity": CATEGORY_TO_SEVERITY.get(category, "medium"),
        "source_system": "EDR" if entity_type in ("Process", "File", "RegistryKey", "RegistryValueName",
                                                  "RegistryValueData", "Machine") else "SIEM",
        "process_name": proc,
        "command_line": cmd,
        "registry_key": reg_key,
        "parent_process": parent,
        "file_path": file_path,
        "raw_log_line": raw,
        "destination_ip": dest["destination_ip"] if dest else None,
        "destination_domain": dest["destination_domain"] if dest else None,
        "_destination_reputation": dest["reputation"] if dest else None,
        "_bucket": b,
    }
