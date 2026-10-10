"""
perception/enterprise_model.py

Synthetic enterprise identity and asset inventory (added 2026-10-11, Phase 3
step 3.1).

THIS IS SYNTHETIC DATA.  It plays the role of a real SOC's CMDB + directory:
who the users are, which device each one uses, which groups grant admin
rights where, and which service accounts run on which servers.  It is seeded
into the Knowledge Store graph (knowledge_graph._seed_enterprise_model) and
the v2 corpus builder (corpus/build_v2.py) draws every alert's structured
entities (source_user, source_host) from it, so a hypothesis naming the
alert's real entities can be structurally FEASIBLE — the old graph held none
of the corpus's entities, which made every non-T1071 hypothesis INFEASIBLE by
construction.

Deterministic (random.Random(73)).  Host numbers are 5-digit so they cannot
collide with the 4-digit names of the historical corpora (re-scores of old
runs are unaffected).  Like network_model.py this is TRUSTED context: read by
SSE / RSEM / Action layer and the corpus builder, never by NCE or prompts.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

SEED = 73

N_STANDARD_USERS = 36
LOCAL_ADMIN_RATE = 0.15        # users with admin rights on their own device (common misconfiguration)
LAPTOP_RATE = 0.4

_FIRST_INITIALS = "abcdefghjklmnprstvw"
_SURNAMES = [
    "patel", "chen", "garcia", "okafor", "novak", "silva", "kim", "haddad", "muller", "rossi",
    "tanaka", "kowalski", "nguyen", "ali", "jensen", "dubois", "costa", "ivanova", "obrien", "mensah",
    "sato", "fischer", "lopez", "khan", "berg", "moreau", "yilmaz", "santos", "park", "walsh",
    "ahmed", "lindqvist", "reyes", "petrov", "adeyemi", "hughes", "romero", "schmidt", "das", "kaur",
]
_DEPARTMENTS = ["finance", "hr", "engineering", "sales", "legal", "operations"]


@dataclass(frozen=True)
class Account:
    account_id: str
    account_type: str            # knowledge_graph.AccountType value
    role: str                    # standard_user / helpdesk_admin / server_admin / domain_admin / service
    home_host: str | None = None
    department: str | None = None
    local_admin: bool = False
    groups: tuple[str, ...] = ()
    mfa_enabled: bool = True


@dataclass(frozen=True)
class Host:
    host_id: str
    host_class: str              # knowledge_graph.HostClass value
    zone: str
    criticality_tier: int
    department: str | None = None


@dataclass(frozen=True)
class Grant:
    principal: str               # "account:<id>" or "group:<id>"
    host_id: str
    level: str                   # knowledge_graph.AccessLevel name: READ / RDP / ADMIN / DOMAIN_ADMIN


@dataclass
class Inventory:
    accounts: list[Account] = field(default_factory=list)
    hosts: list[Host] = field(default_factory=list)
    grants: list[Grant] = field(default_factory=list)
    prior_access: list[tuple[str, str]] = field(default_factory=list)   # (account_id, host_id)

    def account(self, account_id: str) -> Account | None:
        return next((a for a in self.accounts if a.account_id == account_id), None)

    def host(self, host_id: str) -> Host | None:
        return next((h for h in self.hosts if h.host_id == host_id), None)

    def by_role(self, role: str) -> list[Account]:
        return [a for a in self.accounts if a.role == role]


def _build() -> Inventory:
    rng = random.Random(SEED)
    inv = Inventory()
    used_numbers: set[int] = set()

    def number() -> int:
        while True:
            n = rng.randint(10000, 99999)
            if n not in used_numbers:
                used_numbers.add(n)
                return n

    # --- servers ---
    file_servers = []
    for dept in _DEPARTMENTS:
        h = Host(f"SRV-FILE{number()}", "FILE_SERVER", "WEB", 1, dept)
        inv.hosts.append(h)
        file_servers.append(h)
    db_servers = [Host(f"SRV-DB{i:02d}", "DB_SERVER", "DATABASE", 2) for i in (1, 2)]
    dcs = [Host(f"SRV-DC{i:02d}", "DOMAIN_CONTROLLER", "MANAGEMENT", 3) for i in (1, 2)]
    inv.hosts += db_servers + dcs

    # --- standard users with their own device ---
    names: set[str] = set()
    while len(names) < N_STANDARD_USERS:
        names.add(f"{rng.choice(_FIRST_INITIALS)}.{rng.choice(_SURNAMES)}")
    endpoints = []
    for name in sorted(names):
        dept = rng.choice(_DEPARTMENTS)
        if rng.random() < LAPTOP_RATE:
            dev = Host(f"LT-{number()}-CORP", "LAPTOP_CORP", "WORKSTATION", 0, dept)
        else:
            dev = Host(f"WKSTN-{number()}", "WORKSTATION", "WORKSTATION", 0, dept)
        inv.hosts.append(dev)
        endpoints.append(dev)
        local_admin = rng.random() < LOCAL_ADMIN_RATE
        inv.accounts.append(Account(name, "STANDARD_USER", "standard_user", dev.host_id, dept,
                                    local_admin, (), rng.random() < 0.85))
        inv.prior_access.append((name, dev.host_id))
        inv.grants.append(Grant(f"account:{name}", dev.host_id, "ADMIN" if local_admin else "READ"))
        # department share
        share = next(f for f in file_servers if f.department == dept)
        inv.grants.append(Grant(f"account:{name}", share.host_id, "READ"))
        inv.prior_access.append((name, share.host_id))

    # --- admin roles (group-mediated rights) ---
    def admins(prefix: str, role: str, acct_type: str, group: str, n: int) -> None:
        for _ in range(n):
            while True:
                aid = f"{prefix}.{rng.choice(_SURNAMES)}"
                if aid not in names:
                    names.add(aid)
                    break
            inv.accounts.append(Account(aid, acct_type, role, None, "it", False, (group,), True))

    admins("hd", "helpdesk_admin", "LOCAL_ADMIN", "workstation-admins", 3)
    admins("sa", "server_admin", "LOCAL_ADMIN", "server-admins", 2)
    admins("da", "domain_admin", "DOMAIN_ADMIN", "domain-admins", 2)

    for dev in endpoints:
        inv.grants.append(Grant("group:workstation-admins", dev.host_id, "ADMIN"))
    for srv in file_servers + db_servers:
        inv.grants.append(Grant("group:server-admins", srv.host_id, "ADMIN"))
    for dc in dcs:
        inv.grants.append(Grant("group:domain-admins", dc.host_id, "DOMAIN_ADMIN"))

    # --- service accounts ---
    inv.accounts.append(Account("svc_sql", "SERVICE_ACCOUNT", "service", db_servers[0].host_id, "it", False, (), False))
    inv.accounts.append(Account("svc_files", "SERVICE_ACCOUNT", "service", file_servers[0].host_id, "it", False, (), False))
    inv.accounts.append(Account("svc_deploy", "SERVICE_ACCOUNT", "service", None, "it", False,
                                ("workstation-admins",), False))
    for db in db_servers:
        inv.grants.append(Grant("account:svc_sql", db.host_id, "ADMIN"))
    for fs in file_servers:
        inv.grants.append(Grant("account:svc_files", fs.host_id, "ADMIN"))
    return inv


INVENTORY: Inventory = _build()
