"""E1 (2026-10-18): attacker-written text in the attacker's own command lines, and NCE routing per family."""
from __future__ import annotations

from experiments.dedale_inject import FAMILIES, InjectedRouter, Injector, comment


def _event(rid=1, image="C:\\Windows\\System32\\cmd.exe", cmd="cmd.exe /c whoami", code=1, host="CLIENT2"):
    return {"t": "2025-01-06T10:00:00Z", "host": host, "rid": rid, "ch": "sysmon", "code": code,
            "image": image, "parent_image": "C:\\x\\p.exe", "cmd": cmd, "user": "BREACH\\client2"}


LABELS = {("CLIENT2", "sysmon", 1): 1, ("CLIENT2", "sysmon", 2): 2}


def test_only_the_attackers_process_command_lines_change():
    inj = Injector("suppress", LABELS)
    out = inj(_event())
    assert out["cmd"].startswith("cmd.exe /c whoami & rem ") and any(t in out["cmd"] for t in FAMILIES["suppress"])
    assert {k: v for k, v in out.items() if k != "cmd"} == {k: v for k, v in _event().items() if k != "cmd"}
    assert inj(_event(rid=2)) == _event(rid=2)                         # class 2: not the attacker's command
    assert inj(_event(rid=3)) == _event(rid=3)                         # unlabelled
    assert inj(_event(code=11)) == _event(code=11)                     # not a process creation
    assert inj(_event(cmd=None)) == _event(cmd=None)
    assert inj.injected == 1
    assert Injector("suppress", LABELS)(_event()) == out               # reproducible


def test_comment_syntax_per_shell():
    assert comment("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "x") == " # x"
    assert comment("C:\\Windows\\System32\\cmd.exe", "x") == " & rem x"
    assert comment("C:\\Temp\\svcmon.exe", "x") == ' --note "x"'


class _NCE:
    def __init__(self, name):
        self.name, self.live_calls, self.cache_hits, self.cache_misses = name, 1, 2, 3

    def __call__(self, alert):
        return self.name


def test_router_sends_injected_alerts_to_the_family_cache():
    r = InjectedRouter("steer", _NCE("main"), _NCE("family"))
    payload = FAMILIES["steer"][0]
    assert r({"command_line": f"cmd /c x & rem {payload}"}) == "family"
    assert r({"command_line": "cmd /c x"}) == "main" and r({}) == "main"
    assert (r.live_calls, r.cache_hits, r.cache_misses) == (2, 4, 6)
