"""Checklist A8: a planted event keeps the attack event's detector key, drops its text, and carries no label."""
import pytest

from experiments.dedale_plant import PLANTABLE, _harmless, plants
from perception.host_detection import DETECTORS

LINEAGE = {"t": "2025-01-06T10:01:13.986Z", "host": "CLIENT2", "rid": 4242, "ch": "sysmon", "code": 1,
           "image": "C:\\Windows\\System32\\cmd.exe", "parent_image": "C:\\Program Files\\Office\\WINWORD.EXE",
           "cmd": "cmd.exe /c powershell -enc AAAA", "parent_cmd": "WINWORD.EXE /n evil.docm"}
WRITE = {"t": "2025-01-06T10:02:00.000Z", "host": "CLIENT2", "rid": 4243, "ch": "sysmon", "code": 11,
         "image": "C:\\Windows\\System32\\cmd.exe", "file": "C:\\Users\\x\\AppData\\payload.exe"}


@pytest.mark.parametrize("event,detector", [(LINEAGE, "lineage"), (WRITE, "exec_file_write")])
def test_harmless_copy_keeps_the_key(event, detector):
    p = _harmless(event, detector, 3)
    assert DETECTORS[detector].key(p) == DETECTORS[detector].key(event)
    assert p["rid"] == -4 and p["planted"] == detector


def test_harmless_copy_drops_the_attack_text():
    p = _harmless(LINEAGE, "lineage", 0)
    assert "enc" not in p["cmd"] and "evil" not in p["parent_cmd"]
    assert "payload" not in _harmless(WRITE, "exec_file_write", 0)["file"]


def test_powershell_is_not_plantable_by_default():
    assert "powershell" not in PLANTABLE


def test_plants_rejects_unknown_timing():
    with pytest.raises(ValueError):
        plants("later")
