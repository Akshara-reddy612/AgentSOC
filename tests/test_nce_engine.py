"""
tests/test_nce_engine.py

Tests for the NCE LLM-calling adapter (Phase NCE-3).

Split into:
- MOCKED tests (7): no real API calls, all LLM responses are pre-crafted
- SMOKE test (1): one real Gemini call, skipped by default via @pytest.mark.smoke

The smoke test requires:
1. A valid GEMINI_API_KEY or GEMINI_API_KEYS environment variable
2. Explicit opt-in: pytest -m smoke
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

from perception.nce_contract import (
    HypothesisStatus,
    MissingContextFlag,
    NCEInput,
    NCEOutput,
    FORBIDDEN_FIELD_NAMES,
)
from perception.nce_engine import (
    NCECallResult,
    _extract_hypotheses_array,
    _parse_single_hypothesis,
    generate_hypotheses,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_nce_input(**evidence_fields: str) -> NCEInput:
    """Build a valid NCEInput with the given evidence fields."""
    if not evidence_fields:
        evidence_fields = {"raw_log_line": "User login from 10.0.0.1"}
    return NCEInput(
        incident_id="INC-TEST-001",
        evidence_fields=dict(evidence_fields),
        timestamp=datetime.now(timezone.utc),
    )


def _make_valid_hypothesis_dict(
    technique_id: str = "T1078",
    nce_confidence: float = 0.85,
    **overrides: object,
) -> dict:
    """Build a valid hypothesis dict as the LLM would return it."""
    base = {
        "technique_id": technique_id,
        "source_account": "admin@corp.local",
        "source_host": "WS-001",
        "target_host": "SRV-DC-01",
        "nce_confidence": nce_confidence,
        "supporting_evidence_refs": ["raw_log_line"],
        "missing_context_flags": [],
    }
    base.update(overrides)
    return base


def _mock_gemini_response(parsed_json: object) -> dict:
    """Build a _call_gemini_nce-style result dict for a successful parse."""
    raw = json.dumps(parsed_json)
    return {
        "raw_response": raw,
        "parsed": parsed_json,
        "parse_error": None,
    }


def _mock_gemini_parse_error(raw_text: str = "not json at all") -> dict:
    """Build a _call_gemini_nce-style result dict for a JSON parse failure."""
    return {
        "raw_response": raw_text,
        "parsed": None,
        "parse_error": f"JSON_PARSE_ERROR: Expecting value: line 1 column 1 (char 0)",
    }


def _mock_gemini_api_error() -> dict:
    """Build a _call_gemini_nce-style result dict for an API error."""
    return {
        "raw_response": None,
        "parsed": None,
        "parse_error": "API_ERROR: ConnectionError: test error",
    }


# ---------------------------------------------------------------------------
# 1. [MOCKED] Valid 2-hypothesis response
# ---------------------------------------------------------------------------

class TestValidTwoHypotheses:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_success_with_two_hypotheses(self, mock_call: MagicMock) -> None:
        """
        A valid JSON array with 2 well-formed hypotheses should produce
        success=True, output with 2 hypotheses, both stamped with the
        correct incident_id and status=GENERATED.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.85),
            _make_valid_hypothesis_dict("T1550", 0.70),
        ])

        nce_input = _make_nce_input(raw_log_line="User login from 10.0.0.1")
        result = generate_hypotheses(nce_input)

        assert isinstance(result, NCECallResult)
        assert result.success is True
        assert result.error is None
        assert result.output is not None
        assert len(result.output.hypotheses) == 2
        assert result.api_call_count == 1

        for h in result.output.hypotheses:
            assert h.incident_id == "INC-TEST-001"
            assert h.status == HypothesisStatus.GENERATED

        # Verify technique IDs
        technique_ids = {h.technique_id for h in result.output.hypotheses}
        assert technique_ids == {"T1078", "T1550"}


# ---------------------------------------------------------------------------
# 2. [MOCKED] 1 valid + 1 invalid hypothesis (bad technique_id)
# ---------------------------------------------------------------------------

class TestPartialInvalidHypotheses:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_invalid_hypothesis_dropped_not_fatal(self, mock_call: MagicMock) -> None:
        """
        A response with 1 valid + 1 invalid hypothesis (bad technique_id)
        should succeed with only 1 hypothesis — the invalid one is dropped.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.85),
            _make_valid_hypothesis_dict("T9999_INVALID", 0.60),  # bad technique
        ])

        nce_input = _make_nce_input(raw_log_line="Suspicious command")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 1
        assert result.output.hypotheses[0].technique_id == "T1078"

    @patch("perception.nce_engine._call_gemini_nce")
    def test_invalid_flag_rejects_entire_hypothesis(self, mock_call: MagicMock) -> None:
        """
        BUG 1 FIX: A hypothesis with one valid + one invalid
        missing_context_flag must be ENTIRELY rejected — not partially
        repaired by silently stripping the bad flag.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict(
                "T1078", 0.85,
                missing_context_flags=["target_privilege_level", "INVALID_FLAG"],
            ),
            _make_valid_hypothesis_dict("T1550", 0.70),  # this one is fine
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        # Only the valid hypothesis (T1550) should survive
        assert len(result.output.hypotheses) == 1
        assert result.output.hypotheses[0].technique_id == "T1550"

    @patch("perception.nce_engine._call_gemini_nce")
    def test_all_flags_invalid_rejects_hypothesis(self, mock_call: MagicMock) -> None:
        """
        A hypothesis where ALL flags are invalid is also rejected entirely.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict(
                "T1078", 0.85,
                missing_context_flags=["BOGUS_1", "BOGUS_2"],
            ),
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is False
        assert result.output is None
        assert "BOGUS_1" in (result.error or "")

    @patch("perception.nce_engine._call_gemini_nce")
    def test_empty_flags_list_is_fine(self, mock_call: MagicMock) -> None:
        """
        An empty missing_context_flags list is NOT an error — only reject
        when a flag VALUE present in the list is invalid.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict(
                "T1078", 0.85,
                missing_context_flags=[],
            ),
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 1


# ---------------------------------------------------------------------------
# 3. [MOCKED] All hypotheses invalid -> success=False
# ---------------------------------------------------------------------------

class TestAllHypothesesInvalid:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_all_invalid_produces_failure(self, mock_call: MagicMock) -> None:
        """
        When ALL hypotheses in the response are invalid, the call should
        fail with a clear error and raw_response preserved.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("INVALID_1", 0.85),
            _make_valid_hypothesis_dict("INVALID_2", 0.60),
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is False
        assert result.output is None
        assert result.raw_response is not None
        assert result.error is not None
        assert "failed validation" in result.error.lower() or "drop" in result.error.lower()

    @patch("perception.nce_engine._call_gemini_nce")
    def test_all_invalid_preserves_raw_response(self, mock_call: MagicMock) -> None:
        """raw_response must be preserved even when all hypotheses fail."""
        response_data = [
            _make_valid_hypothesis_dict("BAD_ID", 2.5),  # bad confidence too
        ]
        mock_call.return_value = _mock_gemini_response(response_data)

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is False
        assert result.raw_response is not None
        assert json.dumps(response_data) in result.raw_response


# ---------------------------------------------------------------------------
# 4. [MOCKED] Non-JSON response triggers retry
# ---------------------------------------------------------------------------

class TestRetryOnJsonParseFailure:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_retries_on_json_failure_then_fails(self, mock_call: MagicMock) -> None:
        """
        When the LLM returns non-JSON, retry up to max_retries times.
        If all retries fail, return success=False.
        The mock should be called max_retries + 1 times total.
        """
        mock_call.return_value = _mock_gemini_parse_error("this is not json")

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input, max_retries=2)

        assert result.success is False
        assert result.error is not None
        assert "JSON_PARSE_ERROR" in result.error
        # Should have been called 3 times (1 initial + 2 retries)
        assert mock_call.call_count == 3
        assert result.api_call_count == 3

    @patch("perception.nce_engine._call_gemini_nce")
    def test_retry_succeeds_on_second_attempt(self, mock_call: MagicMock) -> None:
        """
        First call returns bad JSON, second returns valid JSON.
        Should succeed with api_call_count=2.
        """
        mock_call.side_effect = [
            _mock_gemini_parse_error("bad json"),
            _mock_gemini_response([
                _make_valid_hypothesis_dict("T1078", 0.80),
            ]),
        ]

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input, max_retries=1)

        assert result.success is True
        assert result.api_call_count == 2
        assert result.output is not None
        assert len(result.output.hypotheses) == 1

    @patch("perception.nce_engine._call_gemini_nce")
    def test_api_error_not_retried(self, mock_call: MagicMock) -> None:
        """API errors should NOT trigger retries (rate-limit retries are internal)."""
        mock_call.return_value = _mock_gemini_api_error()

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input, max_retries=2)

        assert result.success is False
        assert "API_ERROR" in (result.error or "")
        # Only 1 call — no retries on API errors
        assert mock_call.call_count == 1
        assert result.api_call_count == 1


# ---------------------------------------------------------------------------
# 5. [MOCKED] 4+ hypotheses -> truncated to top 3 by confidence
# ---------------------------------------------------------------------------

class TestHypothesisCapTruncation:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_four_hypotheses_truncated_to_top_three(self, mock_call: MagicMock) -> None:
        """
        If the model returns 4 valid hypotheses, only the top 3 by
        nce_confidence should survive.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.90),   # #1
            _make_valid_hypothesis_dict("T1550", 0.50),   # #4 — should be dropped
            _make_valid_hypothesis_dict("T1562", 0.80),   # #2
            _make_valid_hypothesis_dict("T1484", 0.70),   # #3
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 3

        # Top 3 by confidence: T1078 (0.90), T1562 (0.80), T1484 (0.70)
        confidences = [h.nce_confidence for h in result.output.hypotheses]
        assert confidences == sorted(confidences, reverse=True)
        technique_ids = {h.technique_id for h in result.output.hypotheses}
        assert "T1550" not in technique_ids  # the 0.50 one was dropped
        assert technique_ids == {"T1078", "T1562", "T1484"}

    @patch("perception.nce_engine._call_gemini_nce")
    def test_five_hypotheses_with_invalids(self, mock_call: MagicMock) -> None:
        """
        5 hypotheses total, 1 invalid → 4 valid → truncated to top 3.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.95),
            _make_valid_hypothesis_dict("INVALID", 0.99),   # invalid — dropped before cap
            _make_valid_hypothesis_dict("T1550", 0.85),
            _make_valid_hypothesis_dict("T1562", 0.75),
            _make_valid_hypothesis_dict("T1484", 0.65),
        ])

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 3
        # Top 3 of 4 valid: T1078 (0.95), T1550 (0.85), T1562 (0.75)
        technique_ids = {h.technique_id for h in result.output.hypotheses}
        assert technique_ids == {"T1078", "T1550", "T1562"}


# ---------------------------------------------------------------------------
# 6. [MOCKED] No trusted-context data in prompt sent to LLM
# ---------------------------------------------------------------------------

class TestNoTrustedContextInPrompt:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_prompt_contains_no_trusted_context_fields(self, mock_call: MagicMock) -> None:
        """
        The prompt string sent to the LLM must NOT contain any
        ImmutableContext or DerivedContext field names as XML tags.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.85),
        ])

        nce_input = _make_nce_input(
            raw_log_line="svchost.exe connecting to 10.1.2.3",
            command_line="net use \\\\SRV-01\\c$",
        )
        result = generate_hypotheses(nce_input)

        # Inspect the prompt that was passed to _call_gemini_nce
        assert mock_call.called
        prompt_sent = mock_call.call_args[0][0]  # first positional arg

        # Check that no ImmutableContext/DerivedContext field names appear
        # FORBIDDEN_FIELD_NAMES from nce_contract.py includes:
        # user_role, asset_criticality, network_zone, historical_access,
        # no_prior_access, cross_zone_access, high_criticality_target,
        # privilege_escalation_risk
        for forbidden_name in FORBIDDEN_FIELD_NAMES:
            # Check as XML tag — e.g. <user_role> or <asset_criticality>
            assert f"<{forbidden_name}>" not in prompt_sent, (
                f"Forbidden trusted-context field name '<{forbidden_name}>' "
                f"found in NCE prompt — trusted context must never leak into NCE."
            )

        # Also confirm no <trusted_context> block at all
        assert "<trusted_context>" not in prompt_sent

    @patch("perception.nce_engine._call_gemini_nce")
    def test_no_knowledge_store_values_in_evidence_section(self, mock_call: MagicMock) -> None:
        """
        Strengthened check: the <untrusted_evidence> section must NOT contain
        actual Knowledge-Store-derived values (DerivedContext field values,
        criticality tiers, host class labels, etc.).

        NOTE: MissingContextFlag names like 'target_host_class' legitimately
        appear in the <instructions> block (the model needs the vocabulary).
        This test checks ONLY the <untrusted_evidence> section.
        """
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.85),
        ])

        nce_input = _make_nce_input(
            raw_log_line="normal login event from workstation",
            command_line="cmd.exe /c whoami",
        )
        generate_hypotheses(nce_input)

        prompt_sent = mock_call.call_args[0][0]

        # Extract ONLY the <untrusted_evidence> section
        evidence_start = prompt_sent.find("<untrusted_evidence>")
        evidence_end = prompt_sent.find("</untrusted_evidence>")
        assert evidence_start != -1 and evidence_end != -1, (
            "Could not find <untrusted_evidence> section in prompt"
        )
        evidence_section = prompt_sent[evidence_start:evidence_end]

        # Knowledge-Store-derived facts that must NEVER appear in evidence:
        # DerivedContext field values (these are computed from STRUCTURED data)
        knowledge_store_values = [
            "no_prior_access",
            "cross_zone_access",
            "high_criticality_target",
            "privilege_escalation_risk",
            # Criticality tier labels
            "criticality_tier",
            # Host class labels
            "host_class",
            # Knowledge graph concepts
            "HAS_PRIOR_ACCESS",
            "EGRESS",
        ]
        for ks_value in knowledge_store_values:
            assert ks_value not in evidence_section, (
                f"Knowledge-Store value '{ks_value}' found in <untrusted_evidence> "
                f"section — trusted-context data must never leak into NCE evidence."
            )

    @patch("perception.nce_engine._call_gemini_nce")
    def test_prompt_contains_evidence_data(self, mock_call: MagicMock) -> None:
        """The prompt should contain the actual evidence values."""
        mock_call.return_value = _mock_gemini_response([
            _make_valid_hypothesis_dict("T1078", 0.85),
        ])

        nce_input = _make_nce_input(
            raw_log_line="DISTINCTIVE_LOG_MARKER_12345",
        )
        generate_hypotheses(nce_input)

        prompt_sent = mock_call.call_args[0][0]
        # The evidence value should appear (XML-escaped) in the prompt
        assert "DISTINCTIVE_LOG_MARKER_12345" in prompt_sent


# ---------------------------------------------------------------------------
# 7. [MOCKED] Wrapped JSON response (dict with hypotheses key)
# ---------------------------------------------------------------------------

class TestWrappedJsonResponse:

    @patch("perception.nce_engine._call_gemini_nce")
    def test_dict_wrapped_response_accepted(self, mock_call: MagicMock) -> None:
        """
        If the LLM wraps the array in a dict like {"hypotheses": [...]},
        it should still be parsed correctly.
        """
        mock_call.return_value = _mock_gemini_response({
            "hypotheses": [
                _make_valid_hypothesis_dict("T1078", 0.80),
            ]
        })

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 1

    @patch("perception.nce_engine._call_gemini_nce")
    def test_dict_with_metadata_and_hypotheses_keys(self, mock_call: MagicMock) -> None:
        """
        BUG 2 FIX: A dict like {"metadata": [], "hypotheses": [...]} must
        extract the "hypotheses" list — NOT accidentally match "metadata"
        (which also happens to be a list) or fail.
        """
        valid_hyp = _make_valid_hypothesis_dict("T1078", 0.80)
        mock_call.return_value = _mock_gemini_response({
            "metadata": [{"model": "gemini", "timestamp": "2024-01-01"}],
            "hypotheses": [valid_hyp],
        })

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is True
        assert result.output is not None
        assert len(result.output.hypotheses) == 1
        assert result.output.hypotheses[0].technique_id == "T1078"

    @patch("perception.nce_engine._call_gemini_nce")
    def test_dict_without_hypotheses_key_fails(self, mock_call: MagicMock) -> None:
        """
        BUG 2 FIX: A dict without a "hypotheses" key (even if it has other
        list-valued keys) must fail with a clear error, not silently guess.
        """
        mock_call.return_value = _mock_gemini_response({
            "results": [
                _make_valid_hypothesis_dict("T1078", 0.80),
            ],
        })

        nce_input = _make_nce_input(raw_log_line="test")
        result = generate_hypotheses(nce_input)

        assert result.success is False
        assert result.error is not None
        assert "hypotheses" in result.error.lower()


# ---------------------------------------------------------------------------
# 8. [SMOKE TEST] Real Gemini call — skipped by default
# ---------------------------------------------------------------------------

@pytest.mark.smoke
class TestSmokeLiveGeminiCall:
    """
    ONE real call to gemini-3.1-flash-lite with a clean synthetic incident.

    This test is skipped by default — it requires:
    1. A valid GEMINI_API_KEY or GEMINI_API_KEYS env var
    2. Running with: pytest -m smoke

    To skip smoke tests in the regular suite, run: pytest -m "not smoke"
    """

    def test_real_gemini_call_produces_valid_output(self) -> None:
        """
        End-to-end: construct a benign NCEInput, call the real Gemini API,
        and confirm the result is a valid NCEOutput with 1-3 hypotheses.
        """
        import os
        from dotenv import load_dotenv
        load_dotenv()
        api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEYS", "").split(",")[0].strip()
        if not api_key:
            pytest.skip("No GEMINI_API_KEY set — cannot run smoke test")

        # Clean, clearly-benign synthetic incident (not from any contaminated corpus)
        nce_input = NCEInput(
            incident_id="SMOKE-TEST-001",
            evidence_fields={
                "raw_log_line": (
                    "EventID=4624 LogonType=10 TargetUserName=admin "
                    "SourceWorkstation=WS-042 IpAddress=10.0.1.42 "
                    "LogonProcess=User32"
                ),
                "command_line": "mstsc.exe /v:SRV-DC-01",
                "process_name": "mstsc.exe",
            },
            timestamp=datetime.now(timezone.utc),
        )

        result = generate_hypotheses(nce_input, model="gemini-3.1-flash-lite")

        # Must succeed
        assert result.success is True, (
            f"Smoke test failed: {result.error}\n"
            f"Raw response: {result.raw_response}"
        )
        assert result.output is not None
        assert isinstance(result.output, NCEOutput)
        assert 1 <= len(result.output.hypotheses) <= 3
        assert result.api_call_count >= 1

        # Every hypothesis must have the correct incident_id and GENERATED status
        for h in result.output.hypotheses:
            assert h.incident_id == "SMOKE-TEST-001"
            assert h.status == HypothesisStatus.GENERATED
            assert 0.0 <= h.nce_confidence <= 1.0

        # Print result for manual inspection
        print(f"\n[SMOKE] NCE returned {len(result.output.hypotheses)} hypothesis(es):")
        for i, h in enumerate(result.output.hypotheses):
            print(
                f"  [{i}] technique={h.technique_id}, "
                f"confidence={h.nce_confidence:.2f}, "
                f"refs={h.supporting_evidence_refs}, "
                f"flags={[f.value for f in h.missing_context_flags]}"
            )
