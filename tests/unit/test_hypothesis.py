"""
Contract tests untuk Hypothesis model.

Menguji:
- construction & validation
- fingerprint identity
- lifecycle state machine
- confidence
- evidence helpers (supporting/contradicting/missing)
- merge
- graph adapter
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pkg.models.hypothesis import (
    DEFAULT_CONFIDENCE,
    Hypothesis,
    HypothesisSource,
    HypothesisStatus,
    HypothesisType,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_hyp(
    statement: str = "Possible persistence via Application Shimming",
    **kwargs,
) -> Hypothesis:
    return Hypothesis(statement=statement, **kwargs)


# ===========================================================================
# Construction
# ===========================================================================

def test_minimal_hypothesis():
    h = make_hyp()
    assert h.hypothesis_id.startswith("H-")
    assert h.hypothesis_type == HypothesisType.UNKNOWN
    assert h.status == HypothesisStatus.PROPOSED
    assert h.confidence == DEFAULT_CONFIDENCE
    assert h.fingerprint is None


def test_empty_statement_rejected():
    with pytest.raises(ValidationError):
        Hypothesis(statement="   ")


def test_statement_too_short_rejected():
    with pytest.raises(ValidationError):
        Hypothesis(statement="ab")


def test_source_default():
    h = make_hyp()
    assert h.source == HypothesisSource.DETERMINISTIC


def test_mitre_techniques_validated():
    h = make_hyp(mitre_techniques=["t1546.011"])
    assert h.mitre_techniques == ["T1546.011"]


def test_mitre_invalid_rejected():
    with pytest.raises(ValidationError):
        make_hyp(mitre_techniques=["not-a-technique"])


def test_mitre_tactics_validated():
    h = make_hyp(mitre_tactics=["ta0003"])
    assert h.mitre_tactics == ["TA0003"]


def test_mitre_tactics_invalid_rejected():
    with pytest.raises(ValidationError):
        make_hyp(mitre_tactics=["T0003"])


def test_evidence_ids_normalized():
    h = make_hyp(
        supporting_evidence_ids=[" E-2 ", "E-1", "E-1"],
        contradicting_evidence_ids=[" E-3 "],
    )
    assert h.supporting_evidence_ids == ["E-1", "E-2"]
    assert h.contradicting_evidence_ids == ["E-3"]


def test_overlap_supporting_contradicting_rejected():
    with pytest.raises(ValidationError, match="supporting and contradicting"):
        make_hyp(
            supporting_evidence_ids=["E-1"],
            contradicting_evidence_ids=["E-1"],
        )


def test_sub_hypothesis_without_parent_is_allowed():
    """SUB tanpa parent valid: sinyal turunan mandiri."""
    h = make_hyp(hypothesis_type=HypothesisType.SUB)
    assert h.is_sub
    assert h.parent_hypothesis_id is None


def test_sub_hypothesis_with_parent_ok():
    h = make_hyp(
        hypothesis_type=HypothesisType.SUB,
        parent_hypothesis_id="H-001",
    )
    assert h.is_sub
    assert h.parent_hypothesis_id == "H-001"

def test_counter_hypothesis_cannot_have_parent():
    with pytest.raises(ValidationError, match="COUNTER"):
        make_hyp(
            hypothesis_type=HypothesisType.COUNTER,
            parent_hypothesis_id="H-001",
        )


def test_confirmed_requires_rationale():
    with pytest.raises(ValidationError, match="rationale"):
        make_hyp(status=HypothesisStatus.CONFIRMED)


def test_confirmed_with_rationale_ok():
    h = make_hyp(
        status=HypothesisStatus.CONFIRMED,
        rationale="Confirmed by analyst review",
    )
    assert h.status == HypothesisStatus.CONFIRMED


def test_temporal_consistency():
    with pytest.raises(ValidationError):
        make_hyp(
            first_seen=BASE + timedelta(hours=1),
            last_seen=BASE,
        )


def test_updated_before_created_rejected():
    with pytest.raises(ValidationError):
        make_hyp(
            created_at=BASE + timedelta(hours=1),
            updated_at=BASE,
        )


# ===========================================================================
# Classification properties
# ===========================================================================

def test_is_main_counter_sub():
    m = make_hyp(hypothesis_type=HypothesisType.MAIN)
    c = make_hyp(
        statement="Alternative legitimate activity",
        hypothesis_type=HypothesisType.COUNTER,
    )
    s = make_hyp(
        statement="Sub-finding",
        hypothesis_type=HypothesisType.SUB,
        parent_hypothesis_id="H-1",
    )
    assert m.is_main
    assert c.is_counter
    assert s.is_sub


def test_is_terminal_and_active():
    h = make_hyp()
    assert h.is_active
    assert not h.is_terminal

    confirmed = make_hyp(
        status=HypothesisStatus.CONFIRMED,
        rationale="ok",
    )
    assert confirmed.is_terminal
    assert not confirmed.is_active


def test_evidence_balance():
    h = make_hyp(
        supporting_evidence_ids=["E-1", "E-2"],
        contradicting_evidence_ids=["E-3"],
    )
    assert h.support_count == 2
    assert h.contradict_count == 1
    assert h.evidence_balance == 1


# ===========================================================================
# Fingerprint
# ===========================================================================

def test_fingerprint_deterministic():
    a = make_hyp()
    b = make_hyp()
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_normalizes_statement():
    a = make_hyp("Possible Persistence")
    b = make_hyp("  possible    persistence  ")
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_distinguishes_type():
    a = make_hyp(hypothesis_type=HypothesisType.MAIN)
    b = make_hyp(hypothesis_type=HypothesisType.COUNTER)
    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_fingerprint_distinguishes_tenant():
    a = make_hyp(tenant_id="tenant-a")
    b = make_hyp(tenant_id="tenant-b")
    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_fingerprint_ignores_evidence():
    a = make_hyp(supporting_evidence_ids=["E-1"])
    b = make_hyp(supporting_evidence_ids=["E-2"])
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_ignores_status_and_confidence():
    a = make_hyp(
        status=HypothesisStatus.SUPPORTED,
        confidence=0.9,
    )
    b = make_hyp(
        status=HypothesisStatus.PROPOSED,
        confidence=0.1,
    )
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_with_and_verify_fingerprint():
    h = make_hyp().with_fingerprint()
    assert h.fingerprint is not None
    assert h.verify_fingerprint()


def test_verify_without_fingerprint():
    h = make_hyp()
    assert h.verify_fingerprint() is False


def test_same_identity():
    a = make_hyp()
    b = make_hyp()
    assert a.same_identity(b)


def test_different_identity():
    a = make_hyp("Statement A")
    b = make_hyp("Statement B")
    assert not a.same_identity(b)


def test_same_identity_with_non_hypothesis():
    a = make_hyp()
    assert not a.same_identity("not a hypothesis")


# ===========================================================================
# Lifecycle state machine
# ===========================================================================

def test_can_transition_proposed_to_supported():
    h = make_hyp()
    assert h.can_transition_to(HypothesisStatus.SUPPORTED)


def test_cannot_transition_proposed_to_confirmed():
    h = make_hyp()
    assert not h.can_transition_to(HypothesisStatus.CONFIRMED)


def test_transition_proposed_to_supported():
    h = make_hyp()
    h2 = h.transition_to(HypothesisStatus.SUPPORTED)
    assert h2.status == HypothesisStatus.SUPPORTED


def test_illegal_transition_raises():
    h = make_hyp()
    with pytest.raises(ValueError, match="illegal transition"):
        h.transition_to(HypothesisStatus.CONFIRMED)


def test_confirmed_is_terminal():
    h = make_hyp(
        status=HypothesisStatus.CONFIRMED,
        rationale="ok",
    )
    assert not h.can_transition_to(HypothesisStatus.SUPPORTED)
    with pytest.raises(ValueError):
        h.transition_to(HypothesisStatus.SUPPORTED)


def test_transition_to_confirmed_requires_rationale():
    h = make_hyp(status=HypothesisStatus.SUPPORTED)
    with pytest.raises(ValueError, match="requires rationale"):
        h.transition_to(HypothesisStatus.CONFIRMED)


def test_transition_to_confirmed_with_rationale():
    h = make_hyp(status=HypothesisStatus.SUPPORTED)
    h2 = h.transition_to(
        HypothesisStatus.CONFIRMED,
        rationale="Evidence strong",
    )
    assert h2.status == HypothesisStatus.CONFIRMED
    assert h2.rationale == "Evidence strong"


def test_full_lifecycle():
    h = make_hyp()
    h = h.transition_to(HypothesisStatus.SUPPORTED)
    h = h.transition_to(
        HypothesisStatus.CONFIRMED,
        rationale="Confirmed",
    )
    assert h.is_terminal
    assert h.status == HypothesisStatus.CONFIRMED


# ===========================================================================
# Confidence
# ===========================================================================

def test_with_confidence():
    h = make_hyp()
    h2 = h.with_confidence(0.85)
    assert h2.confidence == 0.85


def test_with_confidence_invalid():
    h = make_hyp()
    with pytest.raises(ValueError):
        h.with_confidence(1.5)
    with pytest.raises(ValueError):
        h.with_confidence(-0.1)


def test_is_high_confidence():
    h = make_hyp(confidence=0.85)
    assert h.is_high_confidence
    h2 = make_hyp(confidence=0.5)
    assert not h2.is_high_confidence


# ===========================================================================
# Evidence helpers
# ===========================================================================

def test_add_supporting_evidence():
    h = make_hyp()
    h = h.add_supporting_evidence("E-1").add_supporting_evidence("E-2")
    assert h.supporting_evidence_ids == ["E-1", "E-2"]


def test_add_supporting_evidence_dedup():
    h = make_hyp()
    h = h.add_supporting_evidence("E-1").add_supporting_evidence("E-1")
    assert h.supporting_evidence_ids == ["E-1"]


def test_add_supporting_evidence_ignores_empty():
    h = make_hyp()
    h = h.add_supporting_evidence("   ")
    assert h.supporting_evidence_ids == []


def test_add_contradicting_evidence():
    h = make_hyp()
    h = h.add_contradicting_evidence("E-1")
    assert h.contradicting_evidence_ids == ["E-1"]


def test_add_supporting_when_contradicting_raises():
    h = make_hyp(contradicting_evidence_ids=["E-1"])
    with pytest.raises(ValueError, match="already contradicts"):
        h.add_supporting_evidence("E-1")


def test_add_contradicting_when_supporting_raises():
    h = make_hyp(supporting_evidence_ids=["E-1"])
    with pytest.raises(ValueError, match="already supports"):
        h.add_contradicting_evidence("E-1")


def test_add_missing_evidence():
    h = make_hyp()
    h = h.add_missing_evidence("shim db modification")
    h = h.add_missing_evidence("registry change")
    assert h.missing_evidence == [
        "registry change", "shim db modification",
    ]


def test_has_evidence():
    h = make_hyp()
    assert not h.has_evidence
    h = h.add_supporting_evidence("E-1")
    assert h.has_evidence


# ===========================================================================
# Merge
# ===========================================================================

def test_merge_rejects_different_identity():
    a = make_hyp("Statement A")
    b = make_hyp("Statement B")
    with pytest.raises(ValueError, match="different fingerprint"):
        a.merge(b)


def test_merge_unions_evidence():
    a = make_hyp(supporting_evidence_ids=["E-1"])
    b = make_hyp(supporting_evidence_ids=["E-2"])
    merged = a.merge(b)
    assert merged.supporting_evidence_ids == ["E-1", "E-2"]


def test_merge_confidence_max():
    a = make_hyp(confidence=0.3)
    b = make_hyp(confidence=0.7)
    merged = a.merge(b)
    assert merged.confidence == 0.7


def test_merge_status_prefers_more_advanced():
    a = make_hyp(status=HypothesisStatus.PROPOSED)
    b = make_hyp(status=HypothesisStatus.SUPPORTED)
    merged = a.merge(b)
    assert merged.status == HypothesisStatus.SUPPORTED


def test_merge_confirmed_wins():
    a = make_hyp(status=HypothesisStatus.SUPPORTED)
    b = make_hyp(
        status=HypothesisStatus.CONFIRMED,
        rationale="Confirmed",
    )
    merged = a.merge(b)
    assert merged.status == HypothesisStatus.CONFIRMED
    assert merged.rationale == "Confirmed"


def test_merge_unions_missing_evidence():
    a = make_hyp(missing_evidence=["shim db"])
    b = make_hyp(missing_evidence=["registry"])
    merged = a.merge(b)
    assert merged.missing_evidence == ["registry", "shim db"]


def test_merge_unions_mitre():
    a = make_hyp(mitre_techniques=["T1546.011"])
    b = make_hyp(mitre_techniques=["T1059.001"])
    merged = a.merge(b)
    assert merged.mitre_techniques == ["T1059.001", "T1546.011"]


def test_merge_temporal_min_max():
    a = make_hyp(
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=5),
    )
    b = make_hyp(
        first_seen=BASE - timedelta(minutes=10),
        last_seen=BASE + timedelta(minutes=30),
    )
    merged = a.merge(b)
    assert merged.first_seen == BASE - timedelta(minutes=10)
    assert merged.last_seen == BASE + timedelta(minutes=30)


def test_merge_recomputes_fingerprint():
    a = make_hyp().with_fingerprint()
    b = make_hyp()
    merged = a.merge(b)
    assert merged.fingerprint == merged.calculate_fingerprint()
    assert merged.verify_fingerprint()


# ===========================================================================
# Graph
# ===========================================================================

def test_to_graph_node():
    h = make_hyp(
        hypothesis_type=HypothesisType.MAIN,
        supporting_evidence_ids=["E-1"],
        contradicting_evidence_ids=["E-2"],
    ).with_fingerprint()

    node = h.to_graph_node()
    assert node["type"] == "Hypothesis"
    assert node["statement"] == h.statement
    assert node["support_count"] == 1
    assert node["contradict_count"] == 1
    assert node["evidence_balance"] == 0
    assert node["fingerprint"] == h.fingerprint


def test_debug_relationships_marked_debug():
    h = make_hyp(
        supporting_evidence_ids=["E-1"],
        contradicting_evidence_ids=["E-2"],
    )
    edges = h.debug_relationships()
    rels = [e["relationship"] for e in edges]
    assert "SUPPORTS" in rels
    assert "CONTRADICTS" in rels
    assert all(e["properties"].get("_debug") for e in edges)


# ===========================================================================
# Deterministic
# ===========================================================================

def test_deterministic_fingerprint_across_runs():
    h1 = make_hyp(
        tenant_id="tenant-a",
        hypothesis_type=HypothesisType.MAIN,
        statement="Possible persistence via Application Shimming",
    )
    h2 = make_hyp(
        tenant_id="tenant-a",
        hypothesis_type=HypothesisType.MAIN,
        statement="Possible persistence via Application Shimming",
    )
    assert h1.calculate_fingerprint() == h2.calculate_fingerprint()
