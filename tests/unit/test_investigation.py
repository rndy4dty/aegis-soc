from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from pkg.models.investigation import (
    InvestigationCase,
    InvestigationCategory,
    InvestigationPriority,
    InvestigationStatus,
    ResolutionOutcome,
)


def test_create_investigation_case():
    case = InvestigationCase(
        title="Suspicious sdbinst.exe execution",
        description="Potential application shimming activity.",
        category=InvestigationCategory.DEFENSE_EVASION,
        severity=70,
        priority=InvestigationPriority.HIGH,
    )

    assert case.case_id.startswith("CASE-")
    assert case.status == InvestigationStatus.DETECTED
    assert case.severity == 70
    assert case.priority == InvestigationPriority.HIGH


def test_reference_ids_are_normalized():
    case = InvestigationCase(
        title="Test case",
        alert_ids=[" A-002 ", "A-001", "A-002"],
        event_ids=["E-002", "E-001"],
        evidence_ids=["EV-002", "EV-001", "EV-002"],
    )

    assert case.alert_ids == ["A-001", "A-002"]
    assert case.event_ids == ["E-001", "E-002"]
    assert case.evidence_ids == ["EV-001", "EV-002"]


def test_tags_are_normalized():
    case = InvestigationCase(
        title="Test case",
        tags=[" SOC ", "Malware", "soc", " MALWARE "],
    )

    assert case.tags == ["malware", "soc"]


def test_risk_score_and_confidence_validation():
    case = InvestigationCase(
        title="Test case",
        risk_score=80,
        confidence=0.9,
    )

    assert case.risk_score == 80
    assert case.confidence == 0.9
    assert case.is_high_risk is True
    assert case.is_high_confidence is True


def test_invalid_risk_score_is_rejected():
    with pytest.raises(ValidationError):
        InvestigationCase(
            title="Invalid case",
            risk_score=101,
        )


def test_invalid_confidence_is_rejected():
    with pytest.raises(ValidationError):
        InvestigationCase(
            title="Invalid case",
            confidence=1.1,
        )


def test_add_references():
    case = InvestigationCase(title="Test case")

    case.add_alert(" A-001 ")
    case.add_event(" E-001 ")
    case.add_evidence(" EV-001 ")
    case.add_hypothesis(" H-001 ")
    case.add_entity(" HOST-001 ")

    assert case.alert_ids == ["A-001"]
    assert case.event_ids == ["E-001"]
    assert case.evidence_ids == ["EV-001"]
    assert case.hypothesis_ids == ["H-001"]
    assert case.entity_ids == ["HOST-001"]


def test_duplicate_references_are_not_added():
    case = InvestigationCase(title="Test case")

    case.add_evidence("EV-001")
    case.add_evidence("EV-001")

    assert case.evidence_ids == ["EV-001"]


def test_state_machine_allows_valid_transition():
    case = InvestigationCase(title="Test case")

    assert case.can_transition_to(InvestigationStatus.TRIAGED)

    case.transition_to(InvestigationStatus.TRIAGED)

    assert case.status == InvestigationStatus.TRIAGED


def test_state_machine_rejects_invalid_transition():
    case = InvestigationCase(title="Test case")

    with pytest.raises(ValueError, match="illegal transition"):
        case.transition_to(InvestigationStatus.CONFIRMED)


def test_lifecycle_transition():
    case = InvestigationCase(title="Test case")

    case.transition_to(InvestigationStatus.TRIAGED)
    case.transition_to(InvestigationStatus.INVESTIGATING)
    case.transition_to(InvestigationStatus.CONFIRMED)

    assert case.status == InvestigationStatus.CONFIRMED
    assert case.is_open is True
    assert case.closed_at is None


def test_mark_resolved():
    case = InvestigationCase(title="Test case")

    case.transition_to(InvestigationStatus.TRIAGED)
    case.transition_to(InvestigationStatus.INVESTIGATING)
    case.transition_to(InvestigationStatus.CONFIRMED)

    case.mark_resolved(
        outcome=ResolutionOutcome.TRUE_POSITIVE,
        summary="Malicious application shimming activity confirmed.",
    )

    assert case.status == InvestigationStatus.RESOLVED
    assert case.outcome == ResolutionOutcome.TRUE_POSITIVE
    assert case.summary == (
        "Malicious application shimming activity confirmed."
    )
    assert case.closed_at is not None
    assert case.is_closed is True
    assert case.is_open is False


def test_resolved_case_requires_closed_at_and_outcome():
    with pytest.raises(ValidationError):
        InvestigationCase(
            title="Invalid resolved case",
            status=InvestigationStatus.RESOLVED,
        )


def test_closed_at_requires_resolved_status():
    with pytest.raises(ValidationError):
        InvestigationCase(
            title="Invalid closed case",
            closed_at=datetime.now(timezone.utc),
        )


def test_update_risk_creates_risk_evolution():
    case = InvestigationCase(title="Test case")

    case.update_risk(
        risk_score=75,
        confidence=0.85,
        reason="Strong persistence evidence identified.",
        risk_factors=[
            "Suspicious process",
            "Persistence indicator",
        ],
        evidence_ids=["EV-001"],
        hypothesis_ids=["H-001"],
    )

    assert case.risk_score == 75
    assert case.confidence == 0.85
    assert len(case.risk_history) == 1

    evolution = case.risk_history[0]

    assert evolution.risk_score == 75
    assert evolution.confidence == 0.85
    assert evolution.previous_risk_score == 0
    assert evolution.previous_confidence == 0.0
    assert evolution.delta == 75
    assert evolution.reason == "Strong persistence evidence identified."
    assert evolution.evidence_ids == ["EV-001"]
    assert evolution.hypothesis_ids == ["H-001"]


def test_risk_evolution_tracks_multiple_changes():
    case = InvestigationCase(title="Test case")

    case.update_risk(
        risk_score=40,
        confidence=0.50,
        reason="Initial triage.",
    )

    case.update_risk(
        risk_score=70,
        confidence=0.75,
        reason="Additional evidence correlated.",
    )

    assert len(case.risk_history) == 2

    first = case.risk_history[0]
    second = case.risk_history[1]

    assert first.delta == 40
    assert second.previous_risk_score == 40
    assert second.previous_confidence == 0.50
    assert second.delta == 30


def test_attach_notes_and_summary():
    case = InvestigationCase(title="Test case")

    case.attach_notes(" Analyst note ")
    case.attach_summary(" Investigation summary ")

    assert case.analyst_notes == "Analyst note"
    assert case.summary == "Investigation summary"


def test_assign_analyst():
    case = InvestigationCase(title="Test case")

    case.assign_analyst(" analyst01 ")

    assert case.analyst == "analyst01"
    assert case.has_analyst is True


def test_assign_empty_analyst_is_rejected():
    case = InvestigationCase(title="Test case")

    with pytest.raises(ValueError, match="analyst cannot be empty"):
        case.assign_analyst("   ")


def test_age_and_duration():
    created = datetime(
        2026,
        9,
        26,
        10,
        0,
        tzinfo=timezone.utc,
    )

    closed = datetime(
        2026,
        9,
        26,
        11,
        0,
        tzinfo=timezone.utc,
    )

    case = InvestigationCase(
        title="Test case",
        status=InvestigationStatus.RESOLVED,
        outcome=ResolutionOutcome.BENIGN,
        created_at=created,
        updated_at=closed,
        closed_at=closed,
    )

    assert case.age_seconds == 3600
    assert case.duration_seconds == 3600


def test_graph_node():
    case = InvestigationCase(
        title="Suspicious execution",
        category=InvestigationCategory.EXECUTION,
        priority=InvestigationPriority.HIGH,
        severity=80,
        risk_score=75,
        confidence=0.8,
    )

    node = case.to_graph_node()

    assert node["id"] == case.case_id
    assert node["type"] == "InvestigationCase"
    assert node["status"] == "detected"
    assert node["priority"] == "high"
    assert node["risk_score"] == 75
    assert node["confidence"] == 0.8


def test_relationship_projection():
    case = InvestigationCase(
        title="Suspicious execution",
        alert_ids=["A-001"],
        event_ids=["EVT-001"],
        evidence_ids=["E-001"],
        hypothesis_ids=["H-001"],
        entity_ids=["HOST-001"],
        analyst="analyst01",
    )

    relationships = case.to_relationships()

    assert len(relationships) == 6

    relationship_types = {
        relationship["relationship"]
        for relationship in relationships
    }

    assert relationship_types == {
        "TRIGGERED_BY",
        "OBSERVED",
        "CONTAINS",
        "EXPLORES",
        "INVOLVES",
        "OWNED_BY",
    }
