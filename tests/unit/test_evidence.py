from datetime import datetime, timezone

from pkg.models.evidence import (
    Evidence,
    EvidenceAssessment,
    EvidenceProvenance,
    EvidenceStrength,
    EvidenceType,
)


def test_create_evidence():
    evidence = Evidence(
        evidence_type=EvidenceType.PROCESS,
        strength=EvidenceStrength.STRONG,
        title="Suspicious process execution",
        description="sdbinst.exe was executed by SYSTEM.",
        event_id="evt-001",
        case_id="case-001",
        confidence=0.95,
        provenance=EvidenceProvenance(
            source="wazuh",
            collector="wazuh-parser",
            parent_event_id="evt-001",
            collected_at=datetime.now(timezone.utc),
        ),
    )

    assert evidence.evidence_type == EvidenceType.PROCESS
    assert evidence.strength == EvidenceStrength.STRONG
    assert evidence.confidence == 0.95
    assert evidence.event_id == "evt-001"
    assert evidence.case_id == "case-001"


def test_hypothesis_link():
    evidence = Evidence(
        evidence_type=EvidenceType.PROCESS,
        title="Suspicious process execution",
        hypothesis_links=[
            {
                "hypothesis_id": "H-001",
                "assessment": EvidenceAssessment.SUPPORTS,
                "weight": 0.9,
                "rationale": "Execution matches the suspected persistence technique.",
            },
            {
                "hypothesis_id": "H-002",
                "assessment": EvidenceAssessment.CONTRADICTS,
                "weight": 0.2,
            },
        ],
        provenance=EvidenceProvenance(
            source="wazuh",
        ),
    )

    assert evidence.get_hypothesis_link("H-001") is not None
    assert (
        evidence.get_hypothesis_link("H-001").assessment
        == EvidenceAssessment.SUPPORTS
    )
    assert (
        evidence.get_hypothesis_link("H-001").weight
        == 0.9
    )


def test_evidence_hash_is_stable():
    evidence = Evidence(
        evidence_type=EvidenceType.ALERT,
        title="Application Shimming alert",
        description="Wazuh detected Application Shimming activity.",
        event_id="evt-001",
        provenance=EvidenceProvenance(
            source="wazuh",
            parent_event_id="evt-001",
        ),
    )

    hash_1 = evidence.calculate_content_hash()
    hash_2 = evidence.calculate_content_hash()

    assert hash_1 == hash_2
    assert len(hash_1) == 64


def test_evidence_hash_verification():
    evidence = Evidence(
        evidence_type=EvidenceType.PROCESS,
        title="Process execution",
        description="sdbinst.exe executed.",
        event_id="evt-001",
        provenance=EvidenceProvenance(
            source="wazuh",
        ),
    ).with_content_hash()

    assert evidence.integrity.content_hash is not None
    assert evidence.verify_content_hash()


def test_evidence_hash_detects_modification():
    evidence = Evidence(
        evidence_type=EvidenceType.PROCESS,
        title="Process execution",
        description="sdbinst.exe executed.",
        event_id="evt-001",
        provenance=EvidenceProvenance(
            source="wazuh",
        ),
    ).with_content_hash()

    modified = evidence.model_copy(
        update={
            "description": "A different process executed."
        }
    )

    assert not modified.verify_content_hash()


def test_verified_evidence():
    evidence = Evidence(
        evidence_type=EvidenceType.ANALYST,
        title="Analyst verification",
        provenance=EvidenceProvenance(
            source="analyst",
        ),
    )

    verified = evidence.mark_verified(
        verified_by="Renstt",
        method="manual_review",
    )

    assert verified.verification.verified is True
    assert verified.verification.verified_by == "Renstt"
    assert verified.verification.verified_at is not None


def test_verified_evidence_requires_metadata():
    try:
        EvidenceVerification = __import__(
            "pkg.models.evidence",
            fromlist=["EvidenceVerification"],
        ).EvidenceVerification

        EvidenceVerification(verified=True)

        assert False, "Expected validation error"

    except ValueError:
        pass


def test_derived_evidence():
    evidence = Evidence(
        evidence_type=EvidenceType.DERIVED,
        title="Correlated execution chain",
        description="Process execution was correlated with a persistence event.",
        provenance=EvidenceProvenance(
            source="correlation_engine",
            collector="aegis-correlation",
            transformation="Event correlation",
            derived_from=["E-001", "E-002"],
        ),
    )

    assert evidence.is_derived
    assert evidence.provenance.derived_from == [
        "E-001",
        "E-002",
    ]


def test_graph_relationships():
    evidence = Evidence(
        evidence_type=EvidenceType.PROCESS,
        title="Suspicious process",
        description="sdbinst.exe executed.",
        event_id="evt-001",
        entity_ids=["process-sdbinst"],
        hypothesis_links=[
            {
                "hypothesis_id": "H-001",
                "assessment": EvidenceAssessment.SUPPORTS,
                "weight": 0.9,
            }
        ],
        provenance=EvidenceProvenance(
            source="wazuh",
            parent_event_id="evt-001",
            derived_from=["E-000"],
        ),
    )

    hypothesis_edges = evidence.to_hypothesis_edges()
    reference_edges = evidence.to_reference_edges()

    assert len(hypothesis_edges) == 1
    assert hypothesis_edges[0]["relationship"] == "SUPPORTS"
    assert hypothesis_edges[0]["target"] == "H-001"
    assert hypothesis_edges[0]["properties"]["weight"] == 0.9

    relations = {
        edge["relationship"]
        for edge in reference_edges
    }

    assert "REFERENCES" in relations
    assert "ABOUT" in relations
    assert "DERIVED_FROM" in relations


def test_from_event_dict():
    event = {
        "event_id": "evt-001",
        "timestamp": "2026-09-26T12:00:00Z",
        "source": "wazuh",
        "rule_id": "92058",
        "rule_name": "Application Shimming",
    }

    evidence = Evidence.from_event(
        event,
        title="Application Shimming Detection",
        description="Wazuh detected possible Application Shimming activity.",
        evidence_type=EvidenceType.ALERT,
        strength=EvidenceStrength.STRONG,
        confidence=0.95,
    )

    assert evidence.evidence_id == "E-evt-001"
    assert evidence.event_id == "evt-001"
    assert evidence.evidence_type == EvidenceType.ALERT
    assert evidence.confidence == 0.95
    assert evidence.provenance.source == "wazuh"
    assert evidence.observed_at is not None


def test_content_hash_excludes_evidence_identity():
    evidence_a = Evidence(
        evidence_id="E-001",
        evidence_type=EvidenceType.PROCESS,
        title="Suspicious process",
        description="sdbinst.exe executed.",
        event_id="evt-001",
        provenance=EvidenceProvenance(
            source="wazuh",
        ),
    )

    evidence_b = Evidence(
        evidence_id="E-002",
        evidence_type=EvidenceType.PROCESS,
        title="Suspicious process",
        description="sdbinst.exe executed.",
        event_id="evt-001",
        provenance=EvidenceProvenance(
            source="wazuh",
        ),
    )

    assert (
        evidence_a.calculate_content_hash()
        == evidence_b.calculate_content_hash()
    )
