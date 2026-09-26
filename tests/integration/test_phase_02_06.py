from datetime import datetime, timezone

from pkg.models.event import Event
from pkg.models.evidence import Evidence
from pkg.models.investigation import InvestigationCase
from pkg.models.ledger import EvidenceLedger
from internal.correlation.correlation import PairCorrelationEngine


def test_phase_02_to_06_end_to_end():
    timestamp = datetime.now(timezone.utc)

    # ================================================================
    # PHASE 02 — Canonical Event
    # ================================================================

    event = Event(
        event_id="evt-integration-001",
        tenant_id="aegis-lab",
        timestamp=timestamp,
        ingested_at=timestamp,
        source="manual",
        platform="windows",
        category="process",
        event_type="process_creation",
        severity=70,
        host="WINDOWS-LAB",
        user="REN",
        process={
            "pid": 4242,
            "parent_pid": 4000,
            "name": "powershell.exe",
        },
        mitre_techniques=["T1059.001"],
        rule_id="92027",
        rule_name="PowerShell",
        rule_level=4,
        raw_data={
            "integration_test": True,
        },
    )

    assert event.event_id == "evt-integration-001"
    assert event.category.value == "process"

    # ================================================================
    # PHASE 03 — Evidence
    # ================================================================

    evidence = Evidence(
        evidence_type="event",
        title="PowerShell Process Creation",
        description="Integration test evidence generated from canonical event.",
        provenance={
            "source": "integration-test",
            "parent_event_id": event.event_id,
        },
        observed_at=timestamp,
        confidence=0.90,
        event_id=event.event_id,
        data={
            "event_type": event.event_type,
            "process_name": event.process.name,
            "pid": event.process.pid,
        },
    )

    evidence = evidence.with_content_hash()

    assert evidence.integrity is not None
    assert evidence.integrity.content_hash
    assert evidence.verify_content_hash() is True

    # ================================================================
    # PHASE 04 — Investigation Case
    # ================================================================

    case = InvestigationCase(
        case_id="case-integration-001",
        tenant_id="aegis-lab",
        title="Integration Test Investigation",
        description="End-to-end validation of AegisSOC Phase 02-06.",
    )

    assert case.case_id == "case-integration-001"

    # ================================================================
    # PHASE 05 — Evidence Ledger
    # ================================================================

    ledger = EvidenceLedger()

    entry = ledger.append_evidence(evidence)

    assert entry.evidence_id == evidence.evidence_id
    assert entry.evidence_hash == evidence.integrity.content_hash
    assert len(ledger.entries) == 1

    verification = ledger.verify()
    assert verification is True
    # ================================================================
    # PHASE 06 — Correlation
    # ================================================================

    event_2 = Event(
        event_id="evt-integration-002",
        tenant_id="aegis-lab",
        timestamp=timestamp,
        ingested_at=timestamp,
        source="manual",
        platform="windows",
        category="process",
        event_type="process_creation",
        severity=80,
        host="WINDOWS-LAB",
        user="REN",
        process={
            "pid": 4243,
            "parent_pid": 4242,
            "name": "cmd.exe",
        },
        mitre_techniques=["T1059.001"],
        rule_id="92027",
        rule_name="PowerShell",
        rule_level=4,
        raw_data={
            "integration_test": True,
        },
    )

    engine = PairCorrelationEngine()

    results = engine.correlate(
        event,
        [event_2],
    )

    assert len(results) == 1

    result = results[0]

    assert result.source_event_id == event.event_id
    assert result.related_event_id == event_2.event_id
    assert result.score > 0
    assert result.confidence > 0
    assert len(result.reasons) > 0
