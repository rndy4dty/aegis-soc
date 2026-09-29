"""
Contract tests untuk InvestigationEngine.

Menguji:
- orkestrasi end-to-end events → InvestigationResult
- pipeline graph (entity + relationship)
- pipeline evidence
- pipeline correlation
- pipeline hypothesis
- pipeline risk
- InvestigationCase assembly
- priority derivation
- determinisme
- edge cases
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.investigation.investigation_engine import (
    InvestigationEngine,
    InvestigationResult,
    investigate,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
)
from pkg.models.investigation import (
    InvestigationCategory,
    InvestigationPriority,
    InvestigationStatus,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
    host: str = "WIN-01",
    user: str | None = "ren",
    process_name: str | None = None,
    pid: int | None = None,
    parent_name: str | None = None,
    parent_pid: int | None = None,
    file_path: str | None = None,
    file_hashes: dict | None = None,
    destination_ip: str | None = None,
    severity: int = 50,
    category: EventCategory = EventCategory.PROCESS,
    event_type: str = "process_creation",
    mitre: list[str] | None = None,
    rule_id: str | None = None,
    tenant_id: str | None = None,
) -> Event:
    process = None
    if (
        process_name is not None
        or pid is not None
        or parent_name is not None
    ):
        process = ProcessContext(
            name=process_name,
            pid=pid,
            parent_name=parent_name,
            parent_pid=parent_pid,
        )

    file_ctx = None
    if file_path or file_hashes:
        file_ctx = FileContext(
            path=file_path,
            hashes=file_hashes or {},
        )

    network = None
    if destination_ip:
        network = NetworkContext(destination_ip=destination_ip)

    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=category,
        event_type=event_type,
        severity=severity,
        host=host,
        user=user,
        process=process,
        file=file_ctx,
        network=network,
        mitre_techniques=mitre or [],
        rule_id=rule_id,
        tenant_id=tenant_id,
    )


# ===========================================================================
# Empty & minimal
# ===========================================================================

def test_empty_events():
    result = investigate([], title="Empty case")
    assert isinstance(result, InvestigationResult)
    assert result.evidence == []
    assert result.hypotheses == []
    assert result.risk_score == 0
    assert result.case.status in (
        InvestigationStatus.DETECTED,
        InvestigationStatus.TRIAGED,
    )


def test_single_event():
    ev = make_event(
        host="WIN-01",
        process_name="powershell.exe",
        pid=1234,
        severity=70,
    )
    result = investigate([ev], title="Single event case")

    assert result.evidence_count == 1
    assert result.graph.entity_count >= 2  # host + process
    assert result.risk_score > 0


# ===========================================================================
# Graph pipeline
# ===========================================================================

def test_graph_entity_extraction():
    ev = make_event(
        host="WIN-01",
        process_name="powershell.exe",
        pid=1234,
        file_path="C:\\tmp\\p.exe",
        file_hashes={"sha256": "abc123"},
    )
    result = investigate([ev], title="Graph test")

    from pkg.models.entity import EntityType

    hosts = result.graph.entities_by_type(EntityType.HOST)
    procs = result.graph.entities_by_type(EntityType.PROCESS)
    files = result.graph.entities_by_type(EntityType.FILE)
    hashes = result.graph.entities_by_type(EntityType.HASH)

    assert len(hosts) == 1
    assert len(procs) == 1
    assert len(files) == 1
    assert len(hashes) == 1


def test_graph_relationship_spawned():
    ev = make_event(
        host="WIN-01",
        process_name="cmd.exe",
        pid=2000,
        parent_name="powershell.exe",
        parent_pid=1234,
    )
    result = investigate([ev], title="Spawned test")

    from pkg.models.relationship import RelationshipType

    spawned = result.graph.relationships_by_type(
        RelationshipType.SPAWNED
    )
    assert len(spawned) == 1


# ===========================================================================
# Evidence pipeline
# ===========================================================================

def test_evidence_generated():
    events = [
        make_event(event_id="E-1", severity=70),
        make_event(event_id="E-2", severity=85, offset_seconds=10),
    ]
    result = investigate(events, title="Evidence test")

    assert result.evidence_count == 2
    for ev in result.evidence:
        assert ev.verify_content_hash()


# ===========================================================================
# Correlation pipeline
# ===========================================================================

def test_correlation_pipeline_runs():
    events = [
        make_event(
            event_id="E-1",
            host="WIN-01",
            process_name="powershell.exe",
            pid=1234,
            severity=70,
        ),
        make_event(
            event_id="E-2",
            host="WIN-01",
            process_name="powershell.exe",
            pid=1234,
            severity=70,
            offset_seconds=5,
        ),
    ]
    result = investigate(events, title="Correlation test")

    assert result.correlation_count >= 1


# ===========================================================================
# Hypothesis pipeline
# ===========================================================================

def test_hypothesis_generated_from_mitre():
    events = [
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
        make_event(
            event_id="E-2",
            severity=70,
            mitre=["T1546.011"],
            offset_seconds=10,
        ),
    ]
    result = investigate(events, title="Hypothesis test")

    assert result.hypothesis_count >= 2  # MAIN + COUNTER


# ===========================================================================
# Risk pipeline
# ===========================================================================

def test_risk_computed():
    events = [
        make_event(
            event_id="E-1",
            severity=85,
            mitre=["T1546.011"],
        ),
        make_event(
            event_id="E-2",
            severity=85,
            mitre=["T1546.011"],
            offset_seconds=5,
        ),
    ]
    result = investigate(events, title="Risk test")

    assert result.risk is not None
    assert result.risk_score > 0
    assert result.risk.breakdown["evidence"] > 0


def test_risk_reflected_in_case():
    events = [
        make_event(event_id="E-1", severity=85),
    ]
    result = investigate(events, title="Case risk test")

    assert result.case.risk_score == result.risk.risk_score
    assert result.case.confidence == result.risk.confidence
    assert len(result.case.risk_history) == 1


# ===========================================================================
# Case assembly
# ===========================================================================

def test_case_has_evidence_ids():
    events = [
        make_event(event_id="E-1", severity=70),
        make_event(event_id="E-2", severity=70, offset_seconds=5),
    ]
    result = investigate(events, title="Case evidence test")

    for ev in result.evidence:
        assert ev.evidence_id in result.case.evidence_ids


def test_case_has_hypothesis_ids():
    events = [
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ]
    result = investigate(events, title="Case hypothesis test")

    for h in result.hypotheses:
        assert h.hypothesis_id in result.case.hypothesis_ids


def test_case_has_event_ids():
    events = [
        make_event(event_id="E-1", severity=50),
        make_event(event_id="E-2", severity=50, offset_seconds=5),
    ]
    result = investigate(events, title="Case event test")

    assert "E-1" in result.case.event_ids
    assert "E-2" in result.case.event_ids


def test_case_has_entity_ids():
    ev = make_event(
        host="WIN-01",
        process_name="powershell.exe",
        pid=1234,
    )
    result = investigate([ev], title="Case entity test")

    assert len(result.case.entity_ids) == result.graph.entity_count


def test_case_transitions_to_triaged():
    ev = make_event(severity=50)
    result = investigate([ev], title="Transition test")

    assert result.case.status == InvestigationStatus.TRIAGED


def test_case_analyst_assigned():
    ev = make_event(severity=50)
    result = investigate(
        [ev], title="Analyst test", analyst="ren",
    )

    assert result.case.analyst == "ren"


# ===========================================================================
# Priority derivation
# ===========================================================================

def test_priority_critical():
    ev = make_event(severity=90)
    result = investigate([ev], title="Priority test")
    assert result.case.priority == InvestigationPriority.CRITICAL


def test_priority_high():
    ev = make_event(severity=75)
    result = investigate([ev], title="Priority test")
    assert result.case.priority == InvestigationPriority.HIGH


def test_priority_medium():
    ev = make_event(severity=50)
    result = investigate([ev], title="Priority test")
    assert result.case.priority == InvestigationPriority.MEDIUM


def test_priority_low():
    ev = make_event(severity=20)
    result = investigate([ev], title="Priority test")
    assert result.case.priority == InvestigationPriority.LOW


def test_priority_explicit_override():
    ev = make_event(severity=20)
    result = investigate(
        [ev],
        title="Priority test",
        priority=InvestigationPriority.CRITICAL,
    )
    assert result.case.priority == InvestigationPriority.CRITICAL


# ===========================================================================
# Tenant
# ===========================================================================

def test_tenant_propagated():
    ev = make_event(
        tenant_id="tenant-a",
        severity=50,
    )
    result = investigate(
        [ev],
        title="Tenant test",
        tenant_id="tenant-a",
    )

    assert result.case.tenant_id == "tenant-a"
    for e in result.evidence:
        assert e.tenant_id == "tenant-a"


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_evidence_ids():
    ev = make_event(event_id="E-1", severity=50)

    r1 = investigate([ev], title="Determinism test")
    r2 = investigate([ev], title="Determinism test")

    hashes1 = [e.integrity.content_hash for e in r1.evidence]
    hashes2 = [e.integrity.content_hash for e in r2.evidence]
    assert hashes1 == hashes2


def test_deterministic_hypothesis_fingerprints():
    events = [
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ]

    r1 = investigate(events, title="Det test")
    r2 = investigate(events, title="Det test")

    fps1 = sorted(h.fingerprint for h in r1.hypotheses)
    fps2 = sorted(h.fingerprint for h in r2.hypotheses)
    assert fps1 == fps2


def test_deterministic_risk_score():
    events = [
        make_event(event_id="E-1", severity=85, mitre=["T1546.011"]),
        make_event(
            event_id="E-2", severity=85, mitre=["T1546.011"],
            offset_seconds=5,
        ),
    ]

    r1 = investigate(events, title="Det test")
    r2 = investigate(events, title="Det test")

    assert r1.risk_score == r2.risk_score
    assert r1.confidence == r2.confidence


# ===========================================================================
# Result summary
# ===========================================================================

def test_result_summary():
    events = [
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ]
    result = investigate(events, title="Summary test")
    summary = result.summary()

    assert "case_id" in summary
    assert "risk_score" in summary
    assert "evidence_count" in summary
    assert summary["evidence_count"] == result.evidence_count


# ===========================================================================
# Engine reuse
# ===========================================================================

def test_engine_reusable():
    engine = InvestigationEngine()
    ev1 = make_event(event_id="E-1", host="WIN-01", severity=50)
    ev2 = make_event(event_id="E-2", host="WIN-02", severity=50)

    r1 = engine.run([ev1], title="Test 1")
    r2 = engine.run([ev2], title="Test 2")

    assert r1.case.case_id != r2.case.case_id
    assert r1.case.title != r2.case.title


# ===========================================================================
# Full scenario
# ===========================================================================

def test_full_scenario():
    events = [
        make_event(
            event_id="E-1",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            file_path="C:\\tmp\\payload.exe",
            file_hashes={"sha256": "deadbeef"},
            severity=85,
            mitre=["T1546.011", "T1059.001"],
            rule_id="92058",
        ),
        make_event(
            event_id="E-2",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            severity=85,
            mitre=["T1546.011"],
            offset_seconds=10,
        ),
    ]

    result = investigate(
        events,
        title="Application Shimming investigation",
        category=InvestigationCategory.PERSISTENCE,
    )

    # Evidence
    assert result.evidence_count == 2

    # Graph
    assert result.graph.entity_count >= 5
    assert result.graph.relationship_count >= 2

    # Hypotheses
    assert result.hypothesis_count >= 2

    # Risk
    assert result.risk_score >= 35
    assert result.case.risk_score == result.risk_score

    # Case
    assert result.case.category == InvestigationCategory.PERSISTENCE
    assert result.case.priority == InvestigationPriority.CRITICAL
    assert "E-1" in result.case.event_ids
    assert "E-2" in result.case.event_ids
    assert result.case.analyst is None


def test_full_scenario_with_analyst():
    events = [
        make_event(
            event_id="E-1",
            severity=85,
            mitre=["T1546.011"],
        ),
    ]
    result = investigate(
        events,
        title="Analyst test",
        analyst="ren",
    )

    assert result.case.analyst == "ren"
