"""
Unit tests untuk PairCorrelationEngine.

Fokus:
- Setiap reason (host, user, process, IP, hash, MITRE) terdeteksi.
- Time window membatasi korelasi.
- Kombinasi reason menaikkan skor/confidence.
- Audit trail (breakdown) konsisten dengan score.
- Event yang tidak terkait tidak menghasilkan korelasi.
"""

from datetime import datetime, timezone

from internal.correlation.correlation import PairCorrelationEngine
from pkg.models.correlation import CorrelationReason
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str,
    timestamp: datetime,
    *,
    host: str = "WINDOWS-LAB",
    user: str = "ren",
    pid: int | None = None,
    parent_pid: int | None = None,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    file_hash: str | None = None,
    mitre: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=timestamp,
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
        host=host,
        user=user,
        process=ProcessContext(
            pid=pid,
            parent_pid=parent_pid,
        ) if pid is not None or parent_pid is not None else None,
        network=NetworkContext(
            source_ip=source_ip,
            destination_ip=destination_ip,
        ) if source_ip or destination_ip else None,
        file=FileContext(
            hashes={"sha256": file_hash} if file_hash else {},
        ) if file_hash else None,
        mitre_techniques=mitre or [],
    )


def engine_sensitive() -> PairCorrelationEngine:
    """
    Engine dengan min_confidence=0.0 supaya single reason tetap lolos.

    Dipakai untuk test yang menguji deteksi reason, bukan threshold.
    """
    return PairCorrelationEngine(min_confidence=0.0)


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------

def test_no_correlation_for_unrelated_events():
    source = make_event(
        "EV-001", BASE,
        host="HOST-A", user="alice", pid=100,
    )
    unrelated = make_event(
        "EV-002", BASE.replace(minute=30),
        host="HOST-B", user="bob", pid=200,
    )

    results = engine_sensitive().correlate(source, [unrelated])

    assert results == []


def test_same_event_id_is_ignored():
    a = make_event("EV-001", BASE, pid=100)
    results = engine_sensitive().correlate(a, [a])
    assert results == []


# ---------------------------------------------------------------------------
# Positive cases — single reason
# ---------------------------------------------------------------------------

def test_same_host_is_correlated():
    source = make_event("EV-001", BASE, host="WINDOWS-LAB")
    related = make_event(
        "EV-002", BASE.replace(second=5),
        host="WINDOWS-LAB",
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_HOST in results[0].reasons


def test_same_user_is_correlated():
    source = make_event("EV-001", BASE, user="ren")
    related = make_event(
        "EV-002", BASE.replace(second=5),
        user="ren",
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_USER in results[0].reasons


def test_same_process_id_is_correlated():
    source = make_event("EV-001", BASE, pid=4210)
    related = make_event(
        "EV-002", BASE.replace(second=3),
        pid=4210,
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_PROCESS_ID in results[0].reasons


def test_same_source_ip_is_correlated():
    source = make_event("EV-001", BASE, source_ip="10.10.10.10")
    related = make_event(
        "EV-002", BASE.replace(second=5),
        source_ip="10.10.10.10",
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_SOURCE_IP in results[0].reasons


def test_same_destination_ip_is_correlated():
    source = make_event("EV-001", BASE, destination_ip="8.8.8.8")
    related = make_event(
        "EV-002", BASE.replace(second=5),
        destination_ip="8.8.8.8",
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_DESTINATION_IP in results[0].reasons


def test_same_file_hash_is_correlated():
    h = "a" * 64
    source = make_event("EV-001", BASE, file_hash=h)
    related = make_event(
        "EV-002", BASE.replace(second=5),
        file_hash=h,
    )

    # Default min_confidence = 0.40, dan SAME_FILE_HASH weight = 0.40.
    # Jadi single reason ini tepat di threshold dan tetap lolos.
    results = PairCorrelationEngine().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_FILE_HASH in results[0].reasons


def test_shared_mitre_technique_is_correlated():
    source = make_event("EV-001", BASE, mitre=["T1546.011"])
    related = make_event(
        "EV-002", BASE.replace(second=5),
        mitre=["T1546.011"],
    )

    results = engine_sensitive().correlate(source, [related])

    assert len(results) == 1
    assert CorrelationReason.SAME_MITRE_TECHNIQUE in results[0].reasons


# ---------------------------------------------------------------------------
# Time window
# ---------------------------------------------------------------------------

def test_time_window_excludes_distant_events():
    source = make_event("EV-001", BASE, host="WINDOWS-LAB", pid=100)
    related = make_event(
        "EV-002", BASE.replace(minute=30),
        host="WINDOWS-LAB", pid=100,
    )

    # Default window = 300 detik, jarak = 1800 detik
    results = PairCorrelationEngine().correlate(source, [related])

    assert results == []


def test_time_window_includes_close_events():
    source = make_event("EV-001", BASE, pid=4210)
    related = make_event(
        "EV-002", BASE.replace(second=10),
        pid=4210,
    )

    results = PairCorrelationEngine(
        time_window_seconds=30
    ).correlate(source, [related])

    assert len(results) == 1


# ---------------------------------------------------------------------------
# Combined reasons — threshold & audit
# ---------------------------------------------------------------------------

def test_combined_reasons_pass_default_threshold():
    h = "b" * 64
    source = make_event(
        "EV-001", BASE,
        host="WINDOWS-LAB", user="ren",
        pid=4210, file_hash=h,
    )
    related = make_event(
        "EV-002", BASE.replace(second=3),
        host="WINDOWS-LAB", user="ren",
        pid=4210, file_hash=h,
    )

    results = PairCorrelationEngine().correlate(source, [related])

    assert len(results) == 1
    r = results[0]

    # Banyak reason → melewati threshold default
    assert r.confidence >= 0.40
    assert r.reason_count >= 3

    # Audit trail terisi
    assert len(r.breakdown) == r.reason_count
    weights = [b.weight for b in r.breakdown]
    assert weights == sorted(weights, reverse=True)


def test_confidence_increases_with_more_reasons():
    # Hanya PID
    a1 = make_event("EV-001", BASE, pid=4210)
    b1 = make_event("EV-002", BASE.replace(second=3), pid=4210)

    # PID + host + user + hash
    h = "c" * 64
    a2 = make_event(
        "EV-003", BASE,
        host="WINDOWS-LAB", user="ren",
        pid=4210, file_hash=h,
    )
    b2 = make_event(
        "EV-004", BASE.replace(second=3),
        host="WINDOWS-LAB", user="ren",
        pid=4210, file_hash=h,
    )

    engine = engine_sensitive()

    r1 = engine.correlate(a1, [b1])[0]
    r2 = engine.correlate(a2, [b2])[0]

    assert r2.confidence > r1.confidence
    assert r2.reason_count > r1.reason_count


def test_audit_breakdown_matches_score():
    h = "d" * 64
    source = make_event(
        "EV-001", BASE,
        host="WINDOWS-LAB", pid=4210, file_hash=h,
    )
    related = make_event(
        "EV-002", BASE.replace(second=3),
        host="WINDOWS-LAB", pid=4210, file_hash=h,
    )

    r = engine_sensitive().correlate(source, [related])[0]

    total = sum(b.weight for b in r.breakdown)
    # ADDITIVE: score = min(total, 1.0)
    assert abs(r.score - min(total, 1.0)) < 1e-9
    assert abs(r.total_raw - total) < 1e-9


def test_render_audit_is_human_readable():
    source = make_event("EV-001", BASE, pid=4210)
    related = make_event("EV-002", BASE.replace(second=3), pid=4210)

    r = engine_sensitive().correlate(source, [related])[0]
    text = r.render_audit()

    assert "score:" in text
    assert "confidence:" in text
    assert "same_process_id" in text
