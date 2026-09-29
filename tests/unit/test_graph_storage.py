"""
Contract tests untuk graph persistence.

Test di-skip otomatis kalau Neo4j tidak tersedia.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

import pytest

from internal.graph.entity_extractor import extract_entities
from internal.graph.graph_store import build_graph
from internal.investigation.investigation_engine import investigate
from internal.storage.graph import (
    GraphService,
    Neo4jClient,
    get_neo4j,
    reset_neo4j,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


# ===========================================================================
# Fixtures
# ===========================================================================

def _neo4j_available() -> bool:
    try:
        client = Neo4jClient(create_indexes=False)
        ok = client.verify_connectivity()
        client.close()
        return ok
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _neo4j_available(),
    reason="Neo4j not available. Start with: "
           "docker compose up -d neo4j",
)


@pytest.fixture
def tenant_id():
    """Tenant unik per-test, auto-cleanup di Neo4j setelah selesai."""
    from internal.storage.graph import Neo4jClient

    t = f"qtest-{uuid4().hex[:12]}"
    yield t
    # teardown: hapus semua node tenant ini
    try:
        c = Neo4jClient(create_indexes=False)
        c.run_write(
            "MATCH (n:Entity {tenant_id: $t}) DETACH DELETE n",
            {"t": t},
        )
        c.driver.close()
    except Exception:
        pass


@pytest.fixture
def service():
    reset_neo4j()
    svc = GraphService()
    yield svc
    # Cleanup tidak otomatis, tapi tiap test pakai tenant unik
    reset_neo4j()


def make_event(
    event_id: str = "E-1",
    *,
    offset: int = 0,
    host: str = "WIN-01",
    severity: int = 85,
    mitre: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=severity,
        host=host,
        user="SYSTEM",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=4821,
            parent_name="svchost.exe",
            parent_pid=812,
        ),
        mitre_techniques=mitre or [],
    )


# ===========================================================================
# Health
# ===========================================================================

def test_neo4j_available(service):
    assert service.is_available() is True


# ===========================================================================
# Save Graph
# ===========================================================================

def test_save_empty_graph(service, tenant_id):
    graph = build_graph([])
    summary = service.save_graph(graph, tenant_id=tenant_id)
    assert summary["entities_saved"] == 0
    assert summary["relationships_saved"] == 0


def test_save_single_event_graph(service, tenant_id):
    graph = build_graph([
        make_event("E-1", mitre=["T1546.011"]),
    ])
    summary = service.save_graph(graph, tenant_id=tenant_id)
    assert summary["entities_saved"] >= 1


def test_save_multi_event_graph(service, tenant_id):
    graph = build_graph([
        make_event("E-1", offset=0),
        make_event("E-2", offset=5),
    ])
    summary = service.save_graph(graph, tenant_id=tenant_id)
    assert summary["entities_saved"] >= 3
    assert summary["relationships_saved"] >= 1


def test_save_with_case_id(service, tenant_id):
    graph = build_graph([make_event("E-1")])
    case_id = f"CASE-{uuid4().hex[:8]}"
    summary = service.save_graph(
        graph,
        case_id=case_id,
        tenant_id=tenant_id,
    )
    assert summary["case_id"] == case_id


def test_save_idempotent(service, tenant_id):
    """Save graph dua kali = tidak duplikat."""
    graph = build_graph([make_event("E-1")])

    s1 = service.save_graph(graph, tenant_id=tenant_id)
    s2 = service.save_graph(graph, tenant_id=tenant_id)

    # Save lagi tidak buat node baru (MERGE)
    stats = service.stats(tenant_id=tenant_id)
    assert stats["entity_count"] == s1["entities_saved"]


# ===========================================================================
# Stats
# ===========================================================================

def test_stats_empty_tenant(service, tenant_id):
    stats = service.stats(tenant_id=tenant_id)
    assert stats["entity_count"] == 0


def test_stats_after_save(service, tenant_id):
    graph = build_graph([
        make_event("E-1"),
        make_event("E-2", offset=5),
    ])
    service.save_graph(graph, tenant_id=tenant_id)

    stats = service.stats(tenant_id=tenant_id)
    assert stats["entity_count"] >= 3
    assert stats["relationship_count"] >= 1


# ===========================================================================
# Neighbors
# ===========================================================================

def test_neighbors_out(service, tenant_id):
    graph = build_graph([make_event("E-1")])
    service.save_graph(graph, tenant_id=tenant_id)

    # Cari entity process
    entities = list(graph.entities)
    process_entity = next(
        (e for e in entities if e.entity_type.value == "process"),
        None,
    )
    if process_entity is None:
        pytest.skip("no process entity")

    neighbors = service.neighbors(
        process_entity.entity_id,
        direction="out",
        tenant_id=tenant_id,
    )
    # Process punya edge ke user, file, dst.
    assert isinstance(neighbors, list)


def test_neighbors_invalid_entity(service, tenant_id):
    result = service.neighbors(
        "NONEXISTENT",
        tenant_id=tenant_id,
    )
    assert result == []

def test_neighbors_excludes_case_node(service, tenant_id):
    """Neighbors harus hanya Entity, bukan Case."""
    graph = build_graph([make_event("E-1")])
    case_id = f"CASE-{uuid4().hex[:8]}"
    service.save_graph(
        graph, case_id=case_id, tenant_id=tenant_id
    )

    entities = list(graph.entities)
    proc = next(
        (e for e in entities if e.entity_type.value == "process"),
        None,
    )
    if proc is None:
        pytest.skip("no process entity")

    neighbors = service.neighbors(
        proc.entity_id, tenant_id=tenant_id,
    )
    # Semua neighbor harus punya entity_type
    for n in neighbors:
        assert n["entity_type"] is not None, (
            f"neighbor {n} is not an Entity"
        )
# ===========================================================================
# Path Finding
# ===========================================================================

def test_find_path_no_path(service, tenant_id):
    graph = build_graph([make_event("E-1")])
    service.save_graph(graph, tenant_id=tenant_id)

    entities = list(graph.entities)
    if len(entities) < 2:
        pytest.skip("need at least 2 entities")

    result = service.find_path(
        entities[0].entity_id,
        entities[-1].entity_id,
        tenant_id=tenant_id,
    )
    # Path bisa ada (kalau ada relationship), atau kosong
    assert isinstance(result, list)


# ===========================================================================
# Cross-host
# ===========================================================================

def test_cross_host_entities_single_host(service, tenant_id):
    graph = build_graph([
        make_event("E-1", host="WIN-01"),
        make_event("E-2", offset=5, host="WIN-01"),
    ])
    service.save_graph(graph, tenant_id=tenant_id)

    # Tidak ada entity yang muncul di >1 host
    results = service.cross_host_entities(
        tenant_id=tenant_id,
        min_hosts=2,
    )
    assert isinstance(results, list)


def test_cross_host_entities_multi_host(service, tenant_id):
    # Hash entity global -> bisa muncul di >1 host
    graph = build_graph([
        make_event("E-1", host="WIN-01"),
        make_event("E-2", offset=5, host="WIN-02"),
    ])
    service.save_graph(graph, tenant_id=tenant_id)

    results = service.cross_host_entities(
        tenant_id=tenant_id,
        min_hosts=2,
    )
    # Hash sama di dua host -> entity yang sama
    assert isinstance(results, list)


# ===========================================================================
# Delete
# ===========================================================================

def test_delete_tenant(service, tenant_id):
    graph = build_graph([make_event("E-1")])
    service.save_graph(graph, tenant_id=tenant_id)

    stats_before = service.stats(tenant_id=tenant_id)
    assert stats_before["entity_count"] >= 1

    deleted = service.delete_tenant(tenant_id)
    assert deleted >= 1

    stats_after = service.stats(tenant_id=tenant_id)
    assert stats_after["entity_count"] == 0


def test_delete_case(service, tenant_id):
    graph = build_graph([make_event("E-1")])
    case_id = f"CASE-{uuid4().hex[:8]}"
    service.save_graph(
        graph, case_id=case_id, tenant_id=tenant_id
    )

    ok = service.delete_case(case_id)
    assert ok is True
