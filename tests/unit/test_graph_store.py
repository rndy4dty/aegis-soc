"""
Contract tests untuk GraphStore & InvestigationGraph.

Menguji:
- build end-to-end dari events
- entity canonical (merge antar event)
- relationship dibangun dari entity canonical
- dedup relationship antar event
- stats
- lookup entity / relationship
- neighbors
- subgraph
- determinisme
- edge cases: empty, single event, multiple events
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.graph.graph_store import (
    GraphStore,
    InvestigationGraph,
    build_graph,
)
from pkg.models.entity import EntityType
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    FileContext,
    Platform,
    ProcessContext,
    UserContext,
)
from pkg.models.relationship import RelationshipType


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
    host: str = "WIN-01",
    user: str | None = "ren",
    user_domain: str | None = None,
    process_name: str | None = None,
    pid: int | None = None,
    guid: str | None = None,
    parent_name: str | None = None,
    parent_pid: int | None = None,
    parent_guid: str | None = None,
    file_path: str | None = None,
    file_hashes: dict | None = None,
    category: EventCategory = EventCategory.PROCESS,
    event_type: str = "process_creation",
) -> Event:
    process = None
    if (
        process_name is not None
        or pid is not None
        or guid is not None
        or parent_name is not None
    ):
        process = ProcessContext(
            name=process_name,
            pid=pid,
            guid=guid,
            parent_name=parent_name,
            parent_pid=parent_pid,
            parent_guid=parent_guid,
        )

    file_ctx = None
    if file_path or file_hashes:
        file_ctx = FileContext(
            path=file_path,
            hashes=file_hashes or {},
        )

    user_ctx = None
    if user and user_domain:
        user_ctx = UserContext(name=user, domain=user_domain)

    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=category,
        event_type=event_type,
        severity=50,
        host=host,
        user=user,
        user_context=user_ctx,
        process=process,
        file=file_ctx,
    )


# ===========================================================================
# Empty & trivial
# ===========================================================================

def test_build_empty_events():
    graph = build_graph([])
    assert graph.is_empty
    assert graph.entity_count == 0
    assert graph.relationship_count == 0
    assert graph.events_processed == 0


def test_build_single_event_host_only():
    graph = build_graph([make_event(host="WIN-01", user=None)])
    assert graph.entity_count >= 1
    hosts = graph.entities_by_type(EntityType.HOST)
    assert len(hosts) == 1
    assert hosts[0].value == "WIN-01"


def test_build_single_event_with_process():
    graph = build_graph([
        make_event(
            host="WIN-01",
            process_name="powershell.exe",
            pid=1234,
        ),
    ])
    procs = graph.entities_by_type(EntityType.PROCESS)
    assert len(procs) == 1
    assert procs[0].value == "powershell.exe"


# ===========================================================================
# Entity merge across events
# ===========================================================================

def test_entity_merged_across_events():
    """
    Host WIN-01 muncul di dua event -> satu entity canonical,
    dengan union source_event_ids.
    """
    events = [
        make_event("E-1", host="WIN-01", user=None),
        make_event("E-2", host="WIN-01", user=None),
    ]
    graph = build_graph(events)

    hosts = graph.entities_by_type(EntityType.HOST)
    assert len(hosts) == 1
    assert hosts[0].source_event_ids == ["E-1", "E-2"]


def test_process_same_instance_merged_across_events():
    events = [
        make_event(
            "E-1", host="WIN-01",
            process_name="powershell.exe", pid=1234,
        ),
        make_event(
            "E-2", host="WIN-01",
            process_name="powershell.exe", pid=1234,
        ),
    ]
    graph = build_graph(events)

    procs = graph.entities_by_type(EntityType.PROCESS)
    assert len(procs) == 1
    assert procs[0].source_event_ids == ["E-1", "E-2"]


def test_different_hosts_not_merged():
    events = [
        make_event("E-1", host="WIN-01", user=None),
        make_event("E-2", host="WIN-02", user=None),
    ]
    graph = build_graph(events)

    hosts = graph.entities_by_type(EntityType.HOST)
    assert len(hosts) == 2


# ===========================================================================
# Relationship from canonical entities
# ===========================================================================

def test_spawned_relationship_built():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    spawned = graph.relationships_by_type(RelationshipType.SPAWNED)
    assert len(spawned) == 1


def test_relationship_merged_across_events():
    """
    SPAWNED yang sama muncul di dua event -> satu relationship canonical,
    dengan union source_event_ids.
    """
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
        make_event(
            "E-2",
            host="WIN-01",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    spawned = graph.relationships_by_type(RelationshipType.SPAWNED)
    assert len(spawned) == 1
    assert spawned[0].source_event_ids == ["E-1", "E-2"]


def test_run_as_relationship_built():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user="ren",
            process_name="powershell.exe",
            pid=1234,
        ),
    ]
    graph = build_graph(events)

    run_as = graph.relationships_by_type(RelationshipType.RUN_AS)
    assert len(run_as) == 1


def test_has_hash_relationship_built():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            file_path="C:\\tmp\\p.exe",
            file_hashes={"sha256": "abc123"},
        ),
    ]
    graph = build_graph(events)

    hh = graph.relationships_by_type(RelationshipType.HAS_HASH)
    assert len(hh) == 1


# ===========================================================================
# Stats
# ===========================================================================

def test_stats():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)
    stats = graph.stats()

    assert stats["events_processed"] == 1
    assert stats["entity_count"] > 0
    assert stats["relationship_count"] > 0
    assert "entity_types" in stats
    assert "relationship_types" in stats
    assert stats["relationship_types"].get("spawned", 0) == 1


# ===========================================================================
# Lookup
# ===========================================================================

def test_get_entity_by_fingerprint():
    events = [make_event("E-1", host="WIN-01", user=None)]
    graph = build_graph(events)

    host = graph.entities_by_type(EntityType.HOST)[0]
    found = graph.get_entity(host.fingerprint)
    assert found is not None
    assert found.value == "WIN-01"


def test_find_entity():
    events = [make_event("E-1", host="WIN-01", user=None)]
    graph = build_graph(events)

    found = graph.find_entity(EntityType.HOST, "win-01")
    assert found is not None
    assert found.value == "WIN-01"


def test_get_relationship_by_fingerprint():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    spawned = graph.relationships_by_type(RelationshipType.SPAWNED)[0]
    found = graph.get_relationship(spawned.fingerprint)
    assert found is not None


# ===========================================================================
# Neighbors & subgraph
# ===========================================================================

def test_outgoing_and_incoming():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    parent = graph.find_entity(EntityType.PROCESS, "powershell.exe|pid:1234")
    child = graph.find_entity(EntityType.PROCESS, "cmd.exe|pid:2000")
    assert parent is not None
    assert child is not None

    out_parent = graph.outgoing(parent.entity_id)
    in_child = graph.incoming(child.entity_id)
    assert len(out_parent) == 1
    assert len(in_child) == 1


def test_neighbors():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    parent = graph.find_entity(EntityType.PROCESS, "powershell.exe|pid:1234")
    neighbors = graph.neighbors(parent.entity_id)
    assert len(neighbors) == 1
    assert neighbors[0].value == "cmd.exe"


def test_subgraph():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
        make_event(
            "E-2",
            host="WIN-02",
            user=None,
            process_name="other.exe",
            pid=9999,
        ),
    ]
    graph = build_graph(events)

    parent = graph.find_entity(EntityType.PROCESS, "powershell.exe|pid:1234")
    sub = graph.subgraph([parent.entity_id], depth=1)

    assert sub.entity_count == 2
    assert sub.relationship_count == 1


def test_subgraph_depth_zero():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user=None,
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)
    parent = graph.find_entity(EntityType.PROCESS, "powershell.exe|pid:1234")
    sub = graph.subgraph([parent.entity_id], depth=0)

    # depth=0 -> hanya entity itu sendiri (tidak meluas)
    assert sub.entity_count == 1
    assert sub.relationship_count == 0


def test_subgraph_invalid_depth():
    graph = build_graph([])
    with pytest.raises(ValueError, match="depth"):
        graph.subgraph([], depth=-1)


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_build_entity_fingerprint():
    """
    Entity fingerprint deterministik lintas run karena dihitung dari
    canonical_payload(), bukan entity_id.
    """
    def build():
        events = [
            make_event(
                "E-1",
                host="WIN-01",
                user="ren",
                process_name="cmd.exe",
                pid=2000,
                parent_name="powershell.exe",
                parent_pid=1234,
                file_path="C:\\tmp\\p.exe",
                file_hashes={"sha256": "abc"},
            ),
        ]
        return build_graph(events)

    g1 = build()
    g2 = build()

    fps1 = [e.fingerprint for e in g1.entities]
    fps2 = [e.fingerprint for e in g2.entities]
    assert fps1 == fps2


def test_deterministic_build_relationship_structure():
    """
    Relationship fingerprint mengandung entity_id (UUID), sehingga
    TIDAK deterministik lintas proses.

    Yang deterministik adalah STRUKTUR relationship: tipe + identitas
    endpoint (via fingerprint Entity).
    """
    def build():
        events = [
            make_event(
                "E-1",
                host="WIN-01",
                user="ren",
                process_name="cmd.exe",
                pid=2000,
                parent_name="powershell.exe",
                parent_pid=1234,
                file_path="C:\\tmp\\p.exe",
                file_hashes={"sha256": "abc"},
            ),
        ]
        return build_graph(events)

    def shape(graph):
        # Map entity_id -> entity fingerprint (deterministik)
        id_to_fp = {e.entity_id: e.fingerprint for e in graph.entities}

        return sorted(
            (
                r.relationship_type.value,
                id_to_fp.get(r.source_id),
                id_to_fp.get(r.target_id),
            )
            for r in graph.relationships
        )

    g1 = build()
    g2 = build()

    assert shape(g1) == shape(g2)


def test_relationship_fingerprint_stable_within_graph():
    """
    Dalam satu graph, fingerprint relationship unik dan konsisten
    dengan entity_id yang sama.
    """
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]
    graph = build_graph(events)

    # Tidak ada dua relationship dengan fingerprint sama
    fps = [r.fingerprint for r in graph.relationships]
    assert len(fps) == len(set(fps))

    # Setiap fingerprint non-None
    assert all(fp is not None for fp in fps)

def test_deterministic_regardless_of_event_order():
    e1 = make_event(
        "E-1", host="WIN-01", user=None,
        process_name="cmd.exe", pid=2000,
        parent_name="powershell.exe", parent_pid=1234,
    )
    e2 = make_event(
        "E-2", host="WIN-01", user=None,
        process_name="other.exe", pid=3000,
    )

    g1 = build_graph([e1, e2])
    g2 = build_graph([e2, e1])

    fps1 = sorted(e.fingerprint for e in g1.entities)
    fps2 = sorted(e.fingerprint for e in g2.entities)
    assert fps1 == fps2


# ===========================================================================
# Serialization
# ===========================================================================

def test_to_dict():
    events = [make_event("E-1", host="WIN-01", user=None)]
    graph = build_graph(events)
    data = graph.to_dict()

    assert "stats" in data
    assert "entities" in data
    assert "relationships" in data
    assert data["stats"]["events_processed"] == 1


# ===========================================================================
# GraphStore reuse
# ===========================================================================

def test_graph_store_is_reusable():
    store = GraphStore()
    events1 = [make_event("E-1", host="WIN-01", user=None)]
    events2 = [make_event("E-2", host="WIN-02", user=None)]

    g1 = store.build(events1)
    g2 = store.build(events2)

    assert g1.entity_count == 1
    assert g2.entity_count == 1


# ===========================================================================
# Multi-event complex
# ===========================================================================

def test_multi_event_complex():
    events = [
        make_event(
            "E-1",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            file_path="C:\\tmp\\p.exe",
            file_hashes={"sha256": "abc"},
        ),
        make_event(
            "E-2",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
        ),
    ]

    graph = build_graph(events)

    # Entities canonical
    assert graph.entity_count >= 4

    # SPAWNED muncul sekali (di-merge)
    spawned = graph.relationships_by_type(RelationshipType.SPAWNED)
    assert len(spawned) == 1

    # HAS_HASH hanya di E-1, masih ada
    hh = graph.relationships_by_type(RelationshipType.HAS_HASH)
    assert len(hh) == 1

    # RUN_AS di dua event -> merge
    run_as = graph.relationships_by_type(RelationshipType.RUN_AS)
    assert len(run_as) == 1

    # Prov untuk SPAWNED harusnya union
    assert "E-1" in spawned[0].source_event_ids
    assert "E-2" in spawned[0].source_event_ids
