"""
Contract tests untuk RelationshipBuilder.

Menguji:
- SPAWNED dari parent-child
- RUN_AS dari process + user
- HAS_HASH dari file + hash(es)
- CONNECTED_TO dari process + destination_ip (network/http)
- tidak membangun relationship saat entity tidak lengkap
- provenance & tenant propagation
- determinisme struktur output
- dedup by fingerprint
- edge cases: event tanpa entity, event tanpa context
"""

from datetime import datetime, timezone

import pytest

from internal.graph.entity_extractor import extract_entities
from internal.graph.relationship_builder import (
    RelationshipBuilder,
    build_relationships,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
    UserContext,
)
from pkg.models.relationship import (
    NodeType,
    Relationship,
    RelationshipType,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(**kwargs) -> Event:
    defaults = dict(
        event_id="E-1",
        timestamp=BASE,
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
    )
    defaults.update(kwargs)
    return Event(**defaults)


def by_type(rels, rel_type):
    return [r for r in rels if r.relationship_type == rel_type]


def entity_value(entities, entity_id):
    for e in entities:
        if e.entity_id == entity_id:
            return e.value
    return None


def shape(rels, entities):
    """
    Representasi struktur relationship yang stabil lintas run,
    menggantikan entity_id (UUID) dengan entity value.
    """
    return sorted([
        (
            r.relationship_type.value,
            entity_value(entities, r.source_id),
            entity_value(entities, r.target_id),
        )
        for r in rels
    ])


# ===========================================================================
# SPAWNED
# ===========================================================================

def test_spawned_from_parent_child():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    spawned = by_type(rels, RelationshipType.SPAWNED)
    assert len(spawned) == 1
    assert entity_value(entities, spawned[0].source_id) == "powershell.exe"
    assert entity_value(entities, spawned[0].target_id) == "cmd.exe"


def test_spawned_with_guid():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000, guid="CHILD-G",
            parent_name="powershell.exe", parent_pid=1234,
            parent_guid="PARENT-G",
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    spawned = by_type(rels, RelationshipType.SPAWNED)
    assert len(spawned) == 1


def test_no_spawned_without_parent():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.SPAWNED) == []


def test_no_spawned_without_child():
    # Event tanpa process context
    e = make_event(host="WIN-01", user="ren")
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.SPAWNED) == []


def test_no_self_spawned():
    """
    Parent dan child punya name sama dan tidak ada disambiguasi PID/GUID
    -> entity lookup mengembalikan entity yang sama -> skip SPAWNED.
    """
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe",
            parent_name="cmd.exe",
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.SPAWNED) == []


# ===========================================================================
# RUN_AS
# ===========================================================================

def test_run_as():
    e = make_event(
        host="WIN-01",
        user="ren",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    run_as = by_type(rels, RelationshipType.RUN_AS)
    assert len(run_as) == 1
    assert entity_value(entities, run_as[0].source_id) == "powershell.exe"
    assert entity_value(entities, run_as[0].target_id) == "ren"


def test_run_as_with_domain_user():
    e = make_event(
        host="WIN-01",
        user="ren",
        user_context=UserContext(name="ren", domain="CORP"),
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    run_as = by_type(rels, RelationshipType.RUN_AS)
    assert len(run_as) == 1
    assert entity_value(entities, run_as[0].target_id) == "ren"


def test_no_run_as_without_user():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.RUN_AS) == []


def test_no_run_as_without_process():
    e = make_event(host="WIN-01", user="ren")
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.RUN_AS) == []


# ===========================================================================
# HAS_HASH
# ===========================================================================

def test_has_hash_single():
    e = make_event(
        host="WIN-01",
        file=FileContext(
            path="C:\\tmp\\payload.exe",
            hashes={"sha256": "abc123"},
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    hh = by_type(rels, RelationshipType.HAS_HASH)
    assert len(hh) == 1
    assert entity_value(entities, hh[0].source_id) == "C:\\tmp\\payload.exe"
    assert entity_value(entities, hh[0].target_id) == "abc123"


def test_has_hash_multiple_algorithms():
    e = make_event(
        host="WIN-01",
        file=FileContext(
            path="C:\\tmp\\payload.exe",
            hashes={"md5": "aaa", "sha256": "bbb"},
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    hh = by_type(rels, RelationshipType.HAS_HASH)
    assert len(hh) == 2
    targets = {entity_value(entities, r.target_id) for r in hh}
    assert targets == {"aaa", "bbb"}


def test_no_has_hash_without_file():
    e = make_event(host="WIN-01")
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.HAS_HASH) == []


def test_no_has_hash_without_hash_entities():
    e = make_event(
        host="WIN-01",
        file=FileContext(path="C:\\tmp\\payload.exe"),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.HAS_HASH) == []


# ===========================================================================
# CONNECTED_TO
# ===========================================================================

def test_connected_to_network_category():
    e = make_event(
        host="WIN-01",
        category=EventCategory.NETWORK,
        event_type="network_connection",
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    ct = by_type(rels, RelationshipType.CONNECTED_TO)
    assert len(ct) == 1
    assert entity_value(entities, ct[0].source_id) == "powershell.exe"
    assert entity_value(entities, ct[0].target_id) == "8.8.8.8"


def test_connected_to_requires_network_category():
    """
    Category PROCESS + destination_ip tidak boleh menghasilkan CONNECTED_TO.
    """
    e = make_event(
        host="WIN-01",
        category=EventCategory.PROCESS,
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(destination_ip="8.8.8.8"),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.CONNECTED_TO) == []


def test_connected_to_requires_process():
    e = make_event(
        host="WIN-01",
        category=EventCategory.NETWORK,
        event_type="network_connection",
        network=NetworkContext(destination_ip="8.8.8.8"),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.CONNECTED_TO) == []


def test_connected_to_requires_destination_ip():
    e = make_event(
        host="WIN-01",
        category=EventCategory.NETWORK,
        event_type="network_connection",
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(source_ip="10.0.0.1"),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)
    assert by_type(rels, RelationshipType.CONNECTED_TO) == []


# ===========================================================================
# Provenance, tenant, timestamps
# ===========================================================================

def test_source_event_ids_propagated():
    e = make_event(
        event_id="E-42",
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    assert rels
    for r in rels:
        assert "E-42" in r.source_event_ids


def test_tenant_propagated():
    e = make_event(
        tenant_id="tenant-a",
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    assert rels
    for r in rels:
        assert r.tenant_id == "tenant-a"


def test_timestamps_propagated():
    ts = datetime(2026, 9, 26, 11, 0, tzinfo=timezone.utc)
    e = make_event(
        timestamp=ts,
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    assert rels
    for r in rels:
        assert r.first_seen == ts
        assert r.last_seen == ts


# ===========================================================================
# Fingerprint
# ===========================================================================

def test_all_relationships_have_fingerprint():
    e = make_event(
        host="WIN-01",
        user="ren",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
        file=FileContext(
            path="C:\\tmp\\p.exe",
            hashes={"sha256": "abc"},
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    assert rels
    for r in rels:
        assert r.fingerprint is not None
        assert r.verify_fingerprint()


def test_relationship_source_type_is_entity():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    assert rels
    for r in rels:
        assert r.source_type == NodeType.ENTITY
        assert r.target_type == NodeType.ENTITY


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_structure():
    """
    Extract ulang + build ulang harus menghasilkan struktur
    relationship yang sama (menggunakan entity value, bukan entity_id).
    """
    def make():
        e = make_event(
            host="WIN-01",
            user="ren",
            process=ProcessContext(
                name="cmd.exe", pid=2000,
                parent_name="powershell.exe", parent_pid=1234,
            ),
            file=FileContext(
                path="C:\\tmp\\p.exe",
                hashes={"sha256": "abc"},
            ),
        )
        return e, extract_entities(e)

    e1, ents1 = make()
    e2, ents2 = make()
    rels1 = build_relationships(e1, ents1)
    rels2 = build_relationships(e2, ents2)

    assert shape(rels1, ents1) == shape(rels2, ents2)


def test_sort_is_by_type_then_source_target():
    e = make_event(
        host="WIN-01",
        user="ren",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
        file=FileContext(
            path="C:\\tmp\\p.exe",
            hashes={"sha256": "abc"},
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    keys = [
        (r.relationship_type.value, r.source_id, r.target_id)
        for r in rels
    ]
    assert keys == sorted(keys)


# ===========================================================================
# Deduplication
# ===========================================================================

def test_dedup_does_not_merge_distinct_relationships():
    e = make_event(
        host="WIN-01",
        user="ren",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
        file=FileContext(
            path="C:\\tmp\\p.exe",
            hashes={"sha256": "abc"},
        ),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    fps = [r.fingerprint for r in rels]
    assert len(fps) == len(set(fps))


# ===========================================================================
# Edge cases
# ===========================================================================

def test_empty_entities_returns_empty():
    e = make_event(host="WIN-01")
    assert build_relationships(e, []) == []


def test_empty_event_no_relationships():
    e = make_event()
    entities = extract_entities(e)
    assert build_relationships(e, entities) == []


def test_builder_is_reusable():
    builder = RelationshipBuilder()
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    entities = extract_entities(e)
    out1 = builder.build(e, entities)
    out2 = builder.build(e, entities)
    assert len(out1) == len(out2)


def test_full_event_produces_expected_set():
    e = make_event(
        host="WIN-01",
        user="ren",
        category=EventCategory.NETWORK,
        event_type="network_connection",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
        file=FileContext(
            path="C:\\tmp\\p.exe",
            hashes={"sha256": "abc"},
        ),
        network=NetworkContext(destination_ip="8.8.8.8"),
    )
    entities = extract_entities(e)
    rels = build_relationships(e, entities)

    types = {r.relationship_type for r in rels}
    assert RelationshipType.SPAWNED in types
    assert RelationshipType.RUN_AS in types
    assert RelationshipType.HAS_HASH in types
    assert RelationshipType.CONNECTED_TO in types
