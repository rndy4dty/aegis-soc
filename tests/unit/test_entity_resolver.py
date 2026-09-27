"""
Contract tests untuk EntityResolver.

Menguji:
- merge entity dengan fingerprint sama
- union provenance (source_event_ids, source_evidence_ids)
- temporal min/max
- dedup by fingerprint
- store lookup: get, by_type, by_value, find
- determinisme urutan
- preserve tenant, value, host dari entity pertama
- edge case: empty, single, many
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.graph.entity_resolver import (
    EntityResolver,
    EntityStore,
    resolve_entities,
)
from pkg.models.entity import Entity, EntityType


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_host(
    value: str = "WIN-01",
    *,
    event_ids: list[str] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    tenant_id: str | None = None,
    tags: list[str] | None = None,
    properties: dict | None = None,
) -> Entity:
    return Entity(
        tenant_id=tenant_id,
        entity_type=EntityType.HOST,
        value=value,
        normalized_value=value.lower(),
        source_event_ids=event_ids or [],
        first_seen=first_seen,
        last_seen=last_seen,
        tags=tags or [],
        properties=properties or {},
    ).with_fingerprint()


def make_hash(
    value: str = "abc123",
    *,
    algorithm: str = "sha256",
    event_ids: list[str] | None = None,
) -> Entity:
    return Entity(
        entity_type=EntityType.HASH,
        value=value,
        normalized_value=value.lower(),
        hash_algorithm=algorithm,
        source_event_ids=event_ids or [],
    ).with_fingerprint()


# ===========================================================================
# Empty & trivial
# ===========================================================================

def test_empty_resolution():
    store = resolve_entities([])
    assert store.is_empty
    assert store.size == 0
    assert store.entities == ()


def test_single_entity_preserved():
    e = make_host("WIN-01", event_ids=["E-1"])
    store = resolve_entities([e])

    assert store.size == 1
    resolved = store.get(e.fingerprint)
    assert resolved is not None
    assert resolved.source_event_ids == ["E-1"]


# ===========================================================================
# Merge by fingerprint
# ===========================================================================

def test_merge_identical_entities():
    a = make_host("WIN-01", event_ids=["E-1"])
    b = make_host("WIN-01", event_ids=["E-2"])

    store = resolve_entities([a, b])

    assert store.size == 1
    merged = store.entities[0]
    assert merged.source_event_ids == ["E-1", "E-2"]


def test_merge_dedup_event_ids():
    a = make_host("WIN-01", event_ids=["E-1", "E-2"])
    b = make_host("WIN-01", event_ids=["E-2", "E-3"])

    store = resolve_entities([a, b])
    assert store.size == 1
    assert store.entities[0].source_event_ids == ["E-1", "E-2", "E-3"]


def test_different_hosts_not_merged():
    a = make_host("WIN-01", event_ids=["E-1"])
    b = make_host("WIN-02", event_ids=["E-2"])

    store = resolve_entities([a, b])
    assert store.size == 2


def test_different_hash_algorithm_not_merged():
    a = make_hash("abc123", algorithm="md5")
    b = make_hash("abc123", algorithm="sha256")

    store = resolve_entities([a, b])
    assert store.size == 2


# ===========================================================================
# Temporal merge
# ===========================================================================

def test_merge_temporal_min_max():
    a = make_host(
        "WIN-01",
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=5),
    )
    b = make_host(
        "WIN-01",
        first_seen=BASE - timedelta(minutes=10),
        last_seen=BASE + timedelta(minutes=30),
    )

    store = resolve_entities([a, b])
    merged = store.entities[0]
    assert merged.first_seen == BASE - timedelta(minutes=10)
    assert merged.last_seen == BASE + timedelta(minutes=30)


def test_merge_temporal_none_handling():
    a = make_host("WIN-01", first_seen=BASE, last_seen=BASE)
    b = make_host("WIN-01")  # tanpa timestamps

    store = resolve_entities([a, b])
    merged = store.entities[0]
    assert merged.first_seen == BASE
    assert merged.last_seen == BASE


# ===========================================================================
# Properties & tags merge
# ===========================================================================

def test_merge_properties():
    a = make_host("WIN-01", properties={"os": "Windows 11", "ip": "10.0.0.1"})
    b = make_host("WIN-01", properties={"os": "Windows 10", "cpu": "Intel"})

    store = resolve_entities([a, b])
    merged = store.entities[0]
    assert merged.properties["os"] == "Windows 10"  # b menang (scalar)
    assert merged.properties["ip"] == "10.0.0.1"
    assert merged.properties["cpu"] == "Intel"


def test_merge_tags_union():
    a = make_host("WIN-01", tags=["critical"])
    b = make_host("WIN-01", tags=["soc", "critical"])

    store = resolve_entities([a, b])
    merged = store.entities[0]
    assert merged.tags == ["critical", "soc"]


# ===========================================================================
# Tenant
# ===========================================================================

def test_tenant_preserved_from_first():
    a = make_host("WIN-01", tenant_id="tenant-a")
    b = make_host("WIN-01", tenant_id="tenant-a")

    store = resolve_entities([a, b])
    assert store.entities[0].tenant_id == "tenant-a"


def test_different_tenant_not_merged():
    """
    Dua host dengan value sama di tenant berbeda -> fingerprint berbeda
    (tenant_id masuk canonical_payload).
    """
    a = make_host("WIN-01", tenant_id="tenant-a")
    b = make_host("WIN-01", tenant_id="tenant-b")

    store = resolve_entities([a, b])
    assert store.size == 2


# ===========================================================================
# Fingerprint auto-fill
# ===========================================================================

def test_entity_without_fingerprint_gets_filled():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )
    assert e.fingerprint is None

    store = resolve_entities([e])
    assert store.size == 1
    assert store.entities[0].fingerprint is not None


# ===========================================================================
# Store lookup
# ===========================================================================

def test_store_get_by_fingerprint():
    e = make_host("WIN-01")
    store = resolve_entities([e])
    found = store.get(e.fingerprint)
    assert found is not None
    assert found.value == "WIN-01"


def test_store_get_missing_returns_none():
    store = resolve_entities([make_host("WIN-01")])
    assert store.get("nonexistent") is None


def test_store_by_type():
    entities = [
        make_host("WIN-01"),
        make_host("WIN-02"),
        make_hash("abc123"),
    ]
    store = resolve_entities(entities)

    hosts = store.by_type(EntityType.HOST)
    hashes = store.by_type(EntityType.HASH)

    assert len(hosts) == 2
    assert len(hashes) == 1


def test_store_by_value():
    entities = [
        make_host("WIN-01"),
        make_hash("abc123", algorithm="md5"),
        make_hash("abc123", algorithm="sha256"),
    ]
    store = resolve_entities(entities)

    # HASH abc123 punya dua entri (md5 + sha256)
    hashes = store.by_value(EntityType.HASH, "abc123")
    assert len(hashes) == 2


def test_store_find_unique():
    store = resolve_entities([make_host("WIN-01")])
    found = store.find(EntityType.HOST, "win-01")
    assert found is not None
    assert found.value == "WIN-01"


def test_store_find_ambiguous_returns_none():
    """
    Hash abc123 dengan dua algoritma -> find() ambiguous -> None.
    """
    store = resolve_entities([
        make_hash("abc123", algorithm="md5"),
        make_hash("abc123", algorithm="sha256"),
    ])
    assert store.find(EntityType.HASH, "abc123") is None


def test_store_find_with_host_filter():
    a = Entity(
        entity_type=EntityType.PROCESS,
        value="svchost.exe",
        normalized_value="svchost.exe|pid:1000",
        host="host-a",
    ).with_fingerprint()
    b = Entity(
        entity_type=EntityType.PROCESS,
        value="svchost.exe",
        normalized_value="svchost.exe|pid:1000",
        host="host-b",
    ).with_fingerprint()

    store = resolve_entities([a, b])

    found = store.find(
        EntityType.PROCESS,
        "svchost.exe|pid:1000",
        host="host-a",
    )
    assert found is not None
    assert found.host == "host-a"


# ===========================================================================
# Aggregation
# ===========================================================================

def test_type_counts():
    store = resolve_entities([
        make_host("WIN-01"),
        make_host("WIN-02"),
        make_hash("abc"),
    ])
    counts = store.type_counts()
    assert counts[EntityType.HOST] == 2
    assert counts[EntityType.HASH] == 1


def test_types_sorted():
    store = resolve_entities([
        make_hash("abc"),
        make_host("WIN-01"),
    ])
    # Urut by enum value (alphabetic)
    assert store.types() == [EntityType.HASH, EntityType.HOST]


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_order():
    entities = [
        make_host("WIN-02"),
        make_hash("bbb"),
        make_host("WIN-01"),
        make_hash("aaa"),
    ]
    s1 = resolve_entities(entities)
    s2 = resolve_entities(list(reversed(entities)))

    fps1 = [e.fingerprint for e in s1]
    fps2 = [e.fingerprint for e in s2]
    assert fps1 == fps2


def test_type_ordering():
    entities = [
        make_hash("abc"),
        make_host("WIN-01"),
    ]
    store = resolve_entities(entities)
    types = [e.entity_type for e in store]
    # HOST sebelum HASH
    assert types.index(EntityType.HOST) < types.index(EntityType.HASH)


# ===========================================================================
# resolve_many
# ===========================================================================

def test_resolve_many():
    list1 = [make_host("WIN-01", event_ids=["E-1"])]
    list2 = [make_host("WIN-01", event_ids=["E-2"])]

    store = EntityResolver().resolve_many([list1, list2])

    assert store.size == 1
    assert store.entities[0].source_event_ids == ["E-1", "E-2"]


# ===========================================================================
# Store contains & iteration
# ===========================================================================

def test_store_contains():
    e = make_host("WIN-01")
    store = resolve_entities([e])
    assert e in store


def test_store_contains_unfingerprinted_returns_false():
    e = Entity(entity_type=EntityType.HOST, value="X")
    store = resolve_entities([make_host("WIN-01")])
    assert e not in store


def test_store_iteration_and_indexing():
    store = resolve_entities([
        make_host("WIN-01"),
        make_host("WIN-02"),
    ])
    assert len(store) == 2
    assert store[0].entity_type == EntityType.HOST
    assert [e.value for e in store] == ["WIN-01", "WIN-02"]


def test_store_to_dicts():
    store = resolve_entities([make_host("WIN-01")])
    dicts = store.to_dicts()
    assert len(dicts) == 1
    assert dicts[0]["type"] == "Entity"
    assert dicts[0]["value"] == "WIN-01"


def test_store_to_list():
    store = resolve_entities([make_host("WIN-01")])
    lst = store.to_list()
    assert isinstance(lst, list)
    assert len(lst) == 1


# ===========================================================================
# Edge cases
# ===========================================================================

def test_resolver_ignores_non_entity():
    store = resolve_entities([
        make_host("WIN-01"),
        "not-an-entity",  # type: ignore[list-item]
        None,             # type: ignore[list-item]
    ])
    assert store.size == 1


def test_resolver_is_reusable():
    r = EntityResolver()
    e1 = make_host("WIN-01")
    e2 = make_host("WIN-02")

    store1 = r.resolve([e1])
    store2 = r.resolve([e2])

    assert store1.size == 1
    assert store2.size == 1
    assert store1.entities[0].value == "WIN-01"
    assert store2.entities[0].value == "WIN-02"


def test_merge_three_entities():
    a = make_host("WIN-01", event_ids=["E-1"])
    b = make_host("WIN-01", event_ids=["E-2"])
    c = make_host("WIN-01", event_ids=["E-3"])

    store = resolve_entities([a, b, c])
    assert store.size == 1
    assert store.entities[0].source_event_ids == ["E-1", "E-2", "E-3"]
