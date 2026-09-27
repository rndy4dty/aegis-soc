"""
Contract tests untuk RelationshipResolver.

Menguji:
- merge relationship dengan fingerprint sama
- union provenance, min/max temporal
- weight/confidence combine via on_strength
- dedup by fingerprint
- store lookup: get, by_type, by_source, by_target, between
- determinisme urutan
- edge case: empty, single, non-Relationship input
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.graph.relationship_resolver import (
    RelationshipResolver,
    RelationshipStore,
    resolve_relationships,
)
from pkg.models.relationship import (
    NodeType,
    Relationship,
    RelationshipType,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_rel(
    *,
    source_id: str = "P-1000",
    target_id: str = "P-2000",
    rel_type: RelationshipType = RelationshipType.SPAWNED,
    weight: float = 1.0,
    confidence: float = 1.0,
    event_ids: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    first_seen: datetime | None = None,
    last_seen: datetime | None = None,
    tags: list[str] | None = None,
    properties: dict | None = None,
) -> Relationship:
    return Relationship(
        source_type=NodeType.ENTITY,
        source_id=source_id,
        target_type=NodeType.ENTITY,
        target_id=target_id,
        relationship_type=rel_type,
        weight=weight,
        confidence=confidence,
        source_event_ids=event_ids or [],
        source_evidence_ids=evidence_ids or [],
        first_seen=first_seen,
        last_seen=last_seen,
        tags=tags or [],
        properties=properties or {},
    ).with_fingerprint()


# ===========================================================================
# Empty & trivial
# ===========================================================================

def test_empty_resolution():
    store = resolve_relationships([])
    assert store.is_empty
    assert store.size == 0
    assert store.relationships == ()


def test_single_relationship_preserved():
    r = make_rel(event_ids=["E-1"])
    store = resolve_relationships([r])

    assert store.size == 1
    resolved = store.get(r.fingerprint)
    assert resolved is not None
    assert resolved.source_event_ids == ["E-1"]


# ===========================================================================
# Merge by fingerprint
# ===========================================================================

def test_merge_identical_relationships():
    a = make_rel(event_ids=["E-1"])
    b = make_rel(event_ids=["E-2"])

    store = resolve_relationships([a, b])

    assert store.size == 1
    merged = store.relationships[0]
    assert merged.source_event_ids == ["E-1", "E-2"]


def test_merge_dedup_event_ids():
    a = make_rel(event_ids=["E-1", "E-2"])
    b = make_rel(event_ids=["E-2", "E-3"])

    store = resolve_relationships([a, b])
    assert store.size == 1
    assert store.relationships[0].source_event_ids == [
        "E-1", "E-2", "E-3"
    ]


def test_different_source_not_merged():
    a = make_rel(source_id="A")
    b = make_rel(source_id="B")

    store = resolve_relationships([a, b])
    assert store.size == 2


def test_different_target_not_merged():
    a = make_rel(target_id="A")
    b = make_rel(target_id="B")

    store = resolve_relationships([a, b])
    assert store.size == 2


def test_different_type_not_merged():
    a = make_rel(
        source_id="X", target_id="Y",
        rel_type=RelationshipType.SPAWNED,
    )
    b = make_rel(
        source_id="X", target_id="Y",
        rel_type=RelationshipType.RUN_AS,
    )

    store = resolve_relationships([a, b])
    assert store.size == 2


# ===========================================================================
# Temporal merge
# ===========================================================================

def test_merge_temporal_min_max():
    a = make_rel(
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=5),
    )
    b = make_rel(
        first_seen=BASE - timedelta(minutes=10),
        last_seen=BASE + timedelta(minutes=30),
    )

    store = resolve_relationships([a, b])
    merged = store.relationships[0]
    assert merged.first_seen == BASE - timedelta(minutes=10)
    assert merged.last_seen == BASE + timedelta(minutes=30)


# ===========================================================================
# Weight & confidence merge
# ===========================================================================

def test_merge_weight_max_by_default():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)

    store = resolve_relationships([a, b])
    assert store.relationships[0].weight == 0.7


def test_merge_confidence_max_by_default():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)

    store = resolve_relationships([a, b])
    assert store.relationships[0].confidence == 0.7


def test_merge_weight_avg():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)

    store = resolve_relationships([a, b], on_strength="avg")
    assert abs(store.relationships[0].weight - 0.5) < 1e-9


def test_merge_confidence_left():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)

    store = resolve_relationships([a, b], on_strength="left")
    assert store.relationships[0].confidence == 0.3


def test_resolver_rejects_invalid_on_strength():
    with pytest.raises(ValueError, match="on_strength"):
        RelationshipResolver(on_strength="min")


def test_resolver_rejects_invalid_property_conflict():
    with pytest.raises(ValueError, match="on_property_conflict"):
        RelationshipResolver(on_property_conflict="whatever")


# ===========================================================================
# Properties & tags merge
# ===========================================================================

def test_merge_properties():
    a = make_rel(properties={"protocol": "TCP", "port": 443})
    b = make_rel(properties={"protocol": "TCP", "bytes": 1024})

    store = resolve_relationships([a, b])
    merged = store.relationships[0]
    assert merged.properties["protocol"] == "TCP"
    assert merged.properties["port"] == 443
    assert merged.properties["bytes"] == 1024


def test_merge_tags_union():
    a = make_rel(tags=["c2"])
    b = make_rel(tags=["suspicious", "c2"])

    store = resolve_relationships([a, b])
    merged = store.relationships[0]
    assert merged.tags == ["c2", "suspicious"]


# ===========================================================================
# Fingerprint auto-fill
# ===========================================================================

def test_relationship_without_fingerprint_gets_filled():
    r = Relationship(
        source_type=NodeType.ENTITY,
        source_id="A",
        target_type=NodeType.ENTITY,
        target_id="B",
        relationship_type=RelationshipType.SPAWNED,
    )
    assert r.fingerprint is None

    store = resolve_relationships([r])
    assert store.size == 1
    assert store.relationships[0].fingerprint is not None


# ===========================================================================
# Store lookup
# ===========================================================================

def test_store_get_by_fingerprint():
    r = make_rel()
    store = resolve_relationships([r])
    found = store.get(r.fingerprint)
    assert found is not None
    assert found.source_id == "P-1000"


def test_store_get_missing_returns_none():
    store = resolve_relationships([make_rel()])
    assert store.get("nonexistent") is None


def test_store_by_type():
    rels = [
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.SPAWNED),
        make_rel(source_id="C", target_id="D",
                 rel_type=RelationshipType.SPAWNED),
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.RUN_AS),
    ]
    store = resolve_relationships(rels)

    spawned = store.by_type(RelationshipType.SPAWNED)
    run_as = store.by_type(RelationshipType.RUN_AS)
    assert len(spawned) == 2
    assert len(run_as) == 1


def test_store_by_source():
    rels = [
        make_rel(source_id="A", target_id="B"),
        make_rel(source_id="A", target_id="C"),
        make_rel(source_id="X", target_id="Y"),
    ]
    store = resolve_relationships(rels)

    from_a = store.by_source("A")
    assert len(from_a) == 2


def test_store_by_target():
    rels = [
        make_rel(source_id="A", target_id="B"),
        make_rel(source_id="C", target_id="B"),
    ]
    store = resolve_relationships(rels)

    to_b = store.by_target("B")
    assert len(to_b) == 2


def test_store_between():
    rels = [
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.SPAWNED),
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.RUN_AS),
        make_rel(source_id="A", target_id="C",
                 rel_type=RelationshipType.SPAWNED),
    ]
    store = resolve_relationships(rels)

    between_ab = store.between("A", "B")
    assert len(between_ab) == 2

    between_ac = store.between("A", "C")
    assert len(between_ac) == 1

    between_ax = store.between("A", "X")
    assert between_ax == []


# ===========================================================================
# Aggregation
# ===========================================================================

def test_type_counts():
    rels = [
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.SPAWNED),
        make_rel(source_id="C", target_id="D",
                 rel_type=RelationshipType.SPAWNED),
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.HAS_HASH),
    ]
    store = resolve_relationships(rels)

    counts = store.type_counts()
    assert counts[RelationshipType.SPAWNED] == 2
    assert counts[RelationshipType.HAS_HASH] == 1


def test_types_sorted():
    rels = [
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.RUN_AS),
        make_rel(source_id="X", target_id="Y",
                 rel_type=RelationshipType.SPAWNED),
    ]
    store = resolve_relationships(rels)

    types = store.types()
    # Urut by enum value (alphabetic)
    assert types == sorted(types, key=lambda t: t.value)


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_order():
    rels = [
        make_rel(source_id="Z", target_id="A"),
        make_rel(source_id="A", target_id="Z"),
        make_rel(source_id="M", target_id="N"),
    ]
    s1 = resolve_relationships(rels)
    s2 = resolve_relationships(list(reversed(rels)))

    fps1 = [r.fingerprint for r in s1]
    fps2 = [r.fingerprint for r in s2]
    assert fps1 == fps2


def test_type_ordering():
    rels = [
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.RUN_AS),
        make_rel(source_id="A", target_id="B",
                 rel_type=RelationshipType.SPAWNED),
    ]
    store = resolve_relationships(rels)
    types = [r.relationship_type for r in store]
    # SPAWNED sebelum RUN_AS (alphabetic: "run_as" < "spawned" -> sebaliknya)
    # Cek berdasarkan nilai string:
    assert types == sorted(types, key=lambda t: t.value)


# ===========================================================================
# resolve_many
# ===========================================================================

def test_resolve_many():
    list1 = [make_rel(event_ids=["E-1"])]
    list2 = [make_rel(event_ids=["E-2"])]

    store = RelationshipResolver().resolve_many([list1, list2])

    assert store.size == 1
    assert store.relationships[0].source_event_ids == ["E-1", "E-2"]


# ===========================================================================
# Store contains & iteration
# ===========================================================================

def test_store_contains():
    r = make_rel()
    store = resolve_relationships([r])
    assert r in store


def test_store_contains_unfingerprinted_returns_false():
    r = Relationship(
        source_type=NodeType.ENTITY,
        source_id="X",
        target_type=NodeType.ENTITY,
        target_id="Y",
        relationship_type=RelationshipType.SPAWNED,
    )
    store = resolve_relationships([make_rel()])
    assert r not in store


def test_store_iteration_and_indexing():
    store = resolve_relationships([
        make_rel(source_id="A", target_id="B"),
        make_rel(source_id="C", target_id="D"),
    ])
    assert len(store) == 2
    assert store[0].source_type == NodeType.ENTITY


def test_store_to_dicts():
    store = resolve_relationships([make_rel()])
    dicts = store.to_dicts()
    assert len(dicts) == 1
    assert dicts[0]["type"] == "Relationship"
    assert dicts[0]["source"] == "P-1000"


def test_store_to_list():
    store = resolve_relationships([make_rel()])
    lst = store.to_list()
    assert isinstance(lst, list)
    assert len(lst) == 1


# ===========================================================================
# Edge cases
# ===========================================================================

def test_resolver_ignores_non_relationship():
    store = resolve_relationships([
        make_rel(),
        "not-a-relationship",  # type: ignore[list-item]
        None,                   # type: ignore[list-item]
    ])
    assert store.size == 1


def test_resolver_is_reusable():
    r = RelationshipResolver()
    a = make_rel(source_id="A", target_id="B")
    b = make_rel(source_id="C", target_id="D")

    store1 = r.resolve([a])
    store2 = r.resolve([b])

    assert store1.size == 1
    assert store2.size == 1
    assert store1.relationships[0].source_id == "A"
    assert store2.relationships[0].source_id == "C"


def test_merge_three_relationships():
    a = make_rel(event_ids=["E-1"])
    b = make_rel(event_ids=["E-2"])
    c = make_rel(event_ids=["E-3"])

    store = resolve_relationships([a, b, c])
    assert store.size == 1
    assert store.relationships[0].source_event_ids == [
        "E-1", "E-2", "E-3"
    ]


def test_merge_evidence_ids():
    a = make_rel(evidence_ids=["EV-1"])
    b = make_rel(evidence_ids=["EV-2"])
    store = resolve_relationships([a, b])
    assert store.size == 1
    assert store.relationships[0].source_evidence_ids == ["EV-1", "EV-2"]
