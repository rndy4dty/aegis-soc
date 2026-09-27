"""
Contract tests for Relationship model.

Menguji:
- construction & validation
- category & inverse helpers
- fingerprint identity
- reverse() dengan inverse eksplisit
- touch() temporal
- merge() weight & confidence via on_strength
- provenance helpers
- graph adapter
"""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pkg.models.relationship import (
    DEFAULT_CONFIDENCE,
    DEFAULT_WEIGHT,
    INVERSE_RELATIONSHIP,
    RELATIONSHIP_CATEGORY,
    SYMMETRIC_RELATIONSHIPS,
    NodeType,
    Relationship,
    RelationshipType,
    category_of,
    inverse_of,
    is_symmetric,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_rel(
    *,
    source_type: NodeType = NodeType.ENTITY,
    source_id: str = "P-1000",
    target_type: NodeType = NodeType.ENTITY,
    target_id: str = "P-2000",
    relationship_type: RelationshipType = RelationshipType.SPAWNED,
    **kwargs,
) -> Relationship:
    return Relationship(
        source_type=source_type,
        source_id=source_id,
        target_type=target_type,
        target_id=target_id,
        relationship_type=relationship_type,
        **kwargs,
    )


# ===========================================================================
# Construction & validation
# ===========================================================================

def test_minimal_relationship():
    r = make_rel()
    assert r.source_id == "P-1000"
    assert r.target_id == "P-2000"
    assert r.relationship_type == RelationshipType.SPAWNED
    assert r.weight == DEFAULT_WEIGHT
    assert r.confidence == DEFAULT_CONFIDENCE
    assert r.fingerprint is None


def test_self_loop_rejected():
    with pytest.raises(ValidationError, match="self-loop"):
        Relationship(
            source_type=NodeType.ENTITY,
            source_id="X",
            target_type=NodeType.ENTITY,
            target_id="X",
            relationship_type=RelationshipType.SPAWNED,
        )


def test_same_id_different_types_allowed():
    r = Relationship(
        source_type=NodeType.ENTITY,
        source_id="X",
        target_type=NodeType.EVENT,
        target_id="X",
        relationship_type=RelationshipType.OBSERVED_IN,
    )
    assert r.source_id == "X"
    assert r.target_id == "X"


def test_empty_node_id_rejected():
    with pytest.raises(ValidationError):
        Relationship(
            source_type=NodeType.ENTITY,
            source_id="   ",
            target_type=NodeType.ENTITY,
            target_id="Y",
            relationship_type=RelationshipType.SPAWNED,
        )


def test_weight_out_of_range_rejected():
    with pytest.raises(ValidationError):
        make_rel(weight=1.5)
    with pytest.raises(ValidationError):
        make_rel(weight=-0.1)


def test_confidence_out_of_range_rejected():
    with pytest.raises(ValidationError):
        make_rel(confidence=1.5)
    with pytest.raises(ValidationError):
        make_rel(confidence=-0.1)


def test_temporal_consistency():
    with pytest.raises(ValidationError):
        make_rel(
            first_seen=BASE + timedelta(hours=1),
            last_seen=BASE,
        )


def test_timestamps_normalized_to_utc():
    naive = datetime(2026, 9, 26, 10, 0)
    r = make_rel(first_seen=naive)
    assert r.first_seen.tzinfo == timezone.utc


def test_source_ids_sorted_deduped():
    r = make_rel(
        source_event_ids=["E-2", "E-1", "E-1"],
        source_evidence_ids=["EV-2", "EV-1"],
    )
    assert r.source_event_ids == ["E-1", "E-2"]
    assert r.source_evidence_ids == ["EV-1", "EV-2"]


def test_tags_sorted_deduped():
    r = make_rel(tags=["Critical", "critical", "soc"])
    assert r.tags == ["critical", "soc"]


# ===========================================================================
# Category & inverse
# ===========================================================================

def test_every_relationship_type_has_category():
    for rt in RelationshipType:
        assert rt in RELATIONSHIP_CATEGORY, rt


def test_category_of():
    assert category_of(RelationshipType.SPAWNED) == "process"
    assert category_of(RelationshipType.OBSERVED_IN) == "investigation"
    assert category_of(RelationshipType.HAS_HASH) == "file"
    assert category_of(RelationshipType.CONNECTED_TO) == "network"
    assert category_of(RelationshipType.RUN_AS) == "identity"
    assert category_of(RelationshipType.PARENT_OF) == "structure"


def test_inverse_map_is_bidirectional():
    for src, dst in INVERSE_RELATIONSHIP.items():
        assert INVERSE_RELATIONSHIP.get(dst) == src, (
            f"{src.value} -> {dst.value} not bidirectional"
        )


def test_inverse_of_parent_child():
    assert inverse_of(RelationshipType.PARENT_OF) == RelationshipType.CHILD_OF
    assert inverse_of(RelationshipType.CHILD_OF) == RelationshipType.PARENT_OF


def test_inverse_of_contains_part_of():
    assert inverse_of(RelationshipType.CONTAINS) == RelationshipType.PART_OF
    assert inverse_of(RelationshipType.PART_OF) == RelationshipType.CONTAINS


def test_inverse_of_symmetric():
    assert inverse_of(RelationshipType.CONNECTED_TO) == RelationshipType.CONNECTED_TO
    assert inverse_of(RelationshipType.MATCHES_HASH) == RelationshipType.MATCHES_HASH
    assert inverse_of(RelationshipType.CONTRADICTS) == RelationshipType.CONTRADICTS


def test_inverse_of_unknown():
    assert inverse_of(RelationshipType.SPAWNED) is None
    assert inverse_of(RelationshipType.EXECUTED) is None
    assert inverse_of(RelationshipType.HAS_HASH) is None


def test_symmetric_set():
    assert RelationshipType.CONNECTED_TO in SYMMETRIC_RELATIONSHIPS
    assert RelationshipType.MATCHES_HASH in SYMMETRIC_RELATIONSHIPS
    assert RelationshipType.CONTRADICTS in SYMMETRIC_RELATIONSHIPS
    assert RelationshipType.PARENT_OF not in SYMMETRIC_RELATIONSHIPS


def test_is_symmetric_helper():
    assert is_symmetric(RelationshipType.CONNECTED_TO) is True
    assert is_symmetric(RelationshipType.PARENT_OF) is False


def test_relationship_category_property():
    r = make_rel(relationship_type=RelationshipType.SPAWNED)
    assert r.category == "process"


def test_relationship_is_symmetric_property():
    r = make_rel(relationship_type=RelationshipType.CONNECTED_TO)
    assert r.is_symmetric is True

    r2 = make_rel(relationship_type=RelationshipType.SPAWNED)
    assert r2.is_symmetric is False


# ===========================================================================
# Fingerprint
# ===========================================================================

def test_fingerprint_deterministic():
    a = make_rel()
    b = make_rel()
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_changes_with_source_id():
    a = make_rel(source_id="X")
    b = make_rel(source_id="Y")
    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_fingerprint_changes_with_relationship_type():
    a = make_rel(relationship_type=RelationshipType.SPAWNED)
    b = make_rel(relationship_type=RelationshipType.EXECUTED)
    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_fingerprint_ignores_weight():
    a = make_rel(weight=0.1)
    b = make_rel(weight=0.9)
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_ignores_confidence():
    a = make_rel(confidence=0.1)
    b = make_rel(confidence=0.9)
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_ignores_properties():
    a = make_rel(properties={"a": 1})
    b = make_rel(properties={"b": 2})
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_ignores_provenance():
    a = make_rel(source_event_ids=["E-1"])
    b = make_rel(source_event_ids=["E-2"])
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_with_and_verify_fingerprint():
    r = make_rel().with_fingerprint()
    assert r.fingerprint is not None
    assert r.verify_fingerprint()


def test_verify_without_fingerprint():
    r = make_rel()
    assert r.verify_fingerprint() is False


def test_verify_detects_identity_change():
    r = make_rel().with_fingerprint()
    tampered = r.model_copy(update={"source_id": "OTHER"})
    assert not tampered.verify_fingerprint()


# ===========================================================================
# Identity comparison
# ===========================================================================

def test_same_identity():
    a = make_rel()
    b = make_rel()
    assert a.same_identity(b)


def test_different_identity():
    a = make_rel(source_id="X")
    b = make_rel(source_id="Y")
    assert not a.same_identity(b)


def test_same_identity_with_non_relationship():
    a = make_rel()
    assert not a.same_identity("not a relationship")


# ===========================================================================
# reverse
# ===========================================================================

def test_can_reverse_true_for_inverse_defined():
    r = make_rel(relationship_type=RelationshipType.PARENT_OF)
    assert r.can_reverse() is True


def test_can_reverse_false_for_no_inverse():
    r = make_rel(relationship_type=RelationshipType.EXECUTED)
    assert r.can_reverse() is False


def test_reverse_swaps_endpoints():
    r = make_rel(
        source_type=NodeType.ENTITY,
        source_id="A",
        target_type=NodeType.ENTITY,
        target_id="B",
        relationship_type=RelationshipType.PARENT_OF,
    )
    rev = r.reverse()

    assert rev.source_id == "B"
    assert rev.target_id == "A"
    assert rev.source_type == NodeType.ENTITY
    assert rev.target_type == NodeType.ENTITY


def test_reverse_uses_inverse_type_parent_child():
    r = make_rel(relationship_type=RelationshipType.PARENT_OF)
    rev = r.reverse()
    assert rev.relationship_type == RelationshipType.CHILD_OF


def test_reverse_uses_inverse_type_contains_part_of():
    r = make_rel(relationship_type=RelationshipType.CONTAINS)
    rev = r.reverse()
    assert rev.relationship_type == RelationshipType.PART_OF


def test_reverse_symmetric_keeps_type():
    r = make_rel(relationship_type=RelationshipType.CONNECTED_TO)
    rev = r.reverse()
    assert rev.relationship_type == RelationshipType.CONNECTED_TO


def test_reverse_raises_for_no_inverse():
    r = make_rel(relationship_type=RelationshipType.EXECUTED)
    with pytest.raises(ValueError, match="has no defined inverse"):
        r.reverse()


def test_reverse_raises_for_spawned():
    r = make_rel(relationship_type=RelationshipType.SPAWNED)
    with pytest.raises(ValueError, match="has no defined inverse"):
        r.reverse()


def test_reverse_has_new_id_and_fingerprint():
    r = make_rel(
        relationship_type=RelationshipType.PARENT_OF
    ).with_fingerprint()
    rev = r.reverse()
    assert rev.relationship_id != r.relationship_id
    assert rev.fingerprint != r.fingerprint


# ===========================================================================
# touch
# ===========================================================================

def test_touch_extends_temporal():
    r = make_rel(first_seen=BASE, last_seen=BASE)
    r2 = r.touch(BASE - timedelta(minutes=5))
    assert r2.first_seen == BASE - timedelta(minutes=5)
    assert r2.last_seen == BASE

    r3 = r.touch(BASE + timedelta(hours=1))
    assert r3.first_seen == BASE
    assert r3.last_seen == BASE + timedelta(hours=1)


def test_touch_from_empty():
    r = make_rel()
    r2 = r.touch(BASE)
    assert r2.first_seen == BASE
    assert r2.last_seen == BASE


# ===========================================================================
# merge — provenance & temporal
# ===========================================================================

def test_merge_unions_provenance_and_time():
    a = make_rel(
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=5),
        source_event_ids=["E-1"],
        source_evidence_ids=["EV-1"],
        tags=["soc"],
    )
    b = make_rel(
        first_seen=BASE - timedelta(minutes=10),
        last_seen=BASE + timedelta(minutes=30),
        source_event_ids=["E-2"],
        source_evidence_ids=["EV-2"],
        tags=["critical"],
    )

    merged = a.merge(b)

    assert merged.first_seen == BASE - timedelta(minutes=10)
    assert merged.last_seen == BASE + timedelta(minutes=30)
    assert merged.source_event_ids == ["E-1", "E-2"]
    assert merged.source_evidence_ids == ["EV-1", "EV-2"]
    assert merged.tags == ["critical", "soc"]


# ===========================================================================
# merge — weight
# ===========================================================================

def test_merge_weight_max_by_default():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)
    merged = a.merge(b)
    assert merged.weight == 0.7


def test_merge_weight_avg():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)
    merged = a.merge(b, on_strength="avg")
    assert abs(merged.weight - 0.5) < 1e-9


def test_merge_weight_left():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)
    merged = a.merge(b, on_strength="left")
    assert merged.weight == 0.3


def test_merge_weight_right():
    a = make_rel(weight=0.3)
    b = make_rel(weight=0.7)
    merged = a.merge(b, on_strength="right")
    assert merged.weight == 0.7


# ===========================================================================
# merge — confidence (sama policy dengan weight via on_strength)
# ===========================================================================

def test_merge_confidence_max_by_default():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)
    merged = a.merge(b)
    assert merged.confidence == 0.7


def test_merge_confidence_avg():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)
    merged = a.merge(b, on_strength="avg")
    assert abs(merged.confidence - 0.5) < 1e-9


def test_merge_confidence_left():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)
    merged = a.merge(b, on_strength="left")
    assert merged.confidence == 0.3


def test_merge_confidence_right():
    a = make_rel(confidence=0.3)
    b = make_rel(confidence=0.7)
    merged = a.merge(b, on_strength="right")
    assert merged.confidence == 0.7


def test_merge_weight_and_confidence_independent_values():
    """
    weight dan confidence field berbeda, tapi dikombinasikan
    dengan policy yang sama.
    """
    a = make_rel(weight=0.2, confidence=0.9)
    b = make_rel(weight=0.8, confidence=0.1)
    merged = a.merge(b)
    assert merged.weight == 0.8          # max
    assert merged.confidence == 0.9      # max


def test_merge_weight_and_confidence_avg_both():
    a = make_rel(weight=0.2, confidence=0.9)
    b = make_rel(weight=0.8, confidence=0.1)
    merged = a.merge(b, on_strength="avg")
    assert abs(merged.weight - 0.5) < 1e-9
    assert abs(merged.confidence - 0.5) < 1e-9


# ===========================================================================
# merge — fingerprint & identity
# ===========================================================================

def test_merge_fingerprint_recomputed():
    a = make_rel().with_fingerprint()
    b = make_rel()
    merged = a.merge(b)
    assert merged.fingerprint == merged.calculate_fingerprint()
    assert merged.verify_fingerprint()


def test_merge_rejects_different_identity():
    a = make_rel(source_id="X")
    b = make_rel(source_id="Y")
    with pytest.raises(ValueError, match="different fingerprint"):
        a.merge(b)


# ===========================================================================
# merge — properties
# ===========================================================================

def test_merge_properties_left_wins_default():
    a = make_rel(properties={"k": "a", "keep": 1})
    b = make_rel(properties={"k": "b", "new": 2})
    merged = a.merge(b)
    assert merged.properties["k"] == "a"
    assert merged.properties["keep"] == 1
    assert merged.properties["new"] == 2


def test_merge_properties_right_wins():
    a = make_rel(properties={"k": "a"})
    b = make_rel(properties={"k": "b"})
    merged = a.merge(b, on_property_conflict="right")
    assert merged.properties["k"] == "b"


def test_merge_properties_raise_on_conflict():
    a = make_rel(properties={"k": "a"})
    b = make_rel(properties={"k": "b"})
    with pytest.raises(ValueError, match="property conflict"):
        a.merge(b, on_property_conflict="raise")


# ===========================================================================
# merge — metadata
# ===========================================================================

def test_merge_metadata_left_wins_default():
    a = make_rel(metadata={"k": "a", "keep": 1})
    b = make_rel(metadata={"k": "b", "new": 2})
    merged = a.merge(b)
    assert merged.metadata["k"] == "a"
    assert merged.metadata["keep"] == 1
    assert merged.metadata["new"] == 2


def test_merge_metadata_right_wins():
    a = make_rel(metadata={"k": "a"})
    b = make_rel(metadata={"k": "b"})
    merged = a.merge(b, on_metadata_conflict="right")
    assert merged.metadata["k"] == "b"


def test_merge_metadata_raise_on_conflict():
    a = make_rel(metadata={"k": "a"})
    b = make_rel(metadata={"k": "b"})
    with pytest.raises(ValueError, match="metadata conflict"):
        a.merge(b, on_metadata_conflict="raise")


def test_merge_property_and_metadata_independent_policies():
    a = make_rel(
        properties={"k": "prop_a"},
        metadata={"k": "meta_a"},
    )
    b = make_rel(
        properties={"k": "prop_b"},
        metadata={"k": "meta_b"},
    )
    merged = a.merge(
        b,
        on_property_conflict="right",
        on_metadata_conflict="left",
    )
    assert merged.properties["k"] == "prop_b"
    assert merged.metadata["k"] == "meta_a"


# ===========================================================================
# Provenance helpers
# ===========================================================================

def test_add_event_trims():
    r = make_rel()
    r = r.add_event("  E-1  ").add_event("E-1").add_event("E-2")
    assert r.source_event_ids == ["E-1", "E-2"]


def test_add_event_ignores_invalid():
    r = make_rel()
    r = r.add_event(123).add_event("").add_event(None)
    assert r.source_event_ids == []


def test_add_evidence_trims():
    r = make_rel()
    r = r.add_evidence("  EV-1  ")
    assert r.source_evidence_ids == ["EV-1"]


def test_add_evidence_ignores_invalid():
    r = make_rel()
    r = r.add_evidence(None).add_evidence("   ")
    assert r.source_evidence_ids == []


def test_add_tag():
    r = make_rel()
    r = r.add_tag("Critical").add_tag("critical").add_tag("  ")
    assert r.tags == ["critical"]


def test_add_tag_ignores_invalid():
    r = make_rel()
    r = r.add_tag(None).add_tag(123).add_tag("")
    assert r.tags == []


# ===========================================================================
# Graph adapter
# ===========================================================================

def test_to_graph_edge():
    r = make_rel(
        source_type=NodeType.ENTITY,
        source_id="P-1",
        target_type=NodeType.ENTITY,
        target_id="P-2",
        relationship_type=RelationshipType.SPAWNED,
        weight=0.8,
        confidence=0.9,
    ).with_fingerprint()

    edge = r.to_graph_edge()
    assert edge["type"] == "Relationship"
    assert edge["source"] == "P-1"
    assert edge["target"] == "P-2"
    assert edge["relationship_type"] == "spawned"
    assert edge["category"] == "process"
    assert edge["is_symmetric"] is False
    assert edge["weight"] == 0.8
    assert edge["confidence"] == 0.9
    assert edge["fingerprint"] == r.fingerprint


def test_to_graph_edge_symmetric():
    r = make_rel(relationship_type=RelationshipType.CONNECTED_TO)
    edge = r.to_graph_edge()
    assert edge["is_symmetric"] is True
    assert edge["category"] == "network"
