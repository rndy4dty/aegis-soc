from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from pkg.models.entity import (
    ALWAYS_HOST_SCOPED,
    GLOBAL_ENTITY_TYPES,
    OCCURRENCE_IDENTITY_TYPES,
    SUBSTANTIVE_ENTITY_TYPES,
    Entity,
    EntityType,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_hash(
    value: str = "deadbeef",
    *,
    algorithm: str = "sha256",
    **kwargs,
) -> Entity:
    return Entity(
        entity_type=EntityType.HASH,
        value=value,
        normalized_value=value.lower(),
        hash_algorithm=algorithm,
        **kwargs,
    )


def make_local_user(
    value: str = "Administrator",
    *,
    host: str | None = "WIN-01",
    **kwargs,
) -> Entity:
    return Entity(
        entity_type=EntityType.USER,
        value=value,
        normalized_value=value.lower(),
        identity_scope="local",
        host=host,
        **kwargs,
    )


def make_domain_user(
    value: str = "ren",
    *,
    domain: str = "CORP",
    **kwargs,
) -> Entity:
    return Entity(
        entity_type=EntityType.USER,
        value=value,
        normalized_value=value.lower(),
        identity_scope="domain",
        identity_domain=domain,
        **kwargs,
    )


# ===========================================================================
# 1. Identity classification
# ===========================================================================

def test_occurrence_and_substantive_are_disjoint():
    assert not (OCCURRENCE_IDENTITY_TYPES & SUBSTANTIVE_ENTITY_TYPES)


def test_occurrence_covers_event_alert_evidence():
    assert OCCURRENCE_IDENTITY_TYPES == {
        EntityType.EVENT,
        EntityType.ALERT,
        EntityType.EVIDENCE,
    }


def test_event_is_occurrence():
    e = Entity(entity_type=EntityType.EVENT, value="E-1")
    assert e.is_occurrence
    assert not e.is_substantive


def test_process_is_substantive():
    e = Entity(entity_type=EntityType.PROCESS, value="powershell.exe")
    assert e.is_substantive
    assert not e.is_occurrence


# ===========================================================================
# 2. Occurrence identity — value = record_id
# ===========================================================================

def test_event_fingerprint_uses_value_not_normalized_value():
    a = Entity(
        entity_type=EntityType.EVENT,
        value="E-1",
        normalized_value="shared",
        host="HOST-A",
    )
    b = Entity(
        entity_type=EntityType.EVENT,
        value="E-2",
        normalized_value="shared",
        host="HOST-A",
    )

    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_event_fingerprint_ignores_host():
    a = Entity(
        entity_type=EntityType.EVENT,
        value="E-1",
        host="HOST-A",
    )
    b = Entity(
        entity_type=EntityType.EVENT,
        value="E-1",
        host="HOST-B",
    )

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_alert_fingerprint_uses_value():
    a = Entity(
        entity_type=EntityType.ALERT,
        value="A-1",
    )
    b = Entity(
        entity_type=EntityType.ALERT,
        value="A-2",
    )

    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_evidence_fingerprint_uses_value():
    a = Entity(
        entity_type=EntityType.EVIDENCE,
        value="EV-1",
    )
    b = Entity(
        entity_type=EntityType.EVIDENCE,
        value="EV-1",
    )

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


# ===========================================================================
# 3. HOST self-identity
# ===========================================================================

def test_host_fingerprint_does_not_include_host_field():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        host="WIN-99",
    )
    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


# ===========================================================================
# 4. USER scope — explicit identity_scope
# ===========================================================================

def test_user_requires_identity_scope():
    with pytest.raises(ValidationError, match="identity_scope"):
        Entity(
            entity_type=EntityType.USER,
            value="Administrator",
        )


def test_user_rejects_invalid_identity_scope():
    with pytest.raises(ValidationError, match="identity_scope"):
        Entity(
            entity_type=EntityType.USER,
            value="Administrator",
            identity_scope="global",
        )


def test_local_user_requires_host():
    with pytest.raises(ValidationError, match="host"):
        make_local_user(host=None)


def test_local_user_is_host_scoped():
    a = make_local_user(host="HOST-A")
    b = make_local_user(host="HOST-B")

    assert a.is_host_scoped
    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_local_user_same_host_same_fingerprint():
    a = make_local_user(host="HOST-A")
    b = make_local_user(host="HOST-A")

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_domain_user_requires_identity_domain():
    with pytest.raises(ValidationError, match="identity_domain"):
        Entity(
            entity_type=EntityType.USER,
            value="ren",
            normalized_value="ren",
            identity_scope="domain",
        )


def test_domain_user_is_host_independent():
    a = make_domain_user(domain="CORP", host="HOST-A")
    b = make_domain_user(domain="CORP", host="HOST-B")

    assert not a.is_host_scoped
    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_domain_user_differs_across_domains():
    a = make_domain_user(domain="CORP")
    b = make_domain_user(domain="DMZ")

    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_identity_scope_normalized_lowercase():
    e = Entity(
        entity_type=EntityType.USER,
        value="ren",
        normalized_value="ren",
        identity_scope="DOMAIN",
        identity_domain="corp",
    )

    assert e.identity_scope == "domain"


def test_identity_domain_normalized_lowercase():
    e = Entity(
        entity_type=EntityType.USER,
        value="ren",
        normalized_value="ren",
        identity_scope="domain",
        identity_domain="CORP.LOCAL",
    )

    assert e.identity_domain == "corp.local"


# ===========================================================================
# 5. USER / HASH identity attribute exclusivity
# ===========================================================================

def test_user_rejects_hash_algorithm():
    with pytest.raises(ValidationError, match="hash_algorithm"):
        Entity(
            entity_type=EntityType.USER,
            value="ren",
            normalized_value="ren",
            identity_scope="local",
            host="HOST-A",
            hash_algorithm="sha256",
        )


def test_hash_rejects_identity_scope():
    with pytest.raises(ValidationError, match="identity_scope"):
        Entity(
            entity_type=EntityType.HASH,
            value="deadbeef",
            normalized_value="deadbeef",
            hash_algorithm="sha256",
            identity_scope="local",
        )


def test_hash_rejects_identity_domain():
    with pytest.raises(ValidationError, match="identity_domain"):
        Entity(
            entity_type=EntityType.HASH,
            value="deadbeef",
            normalized_value="deadbeef",
            hash_algorithm="sha256",
            identity_domain="CORP",
        )


def test_non_user_rejects_identity_scope():
    with pytest.raises(ValidationError, match="identity_scope"):
        Entity(
            entity_type=EntityType.FILE,
            value="test.exe",
            identity_scope="local",
        )


def test_non_user_rejects_identity_domain():
    with pytest.raises(ValidationError, match="identity_domain"):
        Entity(
            entity_type=EntityType.FILE,
            value="test.exe",
            identity_domain="CORP",
        )


def test_non_hash_rejects_hash_algorithm():
    with pytest.raises(ValidationError, match="hash_algorithm"):
        Entity(
            entity_type=EntityType.FILE,
            value="test.exe",
            hash_algorithm="sha256",
        )


# ===========================================================================
# 6. HASH requires hash_algorithm
# ===========================================================================

def test_hash_requires_hash_algorithm():
    with pytest.raises(ValidationError, match="hash_algorithm"):
        Entity(
            entity_type=EntityType.HASH,
            value="deadbeef",
        )


def test_hash_fingerprint_distinguishes_algorithm():
    a = make_hash("deadbeef", algorithm="md5")
    b = make_hash("deadbeef", algorithm="sha256")

    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_hash_fingerprint_same_algorithm():
    a = make_hash(
        "deadbeef",
        algorithm="sha256",
    )
    b = make_hash(
        "DEADBEEF",
        algorithm="SHA256",
    )

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_hash_algorithm_normalized_lowercase():
    e = Entity(
        entity_type=EntityType.HASH,
        value="deadbeef",
        normalized_value="deadbeef",
        hash_algorithm="SHA256",
    )

    assert e.hash_algorithm == "sha256"


# ===========================================================================
# 7. add_event / add_evidence normalisasi
# ===========================================================================

def test_add_event_trims_whitespace():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_event("  E-1  ")

    assert e.source_event_ids == ["E-1"]


def test_add_event_ignores_non_string():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_event(12345)  # type: ignore[arg-type]

    assert e.source_event_ids == []


def test_add_event_ignores_empty():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_event("   ")

    assert e.source_event_ids == []


def test_add_evidence_trims_whitespace():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_evidence("  EV-1  ")

    assert e.source_evidence_ids == ["EV-1"]


def test_add_evidence_ignores_non_string():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_evidence(None)  # type: ignore[arg-type]

    assert e.source_evidence_ids == []


def test_add_event_dedupes():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e = e.add_event("E-1")
    e = e.add_event(" E-1 ")
    e = e.add_event("E-2")

    assert e.source_event_ids == ["E-1", "E-2"]


# ===========================================================================
# 8. same_identity
# ===========================================================================

def test_same_identity_returns_true_for_same_entity():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )
    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    assert a.same_identity(b)


def test_same_identity_returns_false_for_different_entity():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )
    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-02",
        normalized_value="win-02",
    )

    assert not a.same_identity(b)


def test_same_identity_rejects_non_entity():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    assert e.same_identity(None) is False
    assert e.same_identity("WIN-01") is False
    assert e.same_identity(123) is False


# ===========================================================================
# 9. verify_fingerprint = identity only
# ===========================================================================

def test_verify_fingerprint_is_identity_only():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        properties={"os": "Windows 11"},
    ).with_fingerprint()

    assert e.verify_fingerprint()

    e2 = e.model_copy(
        update={
            "properties": {
                "os": "Windows 10",
                "cpu": "Intel",
            },
        }
    )

    assert e2.verify_fingerprint()


def test_verify_fingerprint_detects_identity_change():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    ).with_fingerprint()

    e2 = e.model_copy(
        update={
            "normalized_value": "win-99",
        }
    )

    assert not e2.verify_fingerprint()


def test_verify_fingerprint_returns_false_without_fingerprint():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    assert e.verify_fingerprint() is False


# ===========================================================================
# 10. Fingerprint — substantive
# ===========================================================================

def test_fingerprint_deterministic():
    a = make_hash("deadbeef")
    b = make_hash("deadbeef")

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_uses_normalized_value():
    a = make_hash("DEADBEEF")
    b = make_hash("deadbeef")

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_fingerprint_global_ignores_host():
    a = make_hash(
        "deadbeef",
        host="HOST-A",
    )
    b = make_hash(
        "deadbeef",
        host="HOST-B",
    )

    assert a.calculate_fingerprint() == b.calculate_fingerprint()


def test_process_fingerprint_includes_host():
    a = Entity(
        entity_type=EntityType.PROCESS,
        value="svchost.exe",
        normalized_value="svchost.exe",
        host="HOST-A",
    )
    b = Entity(
        entity_type=EntityType.PROCESS,
        value="svchost.exe",
        normalized_value="svchost.exe",
        host="HOST-B",
    )

    assert a.calculate_fingerprint() != b.calculate_fingerprint()


def test_normalized_value_fallback_is_case_preserving():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    assert e.normalized_value == "WIN-01"


def test_normalized_value_respected_when_provided():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    assert e.normalized_value == "win-01"


def test_url_normalized_value_preserved():
    url = "https://Example.COM/Path?Token=AbC"

    e = Entity(
        entity_type=EntityType.URL,
        value=url,
        normalized_value=url,
    )

    assert e.normalized_value == url


# ===========================================================================
# 11. Validation
# ===========================================================================

def test_value_cannot_be_empty():
    with pytest.raises(ValidationError):
        Entity(
            entity_type=EntityType.HOST,
            value="   ",
        )


def test_source_ids_sorted_and_deduped():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        source_event_ids=[
            "E-2",
            "E-1",
            "E-1",
        ],
        source_evidence_ids=[
            "EV-2",
            "EV-1",
        ],
    )

    assert e.source_event_ids == ["E-1", "E-2"]
    assert e.source_evidence_ids == ["EV-1", "EV-2"]


def test_tags_sorted_and_deduped():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        tags=[
            "Critical",
            "critical",
            "soc",
        ],
    )

    assert e.tags == ["critical", "soc"]


def test_first_seen_cannot_be_after_last_seen():
    with pytest.raises(ValidationError):
        Entity(
            entity_type=EntityType.HOST,
            value="WIN-01",
            first_seen=BASE + timedelta(hours=1),
            last_seen=BASE,
        )


def test_timestamps_normalized_to_utc():
    naive = datetime(
        2026,
        9,
        26,
        10,
        0,
    )

    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        first_seen=naive,
    )

    assert e.first_seen.tzinfo == timezone.utc


# ===========================================================================
# 12. Counts
# ===========================================================================

def test_event_count_and_evidence_count():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        source_event_ids=[
            "E-1",
            "E-2",
        ],
        source_evidence_ids=[
            "EV-1",
        ],
    )

    assert e.event_count == 2
    assert e.evidence_count == 1
    assert e.observation_count == 3


# ===========================================================================
# 13. touch
# ===========================================================================

def test_touch_extends_first_and_last_seen():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        first_seen=BASE,
        last_seen=BASE,
    )

    e2 = e.touch(
        BASE - timedelta(minutes=5)
    )

    assert e2.first_seen == BASE - timedelta(minutes=5)
    assert e2.last_seen == BASE

    e3 = e.touch(
        BASE + timedelta(hours=1)
    )

    assert e3.first_seen == BASE
    assert e3.last_seen == BASE + timedelta(hours=1)


def test_touch_from_empty():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
    )

    e2 = e.touch(BASE)

    assert e2.first_seen == BASE
    assert e2.last_seen == BASE


# ===========================================================================
# 14. merge
# ===========================================================================

def test_merge_unions_provenance_and_time():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        first_seen=BASE,
        last_seen=BASE + timedelta(minutes=5),
        source_event_ids=["E-1"],
        source_evidence_ids=["EV-1"],
        tags=["soc"],
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
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


def test_merge_properties_lists_union():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        properties={
            "ip_addresses": ["10.0.0.1"],
            "os": "Windows 11",
        },
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        properties={
            "ip_addresses": ["10.0.0.2"],
            "os": "Windows 10",
        },
    )

    merged = a.merge(b)

    assert merged.properties["ip_addresses"] == [
        "10.0.0.1",
        "10.0.0.2",
    ]
    assert merged.properties["os"] == "Windows 10"


def test_merge_fingerprint_is_recomputed():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        fingerprint="stale-value-ignored",
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    a = a.model_copy(
        update={
            "fingerprint": b.calculate_fingerprint(),
        }
    )

    merged = a.merge(b)

    assert merged.fingerprint == merged.calculate_fingerprint()
    assert merged.verify_fingerprint()


def test_merge_metadata_left_wins_by_default():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "alice",
            "score": 80,
        },
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "bob",
            "note": "updated",
        },
    )

    merged = a.merge(b)

    assert merged.metadata["analyst"] == "alice"
    assert merged.metadata["note"] == "updated"
    assert merged.metadata["score"] == 80


def test_merge_metadata_right_wins():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "alice",
        },
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "bob",
        },
    )

    merged = a.merge(
        b,
        on_metadata_conflict="right",
    )

    assert merged.metadata["analyst"] == "bob"


def test_merge_metadata_raise_on_conflict():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "alice",
        },
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        metadata={
            "analyst": "bob",
        },
    )

    with pytest.raises(
        ValueError,
        match="metadata conflict",
    ):
        a.merge(
            b,
            on_metadata_conflict="raise",
        )


def test_merge_rejects_different_identity():
    a = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
    )

    b = Entity(
        entity_type=EntityType.HOST,
        value="WIN-02",
        normalized_value="win-02",
    )

    with pytest.raises(
        ValueError,
        match="different fingerprint",
    ):
        a.merge(b)


# ===========================================================================
# 15. Graph
# ===========================================================================

def test_graph_node_includes_identity_attributes():
    e = make_domain_user(
        domain="CORP",
    ).with_fingerprint()

    node = e.to_graph_node()

    assert node["type"] == "Entity"
    assert node["entity_type"] == "user"
    assert node["identity_scope"] == "domain"
    assert node["identity_domain"] == "corp"
    assert node["fingerprint"] == e.fingerprint


def test_graph_node_hash_includes_algorithm():
    e = make_hash(
        "deadbeef",
        algorithm="sha256",
    ).with_fingerprint()

    node = e.to_graph_node()

    assert node["hash_algorithm"] == "sha256"


def test_debug_relationships_are_marked_debug():
    e = Entity(
        entity_type=EntityType.HOST,
        value="WIN-01",
        normalized_value="win-01",
        source_event_ids=[
            "E-1",
            "E-2",
        ],
        source_evidence_ids=[
            "EV-1",
        ],
    )

    edges = e.debug_relationships()

    rels = [
        edge["relationship"]
        for edge in edges
    ]

    assert rels.count("OBSERVED_IN") == 2
    assert rels.count("CITED_BY") == 1
    assert all(
        edge["properties"].get("_debug")
        for edge in edges
    )

"""Regression test: entity_id harus deterministik dari fingerprint."""
from pkg.models.entity import Entity, EntityType


def _make() -> Entity:
    return Entity(
        entity_type=EntityType.PROCESS,
        value="sdbinst.exe",
        normalized_value="sdbinst.exe|pid:4821",
        host="win-01",
    ).with_fingerprint()


def test_entity_id_stable_across_instances():
    """Dua instance dengan identity sama → entity_id sama."""
    e1 = _make()
    e2 = _make()
    assert e1.fingerprint == e2.fingerprint
    assert e1.entity_id == e2.entity_id


def test_entity_id_differs_for_different_identity():
    """Identity beda → entity_id beda."""
    e1 = _make()
    e2 = Entity(
        entity_type=EntityType.PROCESS,
        value="powershell.exe",
        host="win-01",
    ).with_fingerprint()
    assert e1.fingerprint != e2.fingerprint
    assert e1.entity_id != e2.entity_id


def test_entity_id_is_uuid_format():
    """entity_id harus UUID valid (kompatibel Neo4j constraint)."""
    import uuid
    e = _make()
    uuid.UUID(e.entity_id)  # akan raise kalau invalid
