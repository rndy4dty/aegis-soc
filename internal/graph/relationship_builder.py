"""
Relationship builder for AegisSOC.

Tugas:
    (Event, list[Entity])  ->  list[Relationship]

Membangun relationship deterministik dari isi Event dan Entity yang
sudah diekstrak. Tidak melakukan inference di luar data, tidak
memanggil LLM, tidak melakukan correlation, tidak mengubah Event
atau Entity.

Relationship yang dibangun (v1):
    1. SPAWNED        : parent_process  -> child_process
    2. RUN_AS         : child_process   -> user
    3. HAS_HASH       : file            -> hash
    4. CONNECTED_TO   : child_process   -> destination_ip
                        (hanya kalau category ∈ {network, http})

Semua relationship:
    - source_event_ids = [event.event_id] (kalau ada)
    - first_seen = last_seen = event.timestamp
    - fingerprint diisi via Relationship.with_fingerprint()
    - deterministik (dedup by fingerprint, sort stabil)

Catatan:
- Builder mengasumsikan `entities` berasal dari Event yang sama.
- Kalau entity yang dibutuhkan tidak ada di list, relationship tidak
  dibangun. Ini mencegah false positive.
- Lookup entity by `normalized_value` — mengikuti kontrak extractor.
"""

from __future__ import annotations

from typing import Any

from internal.graph.entity_extractor import (
    IDENTITY_QUALITY_NAME_ONLY,
    PROPERTY_IDENTITY_QUALITY,
)
from pkg.models.entity import Entity, EntityType
from pkg.models.relationship import (
    NodeType,
    Relationship,
    RelationshipType,
)


# ===========================================================================
# Internal helpers
# ===========================================================================

def _attr(obj: Any, name: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


def _normalize_str(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _coerce_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    return None


def _process_normalized_value(
    name: str,
    guid: str | None,
    pid: int | None,
) -> str:
    """
    KEEP IN SYNC dengan EntityExtractor._process_identity.

    Identity Process = name + (guid | pid | nothing).
    """
    base = name.lower()
    if guid:
        return f"{base}|guid:{guid.lower()}"
    if pid is not None:
        return f"{base}|pid:{pid}"
    return base


# ===========================================================================
# Entity lookup helpers
# ===========================================================================

def _find_host(entities: list[Entity], host: str) -> Entity | None:
    target = host.lower()
    for e in entities:
        if e.entity_type == EntityType.HOST and e.normalized_value == target:
            return e
    return None


def _find_user(
    entities: list[Entity],
    user: str,
    *,
    host: str | None = None,
    domain: str | None = None,
) -> Entity | None:
    target = user.lower()
    for e in entities:
        if e.entity_type != EntityType.USER:
            continue
        if e.normalized_value != target:
            continue
        if domain is not None:
            if e.identity_domain != domain.lower():
                continue
        else:
            # Local user: match by host (kalau diberikan)
            if host is not None and e.host != host.lower():
                continue
        return e
    return None


def _find_process(
    entities: list[Entity],
    name: str,
    *,
    guid: str | None = None,
    pid: int | None = None,
) -> Entity | None:
    target = _process_normalized_value(name, guid, pid)
    for e in entities:
        if e.entity_type != EntityType.PROCESS:
            continue
        if e.normalized_value == target:
            return e
    return None


def _find_file(
    entities: list[Entity],
    file_value: str,
    *,
    is_windows: bool,
) -> Entity | None:
    target = file_value.lower() if is_windows else file_value
    for e in entities:
        if e.entity_type == EntityType.FILE and e.normalized_value == target:
            return e
    return None


def _find_hashes(entities: list[Entity]) -> list[Entity]:
    return sorted(
        (e for e in entities if e.entity_type == EntityType.HASH),
        key=lambda e: (e.hash_algorithm or "", e.normalized_value),
    )


def _find_ip(entities: list[Entity], ip: str) -> Entity | None:
    for e in entities:
        if e.entity_type == EntityType.IP and e.normalized_value == ip:
            return e
    return None


# ===========================================================================
# RelationshipBuilder
# ===========================================================================

class RelationshipBuilder:
    """
    Stateless builder: (Event, list[Entity]) -> list[Relationship].
    """

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def build(
        self,
        event: Any,
        entities: list[Entity],
    ) -> list[Relationship]:
        if not entities:
            return []

        event_id = _normalize_str(_attr(event, "event_id"))
        tenant_id = _attr(event, "tenant_id")
        event_ts = _attr(event, "timestamp")
        category = _enum_value(_attr(event, "category"))
        platform = _enum_value(_attr(event, "platform"))

        host_raw = _normalize_str(_attr(event, "host"))
        host = host_raw.lower() if host_raw else None
        is_windows = platform == "windows"

        # -- Extract event context ---------------------------------------
        process = _attr(event, "process")
        child_name = _normalize_str(_attr(process, "name"))
        child_pid = _coerce_int(_attr(process, "pid"))
        child_guid = _normalize_str(_attr(process, "guid"))
        parent_name = _normalize_str(_attr(process, "parent_name"))
        parent_pid = _coerce_int(_attr(process, "parent_pid"))
        parent_guid = _normalize_str(_attr(process, "parent_guid"))

        user_raw = _normalize_str(_attr(event, "user"))
        user_ctx = _attr(event, "user_context")
        user_domain = _normalize_str(_attr(user_ctx, "domain"))

        file_ctx = _attr(event, "file")
        file_path = _normalize_str(_attr(file_ctx, "path"))
        file_name = _normalize_str(_attr(file_ctx, "name"))

        network = _attr(event, "network")
        destination_ip = _normalize_str(_attr(network, "destination_ip"))

        # -- Lookup entities ---------------------------------------------
        child_entity: Entity | None = None
        parent_entity: Entity | None = None
        user_entity: Entity | None = None
        file_entity: Entity | None = None
        dest_ip_entity: Entity | None = None

        if child_name:
            child_entity = _find_process(
                entities, child_name,
                guid=child_guid, pid=child_pid,
            )
        if parent_name:
            parent_entity = _find_process(
                entities, parent_name,
                guid=parent_guid, pid=parent_pid,
            )
        if user_raw:
            user_entity = _find_user(
                entities, user_raw,
                host=host, domain=user_domain,
            )
        if file_path or file_name:
            file_value = file_path or file_name
            file_entity = _find_file(
                entities, file_value, is_windows=is_windows,
            )
        hash_entities = _find_hashes(entities)
        if destination_ip:
            dest_ip_entity = _find_ip(entities, destination_ip)

        # -- Build relationships -----------------------------------------
        relationships: list[Relationship] = []

        # 1. SPAWNED
        spawned = self._build_spawned(
            parent_entity=parent_entity,
            child_entity=child_entity,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        )
        if spawned is not None:
            relationships.append(spawned)

        # 2. RUN_AS
        run_as = self._build_run_as(
            child_entity=child_entity,
            user_entity=user_entity,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        )
        if run_as is not None:
            relationships.append(run_as)

        # 3. HAS_HASH
        relationships.extend(self._build_has_hashes(
            file_entity=file_entity,
            hash_entities=hash_entities,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        ))

        # 4. CONNECTED_TO
        connected = self._build_connected_to(
            child_entity=child_entity,
            dest_ip_entity=dest_ip_entity,
            category=category,
            tenant_id=tenant_id,
            event_id=event_id,
            event_ts=event_ts,
        )
        if connected is not None:
            relationships.append(connected)

        # -- Dedup + sort ------------------------------------------------
        deduped = self._deduplicate(relationships)
        return self._sort(deduped)

    # -------------------------------------------------------------------
    # Rule: SPAWNED
    # -------------------------------------------------------------------

    @staticmethod
    def _build_spawned(
        *,
        parent_entity: Entity | None,
        child_entity: Entity | None,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> Relationship | None:
        if parent_entity is None or child_entity is None:
            return None

        # Kalau lookup mengembalikan entity yang sama (mis. name_only
        # parent dan child yang tidak bisa dibedakan), jangan buat
        # relationship self-loop.
        if parent_entity.entity_id == child_entity.entity_id:
            return None

        return _make_relationship(
            tenant_id=tenant_id,
            source=parent_entity,
            target=child_entity,
            rel_type=RelationshipType.SPAWNED,
            event_id=event_id,
            event_ts=event_ts,
        )

    # -------------------------------------------------------------------
    # Rule: RUN_AS
    # -------------------------------------------------------------------

    @staticmethod
    def _build_run_as(
        *,
        child_entity: Entity | None,
        user_entity: Entity | None,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> Relationship | None:
        if child_entity is None or user_entity is None:
            return None

        return _make_relationship(
            tenant_id=tenant_id,
            source=child_entity,
            target=user_entity,
            rel_type=RelationshipType.RUN_AS,
            event_id=event_id,
            event_ts=event_ts,
        )

    # -------------------------------------------------------------------
    # Rule: HAS_HASH
    # -------------------------------------------------------------------

    @staticmethod
    def _build_has_hashes(
        *,
        file_entity: Entity | None,
        hash_entities: list[Entity],
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> list[Relationship]:
        if file_entity is None or not hash_entities:
            return []

        out: list[Relationship] = []
        for h in hash_entities:
            out.append(_make_relationship(
                tenant_id=tenant_id,
                source=file_entity,
                target=h,
                rel_type=RelationshipType.HAS_HASH,
                event_id=event_id,
                event_ts=event_ts,
            ))
        return out

    # -------------------------------------------------------------------
    # Rule: CONNECTED_TO
    # -------------------------------------------------------------------

    @staticmethod
    def _build_connected_to(
        *,
        child_entity: Entity | None,
        dest_ip_entity: Entity | None,
        category: str | None,
        tenant_id: str | None,
        event_id: str | None,
        event_ts: Any,
    ) -> Relationship | None:
        # Hanya untuk event yang memang berorientasi jaringan.
        if category not in ("network", "http"):
            return None

        if child_entity is None or dest_ip_entity is None:
            return None

        return _make_relationship(
            tenant_id=tenant_id,
            source=child_entity,
            target=dest_ip_entity,
            rel_type=RelationshipType.CONNECTED_TO,
            event_id=event_id,
            event_ts=event_ts,
        )

    # -------------------------------------------------------------------
    # Dedup + sort
    # -------------------------------------------------------------------

    @staticmethod
    def _deduplicate(
        relationships: list[Relationship],
    ) -> list[Relationship]:
        """
        Dedup by identity fingerprint.

        Relationship yang sama di-merge via Relationship.merge()
        (union provenance, min/max temporal).
        """
        by_fp: dict[str, Relationship] = {}

        for rel in relationships:
            fp = rel.fingerprint or rel.calculate_fingerprint()
            rel = rel.with_fingerprint() if not rel.fingerprint else rel
            fp = rel.fingerprint

            if fp in by_fp:
                by_fp[fp] = by_fp[fp].merge(rel)
            else:
                by_fp[fp] = rel

        return list(by_fp.values())

    @staticmethod
    def _sort(relationships: list[Relationship]) -> list[Relationship]:
        """
        Deterministic sort.

        Key:
            1. relationship_type
            2. source_id
            3. target_id

        source_id / target_id stabil dalam satu run (entity_id yang
        sama dipakai untuk semua relationship).
        """
        return sorted(relationships, key=lambda r: (
            r.relationship_type.value,
            r.source_id,
            r.target_id,
        ))


# ===========================================================================
# Relationship construction helper
# ===========================================================================

def _make_relationship(
    *,
    tenant_id: str | None,
    source: Entity,
    target: Entity,
    rel_type: RelationshipType,
    event_id: str | None,
    event_ts: Any,
) -> Relationship:
    return Relationship(
        tenant_id=tenant_id,
        source_type=NodeType.ENTITY,
        source_id=source.entity_id,
        target_type=NodeType.ENTITY,
        target_id=target.entity_id,
        relationship_type=rel_type,
        source_event_ids=[event_id] if event_id else [],
        first_seen=event_ts,
        last_seen=event_ts,
    ).with_fingerprint()


# ===========================================================================
# Factory
# ===========================================================================

def build_relationships(
    event: Any,
    entities: list[Entity],
) -> list[Relationship]:
    """Convenience factory."""
    return RelationshipBuilder().build(event, entities)


__all__ = [
    "RelationshipBuilder",
    "build_relationships",
]
