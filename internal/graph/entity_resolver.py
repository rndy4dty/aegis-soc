"""
Entity resolver for AegisSOC.

Tugas:
    list[Entity]  ->  EntityStore

Menggabungkan entity dari banyak Event menjadi canonical EntityStore:

    Event 1  ──►  EntityExtractor  ──►  Entity[]  ─┐
    Event 2  ──►  EntityExtractor  ──►  Entity[]  ─┤
    Event 3  ──►  EntityExtractor  ──►  Entity[]  ─┤
    ...                                            │
                                                   ▼
                                            EntityResolver
                                                   │
                                                   ▼
                                            Canonical EntityStore

Prinsip:
- Merge berdasarkan identity fingerprint, BUKAN entity_id.
- Entity yang sama: union provenance, min/max temporal, merge properties.
- Deterministik: urutan output stabil.
- Tidak mengubah Entity input.
- Tidak melakukan graph traversal, enrichment, atau correlation.

EntityStore adalah aggregate read-only view. Setelah dibangun,
isinya tidak dimutasi.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator

from pkg.models.entity import Entity, EntityType


# ===========================================================================
# EntityStore
# ===========================================================================

class EntityStore:
    """
    Canonical read-only store of resolved entities.

    Semua entity yang tersimpan sudah punya fingerprint dan
    sudah di-merge dengan entity lain yang identik.
    """

    def __init__(self, entities: list[Entity]) -> None:
        # Simpan sorted by (type, normalized_value, hash_algorithm,
        # identity_scope, identity_domain, host, fingerprint)
        self._entities: tuple[Entity, ...] = tuple(
            sorted(entities, key=_sort_key)
        )

        # Index by fingerprint (primary lookup)
        self._by_fingerprint: dict[str, Entity] = {
            e.fingerprint: e for e in self._entities if e.fingerprint
        }

        # Index by entity_type
        self._by_type: dict[EntityType, list[Entity]] = {}
        for e in self._entities:
            self._by_type.setdefault(e.entity_type, []).append(e)

        # Index by (type, normalized_value)
        self._by_type_value: dict[tuple[EntityType, str], list[Entity]] = {}
        for e in self._entities:
            key = (e.entity_type, e.normalized_value)
            self._by_type_value.setdefault(key, []).append(e)

    # -------------------------------------------------------------------
    # Access
    # -------------------------------------------------------------------

    @property
    def entities(self) -> tuple[Entity, ...]:
        return self._entities

    @property
    def size(self) -> int:
        return len(self._entities)

    @property
    def is_empty(self) -> bool:
        return not self._entities

    def __len__(self) -> int:
        return len(self._entities)

    def __iter__(self) -> Iterator[Entity]:
        return iter(self._entities)

    def __getitem__(self, index: int) -> Entity:
        return self._entities[index]

    def __contains__(self, entity: object) -> bool:
        if not isinstance(entity, Entity):
            return False
        if not entity.fingerprint:
            return False
        return entity.fingerprint in self._by_fingerprint

    # -------------------------------------------------------------------
    # Lookup
    # -------------------------------------------------------------------

    def get(self, fingerprint: str) -> Entity | None:
        """Ambil entity by fingerprint."""
        return self._by_fingerprint.get(fingerprint)

    def by_type(self, entity_type: EntityType) -> list[Entity]:
        """Semua entity dengan tipe tertentu (sorted)."""
        return list(self._by_type.get(entity_type, []))

    def by_value(
        self,
        entity_type: EntityType,
        normalized_value: str,
    ) -> list[Entity]:
        """
        Semua entity dengan (type, normalized_value) tertentu.

        Bisa > 1 kalau host / identity_scope / hash_algorithm berbeda.
        """
        return list(self._by_type_value.get(
            (entity_type, normalized_value), []
        ))

    def find(
        self,
        entity_type: EntityType,
        normalized_value: str,
        *,
        host: str | None = None,
    ) -> Entity | None:
        """
        Cari entity unik berdasarkan type + normalized_value.
        Kalau > 1 match, return None (ambigu).

        Opsional filter by host (untuk host-scoped entity).
        """
        candidates = self.by_value(entity_type, normalized_value)
        if host is not None:
            target_host = host.lower()
            candidates = [c for c in candidates if c.host == target_host]
        if len(candidates) == 1:
            return candidates[0]
        return None

    # -------------------------------------------------------------------
    # Aggregation
    # -------------------------------------------------------------------

    def type_counts(self) -> dict[EntityType, int]:
        return {t: len(lst) for t, lst in self._by_type.items()}

    def types(self) -> list[EntityType]:
        return sorted(self._by_type.keys(), key=lambda t: t.value)

    # -------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------

    def to_list(self) -> list[Entity]:
        return list(self._entities)

    def to_dicts(self) -> list[dict]:
        return [e.to_graph_node() for e in self._entities]


# ===========================================================================
# Sort key (KEEP IN SYNC dengan EntityExtractor._sort)
# ===========================================================================

_TYPE_ORDER: dict[EntityType, int] = {
    EntityType.HOST: 0,
    EntityType.USER: 1,
    EntityType.PROCESS: 2,
    EntityType.FILE: 3,
    EntityType.HASH: 4,
    EntityType.IP: 5,
    EntityType.DOMAIN: 6,
    EntityType.MITRE_TECHNIQUE: 7,
    EntityType.REGISTRY: 8,
    EntityType.URL: 9,
    EntityType.ALERT: 10,
    EntityType.EVENT: 11,
    EntityType.EVIDENCE: 12,
}


def _sort_key(e: Entity) -> tuple:
    return (
        _TYPE_ORDER.get(e.entity_type, 99),
        e.normalized_value,
        e.hash_algorithm or "",
        e.identity_scope or "",
        e.identity_domain or "",
        e.host or "",
        e.fingerprint or "",
    )


# ===========================================================================
# EntityResolver
# ===========================================================================

class EntityResolver:
    """
    Stateless resolver: list[Entity] -> EntityStore.
    """

    def resolve(self, entities: Iterable[Entity]) -> EntityStore:
        by_fp: dict[str, Entity] = {}

        for candidate in entities:
            if not isinstance(candidate, Entity):
                continue

            # Ensure fingerprint terisi
            entity = (
                candidate
                if candidate.fingerprint
                else candidate.with_fingerprint()
            )

            fp = entity.fingerprint
            if fp in by_fp:
                by_fp[fp] = by_fp[fp].merge(entity)
            else:
                by_fp[fp] = entity

        return EntityStore(list(by_fp.values()))

    def resolve_many(
        self,
        entity_lists: Iterable[Iterable[Entity]],
    ) -> EntityStore:
        """
        Gabungkan beberapa list entity sekaligus.
        """
        flattened: list[Entity] = []
        for lst in entity_lists:
            flattened.extend(lst)
        return self.resolve(flattened)


# ===========================================================================
# Factory
# ===========================================================================

def resolve_entities(entities: Iterable[Entity]) -> EntityStore:
    """Convenience factory."""
    return EntityResolver().resolve(entities)


__all__ = [
    "EntityStore",
    "EntityResolver",
    "resolve_entities",
]
