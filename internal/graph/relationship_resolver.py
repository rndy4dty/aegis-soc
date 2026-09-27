"""
Relationship resolver for AegisSOC.

Tugas:
    list[Relationship]  ->  RelationshipStore

Menggabungkan relationship dari banyak Event menjadi canonical
RelationshipStore:

    Event 1  ──►  RelationshipBuilder  ──►  Relationship[]  ─┐
    Event 2  ──►  RelationshipBuilder  ──►  Relationship[]  ─┤
    Event 3  ──►  RelationshipBuilder  ──►  Relationship[]  ─┤
    ...                                                      │
                                                             ▼
                                                    RelationshipResolver
                                                             │
                                                             ▼
                                                    RelationshipStore

Prinsip:
- Merge berdasarkan identity fingerprint, BUKAN relationship_id.
- Relationship yang sama: union provenance, min/max temporal,
  weight/confidence di-combine via on_strength (default: max).
- Deterministik: urutan output stabil.
- Tidak mengubah Relationship input.
- Tidak melakukan traversal, inference, atau correlation.

Catatan pipeline:
- Relationship dibangun dengan source_id/target_id = entity_id
  (UUID per-instance).
- Agar merge antar-event bekerja, relationship dari semua event
  HARUS dibangun dari entity yang sudah resolved (EntityStore),
  sehingga entity dengan identity sama punya entity_id yang sama.
- Lihat `build_relationships_from_store` di modul pemanggil untuk
  pola pipeline yang disarankan.
"""

from __future__ import annotations

from typing import Iterable, Iterator

from pkg.models.relationship import (
    Relationship,
    RelationshipType,
)


# ===========================================================================
# Sort key
# ===========================================================================

def _sort_key(r: Relationship) -> tuple:
    return (
        r.relationship_type.value,
        r.source_type.value,
        r.source_id,
        r.target_type.value,
        r.target_id,
    )


# ===========================================================================
# RelationshipStore
# ===========================================================================

class RelationshipStore:
    """
    Canonical read-only store of resolved relationships.

    Semua relationship yang tersimpan sudah punya fingerprint dan
    sudah di-merge dengan relationship lain yang identik.
    """

    def __init__(self, relationships: list[Relationship]) -> None:
        self._relationships: tuple[Relationship, ...] = tuple(
            sorted(relationships, key=_sort_key)
        )

        # Index by fingerprint (primary lookup)
        self._by_fingerprint: dict[str, Relationship] = {
            r.fingerprint: r
            for r in self._relationships
            if r.fingerprint
        }

        # Index by relationship_type
        self._by_type: dict[RelationshipType, list[Relationship]] = {}
        for r in self._relationships:
            self._by_type.setdefault(r.relationship_type, []).append(r)

        # Index by source_id (as Entity side)
        self._by_source: dict[str, list[Relationship]] = {}
        for r in self._relationships:
            self._by_source.setdefault(r.source_id, []).append(r)

        # Index by target_id
        self._by_target: dict[str, list[Relationship]] = {}
        for r in self._relationships:
            self._by_target.setdefault(r.target_id, []).append(r)

        # Index by (source_id, target_id)
        self._by_pair: dict[tuple[str, str], list[Relationship]] = {}
        for r in self._relationships:
            self._by_pair.setdefault(
                (r.source_id, r.target_id), []
            ).append(r)

    # -------------------------------------------------------------------
    # Access
    # -------------------------------------------------------------------

    @property
    def relationships(self) -> tuple[Relationship, ...]:
        return self._relationships

    @property
    def size(self) -> int:
        return len(self._relationships)

    @property
    def is_empty(self) -> bool:
        return not self._relationships

    def __len__(self) -> int:
        return len(self._relationships)

    def __iter__(self) -> Iterator[Relationship]:
        return iter(self._relationships)

    def __getitem__(self, index: int) -> Relationship:
        return self._relationships[index]

    def __contains__(self, relationship: object) -> bool:
        if not isinstance(relationship, Relationship):
            return False
        if not relationship.fingerprint:
            return False
        return relationship.fingerprint in self._by_fingerprint

    # -------------------------------------------------------------------
    # Lookup
    # -------------------------------------------------------------------

    def get(self, fingerprint: str) -> Relationship | None:
        """Ambil relationship by fingerprint."""
        return self._by_fingerprint.get(fingerprint)

    def by_type(
        self, relationship_type: RelationshipType
    ) -> list[Relationship]:
        return list(self._by_type.get(relationship_type, []))

    def by_source(self, source_id: str) -> list[Relationship]:
        return list(self._by_source.get(source_id, []))

    def by_target(self, target_id: str) -> list[Relationship]:
        return list(self._by_target.get(target_id, []))

    def between(
        self,
        source_id: str,
        target_id: str,
    ) -> list[Relationship]:
        """
        Semua relationship dari source_id ke target_id,
        lintas tipe.
        """
        return list(self._by_pair.get((source_id, target_id), []))

    # -------------------------------------------------------------------
    # Aggregation
    # -------------------------------------------------------------------

    def type_counts(self) -> dict[RelationshipType, int]:
        return {
            t: len(lst) for t, lst in self._by_type.items()
        }

    def types(self) -> list[RelationshipType]:
        return sorted(self._by_type.keys(), key=lambda t: t.value)

    # -------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------

    def to_list(self) -> list[Relationship]:
        return list(self._relationships)

    def to_dicts(self) -> list[dict]:
        return [r.to_graph_edge() for r in self._relationships]


# ===========================================================================
# RelationshipResolver
# ===========================================================================

class RelationshipResolver:
    """
    Stateless resolver: list[Relationship] -> RelationshipStore.
    """

    def __init__(
        self,
        *,
        on_strength: str = "max",
        on_property_conflict: str = "left",
        on_metadata_conflict: str = "left",
    ) -> None:
        valid_strength = ("max", "avg", "left", "right")
        valid_conflict = ("left", "right", "raise")

        if on_strength not in valid_strength:
            raise ValueError(
                f"on_strength must be one of {valid_strength}"
            )
        if on_property_conflict not in valid_conflict:
            raise ValueError(
                f"on_property_conflict must be one of {valid_conflict}"
            )
        if on_metadata_conflict not in valid_conflict:
            raise ValueError(
                f"on_metadata_conflict must be one of {valid_conflict}"
            )

        self._on_strength = on_strength
        self._on_property_conflict = on_property_conflict
        self._on_metadata_conflict = on_metadata_conflict

    def resolve(
        self, relationships: Iterable[Relationship]
    ) -> RelationshipStore:
        by_fp: dict[str, Relationship] = {}

        for candidate in relationships:
            if not isinstance(candidate, Relationship):
                continue

            rel = (
                candidate
                if candidate.fingerprint
                else candidate.with_fingerprint()
            )

            fp = rel.fingerprint
            if fp in by_fp:
                by_fp[fp] = by_fp[fp].merge(
                    rel,
                    on_strength=self._on_strength,
                    on_property_conflict=self._on_property_conflict,
                    on_metadata_conflict=self._on_metadata_conflict,
                )
            else:
                by_fp[fp] = rel

        return RelationshipStore(list(by_fp.values()))

    def resolve_many(
        self,
        relationship_lists: Iterable[Iterable[Relationship]],
    ) -> RelationshipStore:
        """
        Gabungkan beberapa list relationship sekaligus.
        """
        flattened: list[Relationship] = []
        for lst in relationship_lists:
            flattened.extend(lst)
        return self.resolve(flattened)


# ===========================================================================
# Factory
# ===========================================================================

def resolve_relationships(
    relationships: Iterable[Relationship],
    **kwargs,
) -> RelationshipStore:
    """Convenience factory."""
    return RelationshipResolver(**kwargs).resolve(relationships)


__all__ = [
    "RelationshipStore",
    "RelationshipResolver",
    "resolve_relationships",
]
