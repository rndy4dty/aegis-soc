"""
Graph store & InvestigationGraph for AegisSOC.

Tugas:
    events  ->  InvestigationGraph

Orkestrasi end-to-end pipeline:

    events
      │
      ▼
    EntityExtractor          (per event)
      │
      ▼
    Entity[]                 (flat)
      │
      ▼
    EntityResolver
      │
      ▼
    EntityStore              (canonical, merged)
      │
      ▼
    RelationshipBuilder      (per event, memakai EntityStore.entities)
      │
      ▼
    Relationship[]           (flat)
      │
      ▼
    RelationshipResolver
      │
      ▼
    RelationshipStore        (canonical, merged)
      │
      ▼
    InvestigationGraph       (aggregate root)

Prinsip:
- Deterministik.
- Relationship dibangun dari entity canonical (EntityStore.entities),
  sehingga entity_id antar event konsisten.
- Tidak melakukan inference, correlation, atau AI.
- InvestigationGraph adalah immutable view setelah dibangun.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator

from internal.graph.entity_extractor import EntityExtractor
from internal.graph.entity_resolver import (
    EntityResolver,
    EntityStore,
)
from internal.graph.relationship_builder import RelationshipBuilder
from internal.graph.relationship_resolver import (
    RelationshipResolver,
    RelationshipStore,
)
from pkg.models.entity import Entity, EntityType
from pkg.models.relationship import (
    NodeType,
    Relationship,
    RelationshipType,
)


# ===========================================================================
# InvestigationGraph
# ===========================================================================

class InvestigationGraph:
    """
    Aggregate root graph hasil orkestrasi.

    Immutable setelah dibangun. Semua query bersifat read-only.
    """

    def __init__(
        self,
        entity_store: EntityStore,
        relationship_store: RelationshipStore,
        *,
        events_processed: int = 0,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._entities = entity_store
        self._relationships = relationship_store
        self._events_processed = events_processed
        self._metadata = metadata or {}

    # -------------------------------------------------------------------
    # Access
    # -------------------------------------------------------------------

    @property
    def entities(self) -> EntityStore:
        return self._entities

    @property
    def relationships(self) -> RelationshipStore:
        return self._relationships

    @property
    def events_processed(self) -> int:
        return self._events_processed

    @property
    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    # -------------------------------------------------------------------
    # Stats
    # -------------------------------------------------------------------

    @property
    def entity_count(self) -> int:
        return self._entities.size

    @property
    def relationship_count(self) -> int:
        return self._relationships.size

    @property
    def is_empty(self) -> bool:
        return self._entities.is_empty and self._relationships.is_empty

    def stats(self) -> dict[str, Any]:
        return {
            "events_processed": self._events_processed,
            "entity_count": self._entities.size,
            "relationship_count": self._relationships.size,
            "entity_types": {
                t.value: n
                for t, n in self._entities.type_counts().items()
            },
            "relationship_types": {
                t.value: n
                for t, n in self._relationships.type_counts().items()
            },
        }

    # -------------------------------------------------------------------
    # Entity queries
    # -------------------------------------------------------------------

    def get_entity(self, fingerprint: str) -> Entity | None:
        return self._entities.get(fingerprint)

    def entities_by_type(self, entity_type: EntityType) -> list[Entity]:
        return self._entities.by_type(entity_type)

    def find_entity(
        self,
        entity_type: EntityType,
        normalized_value: str,
        *,
        host: str | None = None,
    ) -> Entity | None:
        return self._entities.find(
            entity_type, normalized_value, host=host,
        )

    # -------------------------------------------------------------------
    # Relationship queries
    # -------------------------------------------------------------------

    def get_relationship(self, fingerprint: str) -> Relationship | None:
        return self._relationships.get(fingerprint)

    def relationships_by_type(
        self, relationship_type: RelationshipType
    ) -> list[Relationship]:
        return self._relationships.by_type(relationship_type)

    def outgoing(self, entity_id: str) -> list[Relationship]:
        """Semua relationship yang keluar dari entity_id."""
        return self._relationships.by_source(entity_id)

    def incoming(self, entity_id: str) -> list[Relationship]:
        """Semua relationship yang masuk ke entity_id."""
        return self._relationships.by_target(entity_id)

    # -------------------------------------------------------------------
    # Neighbors
    # -------------------------------------------------------------------

    def neighbors(
        self,
        entity_id: str,
        *,
        relationship_type: RelationshipType | None = None,
    ) -> list[Entity]:
        """
        Entity yang bertetangga dengan entity_id (outgoing + incoming).
        Opsional filter by relationship_type.
        """
        results: list[Entity] = []
        seen: set[str] = set()

        for r in self._relationships.by_source(entity_id):
            if relationship_type and r.relationship_type != relationship_type:
                continue
            if r.target_id in seen:
                continue
            seen.add(r.target_id)
            e = self._entity_by_id(r.target_id)
            if e is not None:
                results.append(e)

        for r in self._relationships.by_target(entity_id):
            if relationship_type and r.relationship_type != relationship_type:
                continue
            if r.source_id in seen:
                continue
            seen.add(r.source_id)
            e = self._entity_by_id(r.source_id)
            if e is not None:
                results.append(e)

        return results

    # -------------------------------------------------------------------
    # Subgraph
    # -------------------------------------------------------------------

    def subgraph(
        self,
        seed_entity_ids: list[str],
        *,
        depth: int = 1,
    ) -> "InvestigationGraph":
        """
        Subgraph mulai dari seed entity, meluas `depth` langkah.

        Deterministik. Tidak mengubah graph asli.
        """
        if depth < 0:
            raise ValueError("depth must be >= 0")

        # BFS
        visited_entities: set[str] = set()
        frontier: set[str] = set(seed_entity_ids)

        for _ in range(depth + 1):
            next_frontier: set[str] = set()
            for eid in frontier:
                if eid in visited_entities:
                    continue
                visited_entities.add(eid)
                for r in self._relationships.by_source(eid):
                    if r.target_id not in visited_entities:
                        next_frontier.add(r.target_id)
                for r in self._relationships.by_target(eid):
                    if r.source_id not in visited_entities:
                        next_frontier.add(r.source_id)
            frontier = next_frontier

        # Kumpulkan entity
        sub_entities = [
            e for e in self._entities
            if e.entity_id in visited_entities
        ]

        # Kumpulkan relationship yang kedua endpoint-nya di subgraph
        sub_relationships = [
            r for r in self._relationships
            if r.source_id in visited_entities
            and r.target_id in visited_entities
        ]

        entity_store = EntityStore(sub_entities)
        relationship_store = RelationshipStore(sub_relationships)

        return InvestigationGraph(
            entity_store,
            relationship_store,
            events_processed=self._events_processed,
            metadata={
                **self._metadata,
                "subgraph_from": list(seed_entity_ids),
                "subgraph_depth": depth,
            },
        )

    # -------------------------------------------------------------------
    # Serialization
    # -------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": self.stats(),
            "entities": self._entities.to_dicts(),
            "relationships": self._relationships.to_dicts(),
        }

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    def _entity_by_id(self, entity_id: str) -> Entity | None:
        for e in self._entities:
            if e.entity_id == entity_id:
                return e
        return None


# ===========================================================================
# GraphStore
# ===========================================================================

class GraphStore:
    """
    Orkestrator pipeline: events -> InvestigationGraph.

    Stateless. Bisa di-reuse.
    """

    def __init__(
        self,
        *,
        entity_extractor: EntityExtractor | None = None,
        entity_resolver: EntityResolver | None = None,
        relationship_builder: RelationshipBuilder | None = None,
        relationship_resolver: RelationshipResolver | None = None,
    ) -> None:
        self._extractor = entity_extractor or EntityExtractor()
        self._entity_resolver = entity_resolver or EntityResolver()
        self._relationship_builder = (
            relationship_builder or RelationshipBuilder()
        )
        self._relationship_resolver = (
            relationship_resolver or RelationshipResolver()
        )

    # -------------------------------------------------------------------
    # Build
    # -------------------------------------------------------------------

    def build(self, events: Iterable[Any]) -> InvestigationGraph:
        """
        Bangun InvestigationGraph dari daftar events.

        Pipeline:
            1. Extract entity per event -> flat list
            2. Resolve entities -> EntityStore (canonical)
            3. Build relationship per event, memakai EntityStore.entities
            4. Resolve relationships -> RelationshipStore
            5. Wrap -> InvestigationGraph
        """
        events_list = list(events)

        # 1. Extract entities
        all_entities: list[Entity] = []
        for event in events_list:
            all_entities.extend(self._extractor.extract(event))

        # 2. Resolve entities
        entity_store = self._entity_resolver.resolve(all_entities)
        canonical_entities = entity_store.to_list()

        # 3. Build relationships, per event, dari canonical entities
        all_relationships: list[Relationship] = []
        for event in events_list:
            all_relationships.extend(
                self._relationship_builder.build(
                    event, canonical_entities
                )
            )

        # 4. Resolve relationships
        relationship_store = self._relationship_resolver.resolve(
            all_relationships
        )

        # 5. Wrap
        return InvestigationGraph(
            entity_store,
            relationship_store,
            events_processed=len(events_list),
        )

    # -------------------------------------------------------------------
    # Incremental (opsional)
    # -------------------------------------------------------------------

    def extend(
        self,
        graph: InvestigationGraph,
        events: Iterable[Any],
    ) -> InvestigationGraph:
        """
        Tambahkan events baru ke graph yang sudah ada.

        Cara kerja: bangun ulang seluruh graph dari
        events lama + events baru. Simpel dan deterministik.

        Untuk graph besar, gunakan strategi incremental lain.
        """
        existing_events = self._events_from_graph(graph)
        if not existing_events:
            # Graph tidak menyimpan raw events; bangun dari awal
            return self.build(list(events))
        return self.build(existing_events + list(events))

    # -------------------------------------------------------------------
    # Internal
    # -------------------------------------------------------------------

    @staticmethod
    def _events_from_graph(
        graph: InvestigationGraph,
    ) -> list[Any]:
        # Graph tidak menyimpan raw events.
        return []


# ===========================================================================
# Factory
# ===========================================================================

def build_graph(events: Iterable[Any]) -> InvestigationGraph:
    """Convenience factory."""
    return GraphStore().build(events)


__all__ = [
    "InvestigationGraph",
    "GraphStore",
    "build_graph",
]
