"""
GraphService: high-level API untuk graph persistence.

Task:
- Save InvestigationGraph ke Neo4j (entity + relationship)
- Query neighbors, paths, lineage
- Filter by tenant
"""

from __future__ import annotations

from typing import Any

from internal.graph.graph_store import InvestigationGraph
from internal.storage.graph.client import (
    Neo4jClient,
    get_neo4j,
)
from pkg.models.entity import Entity, EntityType
from pkg.models.relationship import (
    Relationship,
    RelationshipType,
)


class GraphService:
    """
    Facade untuk operasi graph di Neo4j.
    """

    def __init__(self, client: Neo4jClient | None = None) -> None:
        self._client = client or get_neo4j()

    # ==================================================================
    # Save
    # ==================================================================

    def save_graph(
        self,
        graph: InvestigationGraph,
        *,
        case_id: str | None = None,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Simpan seluruh graph ke Neo4j.

        Args:
            graph     : InvestigationGraph
            case_id   : optional, link entities ke Case node
            tenant_id : optional, override tenant

        Return:
            summary statistik
        """
        entities = list(graph.entities)
        relationships = list(graph.relationships)

        # -- Save entities ---------------------------------------------
        for entity in entities:
            self._upsert_entity(
                entity,
                tenant_id=tenant_id,
                case_id=case_id,
            )

        # -- Save relationships ----------------------------------------
        for rel in relationships:
            self._upsert_relationship(
                rel,
                tenant_id=tenant_id,
            )

        # -- Save Case node (optional) --------------------------------
        if case_id is not None:
            self._upsert_case_node(
                case_id=case_id,
                tenant_id=tenant_id,
                entity_ids=[e.entity_id for e in entities],
            )

        return {
            "entities_saved": len(entities),
            "relationships_saved": len(relationships),
            "case_id": case_id,
        }

    def _upsert_entity(
        self,
        entity: Entity,
        *,
        tenant_id: str | None = None,
        case_id: str | None = None,
    ) -> None:
        query = """
        MERGE (e:Entity {entity_id: $entity_id})
        SET e.entity_type = $entity_type,
            e.value = $value,
            e.normalized_value = $normalized_value,
            e.host = $host,
            e.tenant_id = $tenant_id,
            e.fingerprint = $fingerprint,
            e.identity_scope = $identity_scope,
            e.identity_domain = $identity_domain,
            e.hash_algorithm = $hash_algorithm,
            e.first_seen = $first_seen,
            e.last_seen = $last_seen
        """
        params = {
            "entity_id": entity.entity_id,
            "entity_type": entity.entity_type.value,
            "value": entity.value,
            "normalized_value": entity.normalized_value,
            "host": entity.host,
            "tenant_id": tenant_id or entity.tenant_id,
            "fingerprint": entity.fingerprint,
            "identity_scope": entity.identity_scope,
            "identity_domain": entity.identity_domain,
            "hash_algorithm": entity.hash_algorithm,
            "first_seen": (
                entity.first_seen.isoformat()
                if entity.first_seen else None
            ),
            "last_seen": (
                entity.last_seen.isoformat()
                if entity.last_seen else None
            ),
        }
        self._client.run_write(query, params)

        # Link ke Case kalau ada
        if case_id is not None:
            link_query = """
            MATCH (e:Entity {entity_id: $entity_id})
            MERGE (c:Case {case_id: $case_id})
            MERGE (c)-[:CONTAINS]->(e)
            """
            self._client.run_write(
                link_query,
                {
                    "entity_id": entity.entity_id,
                    "case_id": case_id,
                },
            )

    def _upsert_relationship(
        self,
        rel: Relationship,
        *,
        tenant_id: str | None = None,
    ) -> None:
        # Neo4j relationship types: huruf + underscore, tidak boleh
        # ada karakter aneh. RelationshipType kita sudah aman
        # (spawned, run_as, has_hash, dst).
        rel_type = rel.relationship_type.value.upper()

        query = f"""
        MATCH (src:Entity {{entity_id: $source_id}})
        MATCH (tgt:Entity {{entity_id: $target_id}})
        MERGE (src)-[r:{rel_type} {{relationship_id: $rel_id}}]->(tgt)
        SET r.weight = $weight,
            r.confidence = $confidence,
            r.tenant_id = $tenant_id,
            r.fingerprint = $fingerprint,
            r.first_seen = $first_seen,
            r.last_seen = $last_seen
        """
        params = {
            "source_id": rel.source_id,
            "target_id": rel.target_id,
            "rel_id": rel.relationship_id,
            "weight": rel.weight,
            "confidence": rel.confidence,
            "tenant_id": tenant_id or rel.tenant_id,
            "fingerprint": rel.fingerprint,
            "first_seen": (
                rel.first_seen.isoformat()
                if rel.first_seen else None
            ),
            "last_seen": (
                rel.last_seen.isoformat()
                if rel.last_seen else None
            ),
        }
        self._client.run_write(query, params)

    def _upsert_case_node(
        self,
        *,
        case_id: str,
        tenant_id: str | None,
        entity_ids: list[str],
    ) -> None:
        query = """
        MERGE (c:Case {case_id: $case_id})
        SET c.tenant_id = $tenant_id,
            c.entity_count = $entity_count
        """
        self._client.run_write(
            query,
            {
                "case_id": case_id,
                "tenant_id": tenant_id,
                "entity_count": len(entity_ids),
            },
        )

    # ==================================================================
    # Query: Neighbors
    # ==================================================================

    def neighbors(
        self,
        entity_id: str,
        *,
        rel_type: str | None = None,
        direction: str = "both",
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Ambil neighbor entity dari entity_id.

        direction: "out", "in", "both"
        rel_type : filter by relationship type (case-insensitive)
        """
        if direction == "out":
            pattern = "(e)-[r]->(n:Entity)"
        elif direction == "in":
            pattern = "(e)<-[r]-(n:Entity)"
        else:
            pattern = "(e)-[r]-(n:Entity)"

        if rel_type:
            rel_pattern = f"[r:{rel_type.upper()}]"
            if direction == "out":
                pattern = f"(e)-{rel_pattern}->(n:Entity)"
            elif direction == "in":
                pattern = f"(e)<-{rel_pattern}-(n:Entity)"
            else:
                pattern = f"(e)-{rel_pattern}-(n:Entity)"
        where_clauses = ["e.entity_id = $entity_id"]
        if tenant_id:
            where_clauses.append("n.tenant_id = $tenant_id")
            where_clauses.append("e.tenant_id = $tenant_id")

        query = f"""
        MATCH {pattern}
        WHERE {' AND '.join(where_clauses)}
        RETURN DISTINCT
            n.entity_id AS entity_id,
            n.entity_type AS entity_type,
            n.value AS value,
            n.host AS host,
            type(r) AS relationship_type,
            r.weight AS weight,
            r.confidence AS confidence
        ORDER BY n.value
        """
        return self._client.run(
            query,
            {
                "entity_id": entity_id,
                "tenant_id": tenant_id,
            },
        )

    # ==================================================================
    # Query: Path Finding
    # ==================================================================

    def find_path(
        self,
        source_id: str,
        target_id: str,
        *,
        max_depth: int = 5,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Cari path terpendek dari source ke target.

        Return: list of nodes+relationships sepanjang path.
        """
        where_clauses = [
            "src.entity_id = $source_id",
            "tgt.entity_id = $target_id",
        ]
        if tenant_id:
            where_clauses.append("ALL(n IN nodes(p) WHERE n.tenant_id = $tenant_id)")

        query = f"""
        MATCH p = shortestPath(
            (src:Entity)-[*1..{max_depth}]-(tgt:Entity)
        )
        WHERE {' AND '.join(where_clauses)}
        RETURN
            [n IN nodes(p) | {{
                entity_id: n.entity_id,
                entity_type: n.entity_type,
                value: n.value
            }}] AS nodes,
            [r IN relationships(p) | type(r)] AS relationships
        """
        results = self._client.run(
            query,
            {
                "source_id": source_id,
                "target_id": target_id,
                "tenant_id": tenant_id,
            },
        )
        if not results:
            return []
        return results[0].get("nodes", [])

    # ==================================================================
    # Query: Lineage
    # ==================================================================

    def lineage(
        self,
        entity_id: str,
        *,
        max_depth: int = 10,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Ambil parent chain via SPAWNED relationship (upward).
        """
        where = ["e.entity_id = $entity_id"]
        if tenant_id:
            where.append("parent.tenant_id = $tenant_id")

        query = f"""
        MATCH path = (e:Entity {{entity_id: $entity_id}})
            <-[:SPAWNED*1..{max_depth}]-(parent:Entity)
        WHERE {' AND '.join(where)}
        RETURN
            [n IN nodes(path) | {{
                entity_id: n.entity_id,
                value: n.value,
                host: n.host
            }}] AS lineage
        ORDER BY length(path) DESC
        LIMIT 1
        """
        results = self._client.run(
            query,
            {
                "entity_id": entity_id,
                "tenant_id": tenant_id,
            },
        )
        if not results:
            return []
        return results[0].get("lineage", [])

    # ==================================================================
    # Query: Cross-Host Activity
    # ==================================================================

    def cross_host_entities(
        self,
        *,
        tenant_id: str | None = None,
        min_hosts: int = 2,
        limit: int = 50,
    ) -> list[dict[str, Any]]:
        """
        Cari entity yang muncul di banyak host.

        Berguna untuk deteksi lateral movement atau shared artifact.
        """
        where = ["e.host IS NOT NULL"]
        if tenant_id:
            where.append("e.tenant_id = $tenant_id")

        query = f"""
        MATCH (e:Entity)
        WHERE {' AND '.join(where)}
        WITH e.value AS value,
             e.entity_type AS entity_type,
             COLLECT(DISTINCT e.host) AS hosts,
             COUNT(DISTINCT e.host) AS host_count
        WHERE host_count >= $min_hosts
        RETURN
            value,
            entity_type,
            hosts,
            host_count
        ORDER BY host_count DESC, value
        LIMIT $limit
        """
        return self._client.run(
            query,
            {
                "tenant_id": tenant_id,
                "min_hosts": min_hosts,
                "limit": limit,
            },
        )

    # ==================================================================
    # Query: Graph Stats
    # ==================================================================

    def stats(
        self,
        *,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        """
        Statistik graph.
        """
        where = []
        params: dict[str, Any] = {}
        if tenant_id:
            where.append("e.tenant_id = $tenant_id")
            params["tenant_id"] = tenant_id

        where_clause = (
            "WHERE " + " AND ".join(where)
            if where else ""
        )

        query = f"""
        MATCH (e:Entity)
        {where_clause}
        RETURN
            COUNT(e) AS entity_count,
            COUNT(DISTINCT e.entity_type) AS type_count,
            COUNT(DISTINCT e.host) AS host_count
        """
        entity_stats = self._client.run(query, params)

        rel_query = f"""
        MATCH (a:Entity)-[r]->(b:Entity)
        {('WHERE a.tenant_id = $tenant_id AND b.tenant_id = $tenant_id') if tenant_id else ''}
        RETURN COUNT(r) AS relationship_count
        """
        rel_stats = self._client.run(rel_query, params)

        entity_data = entity_stats[0] if entity_stats else {}
        rel_data = rel_stats[0] if rel_stats else {}

        return {
            "entity_count": entity_data.get("entity_count", 0),
            "relationship_count": rel_data.get(
                "relationship_count", 0
            ),
            "type_count": entity_data.get("type_count", 0),
            "host_count": entity_data.get("host_count", 0),
        }

    # ==================================================================
    # Delete
    # ==================================================================

    def delete_case(self, case_id: str) -> bool:
        """
        Hapus Case node dan semua Entity yang CONTAINS-only.
        """
        query = """
        MATCH (c:Case {case_id: $case_id})
        OPTIONAL MATCH (c)-[:CONTAINS]->(e:Entity)
        DETACH DELETE e, c
        RETURN COUNT(e) AS deleted
        """
        result = self._client.run(query, {"case_id": case_id})
        if not result:
            return False
        return result[0].get("deleted", 0) >= 0

    def delete_tenant(self, tenant_id: str) -> int:
        """
        Hapus semua node milik tenant.
        Return jumlah node yang dihapus.
        """
        query = """
        MATCH (e:Entity {tenant_id: $tenant_id})
        DETACH DELETE e
        RETURN COUNT(e) AS deleted
        """
        result = self._client.run(
            query, {"tenant_id": tenant_id}
        )
        return result[0].get("deleted", 0) if result else 0

    # ==================================================================
    # Health
    # ==================================================================

    def is_available(self) -> bool:
        return self._client.verify_connectivity()


__all__ = ["GraphService"]
