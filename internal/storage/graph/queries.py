"""
Preset Cypher queries untuk analyst.

Semua preset adalah factory callable:
- parameterless: bisa dipanggil tanpa argumen (mis. lateral_movement())
- parameterized: butuh argumen wajib (mis. process_lineage(entity_id="P-1"))

Kontrak:
- Cypher selalu parameterized ($param), tidak ada string interpolation user input.
- Setiap query punya LIMIT.
- Return value adalah QueryPreset (cypher + params + metadata).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass
class QueryPreset:
    name: str
    description: str
    cypher: str
    params: dict[str, Any] = field(default_factory=dict)
    category: str = "general"


# ===========================================================================
# Parameterized presets
# ===========================================================================

def process_lineage(
    entity_id: str,
    *,
    max_depth: int = 5,
    limit: int = 100,
) -> QueryPreset:
    """Process tree di sekitar satu entity (parent + children)."""
    return QueryPreset(
        name="process_lineage",
        description="Process tree di sekitar satu entity (parent + children)",
        category="process",
        cypher=f"""
            MATCH path = (e:Entity {{entity_id: $entity_id}})
                -[:SPAWNED*0..{int(max_depth)}]-(related:Entity)
            WHERE related.entity_type = "process"
            RETURN path
            LIMIT $limit
        """,
        params={"entity_id": entity_id, "limit": int(limit)},
    )


def entities_by_mitre(
    technique: str,
    *,
    tenant_id: str | None = None,
    limit: int = 100,
) -> QueryPreset:
    """Entity yang terkait sebuah MITRE technique."""
    return QueryPreset(
        name="entities_by_mitre",
        description=f"Entity terkait MITRE {technique}",
        category="detection",
        cypher="""
            MATCH (e:Entity)
            WHERE $technique IN e.mitre_techniques
              AND ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            RETURN e
            ORDER BY e.host, e.value
            LIMIT $limit
        """,
        params={
            "technique": technique,
            "tenant_id": tenant_id,
            "limit": int(limit),
        },
    )


def case_graph(
    case_id: str,
    *,
    limit: int = 500,
) -> QueryPreset:
    """Semua entity dalam satu case + relasinya."""
    return QueryPreset(
        name="case_graph",
        description=f"Graph entity dalam case {case_id}",
        category="case",
        cypher="""
            MATCH (c:Case {case_id: $case_id})-[:CONTAINS]->(e:Entity)
            OPTIONAL MATCH (e)-[r]-(other:Entity)
            RETURN e, r, other
            LIMIT $limit
        """,
        params={"case_id": case_id, "limit": int(limit)},
    )


# ===========================================================================
# Parameterless presets (masih bisa diberi opsi via keyword)
# ===========================================================================

def lateral_movement(
    *,
    tenant_id: str | None = None,
    limit: int = 50,
) -> QueryPreset:
    """Relationship antar-entity di host berbeda (potensi lateral movement)."""
    return QueryPreset(
        name="lateral_movement",
        description="Relationship antar host berbeda (lateral movement)",
        category="network",
        cypher="""
            MATCH (a:Entity)-[r]->(b:Entity)
            WHERE a.host IS NOT NULL
              AND b.host IS NOT NULL
              AND a.host <> b.host
              AND ($tenant_id IS NULL OR a.tenant_id = $tenant_id)
            RETURN a, r, b
            LIMIT $limit
        """,
        params={"tenant_id": tenant_id, "limit": int(limit)},
    )


def persistence_artifacts(
    *,
    tenant_id: str | None = None,
    limit: int = 100,
) -> QueryPreset:
    """Registry keys / files dengan is_persistence_key atau tags 'persistence'."""
    return QueryPreset(
        name="persistence_artifacts",
        description="Registry keys / files yang ditandai sebagai persistence",
        category="persistence",
        cypher="""
            MATCH (e:Entity)
            WHERE (
                (e.properties IS NOT NULL
                 AND e.properties.is_persistence_key = true)
                OR "persistence" IN coalesce(e.tags, [])
            )
            AND ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            RETURN e
            ORDER BY e.value
            LIMIT $limit
        """,
        params={"tenant_id": tenant_id, "limit": int(limit)},
    )


def shared_hashes_across_hosts(
    *,
    tenant_id: str | None = None,
    min_hosts: int = 2,
    limit: int = 50,
) -> QueryPreset:
    """Hash yang muncul di 2+ host berbeda."""
    return QueryPreset(
        name="shared_hashes_across_hosts",
        description="Hash file yang muncul di 2+ host berbeda",
        category="network",
        cypher="""
            MATCH (e:Entity)
            WHERE e.entity_type = "hash"
              AND e.host IS NOT NULL
              AND ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            WITH e.normalized_value AS hash_value,
                 e.hash_algorithm AS algo,
                 COLLECT(DISTINCT e.host) AS hosts
            WHERE SIZE(hosts) >= $min_hosts
            RETURN hash_value, algo, hosts, SIZE(hosts) AS host_count
            ORDER BY host_count DESC
            LIMIT $limit
        """,
        params={
            "tenant_id": tenant_id,
            "min_hosts": int(min_hosts),
            "limit": int(limit),
        },
    )


def top_connected_entities(
    *,
    tenant_id: str | None = None,
    min_degree: int = 3,
    limit: int = 20,
) -> QueryPreset:
    """Entity dengan degree tertinggi — 'hub' di graph."""
    return QueryPreset(
        name="top_connected_entities",
        description=f"Entity dengan >= 3 relationships (hub analysis)",
        category="general",
        cypher="""
            MATCH (e:Entity)-[r]-()
            WHERE ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            WITH e, COUNT(r) AS degree
            WHERE degree >= $min_degree
            RETURN e.entity_id AS entity_id,
                   e.entity_type AS entity_type,
                   e.value AS value,
                   e.host AS host,
                   degree
            ORDER BY degree DESC
            LIMIT $limit
        """,
        params={
            "tenant_id": tenant_id,
            "min_degree": int(min_degree),
            "limit": int(limit),
        },
    )


def recent_entities(
    *,
    tenant_id: str | None = None,
    limit: int = 50,
) -> QueryPreset:
    """Entity terbaru berdasarkan first_seen."""
    return QueryPreset(
        name="recent_entities",
        description="Entity dengan first_seen terbaru",
        category="general",
        cypher="""
            MATCH (e:Entity)
            WHERE e.first_seen IS NOT NULL
              AND ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            RETURN e
            ORDER BY e.first_seen DESC
            LIMIT $limit
        """,
        params={"tenant_id": tenant_id, "limit": int(limit)},
    )


def high_severity_events(
    *,
    tenant_id: str | None = None,
    min_severity: int = 70,
    limit: int = 100,
) -> QueryPreset:
    """Entity dengan severity tinggi."""
    return QueryPreset(
        name="high_severity_events",
        description=f"Entity dengan severity >= {min_severity}",
        category="detection",
        cypher="""
            MATCH (e:Entity)
            WHERE e.severity IS NOT NULL
              AND e.severity >= $min_severity
              AND ($tenant_id IS NULL OR e.tenant_id = $tenant_id)
            RETURN e
            ORDER BY e.severity DESC
            LIMIT $limit
        """,
        params={
            "tenant_id": tenant_id,
            "min_severity": int(min_severity),
            "limit": int(limit),
        },
    )


# ===========================================================================
# Registry — satu sumber kebenaran, semua callable
# ===========================================================================

PRESETS: dict[str, Callable[..., QueryPreset]] = {
    "process_lineage":            process_lineage,
    "entities_by_mitre":          entities_by_mitre,
    "case_graph":                 case_graph,
    "lateral_movement":           lateral_movement,
    "persistence_artifacts":      persistence_artifacts,
    "shared_hashes_across_hosts": shared_hashes_across_hosts,
    "top_connected_entities":     top_connected_entities,
    "recent_entities":            recent_entities,
    "high_severity_events":       high_severity_events,
}


__all__ = [
    "QueryPreset",
    "PRESETS",
    "process_lineage",
    "entities_by_mitre",
    "case_graph",
    "lateral_movement",
    "persistence_artifacts",
    "shared_hashes_across_hosts",
    "top_connected_entities",
    "recent_entities",
    "high_severity_events",
]
