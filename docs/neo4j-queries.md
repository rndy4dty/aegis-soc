# Neo4j Query Presets — AegisSOC

Setelah graph tersimpan di Neo4j, analyst bisa query lewat:

1. **CLI** (`python -m cli graph ...`)
2. **Neo4j Browser** di http://localhost:7474 (login: `neo4j` / `aegispassword`)

## CLI

    python -m cli graph list
    python -m cli graph run <preset> --dry-run
    python -m cli graph run <preset> [-p key=value ...]

## Preset

| Nama | Kategori | Parameter |
|---|---|---|
| `process_lineage` | process | `entity_id` (wajib), `max_depth` |
| `entities_by_mitre` | detection | `technique` (wajib), `tenant_id` |
| `case_graph` | case | `case_id` (wajib) |
| `lateral_movement` | network | `tenant_id`, `limit` |
| `persistence_artifacts` | persistence | `tenant_id`, `limit` |
| `shared_hashes_across_hosts` | network | `tenant_id`, `min_hosts` |
| `top_connected_entities` | general | `tenant_id`, `min_degree` |
| `recent_entities` | general | `tenant_id`, `limit` |
| `high_severity_events` | detection | `tenant_id`, `min_severity` |

## Contoh

    python -m cli graph run process_lineage -p entity_id=P-1234
    python -m cli graph run entities_by_mitre -p technique=T1546.011
    python -m cli graph run case_graph -p case_id=CASE-ABC123
    python -m cli graph run top_connected_entities -p min_degree=1

## Neo4j Browser tips

    MATCH (e:Entity) RETURN DISTINCT e.entity_type
    MATCH ()-[r]->() RETURN DISTINCT type(r)
    MATCH (e:Entity) RETURN e.entity_type, COUNT(*)

Klik tab **Graph** setelah query untuk visualisasi network.
