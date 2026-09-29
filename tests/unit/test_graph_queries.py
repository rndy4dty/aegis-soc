"""Contract tests untuk graph query presets — tidak butuh Neo4j."""
import re
import pytest
from internal.storage.graph.queries import PRESETS


def _sample(name: str) -> dict:
    if name == "process_lineage":
        return {"entity_id": "P-1"}
    if name == "entities_by_mitre":
        return {"technique": "T1546.011"}
    if name == "case_graph":
        return {"case_id": "CASE-1"}
    return {}


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_preset_has_limit(name: str) -> None:
    p = PRESETS[name](**_sample(name))
    assert re.search(r"\bLIMIT\b", p.cypher, re.I), f"{name}: no LIMIT"


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_all_params_declared(name: str) -> None:
    p = PRESETS[name](**_sample(name))
    used = set(re.findall(r"\$(\w+)", p.cypher))
    missing = used - set(p.params)
    assert not missing, f"{name}: missing params {missing}"


@pytest.mark.parametrize("name", sorted(PRESETS))
def test_metadata_filled(name: str) -> None:
    p = PRESETS[name](**_sample(name))
    assert p.name
    assert p.description
    assert p.category != ""


def test_presets_registry_has_nine() -> None:
    assert len(PRESETS) == 9
    assert "process_lineage" in PRESETS
    assert "lateral_movement" in PRESETS
