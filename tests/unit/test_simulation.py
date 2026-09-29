"""
Contract tests untuk attack simulation.
"""

from __future__ import annotations

import pytest

from internal.investigation.investigation_engine import investigate
from internal.simulation import (
    ATTACK_SCENARIOS,
    AttackScenario,
    build_scenario,
    list_scenarios,
)
from pkg.models.event import Event


# ===========================================================================
# Registry
# ===========================================================================

def test_scenarios_registered():
    names = list_scenarios()
    assert "shimming" in names
    assert "powershell_cradle" in names
    assert "credential_dump" in names
    assert "lateral_movement" in names


def test_scenarios_sorted():
    names = list_scenarios()
    assert names == sorted(names)


def test_scenario_metadata():
    for name, scenario in ATTACK_SCENARIOS.items():
        assert scenario.name == name
        assert scenario.title
        assert scenario.description
        assert scenario.mitre_techniques
        assert scenario.category


def test_scenario_mitre_format():
    for scenario in ATTACK_SCENARIOS.values():
        for tech in scenario.mitre_techniques:
            assert tech.startswith("T")
            assert tech[1:].replace(".", "").isdigit()


# ===========================================================================
# Build
# ===========================================================================

def test_build_shimming():
    events = build_scenario("shimming")
    assert len(events) >= 3
    assert all(isinstance(e, Event) for e in events)
    techs = {t for e in events for t in e.mitre_techniques}
    assert "T1546.011" in techs


def test_build_powershell_cradle():
    events = build_scenario("powershell_cradle")
    assert len(events) >= 4
    techs = {t for e in events for t in e.mitre_techniques}
    assert "T1059.001" in techs
    assert "T1105" in techs


def test_build_credential_dump():
    events = build_scenario("credential_dump")
    assert len(events) >= 3
    techs = {t for e in events for t in e.mitre_techniques}
    assert "T1003.001" in techs


def test_build_lateral_movement():
    events = build_scenario("lateral_movement")
    assert len(events) >= 3
    hosts = {e.host for e in events}
    assert "WIN-04" in hosts
    assert "WIN-05" in hosts


def test_build_unknown_scenario():
    with pytest.raises(KeyError, match="not found"):
        build_scenario("nonexistent")


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_build():
    a = build_scenario("shimming")
    b = build_scenario("shimming")
    assert [e.event_id for e in a] == [e.event_id for e in b]
    assert [e.timestamp for e in a] == [e.timestamp for e in b]


def test_timestamps_ordered():
    for name in list_scenarios():
        events = build_scenario(name)
        timestamps = [e.timestamp for e in events]
        assert timestamps == sorted(timestamps), name


# ===========================================================================
# End-to-end investigation
# ===========================================================================

def test_investigate_shimming_scenario():
    events = build_scenario("shimming")
    result = investigate(events, title="Shimming")

    assert result.evidence_count >= 3
    assert result.risk_score > 0
    assert result.hypothesis_count >= 1


def test_investigate_powershell_scenario():
    events = build_scenario("powershell_cradle")
    result = investigate(events, title="PowerShell Cradle")

    assert result.evidence_count >= 4
    assert result.risk_score > 30


def test_investigate_credential_dump_scenario():
    events = build_scenario("credential_dump")
    result = investigate(events, title="Credential Dump")

    assert result.risk_score > 30
    # Harus ada hypothesis tentang credential access
    hyp_statements = " ".join(
        h.statement.lower() for h in result.hypotheses
    )
    assert "credential" in hyp_statements or "lsass" in hyp_statements


def test_investigate_lateral_movement_scenario():
    events = build_scenario("lateral_movement")
    result = investigate(events, title="Lateral Movement")

    assert result.risk_score > 20
    assert result.graph.entity_count >= 4


def test_all_scenarios_investigable():
    """Sanity: semua scenario bisa di-investigate tanpa error."""
    for name in list_scenarios():
        events = build_scenario(name)
        result = investigate(events, title=f"Test {name}")
        assert result.evidence_count > 0
        assert result.case is not None
