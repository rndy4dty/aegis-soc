"""
Contract tests untuk detection layer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from internal.detection import (
    DetectionEngine,
    DetectionFinding,
    LOLBinDetector,
    Severity,
    SigmaRuleLoader,
)
from internal.detection.sigma_loader import SigmaRule
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


def make_event(
    *,
    event_id: str = "E-1",
    process_name: str | None = "sdbinst.exe",
    parent_name: str | None = "svchost.exe",
    command_line: str | None = "sdbinst.exe -m -bg",
    host: str = "WIN-01",
    user: str = "SYSTEM",
    severity: int = 50,
    category: EventCategory = EventCategory.PROCESS,
) -> Event:
    process = None
    if process_name is not None:
        process = ProcessContext(
            name=process_name,
            pid=1234,
            parent_name=parent_name,
            parent_pid=800,
            command_line=command_line,
        )
    return Event(
        event_id=event_id,
        timestamp="2026-09-26T10:00:00Z",
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=category,
        event_type="process_creation",
        severity=severity,
        host=host,
        user=user,
        process=process,
    )


# ===========================================================================
# Severity
# ===========================================================================

def test_severity_values():
    assert Severity.INFO.value == 10
    assert Severity.LOW.value == 30
    assert Severity.MEDIUM.value == 50
    assert Severity.HIGH.value == 70
    assert Severity.CRITICAL.value == 90


# ===========================================================================
# DetectionFinding
# ===========================================================================

def test_finding_severity_score():
    f = DetectionFinding(
        rule_id="x",
        rule_name="X",
        severity=Severity.HIGH,
        event_id="E-1",
    )
    assert f.severity_score == 70


# ===========================================================================
# LOLBin
# ===========================================================================

def test_lolbin_detects_sdbinst():
    d = LOLBinDetector()
    findings = d.evaluate(make_event(process_name="sdbinst.exe"))
    assert len(findings) == 1
    assert findings[0].rule_id == "lolbin.sdbinst.exe"
    assert "T1546.011" in findings[0].mitre_techniques


def test_lolbin_detects_certutil():
    d = LOLBinDetector()
    findings = d.evaluate(make_event(process_name="certutil.exe"))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_lolbin_case_insensitive():
    d = LOLBinDetector()
    findings = d.evaluate(make_event(process_name="SDBINST.EXE"))
    assert len(findings) == 1


def test_lolbin_basename():
    d = LOLBinDetector()
    findings = d.evaluate(
        make_event(process_name="C:\\Windows\\System32\\sdbinst.exe")
    )
    assert len(findings) == 1


def test_lolbin_no_match():
    d = LOLBinDetector()
    findings = d.evaluate(make_event(process_name="notepad.exe"))
    assert findings == []


def test_lolbin_skips_non_process():
    d = LOLBinDetector()
    findings = d.evaluate(
        make_event(category=EventCategory.NETWORK, process_name=None)
    )
    assert findings == []


def test_lolbin_min_severity_filter():
    d = LOLBinDetector(min_severity=Severity.HIGH)
    findings = d.evaluate(make_event(process_name="wscript.exe"))
    # wscript = MEDIUM, harus tersaring
    assert findings == []


def test_lolbin_empty_registry():
    d = LOLBinDetector(registry={})
    findings = d.evaluate(make_event(process_name="sdbinst.exe"))
    assert findings == []


def test_lolbin_id_and_name():
    d = LOLBinDetector()
    assert d.id() == "lolbin"
    assert d.name() == "LOLBin Detector"


# ===========================================================================
# Sigma
# ===========================================================================

def _sample_sigma_rule() -> dict:
    return {
        "id": "aegis-001",
        "title": "Sdbinst via svchost",
        "level": "high",
        "detection": {
            "selection": {
                "process.name": "sdbinst.exe",
                "process.parent_name": "svchost.exe",
            },
            "condition": "selection",
        },
        "tags": ["attack.persistence", "attack.t1546.011"],
    }


def test_sigma_rule_match():
    rule = SigmaRule(_sample_sigma_rule())
    findings = rule.evaluate(make_event())
    assert len(findings) == 1
    assert findings[0].rule_id == "aegis-001"
    assert findings[0].severity == Severity.HIGH


def test_sigma_rule_no_match():
    rule = SigmaRule(_sample_sigma_rule())
    findings = rule.evaluate(
        make_event(process_name="notepad.exe")
    )
    assert findings == []


def test_sigma_rule_mitre_extracted():
    rule = SigmaRule(_sample_sigma_rule())
    assert "T1546.011" in rule.mitre_techniques()


def test_sigma_wildcard_match():
    rule = SigmaRule({
        "id": "aegis-wild",
        "title": "Wildcard test",
        "level": "medium",
        "detection": {
            "selection": {
                "process.name": "sdb*",
            },
            "condition": "selection",
        },
    })
    findings = rule.evaluate(make_event(process_name="sdbinst.exe"))
    assert len(findings) == 1


def test_sigma_list_value():
    rule = SigmaRule({
        "id": "aegis-list",
        "title": "List test",
        "level": "medium",
        "detection": {
            "selection": {
                "process.name": ["cmd.exe", "sdbinst.exe"],
            },
            "condition": "selection",
        },
    })
    findings = rule.evaluate(make_event(process_name="sdbinst.exe"))
    assert len(findings) == 1


def test_sigma_substring_command_line():
    rule = SigmaRule({
        "id": "aegis-cl",
        "title": "CL test",
        "level": "medium",
        "detection": {
            "selection": {
                "process.command_line": "-m -bg",
            },
            "condition": "selection",
        },
    })
    findings = rule.evaluate(
        make_event(command_line="sdbinst.exe -m -bg --flag")
    )
    assert len(findings) == 1


def test_sigma_and_condition():
    rule = SigmaRule({
        "id": "aegis-and",
        "title": "AND test",
        "level": "high",
        "detection": {
            "s1": {"process.name": "sdbinst.exe"},
            "s2": {"process.parent_name": "svchost.exe"},
            "condition": "s1 and s2",
        },
    })
    findings = rule.evaluate(make_event())
    assert len(findings) == 1


def test_sigma_and_condition_partial_no_match():
    rule = SigmaRule({
        "id": "aegis-and2",
        "title": "AND partial",
        "level": "high",
        "detection": {
            "s1": {"process.name": "sdbinst.exe"},
            "s2": {"process.parent_name": "explorer.exe"},
            "condition": "s1 and s2",
        },
    })
    findings = rule.evaluate(make_event())
    assert findings == []


def test_sigma_or_condition():
    rule = SigmaRule({
        "id": "aegis-or",
        "title": "OR test",
        "level": "medium",
        "detection": {
            "s1": {"process.name": "nonexistent.exe"},
            "s2": {"process.name": "sdbinst.exe"},
            "condition": "s1 or s2",
        },
    })
    findings = rule.evaluate(make_event())
    assert len(findings) == 1


def test_sigma_1_of_wildcard():
    rule = SigmaRule({
        "id": "aegis-1of",
        "title": "1 of wildcard",
        "level": "medium",
        "detection": {
            "sel_a": {"process.name": "sdbinst.exe"},
            "sel_b": {"process.name": "nonexistent.exe"},
            "condition": "1 of sel_*",
        },
    })
    findings = rule.evaluate(make_event())
    assert len(findings) == 1


def test_sigma_all_of_wildcard():
    rule = SigmaRule({
        "id": "aegis-allof",
        "title": "all of wildcard",
        "level": "high",
        "detection": {
            "sel_a": {"process.name": "sdbinst.exe"},
            "sel_b": {"process.parent_name": "svchost.exe"},
            "condition": "all of sel_*",
        },
    })
    findings = rule.evaluate(make_event())
    assert len(findings) == 1


def test_sigma_all_of_wildcard_partial():
    rule = SigmaRule({
        "id": "aegis-allof2",
        "title": "all of wildcard partial",
        "level": "high",
        "detection": {
            "sel_a": {"process.name": "sdbinst.exe"},
            "sel_b": {"process.parent_name": "explorer.exe"},
            "condition": "all of sel_*",
        },
    })
    findings = rule.evaluate(make_event())
    assert findings == []


# ===========================================================================
# SigmaRuleLoader
# ===========================================================================

def test_sigma_loader_add_rule():
    loader = SigmaRuleLoader()
    loader.add_rule(_sample_sigma_rule())
    assert len(loader.rules()) == 1


def test_sigma_loader_load_file(tmp_path: Path):
    f = tmp_path / "rules.json"
    f.write_text(
        json.dumps([_sample_sigma_rule()]),
        encoding="utf-8",
    )
    loader = SigmaRuleLoader()
    count = loader.load_file(f)
    assert count == 1
    assert len(loader.rules()) == 1


def test_sigma_loader_load_directory(tmp_path: Path):
    (tmp_path / "r1.json").write_text(
        json.dumps([_sample_sigma_rule()]),
        encoding="utf-8",
    )
    (tmp_path / "r2.json").write_text(
        json.dumps({
            "id": "aegis-002",
            "title": "Second",
            "level": "low",
            "detection": {
                "selection": {"process.name": "notepad.exe"},
                "condition": "selection",
            },
        }),
        encoding="utf-8",
    )
    loader = SigmaRuleLoader()
    count = loader.load_file(tmp_path)
    assert count == 2


def test_sigma_loader_missing_file():
    loader = SigmaRuleLoader()
    with pytest.raises(FileNotFoundError):
        loader.load_file("/tmp/nonexistent-rules.json")


def test_sigma_loader_evaluate():
    loader = SigmaRuleLoader([_sample_sigma_rule()])
    findings = loader.evaluate(make_event())
    assert len(findings) == 1


# ===========================================================================
# DetectionEngine
# ===========================================================================

def test_engine_default_lolbin():
    engine = DetectionEngine()
    findings = engine.detect(make_event(process_name="sdbinst.exe"))
    assert len(findings) >= 1


def test_engine_with_sigma():
    loader = SigmaRuleLoader([_sample_sigma_rule()])
    engine = DetectionEngine(
        rules=[LOLBinDetector()],
        sigma_loader=loader,
    )
    findings = engine.detect(make_event())
    # LOLBin + Sigma = 2 finding
    assert len(findings) == 2


def test_engine_detect_many():
    engine = DetectionEngine()
    events = [
        make_event(event_id="E-1", process_name="sdbinst.exe"),
        make_event(event_id="E-2", process_name="certutil.exe"),
    ]
    findings = engine.detect_many(events)
    assert len(findings) >= 2


def test_engine_sorted_by_severity():
    loader = SigmaRuleLoader([
        {
            "id": "low",
            "title": "Low sev",
            "level": "low",
            "detection": {
                "selection": {"process.name": "sdbinst.exe"},
                "condition": "selection",
            },
        },
    ])
    engine = DetectionEngine(sigma_loader=loader)
    findings = engine.detect(make_event())
    # Sorted: severity desc, lalu rule_id
    severities = [f.severity.value for f in findings]
    assert severities == sorted(severities, reverse=True)


def test_engine_stats():
    engine = DetectionEngine()
    events = [
        make_event(event_id="E-1", process_name="sdbinst.exe"),
        make_event(event_id="E-2", process_name="certutil.exe"),
    ]
    findings = engine.detect_many(events)
    stats = engine.stats(findings)
    assert stats["total"] >= 2
    assert "lolbin.sdbinst.exe" in stats["by_rule"]
    assert "HIGH" in stats["by_severity"] or "CRITICAL" in stats["by_severity"]


def test_engine_deterministic():
    engine = DetectionEngine()
    ev = make_event()
    a = engine.detect(ev)
    b = engine.detect(ev)
    assert [f.rule_id for f in a] == [f.rule_id for f in b]
