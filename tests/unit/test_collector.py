"""
Contract tests untuk data ingestion layer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from internal.collector import (
    Collector,
    CollectorResult,
    FileSource,
    SysmonCollector,
    WazuhCollector,
)
from internal.collector.wazuh import wazuh_level_to_severity
from pkg.models.event import (
    EventCategory,
    EventSource,
    Platform,
)


# ===========================================================================
# CollectorResult
# ===========================================================================

def test_collector_result_defaults():
    r = CollectorResult()
    assert r.events == []
    assert r.errors == []
    assert r.raw_count == 0


def test_collector_result_success_rate():
    r = CollectorResult(raw_count=10)
    r.events = [None] * 7  # type: ignore[list-item]
    r.errors = ["e1", "e2", "e3"]
    assert r.success_rate == 0.7


def test_collector_result_success_rate_empty():
    r = CollectorResult()
    assert r.success_rate == 0.0


# ===========================================================================
# Protocol
# ===========================================================================

def test_wazuh_implements_collector_protocol():
    c = WazuhCollector({})
    assert isinstance(c, Collector)


def test_sysmon_implements_collector_protocol():
    c = SysmonCollector({})
    assert isinstance(c, Collector)


def test_file_source_implements_collector_protocol(tmp_path):
    c = FileSource(tmp_path)
    assert isinstance(c, Collector)


# ===========================================================================
# Wazuh — level → severity
# ===========================================================================

def test_wazuh_level_to_severity_boundaries():
    assert wazuh_level_to_severity(0) == 0
    assert wazuh_level_to_severity(10) == 75
    assert wazuh_level_to_severity(15) == 100
    assert wazuh_level_to_severity(99) == 100
    assert wazuh_level_to_severity(-5) == 0


# ===========================================================================
# Wazuh — conversion
# ===========================================================================

def _make_wazuh_alert() -> dict:
    return {
        "id": "1606484225.12345",
        "timestamp": "2026-09-26T10:00:00.000+0000",
        "rule": {
            "id": "92058",
            "level": 10,
            "description": "Application Shimming detected",
            "mitre": {
                "id": ["T1546.011"],
                "tactic": ["Persistence"],
            },
            "groups": ["windows", "sysmon"],
        },
        "agent": {
            "id": "001",
            "name": "WIN-01",
        },
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "Image": "C:\\Windows\\System32\\sdbinst.exe",
                    "ProcessId": "4821",
                    "ParentProcessId": "812",
                    "ParentImage": "C:\\Windows\\System32\\svchost.exe",
                    "CommandLine": "sdbinst.exe -m -bg",
                    "User": "NT AUTHORITY\\SYSTEM",
                },
            }
        },
    }


def test_wazuh_single_alert():
    c = WazuhCollector(_make_wazuh_alert())
    result = c.collect()

    assert result.raw_count == 1
    assert result.success_count == 1
    assert result.error_count == 0

    ev = result.events[0]
    assert ev.source == EventSource.WAZUH
    assert ev.platform == Platform.WINDOWS
    assert ev.category == EventCategory.PROCESS
    assert ev.rule_id == "92058"
    assert ev.rule_level == 10
    assert ev.severity == 75
    assert ev.host == "WIN-01"
    assert "T1546.011" in ev.mitre_techniques
    assert ev.process is not None
    assert ev.process.name == "sdbinst.exe"
    assert ev.process.pid == 4821
    assert ev.process.parent_pid == 812
    assert ev.process.parent_name == "svchost.exe"


def test_wazuh_list_of_alerts():
    c = WazuhCollector([_make_wazuh_alert(), _make_wazuh_alert()])
    result = c.collect()
    assert result.raw_count == 2
    assert result.success_count == 2


def test_wazuh_from_file_json_array(tmp_path):
    f = tmp_path / "alerts.json"
    f.write_text(
        json.dumps([_make_wazuh_alert()]),
        encoding="utf-8",
    )
    c = WazuhCollector(f)
    result = c.collect()
    assert result.success_count == 1


def test_wazuh_from_file_ndjson(tmp_path):
    f = tmp_path / "alerts.ndjson"
    f.write_text(
        "\n".join([
            json.dumps(_make_wazuh_alert()),
            json.dumps(_make_wazuh_alert()),
        ]),
        encoding="utf-8",
    )
    c = WazuhCollector(f)
    result = c.collect()
    assert result.success_count == 2


def test_wazuh_from_file_wrapped_object(tmp_path):
    f = tmp_path / "alerts.json"
    f.write_text(
        json.dumps({"alerts": [_make_wazuh_alert()]}),
        encoding="utf-8",
    )
    c = WazuhCollector(f)
    result = c.collect()
    assert result.success_count == 1


def test_wazuh_file_not_found():
    c = WazuhCollector("/tmp/nonexistent-wazuh.json")
    result = c.collect()
    assert result.success_count == 0
    assert result.error_count >= 1


def test_wazuh_mitre_extracted():
    c = WazuhCollector(_make_wazuh_alert())
    result = c.collect()
    ev = result.events[0]
    assert ev.mitre_techniques == ["T1546.011"]
    # "Persistence" dinormalisasi ke TA0003
    assert ev.mitre_tactics == ["TA0003"]


def test_wazuh_mitre_tactic_unknown_skipped():
    """Tactic name yang tidak dikenal → di-skip, tidak raise."""
    alert = _make_wazuh_alert()
    alert["rule"]["mitre"]["tactic"] = ["WeirdTactic", "Persistence"]
    c = WazuhCollector(alert)
    result = c.collect()
    assert result.success_count == 1
    ev = result.events[0]
    # Hanya yang valid
    assert ev.mitre_tactics == ["TA0003"]


def test_wazuh_mitre_tactic_id_passthrough():
    """Kalau Wazuh sudah beri ID (TAxxxx), langsung dipakai."""
    alert = _make_wazuh_alert()
    alert["rule"]["mitre"]["tactic"] = ["TA0003"]
    c = WazuhCollector(alert)
    result = c.collect()
    ev = result.events[0]
    assert ev.mitre_tactics == ["TA0003"]


def test_wazuh_tags_from_groups():
    c = WazuhCollector(_make_wazuh_alert())
    result = c.collect()
    ev = result.events[0]
    assert "windows" in ev.tags
    assert "sysmon" in ev.tags


def test_wazuh_empty_payload():
    c = WazuhCollector([])
    result = c.collect()
    assert result.raw_count == 0
    assert result.success_count == 0


def test_wazuh_invalid_item_type():
    c = WazuhCollector([{"rule": {}}, "not-a-dict", {"rule": {}}])
    result = c.collect()
    assert result.success_count == 2
    assert result.error_count == 1


# ===========================================================================
# Sysmon
# ===========================================================================

def _make_sysmon_event(event_id: int = 1) -> dict:
    return {
        "EventID": event_id,
        "UtcTime": "2026-09-26 10:00:00.000",
        "Computer": "WIN-01",
        "User": "NT AUTHORITY\\SYSTEM",
        "Image": "C:\\Windows\\System32\\sdbinst.exe",
        "ProcessId": "4821",
        "ParentProcessId": "812",
        "ParentImage": "C:\\Windows\\System32\\svchost.exe",
        "CommandLine": "sdbinst.exe -m -bg",
        "Hashes": "MD5=aaa,SHA256=bbb",
    }


def test_sysmon_single_event():
    c = SysmonCollector(_make_sysmon_event())
    result = c.collect()

    assert result.success_count == 1
    ev = result.events[0]
    assert ev.source == EventSource.SYSMON
    assert ev.platform == Platform.WINDOWS
    assert ev.category == EventCategory.PROCESS
    assert ev.event_type == "process_creation"
    assert ev.host == "WIN-01"


def test_sysmon_process_extracted():
    c = SysmonCollector(_make_sysmon_event())
    result = c.collect()
    ev = result.events[0]
    assert ev.process is not None
    assert ev.process.name == "sdbinst.exe"
    assert ev.process.pid == 4821
    assert ev.process.parent_pid == 812
    assert ev.process.parent_name == "svchost.exe"
    assert ev.process.command_line == "sdbinst.exe -m -bg"


def test_sysmon_hashes_parsed():
    c = SysmonCollector(_make_sysmon_event())
    result = c.collect()
    ev = result.events[0]
    assert ev.process.hashes == {"md5": "aaa", "sha256": "bbb"}


def test_sysmon_event_id_3_network():
    item = _make_sysmon_event(event_id=3)
    c = SysmonCollector(item)
    result = c.collect()
    assert result.events[0].category == EventCategory.NETWORK


def test_sysmon_event_id_11_file():
    item = _make_sysmon_event(event_id=11)
    c = SysmonCollector(item)
    result = c.collect()
    assert result.events[0].category == EventCategory.FILE


def test_sysmon_event_id_22_dns():
    item = _make_sysmon_event(event_id=22)
    c = SysmonCollector(item)
    result = c.collect()
    assert result.events[0].category == EventCategory.DNS


def test_sysmon_from_file(tmp_path):
    f = tmp_path / "sysmon.json"
    f.write_text(
        json.dumps([_make_sysmon_event(), _make_sysmon_event(3)]),
        encoding="utf-8",
    )
    c = SysmonCollector(f)
    result = c.collect()
    assert result.success_count == 2


def test_sysmon_source_reliability_a():
    c = SysmonCollector(_make_sysmon_event())
    result = c.collect()
    assert result.events[0].source_reliability.value == "completely_reliable"


# ===========================================================================
# FileSource
# ===========================================================================

def _make_canonical_event_dict(event_id: str = "E-1") -> dict:
    return {
        "event_id": event_id,
        "timestamp": "2026-09-26T10:00:00Z",
        "source": "sysmon",
        "platform": "windows",
        "category": "process",
        "event_type": "process_creation",
        "severity": 70,
        "host": "WIN-01",
    }


def test_file_source_single_file(tmp_path):
    f = tmp_path / "events.json"
    f.write_text(
        json.dumps([_make_canonical_event_dict()]),
        encoding="utf-8",
    )
    result = FileSource(f).collect()
    assert result.success_count == 1


def test_file_source_directory(tmp_path):
    (tmp_path / "a.json").write_text(
        json.dumps([_make_canonical_event_dict("E-1")]),
        encoding="utf-8",
    )
    (tmp_path / "b.json").write_text(
        json.dumps([_make_canonical_event_dict("E-2")]),
        encoding="utf-8",
    )
    result = FileSource(tmp_path).collect()
    assert result.success_count == 2
    assert result.raw_count == 2


def test_file_source_wrapped_object(tmp_path):
    f = tmp_path / "wrapped.json"
    f.write_text(
        json.dumps({"events": [_make_canonical_event_dict()]}),
        encoding="utf-8",
    )
    result = FileSource(f).collect()
    assert result.success_count == 1


def test_file_source_missing_path():
    result = FileSource("/tmp/nonexistent-filesource").collect()
    assert result.error_count == 1
    assert result.success_count == 0


def test_file_source_invalid_json(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text("{not json", encoding="utf-8")
    result = FileSource(f).collect()
    assert result.error_count >= 1


def test_file_source_invalid_event(tmp_path):
    f = tmp_path / "bad.json"
    f.write_text(
        json.dumps([{"event_id": "E-1"}]),  # missing required
        encoding="utf-8",
    )
    result = FileSource(f).collect()
    assert result.error_count >= 1
