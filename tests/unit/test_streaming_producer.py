"""
Contract tests untuk EventProducer.

Skip otomatis kalau Redis tidak tersedia.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import pytest

from internal.streaming import (
    EventProducer,
    StreamBus,
    load_events_from_file,
)
from internal.streaming.producer import DEFAULT_STREAM


def _redis_available() -> bool:
    try:
        bus = StreamBus(url="redis://localhost:6379/14")
        return bus.is_available()
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _redis_available(),
    reason="Redis not available",
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def bus():
    b = StreamBus(url="redis://localhost:6379/14")
    b.client.flushdb()
    yield b
    b.client.flushdb()


@pytest.fixture
def stream() -> str:
    return f"test-alerts-{uuid4().hex[:8]}"


@pytest.fixture
def producer(bus, stream) -> EventProducer:
    return EventProducer(bus=bus, stream=stream)


def _write_canonical(tmp_path: Path) -> Path:
    path = tmp_path / "events.json"
    path.write_text(json.dumps([
        {
            "event_id": "E-1",
            "timestamp": "2026-09-26T10:00:00Z",
            "source": "sysmon",
            "platform": "windows",
            "category": "process",
            "event_type": "process_creation",
            "severity": 85,
            "host": "WIN-01",
            "mitre_techniques": ["T1546.011"],
        },
        {
            "event_id": "E-2",
            "timestamp": "2026-09-26T10:00:05Z",
            "source": "sysmon",
            "platform": "windows",
            "category": "process",
            "event_type": "process_creation",
            "severity": 85,
            "host": "WIN-01",
            "mitre_techniques": ["T1546.011"],
        },
    ]), encoding="utf-8")
    return path


def _write_wazuh(tmp_path: Path) -> Path:
    path = tmp_path / "wazuh.json"
    path.write_text(json.dumps([{
        "id": "1606484225.1",
        "timestamp": "2026-09-26T10:00:00.000+0000",
        "rule": {
            "id": "92058",
            "level": 10,
            "description": "Application Shimming",
            "mitre": {"id": ["T1546.011"], "tactic": ["Persistence"]},
            "groups": ["windows", "sysmon"],
        },
        "agent": {"id": "001", "name": "WIN-01"},
        "data": {
            "win": {
                "system": {"eventID": "1"},
                "eventdata": {
                    "Image": "C:\\Windows\\System32\\sdbinst.exe",
                    "ProcessId": "4821",
                },
            }
        },
    }]), encoding="utf-8")
    return path


# ===========================================================================
# Loader
# ===========================================================================

def test_load_canonical(tmp_path):
    path = _write_canonical(tmp_path)
    events = load_events_from_file(path)
    assert len(events) == 2
    assert events[0].event_id == "E-1"


def test_load_wazuh(tmp_path):
    path = _write_wazuh(tmp_path)
    events = load_events_from_file(path)
    assert len(events) == 1
    assert events[0].rule_id == "92058"
    assert events[0].host == "WIN-01"


def test_load_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_events_from_file(Path("/tmp/nonexistent-xyz.json"))


def test_load_invalid_json(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_events_from_file(path)


def test_load_unrecognized_format(tmp_path):
    path = tmp_path / "weird.json"
    path.write_text(json.dumps([{"foo": "bar"}]), encoding="utf-8")
    with pytest.raises(ValueError, match="unrecognized"):
        load_events_from_file(path)


# ===========================================================================
# Publish
# ===========================================================================

def test_publish_event(producer, bus):
    from pkg.models.event import Event, EventSource, Platform, EventCategory

    ev = Event(
        event_id="E-1",
        timestamp="2026-09-26T10:00:00Z",
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=85,
        host="WIN-01",
    )
    msg_id = producer.publish_event(ev)
    assert isinstance(msg_id, str)
    assert bus.stream_length(producer.stream) == 1


def test_publish_from_canonical_file(producer, bus, tmp_path):
    path = _write_canonical(tmp_path)
    count = producer.publish_from_file(path)
    assert count == 2
    assert bus.stream_length(producer.stream) == 2


def test_publish_from_wazuh_file(producer, bus, tmp_path):
    path = _write_wazuh(tmp_path)
    count = producer.publish_from_file(path)
    assert count == 1
    assert bus.stream_length(producer.stream) == 1


def test_published_data_can_be_consumed(producer, bus, tmp_path):
    path = _write_canonical(tmp_path)
    producer.publish_from_file(path)

    bus.ensure_group(producer.stream, "g1", start_id="0")
    messages = bus.consume(producer.stream, "g1", "w-1", block_ms=100)
    assert len(messages) == 2
    # Data ter-serialize dengan benar
    assert "event_id" in messages[0].data
    assert messages[0].data["event_id"] == "E-1"
    # MITRE tersimpan sebagai JSON string karena list
    assert "T1546.011" in messages[0].data["mitre_techniques"]


def test_default_stream():
    assert DEFAULT_STREAM == "aegis.alerts"
