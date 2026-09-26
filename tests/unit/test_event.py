from datetime import datetime, timezone

from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
)


def test_wazuh_process_event():
    event = Event(
        event_id="evt-001",
        timestamp=datetime.now(timezone.utc),
        source=EventSource.WAZUH,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=70,
        host="WINDOWS-LAB",
        user="SYSTEM",
        rule_id="92058",
        rule_name="Application Shimming",
        mitre_techniques=["T1546.011"],
    )

    assert event.source == EventSource.WAZUH
    assert event.platform == Platform.WINDOWS
    assert event.category == EventCategory.PROCESS
    assert event.severity == 70
    assert event.rule_id == "92058"
    assert "T1546.011" in event.mitre_techniques


def test_process_context():
    event = Event(
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        event_type="process_creation",
        process={
            "name": "powershell.exe",
            "pid": 1234,
            "ppid": 1000,
            "command_line": "powershell.exe -enc ...",
        },
    )

    assert event.is_process_event
    assert event.is_windows
    assert event.process.name == "powershell.exe"
    assert event.process.pid == 1234


def test_network_event():
    event = Event(
        source=EventSource.NETWORK,
        platform=Platform.NETWORK,
        event_type="network_connection",
        network={
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "destination_port": 443,
            "protocol": "tcp",
        },
    )

    assert event.is_network_event
    assert event.network.protocol == "TCP"


def test_fingerprint_is_stable():
    event = Event(
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        event_type="process_creation",
        host="WINDOWS-LAB",
        user="SYSTEM",
        process={
            "name": "powershell.exe",
            "pid": 1234,
        },
    )

    fingerprint_1 = event.fingerprint()
    fingerprint_2 = event.fingerprint()

    assert fingerprint_1 == fingerprint_2
    assert len(fingerprint_1) == 64


def test_entities_are_extracted():
    event = Event(
        source=EventSource.WAZUH,
        platform=Platform.WINDOWS,
        event_type="process_creation",
        host="WINDOWS-LAB",
        user="SYSTEM",
        process={
            "name": "sdbinst.exe",
            "pid": 1234,
        },
        mitre_techniques=["T1546.011"],
    )

    entities = event.to_entities()

    values = {
        (entity["type"], entity["value"])
        for entity in entities
    }

    assert ("Host", "WINDOWS-LAB") in values
    assert ("User", "SYSTEM") in values
    assert ("Process", "sdbinst.exe") in values
    assert ("MITRE", "T1546.011") in values
