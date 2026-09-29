"""
Contract tests untuk EventToEvidenceConverter.

Menguji:
- konversi Event → Evidence (satu per event)
- mapping severity → strength
- mapping source_reliability → confidence
- mapping category → evidence type
- provenance lengkap
- content_hash terisi
- data lengkap (process, network, file, dll.)
- MITRE techniques tersimpan di data
- edge cases
"""

from datetime import datetime, timezone

import pytest

from internal.evidence.event_to_evidence import (
    CATEGORY_TO_EVIDENCE_TYPE,
    RELIABILITY_CONFIDENCE,
    SEVERITY_CRITICAL_THRESHOLD,
    SEVERITY_MODERATE_THRESHOLD,
    SEVERITY_STRONG_THRESHOLD,
    EventToEvidenceConverter,
    event_to_evidence,
    events_to_evidence,
)
from pkg.models.evidence import (
    Evidence,
    EvidenceStrength,
    EvidenceType,
)
from pkg.models.event import (
    DnsContext,
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
    RegistryContext,
    SourceReliability,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(**kwargs) -> Event:
    defaults = dict(
        event_id="E-1",
        timestamp=BASE,
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
    )
    defaults.update(kwargs)
    return Event(**defaults)


# ===========================================================================
# Basic
# ===========================================================================

def test_convert_minimal_event():
    ev = make_event(
        host="WIN-01",
        severity=50,
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    result = event_to_evidence(ev)

    assert len(result) == 1
    assert isinstance(result[0], Evidence)


def test_convert_many():
    events = [
        make_event(event_id="E-1", host="WIN-01", severity=50),
        make_event(event_id="E-2", host="WIN-02", severity=50),
    ]
    result = events_to_evidence(events)
    assert len(result) == 2


def test_empty_event_no_meaningful_content():
    """Tanpa severity, rule_id, mitre, atau context → tidak ada evidence."""
    ev = make_event(severity=0)
    result = event_to_evidence(ev, always_emit=False)
    assert result == []


def test_empty_event_with_always_emit():
    ev = make_event(severity=0)
    result = event_to_evidence(ev, always_emit=True)
    assert len(result) == 1


# ===========================================================================
# Severity → strength
# ===========================================================================

def test_strength_weak():
    ev = make_event(severity=20, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].strength == EvidenceStrength.WEAK


def test_strength_moderate():
    ev = make_event(severity=50, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].strength == EvidenceStrength.MODERATE


def test_strength_strong():
    ev = make_event(severity=75, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].strength == EvidenceStrength.STRONG


def test_strength_critical():
    ev = make_event(severity=90, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].strength == EvidenceStrength.CRITICAL


def test_strength_boundaries():
    assert event_to_evidence(make_event(severity=39))[0].strength \
        == EvidenceStrength.WEAK
    assert event_to_evidence(make_event(severity=40))[0].strength \
        == EvidenceStrength.MODERATE
    assert event_to_evidence(make_event(severity=69))[0].strength \
        == EvidenceStrength.MODERATE
    assert event_to_evidence(make_event(severity=70))[0].strength \
        == EvidenceStrength.STRONG
    assert event_to_evidence(make_event(severity=84))[0].strength \
        == EvidenceStrength.STRONG
    assert event_to_evidence(make_event(severity=85))[0].strength \
        == EvidenceStrength.CRITICAL


# ===========================================================================
# Source reliability → confidence
# ===========================================================================

def test_confidence_reliability_a():
    ev = make_event(
        severity=50,
        source_reliability=SourceReliability.A,
    )
    result = event_to_evidence(ev)
    assert result[0].confidence == 1.0


def test_confidence_reliability_b():
    ev = make_event(
        severity=50,
        source_reliability=SourceReliability.B,
    )
    result = event_to_evidence(ev)
    assert result[0].confidence == 0.85


def test_confidence_reliability_c_default():
    ev = make_event(severity=50)
    # default SourceReliability.C
    result = event_to_evidence(ev)
    assert result[0].confidence == 0.70


def test_confidence_reliability_f():
    ev = make_event(
        severity=50,
        source_reliability=SourceReliability.F,
    )
    result = event_to_evidence(ev)
    assert result[0].confidence == 0.20


# ===========================================================================
# Category → evidence type
# ===========================================================================

def test_category_process():
    ev = make_event(
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.PROCESS


def test_category_network():
    ev = make_event(
        category=EventCategory.NETWORK,
        event_type="network_connection",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.NETWORK


def test_category_http_maps_to_network():
    ev = make_event(
        category=EventCategory.HTTP,
        event_type="http_request",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.NETWORK


def test_category_dns():
    ev = make_event(
        category=EventCategory.DNS,
        event_type="dns_query",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.DNS


def test_category_authentication():
    ev = make_event(
        category=EventCategory.AUTHENTICATION,
        event_type="logon_success",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.AUTHENTICATION


def test_category_account_maps_to_authentication():
    ev = make_event(
        category=EventCategory.ACCOUNT,
        event_type="account_created",
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].evidence_type == EvidenceType.AUTHENTICATION


def test_all_categories_mapped():
    for cat in EventCategory:
        assert cat in CATEGORY_TO_EVIDENCE_TYPE


# ===========================================================================
# Provenance
# ===========================================================================

def test_provenance_event_id():
    ev = make_event(event_id="E-42", severity=50)
    result = event_to_evidence(ev)
    assert result[0].provenance.parent_event_id == "E-42"
    assert result[0].event_id == "E-42"


def test_provenance_source():
    ev = make_event(
        source=EventSource.WAZUH,
        severity=50,
    )
    result = event_to_evidence(ev)
    assert result[0].provenance.source == "wazuh"


def test_provenance_collector():
    ev = make_event(severity=50)
    result = event_to_evidence(ev)
    assert result[0].provenance.collector == "event_to_evidence"


def test_provenance_collected_at():
    ts = datetime(2026, 9, 26, 11, 0, tzinfo=timezone.utc)
    ev = make_event(timestamp=ts, severity=50)
    result = event_to_evidence(ev)
    assert result[0].provenance.collected_at == ts


def test_observed_at():
    ts = datetime(2026, 9, 26, 11, 0, tzinfo=timezone.utc)
    ev = make_event(timestamp=ts, severity=50)
    result = event_to_evidence(ev)
    assert result[0].observed_at == ts


# ===========================================================================
# Content hash
# ===========================================================================

def test_content_hash_present():
    ev = make_event(severity=50, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].integrity.content_hash is not None
    assert len(result[0].integrity.content_hash) == 64


def test_content_hash_verifiable():
    ev = make_event(severity=50, host="WIN-01")
    result = event_to_evidence(ev)
    assert result[0].verify_content_hash()


# ===========================================================================
# Data — context mapping
# ===========================================================================

def test_data_contains_process():
    ev = make_event(
        severity=50,
        process=ProcessContext(
            name="powershell.exe",
            pid=1234,
            parent_pid=800,
        ),
    )
    result = event_to_evidence(ev)
    data = result[0].data
    assert "process" in data
    assert data["process"]["name"] == "powershell.exe"
    assert data["process"]["pid"] == 1234


def test_data_contains_network():
    ev = make_event(
        category=EventCategory.NETWORK,
        event_type="network_connection",
        severity=50,
        network=NetworkContext(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            destination_port=443,
        ),
    )
    result = event_to_evidence(ev)
    data = result[0].data
    assert "network" in data
    assert data["network"]["destination_ip"] == "8.8.8.8"


def test_data_contains_file():
    ev = make_event(
        category=EventCategory.FILE,
        event_type="file_create",
        severity=50,
        file=FileContext(
            path="C:\\temp\\payload.exe",
            hashes={"sha256": "abc123"},
        ),
    )
    result = event_to_evidence(ev)
    data = result[0].data
    assert "file" in data
    assert data["file"]["path"] == "C:\\temp\\payload.exe"


def test_data_contains_registry():
    ev = make_event(
        category=EventCategory.REGISTRY,
        event_type="registry_modify",
        severity=50,
        registry=RegistryContext(
            key="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            value_name="Backdoor",
        ),
    )
    result = event_to_evidence(ev)
    data = result[0].data
    assert "registry" in data


def test_data_contains_dns():
    ev = make_event(
        category=EventCategory.DNS,
        event_type="dns_query",
        severity=50,
        dns=DnsContext(query="example.com", query_type="A"),
    )
    result = event_to_evidence(ev)
    data = result[0].data
    assert "dns" in data
    assert data["dns"]["query"] == "example.com"


# ===========================================================================
# MITRE
# ===========================================================================

def test_mitre_techniques_in_data():
    ev = make_event(
        severity=70,
        mitre_techniques=["T1546.011"],
    )
    result = event_to_evidence(ev)
    assert result[0].data["mitre_techniques"] == ["T1546.011"]


def test_mitre_tactics_in_data():
    ev = make_event(
        severity=70,
        mitre_tactics=["TA0003"],
    )
    result = event_to_evidence(ev)
    assert result[0].data["mitre_tactics"] == ["TA0003"]


# ===========================================================================
# Tenant / investigation propagation
# ===========================================================================

def test_tenant_propagated():
    ev = make_event(
        tenant_id="tenant-a",
        severity=50,
        host="WIN-01",
    )
    result = event_to_evidence(ev)
    assert result[0].tenant_id == "tenant-a"


def test_investigation_propagated():
    ev = make_event(
        investigation_id="INV-1",
        severity=50,
        host="WIN-01",
    )
    result = event_to_evidence(ev)
    assert result[0].case_id == "INV-1"


# ===========================================================================
# Title generation
# ===========================================================================

def test_title_process_event():
    ev = make_event(
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    result = event_to_evidence(ev)
    assert "powershell.exe" in result[0].title
    assert "1234" in result[0].title


def test_title_network_event():
    ev = make_event(
        category=EventCategory.NETWORK,
        event_type="network_connection",
        severity=50,
        network=NetworkContext(
            source_ip="10.0.0.1",
            destination_ip="8.8.8.8",
            destination_port=443,
        ),
    )
    result = event_to_evidence(ev)
    assert "10.0.0.1" in result[0].title
    assert "8.8.8.8" in result[0].title


def test_title_dns_event():
    ev = make_event(
        category=EventCategory.DNS,
        event_type="dns_query",
        severity=50,
        dns=DnsContext(query="example.com"),
    )
    result = event_to_evidence(ev)
    assert "example.com" in result[0].title


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_content_hash():
    ev = make_event(
        event_id="E-1",
        timestamp=BASE,
        severity=50,
        host="WIN-01",
    )
    r1 = event_to_evidence(ev)
    r2 = event_to_evidence(ev)

    assert r1[0].integrity.content_hash == r2[0].integrity.content_hash


def test_converter_reusable():
    converter = EventToEvidenceConverter()
    ev = make_event(severity=50, host="WIN-01")
    r1 = converter.convert(ev)
    r2 = converter.convert(ev)
    assert len(r1) == len(r2) == 1


# ===========================================================================
# Tags
# ===========================================================================

def test_tags_propagated():
    ev = make_event(
        severity=50,
        host="WIN-01",
        tags=["soc", "critical"],
    )
    result = event_to_evidence(ev)
    assert "soc" in result[0].tags
    assert "critical" in result[0].tags
