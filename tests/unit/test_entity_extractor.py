"""
Contract tests untuk EntityExtractor.

Menguji:
- ekstraksi tiap EntityType dari Event
- normalisasi identity (host, user, domain, hash, MITRE)
- user local vs domain
- process instance identity (PID/GUID/name_only)
- parent process identity via parent_guid
- deduplication by fingerprint
- provenance & tenant isolation
- determinisme output (termasuk urutan)
- edge case: context yang tidak tersedia
- MITRE input coercion hardening
"""

from datetime import datetime, timezone

import pytest

from internal.graph.entity_extractor import (
    IDENTITY_QUALITY_GUID,
    IDENTITY_QUALITY_NAME_ONLY,
    IDENTITY_QUALITY_PID,
    PROPERTY_IDENTITY_QUALITY,
    EntityExtractor,
    extract_entities,
)
from pkg.models.entity import Entity, EntityType
from pkg.models.event import (
    DnsContext,
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
    UserContext,
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


def only(entities, entity_type):
    return [e for e in entities if e.entity_type == entity_type]


# ===========================================================================
# HOST
# ===========================================================================

def test_extract_host():
    entities = extract_entities(make_event(host="WIN-01"))
    hosts = only(entities, EntityType.HOST)
    assert len(hosts) == 1
    assert hosts[0].value == "WIN-01"
    assert hosts[0].normalized_value == "win-01"
    assert hosts[0].fingerprint is not None


def test_no_host_no_host_entity():
    entities = extract_entities(make_event())
    assert only(entities, EntityType.HOST) == []


# ===========================================================================
# USER — local
# ===========================================================================

def test_extract_local_user():
    entities = extract_entities(
        make_event(host="WIN-01", user="Administrator")
    )
    users = only(entities, EntityType.USER)
    assert len(users) == 1
    assert users[0].value == "Administrator"
    assert users[0].normalized_value == "administrator"
    assert users[0].identity_scope == "local"
    assert users[0].host == "win-01"


def test_ambiguous_user_skipped():
    """User tanpa host dan tanpa domain -> skip, tidak buat entity ambigu."""
    entities = extract_entities(make_event(user="ghost"))
    assert only(entities, EntityType.USER) == []


# ===========================================================================
# USER — domain
# ===========================================================================

def test_extract_domain_user():
    e = make_event(
        host="WIN-01",
        user="ren",
        user_context=UserContext(name="ren", domain="CORP"),
    )
    entities = extract_entities(e)
    users = only(entities, EntityType.USER)
    assert len(users) == 1
    assert users[0].value == "ren"
    assert users[0].normalized_value == "ren"
    assert users[0].identity_scope == "domain"
    assert users[0].identity_domain == "corp"


def test_domain_user_ignores_host_for_identity():
    e1 = make_event(
        event_id="E-1", host="WIN-01", user="ren",
        user_context=UserContext(name="ren", domain="CORP"),
    )
    e2 = make_event(
        event_id="E-2", host="WIN-99", user="ren",
        user_context=UserContext(name="ren", domain="CORP"),
    )
    u1 = only(extract_entities(e1), EntityType.USER)[0]
    u2 = only(extract_entities(e2), EntityType.USER)[0]
    assert u1.fingerprint == u2.fingerprint


def test_local_user_identity_depends_on_host():
    e1 = make_event(event_id="E-1", host="WIN-01", user="Administrator")
    e2 = make_event(event_id="E-2", host="WIN-99", user="Administrator")
    u1 = only(extract_entities(e1), EntityType.USER)[0]
    u2 = only(extract_entities(e2), EntityType.USER)[0]
    assert u1.fingerprint != u2.fingerprint


# ===========================================================================
# PROCESS — dasar
# ===========================================================================

def test_extract_process():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    procs = only(extract_entities(e), EntityType.PROCESS)
    assert len(procs) == 1
    assert procs[0].value == "powershell.exe"
    assert procs[0].host == "win-01"
    assert procs[0].properties["pid"] == 1234


def test_extract_process_with_parent():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    procs = only(extract_entities(e), EntityType.PROCESS)
    assert len(procs) == 2
    names = {p.value for p in procs}
    assert names == {"cmd.exe", "powershell.exe"}


def test_process_without_host_skipped():
    e = make_event(
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    assert only(extract_entities(e), EntityType.PROCESS) == []


def test_process_without_name_skipped():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(pid=1234),
    )
    assert only(extract_entities(e), EntityType.PROCESS) == []


# ===========================================================================
# PROCESS — identity quality
# ===========================================================================

def test_process_identity_quality_guid():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="powershell.exe", pid=1234, guid="G-1",
        ),
    )
    p = only(extract_entities(e), EntityType.PROCESS)[0]
    assert p.properties[PROPERTY_IDENTITY_QUALITY] == IDENTITY_QUALITY_GUID
    assert "guid:g-1" in p.normalized_value


def test_process_identity_quality_pid():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    p = only(extract_entities(e), EntityType.PROCESS)[0]
    assert p.properties[PROPERTY_IDENTITY_QUALITY] == IDENTITY_QUALITY_PID
    assert "pid:1234" in p.normalized_value


def test_process_identity_quality_name_only_fallback():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(name="powershell.exe"),
    )
    procs = only(extract_entities(e), EntityType.PROCESS)
    assert len(procs) == 1
    assert (
        procs[0].properties[PROPERTY_IDENTITY_QUALITY]
        == IDENTITY_QUALITY_NAME_ONLY
    )
    # name_only tidak pakai prefix
    assert procs[0].normalized_value == "powershell.exe"


def test_same_process_same_pid_same_identity():
    e1 = make_event(
        event_id="E-1", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    e2 = make_event(
        event_id="E-2", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    p1 = only(extract_entities(e1), EntityType.PROCESS)[0]
    p2 = only(extract_entities(e2), EntityType.PROCESS)[0]
    assert p1.fingerprint == p2.fingerprint


def test_different_pid_different_identity():
    e1 = make_event(
        event_id="E-1", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    e2 = make_event(
        event_id="E-2", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=5678),
    )
    p1 = only(extract_entities(e1), EntityType.PROCESS)[0]
    p2 = only(extract_entities(e2), EntityType.PROCESS)[0]
    assert p1.fingerprint != p2.fingerprint


def test_process_guid_preferred_over_pid():
    e1 = make_event(
        event_id="E-1", host="WIN-01",
        process=ProcessContext(
            name="powershell.exe", pid=1234, guid="G-1",
        ),
    )
    e2 = make_event(
        event_id="E-2", host="WIN-01",
        process=ProcessContext(
            name="powershell.exe", pid=5678, guid="G-1",
        ),
    )
    p1 = only(extract_entities(e1), EntityType.PROCESS)[0]
    p2 = only(extract_entities(e2), EntityType.PROCESS)[0]
    assert p1.fingerprint == p2.fingerprint


def test_name_only_does_not_merge_with_pid_instance():
    """
    name_only dan name+pid punya normalized_value berbeda,
    jadi fingerprint berbeda.
    """
    e_name = make_event(
        event_id="E-A", host="WIN-01",
        process=ProcessContext(name="powershell.exe"),
    )
    e_pid = make_event(
        event_id="E-B", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    p_name = only(extract_entities(e_name), EntityType.PROCESS)[0]
    p_pid = only(extract_entities(e_pid), EntityType.PROCESS)[0]
    assert p_name.fingerprint != p_pid.fingerprint


# ===========================================================================
# PROCESS — parent identity
# ===========================================================================

def test_parent_guid_used_when_available():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            parent_guid="PARENT-GUID-1",
        ),
    )
    procs = only(extract_entities(e), EntityType.PROCESS)
    parent = next(p for p in procs if p.value == "powershell.exe")

    assert "guid:parent-guid-1" in parent.normalized_value
    assert (
        parent.properties[PROPERTY_IDENTITY_QUALITY]
        == IDENTITY_QUALITY_GUID
    )


def test_parent_guid_identity_matches_child_guid():
    """
    Parent dari event A (dengan parent_guid) harus punya identity yang
    sama dengan process yang direferensikan di event B (dengan guid).
    """
    e_a = make_event(
        event_id="E-A",
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            parent_guid="PS-GUID",
        ),
    )
    e_b = make_event(
        event_id="E-B",
        host="WIN-01",
        process=ProcessContext(
            name="powershell.exe", pid=9999,
            guid="PS-GUID",
        ),
    )
    parent_from_a = next(
        p for p in only(extract_entities(e_a), EntityType.PROCESS)
        if p.value == "powershell.exe"
    )
    child_from_b = only(extract_entities(e_b), EntityType.PROCESS)[0]

    assert parent_from_a.fingerprint == child_from_b.fingerprint


def test_parent_falls_back_to_pid_without_guid():
    e = make_event(
        host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            parent_guid=None,
        ),
    )
    procs = only(extract_entities(e), EntityType.PROCESS)
    parent = next(p for p in procs if p.value == "powershell.exe")
    assert "pid:1234" in parent.normalized_value
    assert (
        parent.properties[PROPERTY_IDENTITY_QUALITY]
        == IDENTITY_QUALITY_PID
    )


def test_parent_and_child_same_normalized_format():
    """
    Parent dari event A dan child dari event B dengan PID sama
    -> identity sama.
    """
    e1 = make_event(
        event_id="E-1", host="WIN-01",
        process=ProcessContext(
            name="cmd.exe", pid=2000,
            parent_name="powershell.exe", parent_pid=1234,
        ),
    )
    e2 = make_event(
        event_id="E-2", host="WIN-01",
        process=ProcessContext(name="powershell.exe", pid=1234),
    )
    procs1 = {
        p.value: p for p in only(extract_entities(e1), EntityType.PROCESS)
    }
    procs2 = {
        p.value: p for p in only(extract_entities(e2), EntityType.PROCESS)
    }
    assert procs1["powershell.exe"].fingerprint == (
        procs2["powershell.exe"].fingerprint
    )


# ===========================================================================
# FILE
# ===========================================================================

def test_extract_file():
    e = make_event(
        host="WIN-01",
        file=FileContext(path="C:\\temp\\payload.exe"),
    )
    files = only(extract_entities(e), EntityType.FILE)
    assert len(files) == 1
    assert files[0].value == "C:\\temp\\payload.exe"
    # Windows: lowercase
    assert files[0].normalized_value == "c:\\temp\\payload.exe"


def test_extract_file_no_path_uses_name():
    e = make_event(
        host="WIN-01",
        file=FileContext(name="payload.exe"),
    )
    files = only(extract_entities(e), EntityType.FILE)
    assert len(files) == 1
    assert files[0].value == "payload.exe"


def test_no_file_no_file_entity():
    e = make_event(host="WIN-01")
    assert only(extract_entities(e), EntityType.FILE) == []


# ===========================================================================
# HASH
# ===========================================================================

def test_extract_hash():
    # Catatan: FileContext._normalize_hashes di event.py sudah lowercase
    # value hash saat Event dibuat. Jadi extractor menerima "abc123".
    e = make_event(
        host="WIN-01",
        file=FileContext(
            path="C:\\temp\\payload.exe",
            hashes={"sha256": "ABC123"},
        ),
    )
    hashes = only(extract_entities(e), EntityType.HASH)
    assert len(hashes) == 1
    assert hashes[0].value == "abc123"
    assert hashes[0].normalized_value == "abc123"
    assert hashes[0].hash_algorithm == "sha256"

def test_extract_multiple_hashes():
    e = make_event(
        file=FileContext(
            path="/tmp/x",
            hashes={"md5": "aaa", "sha256": "bbb"},
        ),
    )
    hashes = only(extract_entities(e), EntityType.HASH)
    assert len(hashes) == 2
    algos = {h.hash_algorithm for h in hashes}
    assert algos == {"md5", "sha256"}


def test_hash_distinguishes_algorithm():
    e1 = make_event(
        file=FileContext(path="/tmp/x", hashes={"md5": "abc"}),
    )
    e2 = make_event(
        file=FileContext(path="/tmp/x", hashes={"sha256": "abc"}),
    )
    h1 = only(extract_entities(e1), EntityType.HASH)[0]
    h2 = only(extract_entities(e2), EntityType.HASH)[0]
    assert h1.fingerprint != h2.fingerprint


# ===========================================================================
# IP
# ===========================================================================

def test_extract_source_ip():
    e = make_event(network=NetworkContext(source_ip="10.0.0.1"))
    ips = only(extract_entities(e), EntityType.IP)
    assert len(ips) == 1
    assert ips[0].value == "10.0.0.1"
    assert ips[0].normalized_value == "10.0.0.1"


def test_extract_destination_ip():
    e = make_event(network=NetworkContext(destination_ip="8.8.8.8"))
    ips = only(extract_entities(e), EntityType.IP)
    assert len(ips) == 1
    assert ips[0].value == "8.8.8.8"


def test_dedup_same_ip():
    e = make_event(
        network=NetworkContext(
            source_ip="8.8.8.8",
            destination_ip="8.8.8.8",
        ),
    )
    ips = only(extract_entities(e), EntityType.IP)
    assert len(ips) == 1


def test_no_network_no_ip():
    e = make_event(host="WIN-01")
    assert only(extract_entities(e), EntityType.IP) == []


# ===========================================================================
# DOMAIN
# ===========================================================================

def test_extract_domain_lowercased():
    entities = extract_entities(make_event(domain="Example.COM"))
    domains = only(entities, EntityType.DOMAIN)
    assert len(domains) == 1
    assert domains[0].value == "Example.COM"
    assert domains[0].normalized_value == "example.com"


def test_extract_domain_strips_trailing_dot():
    entities = extract_entities(make_event(domain="Example.COM."))
    domains = only(entities, EntityType.DOMAIN)
    assert len(domains) == 1
    assert domains[0].normalized_value == "example.com"


def test_extract_dns_query():
    e = make_event(dns=DnsContext(query="example.com."))
    domains = only(extract_entities(e), EntityType.DOMAIN)
    assert len(domains) == 1
    assert domains[0].normalized_value == "example.com"


def test_domain_and_dns_deduped():
    e = make_event(
        domain="example.com",
        dns=DnsContext(query="EXAMPLE.com."),
    )
    domains = only(extract_entities(e), EntityType.DOMAIN)
    assert len(domains) == 1


# ===========================================================================
# MITRE
# ===========================================================================

def test_extract_mitre():
    e = make_event(mitre_techniques=["T1059.001"])
    mitres = only(extract_entities(e), EntityType.MITRE_TECHNIQUE)
    assert len(mitres) == 1
    assert mitres[0].value == "T1059.001"
    assert mitres[0].normalized_value == "T1059.001"


def test_extract_multiple_mitre():
    e = make_event(mitre_techniques=["T1059.001", "T1105"])
    mitres = only(extract_entities(e), EntityType.MITRE_TECHNIQUE)
    assert len(mitres) == 2
    assert {m.value for m in mitres} == {"T1059.001", "T1105"}


def test_mitre_deduped():
    e = make_event(mitre_techniques=["T1059.001", "T1059.001"])
    mitres = only(extract_entities(e), EntityType.MITRE_TECHNIQUE)
    assert len(mitres) == 1


def test_mitre_lowercase_via_duck_typed_event_normalized_to_uppercase():
    """
    Event Pydantic strict: hanya menerima teknik yang sudah uppercase
    dan format valid. Untuk menguji normalisasi uppercase di extractor,
    kita pakai objek duck-typed.
    """
    raw_event = {
        "event_id": "E-1",
        "tenant_id": None,
        "timestamp": BASE,
        "platform": "windows",
        "host": "WIN-01",
        "mitre_techniques": ["t1059.001"],
    }
    entities = extract_entities(raw_event)
    mitres = only(entities, EntityType.MITRE_TECHNIQUE)
    assert len(mitres) == 1
    assert mitres[0].value == "t1059.001"
    assert mitres[0].normalized_value == "T1059.001"

# ===========================================================================
# MITRE — input coercion hardening
# ===========================================================================
#
# Event._validate_mitre_techniques sudah strict: harus list[str] dengan
# format "T...". Jadi coercion tidak bisa diuji lewat Event.
#
# Extractor menerima `Any`, sehingga kita uji dua level:
#   1. helper _coerce_mitre_collection() secara langsung
#   2. extractor via objek duck-typed (dict) untuk memastikan jalur
#      ekstrasi tetap aman kalau inputnya bukan Event Pydantic
#

def test_coerce_mitre_string_single_technique():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    result = _coerce_mitre_collection("T1059.001")
    assert result == ["T1059.001"]


def test_coerce_mitre_string_not_split_into_characters():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    result = _coerce_mitre_collection("T1059.001")
    # Bukan ["T", "1", "0", "5", ...]
    assert result != list("T1059.001")


def test_coerce_mitre_none_returns_empty():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    assert _coerce_mitre_collection(None) == []


def test_coerce_mitre_invalid_type_returns_empty():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    assert _coerce_mitre_collection(12345) == []
    assert _coerce_mitre_collection(object()) == []


def test_coerce_mitre_set_is_sorted():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    result = _coerce_mitre_collection({"T1105", "T1059.001"})
    assert result == ["T1059.001", "T1105"]


def test_coerce_mitre_list_preserved():
    from internal.graph.entity_extractor import _coerce_mitre_collection
    assert _coerce_mitre_collection(["T1059.001", "T1105"]) == [
        "T1059.001", "T1105",
    ]


def test_mitre_coercion_via_duck_typed_event():
    """
    Extractor menerima Any. Kita kirim dict yang menyerupai Event
    dengan mitre_techniques bertipe string. Harus tetap aman.
    """
    raw_event = {
        "event_id": "E-1",
        "tenant_id": None,
        "timestamp": BASE,
        "platform": "windows",
        "host": "WIN-01",
        "mitre_techniques": "T1059.001",   # string, bukan list
    }
    entities = extract_entities(raw_event)
    mitres = only(entities, EntityType.MITRE_TECHNIQUE)
    assert len(mitres) == 1
    assert mitres[0].value == "T1059.001"


def test_mitre_coercion_via_duck_typed_event_none():
    raw_event = {
        "event_id": "E-1",
        "tenant_id": None,
        "timestamp": BASE,
        "platform": "windows",
        "host": "WIN-01",
        "mitre_techniques": None,
    }
    entities = extract_entities(raw_event)
    assert only(entities, EntityType.MITRE_TECHNIQUE) == []


def test_mitre_coercion_via_duck_typed_event_int():
    raw_event = {
        "event_id": "E-1",
        "tenant_id": None,
        "timestamp": BASE,
        "platform": "windows",
        "host": "WIN-01",
        "mitre_techniques": 12345,
    }
    entities = extract_entities(raw_event)
    assert only(entities, EntityType.MITRE_TECHNIQUE) == []


# ===========================================================================
# MITRE — via Event Pydantic (jalur normal)
# ===========================================================================

def test_mitre_uppercase_input_preserved():
    """
    Event hanya menerima teknik yang sudah uppercase dan format valid.
    Extractor tidak mengubah value, hanya normalized_value.
    """
    e = make_event(mitre_techniques=["T1059.001"])
    mitres = only(extract_entities(e), EntityType.MITRE_TECHNIQUE)
    assert mitres[0].value == "T1059.001"
    assert mitres[0].normalized_value == "T1059.001"

# ===========================================================================
# PROVENANCE & TENANT
# ===========================================================================

def test_source_event_ids_preserved():
    e = make_event(event_id="E-42", host="WIN-01")
    for x in extract_entities(e):
        assert "E-42" in x.source_event_ids


def test_tenant_preserved():
    e = make_event(tenant_id="tenant-a", host="WIN-01")
    for x in extract_entities(e):
        assert x.tenant_id == "tenant-a"


def test_timestamps_set_from_event():
    ts = datetime(2026, 9, 26, 11, 0, tzinfo=timezone.utc)
    e = make_event(timestamp=ts, host="WIN-01")
    for x in extract_entities(e):
        assert x.first_seen == ts
        assert x.last_seen == ts


# ===========================================================================
# DETERMINISM
# ===========================================================================

def test_deterministic_order():
    e = make_event(
        host="WIN-01", user="ren",
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(source_ip="8.8.8.8"),
        mitre_techniques=["T1059.001", "T1105"],
    )
    out1 = extract_entities(e)
    out2 = extract_entities(e)
    types1 = [x.entity_type for x in out1]
    types2 = [x.entity_type for x in out2]
    assert types1 == types2
    fps1 = [x.fingerprint for x in out1]
    fps2 = [x.fingerprint for x in out2]
    assert fps1 == fps2


def test_type_ordering():
    e = make_event(
        host="WIN-01", user="ren",
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(source_ip="8.8.8.8"),
        mitre_techniques=["T1059.001"],
    )
    types = [x.entity_type for x in extract_entities(e)]
    # HOST -> USER -> PROCESS -> IP -> MITRE
    assert types.index(EntityType.HOST) < types.index(EntityType.USER)
    assert types.index(EntityType.USER) < types.index(EntityType.PROCESS)
    assert types.index(EntityType.PROCESS) < types.index(EntityType.IP)
    assert (
        types.index(EntityType.IP)
        < types.index(EntityType.MITRE_TECHNIQUE)
    )


def test_sort_stable_for_same_normalized_value_hash():
    """
    Dua HASH dengan normalized_value sama, algoritma berbeda.
    Urutan harus stabil di dua eksekusi.
    """
    e = make_event(
        file=FileContext(
            path="/tmp/x",
            hashes={"sha256": "abcdef", "md5": "abcdef"},
        ),
    )
    out1 = [x.fingerprint for x in extract_entities(e)]
    out2 = [x.fingerprint for x in extract_entities(e)]
    assert out1 == out2


def test_sort_hash_algorithm_disambiguates():
    """
    md5 dan sha256 dengan value sama harus di-sort dengan
    hash_algorithm ascending (md5 < sha256).
    """
    e = make_event(
        file=FileContext(
            path="/tmp/x",
            hashes={"sha256": "abcdef", "md5": "abcdef"},
        ),
    )
    hashes = only(extract_entities(e), EntityType.HASH)
    assert [h.hash_algorithm for h in hashes] == ["md5", "sha256"]


def test_sort_user_local_vs_domain_deterministic():
    """
    Dengan domain -> jadi domain user, host tidak dipakai di identity.
    """
    e = make_event(
        host="WIN-01",
        user="ren",
        user_context=UserContext(name="ren", domain="CORP"),
    )
    users = only(extract_entities(e), EntityType.USER)
    assert len(users) == 1
    assert users[0].identity_scope == "domain"


def test_sort_not_dependent_on_entity_id():
    """
    Extract dua kali, urutan fingerprint harus identik
    walaupun entity_id UUID acak.
    """
    e = make_event(
        host="WIN-01",
        user="ren",
        process=ProcessContext(name="powershell.exe", pid=1234),
        file=FileContext(
            path="C:\\x.exe",
            hashes={"sha256": "aaa", "md5": "aaa"},
        ),
        network=NetworkContext(source_ip="8.8.8.8"),
        mitre_techniques=["T1059.001", "T1105"],
    )
    fps1 = [x.fingerprint for x in extract_entities(e)]
    fps2 = [x.fingerprint for x in extract_entities(e)]
    assert fps1 == fps2


# ===========================================================================
# EDGE CASES
# ===========================================================================

def test_empty_event_no_crash():
    entities = extract_entities(make_event())
    assert isinstance(entities, list)
    assert entities == []


def test_minimal_event_with_host():
    entities = extract_entities(make_event(host="WIN-01"))
    assert len(entities) == 1
    assert entities[0].entity_type == EntityType.HOST


def test_extractor_is_reusable():
    extractor = EntityExtractor()
    e = make_event(host="WIN-01")
    out1 = extractor.extract(e)
    out2 = extractor.extract(e)
    assert len(out1) == len(out2)


def test_all_entities_have_fingerprint():
    e = make_event(
        host="WIN-01", user="ren",
        process=ProcessContext(name="powershell.exe", pid=1234),
        network=NetworkContext(source_ip="8.8.8.8"),
        mitre_techniques=["T1059.001"],
    )
    for x in extract_entities(e):
        assert x.fingerprint is not None
        assert x.verify_fingerprint()


def test_entity_type_returned():
    e = make_event(host="WIN-01")
    for x in extract_entities(e):
        assert isinstance(x, Entity)
        assert isinstance(x.entity_type, EntityType)


def test_all_entity_types_are_in_order_map():
    """
    Sanity check: setiap EntityType yang mungkin diekstrak punya
    urutan di _TYPE_ORDER.
    """
    from internal.graph.entity_extractor import _TYPE_ORDER

    extractable = {
        EntityType.HOST,
        EntityType.USER,
        EntityType.PROCESS,
        EntityType.FILE,
        EntityType.HASH,
        EntityType.IP,
        EntityType.DOMAIN,
        EntityType.MITRE_TECHNIQUE,
    }
    for et in extractable:
        assert et in _TYPE_ORDER, et
