"""
Contract tests untuk threat intel layer.

Tidak butuh network: provider di-inject dengan http_get/http_post
mock. Provider yang tidak available otomatis di-skip.
"""

from __future__ import annotations

import pytest

from internal.threat_intel import (
    Indicator,
    IndicatorType,
    IntelProvider,
    IntelResult,
    MISPProvider,
    OTXProvider,
    ThreatIntelEnricher,
    VirusTotalProvider,
)
from internal.threat_intel.base import extract_indicators
from pkg.models.event import (
    DnsContext,
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
)


# ===========================================================================
# Helpers
# ===========================================================================

def make_event(
    *,
    event_id: str = "E-1",
    hashes: dict | None = None,
    file_hashes: dict | None = None,
    source_ip: str | None = None,
    dest_ip: str | None = None,
    url: str | None = None,
    dns_query: str | None = None,
) -> Event:
    process = None
    if hashes:
        process = ProcessContext(
            name="payload.exe",
            pid=1234,
            hashes=hashes,
        )

    file_ctx = None
    if file_hashes:
        file_ctx = FileContext(
            path="C:\\tmp\\payload.exe",
            hashes=file_hashes,
        )

    network = None
    if source_ip or dest_ip or url:
        network = NetworkContext(
            source_ip=source_ip,
            destination_ip=dest_ip,
            url=url,
        )

    dns = None
    if dns_query:
        dns = DnsContext(query=dns_query)

    return Event(
        event_id=event_id,
        timestamp="2026-09-26T10:00:00Z",
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=50,
        host="WIN-01",
        process=process,
        file=file_ctx,
        network=network,
        dns=dns,
    )


def fake_http_get(response: dict):
    def _get(url, headers, timeout):
        return response
    return _get


def fake_http_post(response: dict):
    def _post(url, headers, payload, timeout):
        return response
    return _post


# ===========================================================================
# Indicator
# ===========================================================================

def test_indicator_hashable():
    a = Indicator(IndicatorType.HASH, "abc", "process")
    b = Indicator(IndicatorType.HASH, "abc", "file")
    # __hash__ ignores source → equal hash
    assert hash(a) == hash(b)


def test_intel_result_properties():
    ind = Indicator(IndicatorType.HASH, "abc")
    r = IntelResult(
        indicator=ind,
        provider="test",
        found=True,
        malicious_count=5,
        total_count=70,
    )
    assert r.is_malicious is True
    assert r.detection_ratio == 5 / 70
    assert r.is_success is True


def test_intel_result_error():
    ind = Indicator(IndicatorType.HASH, "abc")
    r = IntelResult(indicator=ind, provider="test", error="boom")
    assert r.is_success is False


# ===========================================================================
# extract_indicators
# ===========================================================================

def test_extract_hash_from_process():
    ev = make_event(hashes={"sha256": "ABC123"})
    indicators = extract_indicators(ev)
    assert any(
        i.type == IndicatorType.HASH and i.value == "abc123"
        for i in indicators
    )


def test_extract_hash_from_file():
    ev = make_event(file_hashes={"sha256": "DEF456"})
    indicators = extract_indicators(ev)
    assert any(
        i.type == IndicatorType.HASH and i.value == "def456"
        for i in indicators
    )


def test_extract_ip():
    ev = make_event(source_ip="10.0.0.1", dest_ip="8.8.8.8")
    indicators = extract_indicators(ev)
    values = {i.value for i in indicators if i.type == IndicatorType.IP}
    assert "10.0.0.1" in values
    assert "8.8.8.8" in values


def test_extract_url():
    ev = make_event(url="https://malicious.example.com/a")
    indicators = extract_indicators(ev)
    assert any(i.type == IndicatorType.URL for i in indicators)


def test_extract_domain():
    ev = make_event(dns_query="Example.COM.")
    indicators = extract_indicators(ev)
    assert any(
        i.type == IndicatorType.DOMAIN and i.value == "example.com"
        for i in indicators
    )


def test_extract_empty_event():
    ev = make_event()
    assert extract_indicators(ev) == []


# ===========================================================================
# VirusTotalProvider
# ===========================================================================

def test_vt_implements_protocol():
    assert isinstance(
        VirusTotalProvider(api_key="x"),
        IntelProvider,
    )


def test_vt_unavailable_without_key():
    p = VirusTotalProvider(api_key="")
    assert p.is_available() is False


def test_vt_available_with_key():
    p = VirusTotalProvider(api_key="fake")
    assert p.is_available() is True


def test_vt_name():
    assert VirusTotalProvider(api_key="x").name() == "virustotal"


def test_vt_lookup_without_key_returns_error():
    p = VirusTotalProvider(api_key="")
    ind = Indicator(IndicatorType.HASH, "abc")
    r = p.lookup(ind)
    assert r.error
    assert r.found is False


def test_vt_lookup_mocked_response():
    mock_data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 55,
                    "suspicious": 3,
                    "harmless": 0,
                    "undetected": 10,
                },
                "reputation": -85,
                "tags": ["trojan", "win32"],
            }
        }
    }
    p = VirusTotalProvider(
        api_key="fake",
        http_get=fake_http_get(mock_data),
    )
    ind = Indicator(IndicatorType.HASH, "abc")
    r = p.lookup(ind)
    assert r.found is True
    assert r.malicious_count == 58
    assert r.total_count == 68
    assert r.reputation == -85
    assert "trojan" in r.tags


def test_vt_lookup_not_found():
    p = VirusTotalProvider(
        api_key="fake",
        http_get=fake_http_get({"__not_found__": True}),
    )
    ind = Indicator(IndicatorType.HASH, "abc")
    r = p.lookup(ind)
    assert r.found is False
    assert r.is_success is True


def test_vt_unsupported_type():
    p = VirusTotalProvider(
        api_key="fake",
        http_get=fake_http_get({}),
    )
    ind = Indicator(IndicatorType.URL, "http://x")
    r = p.lookup(ind)
    assert "does not support" in (r.error or "")


# ===========================================================================
# OTXProvider
# ===========================================================================

def test_otx_unavailable_without_key():
    p = OTXProvider(api_key="")
    assert p.is_available() is False


def test_otx_lookup_mocked():
    mock_data = {
        "pulse_info": {
            "count": 12,
            "pulses": [
                {"tags": ["c2", "malware"]},
                {"tags": ["apt28"]},
            ],
        }
    }
    p = OTXProvider(
        api_key="fake",
        http_get=fake_http_get(mock_data),
    )
    ind = Indicator(IndicatorType.IP, "1.2.3.4")
    r = p.lookup(ind)
    assert r.found is True
    assert r.malicious_count == 12
    assert "c2" in r.tags
    assert "apt28" in r.tags


# ===========================================================================
# MISPProvider
# ===========================================================================

def test_misp_unavailable():
    p = MISPProvider(url="", api_key="")
    assert p.is_available() is False


def test_misp_available_with_config():
    p = MISPProvider(url="https://misp.local", api_key="x")
    assert p.is_available() is True


def test_misp_lookup_mocked():
    mock_data = {
        "response": {
            "Attribute": [
                {"Tag": [{"name": "tlp:amber"}]},
                {"Tag": [{"name": "malware"}]},
            ]
        }
    }
    p = MISPProvider(
        url="https://misp.local",
        api_key="x",
        http_post=fake_http_post(mock_data),
    )
    ind = Indicator(IndicatorType.HASH, "abc")
    r = p.lookup(ind)
    assert r.found is True
    assert r.malicious_count == 2
    assert "malware" in r.tags


# ===========================================================================
# Enricher
# ===========================================================================

def test_enricher_no_providers():
    e = ThreatIntelEnricher()
    assert e.available_providers() == []
    assert e.has_available() is False


def test_enricher_providers_skip_unavailable():
    vt = VirusTotalProvider(api_key="")
    otx = OTXProvider(api_key="fake")
    e = ThreatIntelEnricher(providers=[vt, otx])
    assert "virustotal" not in e.available_providers()
    assert "otx" in e.available_providers()


def test_enricher_enrich_event():
    mock_data = {
        "pulse_info": {
            "count": 5,
            "pulses": [{"tags": ["test"]}],
        }
    }
    otx = OTXProvider(
        api_key="fake",
        http_get=fake_http_get(mock_data),
    )
    e = ThreatIntelEnricher(providers=[otx])

    ev = make_event(dest_ip="1.2.3.4")
    results = e.enrich_event(ev)

    assert "1.2.3.4" in results
    assert len(results["1.2.3.4"]) == 1
    assert results["1.2.3.4"][0].found is True


def test_enricher_skip_when_no_indicator():
    otx = OTXProvider(
        api_key="fake",
        http_get=fake_http_get({}),
    )
    e = ThreatIntelEnricher(providers=[otx])
    results = e.enrich_event(make_event())
    assert results == {}


def test_enricher_provider_error_captured():
    def bad_get(url, headers, timeout):
        raise RuntimeError("API down")

    vt = VirusTotalProvider(
        api_key="fake",
        http_get=bad_get,
    )
    e = ThreatIntelEnricher(providers=[vt])
    ev = make_event(hashes={"sha256": "abc"})
    results = e.enrich_event(ev)
    assert "abc" in results
    assert results["abc"][0].error is not None


def test_enricher_enrich_events_dedup():
    mock_data = {"pulse_info": {"count": 1, "pulses": []}}
    otx = OTXProvider(
        api_key="fake",
        http_get=fake_http_get(mock_data),
    )
    e = ThreatIntelEnricher(providers=[otx])

    ev1 = make_event(event_id="E-1", dest_ip="1.2.3.4")
    ev2 = make_event(event_id="E-2", dest_ip="1.2.3.4")
    results = e.enrich_events([ev1, ev2])

    # Hanya satu entry per indicator value
    assert "1.2.3.4" in results
    assert len(results["1.2.3.4"]) == 1


def test_enricher_summary():
    ind = Indicator(IndicatorType.HASH, "abc")
    results = {
        "abc": [
            IntelResult(
                indicator=ind,
                provider="vt",
                found=True,
                malicious_count=5,
            ),
            IntelResult(
                indicator=ind,
                provider="otx",
                error="fail",
            ),
        ],
        "def": [
            IntelResult(
                indicator=ind,
                provider="vt",
                found=False,
            ),
        ],
    }
    e = ThreatIntelEnricher()
    summary = e.summary(results)
    assert summary["indicator_count"] == 2
    assert summary["malicious"] == 1
    assert summary["clean"] == 1
    assert summary["errors"] == 1
