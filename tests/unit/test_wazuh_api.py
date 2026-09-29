"""
Contract tests untuk Wazuh API client & poller.

Mock HTTP: tidak butuh Wazuh API sungguhan.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from internal.collector.wazuh_api import (
    WazuhAPIClient,
    WazuhAlert,
    _parse_wazuh_ts,
)
from internal.collector.wazuh_poller import WazuhPoller


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


# ===========================================================================
# _parse_wazuh_ts
# ===========================================================================

def test_parse_ts_with_offset():
    dt = _parse_wazuh_ts("2026-09-26T10:00:00.000+0000")
    assert dt.year == 2026
    assert dt.tzinfo is not None


def test_parse_ts_with_z():
    dt = _parse_wazuh_ts("2026-09-26T10:00:00Z")
    assert dt.hour == 10


def test_parse_ts_invalid_returns_now():
    dt = _parse_wazuh_ts("not-a-date")
    assert dt.tzinfo is not None


# ===========================================================================
# Client config
# ===========================================================================

def test_client_not_configured():
    c = WazuhAPIClient(password="")
    assert c.is_configured is False


def test_client_configured():
    c = WazuhAPIClient(password="secret")
    assert c.is_configured is True


def test_client_login_without_password_raises():
    c = WazuhAPIClient(password="")
    with pytest.raises(RuntimeError, match="not configured"):
        c.login()


# ===========================================================================
# Poller dedup
# ===========================================================================

def test_poller_mark_seen():
    p = WazuhPoller()
    assert p._is_seen("A-1") is False
    p._mark_seen("A-1")
    assert p._is_seen("A-1") is True


def test_poller_seen_idempotent():
    p = WazuhPoller()
    p._mark_seen("A-1")
    p._mark_seen("A-1")
    p._mark_seen("A-1")
    assert len(p._seen_ids) == 1


def test_poller_seen_trim():
    from internal.collector import wazuh_poller as mod

    p = WazuhPoller()
    old = mod.MAX_SEEN_IDS
    mod.MAX_SEEN_IDS = 5
    try:
        for i in range(10):
            p._mark_seen(f"A-{i}")
        assert len(p._seen_ids) == 5
        assert p._is_seen("A-9") is True
        assert p._is_seen("A-0") is False
    finally:
        mod.MAX_SEEN_IDS = old


# ===========================================================================
# Poller convert
# ===========================================================================

def test_poller_convert_wazuh_alert():
    p = WazuhPoller()
    alert = WazuhAlert(
        alert_id="1606484225.1",
        timestamp=BASE,
        raw={
            "id": "1606484225.1",
            "timestamp": "2026-09-26T10:00:00.000+0000",
            "rule": {
                "id": "92058",
                "level": 10,
                "description": "Application Shimming",
                "mitre": {"id": ["T1546.011"], "tactic": ["Persistence"]},
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
        },
    )
    event = p._convert_alert(alert)
    assert event.event_id == "wazuh-1606484225.1"
    assert event.rule_id == "92058"
    assert event.host == "WIN-01"


# ===========================================================================
# Poller poll_once with mock API
# ===========================================================================

class FakeAPI:
    def __init__(self, alerts, *, raise_on_get=None):
        self._alerts = alerts
        self._raise = raise_on_get
        self.calls = []

    @property
    def url(self): return "https://fake-wazuh:55000"

    @property
    def is_configured(self): return True

    def get_alerts(self, **kwargs):
        self.calls.append(kwargs)
        if self._raise is not None:
            raise self._raise
        return list(self._alerts)


class FakeBus:
    def __init__(self):
        self.published = []

    def is_available(self): return True

    def publish(self, stream, data, **kwargs):
        self.published.append((stream, data))
        return f"msg-{len(self.published)}"


def _make_alert(alert_id, ts_offset=0):
    return WazuhAlert(
        alert_id=alert_id,
        timestamp=BASE + timedelta(seconds=ts_offset),
        raw={
            "id": alert_id,
            "timestamp": (BASE + timedelta(seconds=ts_offset)).isoformat(),
            "rule": {
                "id": "92058", "level": 10, "description": "Test",
                "mitre": {"id": ["T1546.011"]},
            },
            "agent": {"id": "001", "name": "WIN-01"},
        },
    )


def test_poller_poll_once_publishes():
    api = FakeAPI([_make_alert("A-1"), _make_alert("A-2", 5)])
    bus = FakeBus()
    p = WazuhPoller(api=api, bus=bus)
    published = p.poll_once()
    assert published == 2
    assert len(bus.published) == 2


def test_poller_poll_once_dedup():
    api = FakeAPI([_make_alert("A-1"), _make_alert("A-2")])
    bus = FakeBus()
    p = WazuhPoller(api=api, bus=bus)
    p.poll_once()
    assert p.stats.alerts_published == 2

    p.poll_once()
    assert p.stats.alerts_published == 2
    assert p.stats.alerts_skipped == 2


def test_poller_poll_once_handles_api_error():
    api = FakeAPI([], raise_on_get=RuntimeError("API down"))
    bus = FakeBus()
    p = WazuhPoller(api=api, bus=bus)
    published = p.poll_once()
    assert published == 0
    assert len(p.stats.errors) == 1


def test_poller_poll_once_calls_api_with_since():
    api = FakeAPI([_make_alert("A-1")])
    bus = FakeBus()
    p = WazuhPoller(api=api, bus=bus, initial_lookback=300)
    p.poll_once()
    assert len(api.calls) == 1
    assert "since" in api.calls[0]


def test_poller_tracks_last_seen():
    api = FakeAPI([_make_alert("A-1", 0), _make_alert("A-2", 10)])
    bus = FakeBus()
    p = WazuhPoller(api=api, bus=bus)
    p.poll_once()
    assert p._last_seen is not None
    assert p._last_seen == BASE + timedelta(seconds=10)
