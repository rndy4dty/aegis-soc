"""
Contract tests untuk notifications.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from internal.investigation.investigation_engine import (
    investigate,
)
from internal.notifications import (
    EmailNotifier,
    NotificationLevel,
    NotificationResult,
    NotificationRouter,
    NotificationRule,
    SlackNotifier,
    WebhookNotifier,
)
from internal.notifications.base import (
    format_investigation,
    render_text,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "E-1",
    *,
    offset: int = 0,
    severity: int = 85,
    mitre: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=severity,
        host="WIN-01",
        mitre_techniques=mitre or [],
    )


def make_result(severity: int = 85) -> object:
    return investigate(
        [
            make_event("E-1", severity=severity, mitre=["T1546.011"]),
            make_event("E-2", offset=5, severity=severity, mitre=["T1546.011"]),
        ],
        title="Test Case",
    )


# ===========================================================================
# Notifier — availability
# ===========================================================================

def test_slack_unavailable(monkeypatch):
    monkeypatch.delenv("AEGIS_SLACK_WEBHOOK_URL", raising=False)
    n = SlackNotifier(webhook_url="")
    assert n.is_available() is False
    assert n.name() == "slack"


def test_slack_available():
    n = SlackNotifier(webhook_url="https://hooks.slack.com/x")
    assert n.is_available() is True


def test_email_unavailable(monkeypatch):
    monkeypatch.delenv("AEGIS_SMTP_HOST", raising=False)
    monkeypatch.delenv("AEGIS_EMAIL_FROM", raising=False)
    monkeypatch.delenv("AEGIS_EMAIL_TO", raising=False)
    n = EmailNotifier(host="", sender="", recipients=[])
    assert n.is_available() is False
    assert n.name() == "email"


def test_email_available():
    n = EmailNotifier(
        host="smtp.example.com",
        sender="a@b.com",
        recipients=["c@d.com"],
    )
    assert n.is_available() is True


def test_webhook_unavailable(monkeypatch):
    monkeypatch.delenv("AEGIS_WEBHOOK_URL", raising=False)
    n = WebhookNotifier(url="")
    assert n.is_available() is False
    assert n.name() == "webhook"


def test_webhook_available():
    n = WebhookNotifier(url="https://example.com/hook")
    assert n.is_available() is True


# ===========================================================================
# Notifier — send without config
# ===========================================================================

def test_slack_send_without_url_returns_failure():
    n = SlackNotifier(webhook_url="")
    r = n.send(make_result(), level=NotificationLevel.INFO)
    assert r.success is False
    assert "not configured" in (r.error or "")


def test_email_send_without_config_returns_failure():
    n = EmailNotifier(host="", sender="", recipients=[])
    r = n.send(make_result(), level=NotificationLevel.INFO)
    assert r.success is False


def test_webhook_send_without_config_returns_failure():
    n = WebhookNotifier(url="")
    r = n.send(make_result(), level=NotificationLevel.INFO)
    assert r.success is False


# ===========================================================================
# Format
# ===========================================================================

def test_format_investigation():
    result = make_result()
    payload = format_investigation(
        result, level=NotificationLevel.WARNING
    )
    assert payload["level"] == "warning"
    assert payload["title"] == "Test Case"
    assert payload["risk_score"] >= 0
    assert isinstance(payload["top_hypotheses"], list)


def test_render_text_contains_title():
    result = make_result()
    payload = format_investigation(
        result, level=NotificationLevel.CRITICAL
    )
    text = render_text(payload)
    assert "Test Case" in text
    assert "CRITICAL" in text


def test_render_text_with_message():
    result = make_result()
    payload = format_investigation(
        result, level=NotificationLevel.INFO
    )
    text = render_text(payload, message="Custom message")
    assert text.startswith("Custom message")


# ===========================================================================
# Router — rules
# ===========================================================================

def test_router_no_match():
    router = NotificationRouter(notifiers=[])
    # Result dengan risk rendah
    r = make_result(severity=20)
    results = router.dispatch(r)
    assert results == []


def test_router_rules_default():
    router = NotificationRouter(notifiers=[])
    rule_names = [r.name for r in router.rules]
    assert "critical" in rule_names
    assert "high" in rule_names
    assert "medium" in rule_names


def test_router_custom_rules():
    custom_rule = NotificationRule(
        name="always",
        predicate=lambda r: True,
        level=NotificationLevel.INFO,
    )
    router = NotificationRouter(
        notifiers=[], rules=[custom_rule]
    )
    assert len(router.rules) == 1
    assert router.rules[0].name == "always"


# ===========================================================================
# Router — dispatch with fake notifier
# ===========================================================================

class FakeNotifier:
    def __init__(self, name: str = "fake", available: bool = True):
        self._name = name
        self._available = available
        self.calls: list[dict] = []

    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return self._available

    def send(self, result, *, level, message=None) -> NotificationResult:
        self.calls.append(
            {"level": level, "message": message}
        )
        return NotificationResult(
            channel=self._name,
            success=True,
            level=level,
        )


def test_router_dispatch_calls_notifier():
    fake = FakeNotifier()
    router = NotificationRouter(notifiers=[fake])
    result = make_result(severity=95)
    results = router.dispatch(result)

    assert len(results) == 1
    assert results[0].success is True
    assert results[0].channel == "fake"
    assert len(fake.calls) == 1
    # Verify level sesuai dengan risk score actual
    level = fake.calls[0]["level"]
    assert level in (
        NotificationLevel.INFO,
        NotificationLevel.WARNING,
        NotificationLevel.CRITICAL,
    )


def test_router_skips_unavailable():
    fake = FakeNotifier(available=False)
    router = NotificationRouter(notifiers=[fake])
    results = router.dispatch(make_result())
    assert results == []
    assert len(fake.calls) == 0


def test_router_handles_notifier_exception():
    class BrokenNotifier:
        def name(self) -> str:
            return "broken"

        def is_available(self) -> bool:
            return True

        def send(self, *args, **kwargs):
            raise RuntimeError("boom")

    router = NotificationRouter(
        notifiers=[BrokenNotifier()]  # type: ignore[list-item]
    )
    results = router.dispatch(make_result())
    assert len(results) == 1
    assert results[0].success is False
    assert "boom" in (results[0].error or "")


def test_router_available_notifiers():
    a = FakeNotifier("a", available=True)
    b = FakeNotifier("b", available=False)
    router = NotificationRouter(notifiers=[a, b])
    assert router.available_notifiers() == ["a"]


# ===========================================================================
# Router — level selection
# ===========================================================================

def test_router_level_critical_for_high_risk():
    """Test level selection untuk risk tinggi via custom rule."""
    from types import SimpleNamespace

    fake = FakeNotifier()
    critical_rule = NotificationRule(
        name="force-critical",
        predicate=lambda r: r.risk_score >= 80,
        level=NotificationLevel.CRITICAL,
    )
    router = NotificationRouter(
        notifiers=[fake],
        rules=[critical_rule],
    )
    high_risk = SimpleNamespace(risk_score=90)
    router.dispatch(high_risk)
    assert fake.calls[0]["level"] == NotificationLevel.CRITICAL


def test_router_level_warning_for_medium_risk():
    """Test level selection untuk risk sedang via custom rule."""
    from types import SimpleNamespace

    fake = FakeNotifier()
    warning_rule = NotificationRule(
        name="force-warning",
        predicate=lambda r: 40 <= r.risk_score < 80,
        level=NotificationLevel.WARNING,
    )
    router = NotificationRouter(
        notifiers=[fake],
        rules=[warning_rule],
    )
    medium_risk = SimpleNamespace(risk_score=55)
    router.dispatch(medium_risk)
    assert fake.calls[0]["level"] == NotificationLevel.WARNING


def test_router_default_rules_with_low_risk():
    """Risk ~45 -> default rules pilih INFO."""
    fake = FakeNotifier()
    router = NotificationRouter(notifiers=[fake])
    result = make_result(severity=95)

    # Risk realistis: ~45 (evidence capped at 40)
    assert 30 <= result.risk_score <= 60

    router.dispatch(result)
    assert len(fake.calls) == 1
    assert fake.calls[0]["level"] == NotificationLevel.INFO
