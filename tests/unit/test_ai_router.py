"""
Contract tests untuk AI layer.

Menguji:
- AIProvider Protocol
- RuleEngineProvider deterministic narrative
- AIRouter fallback chain
- error handling
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.ai import (
    AIProvider,
    AIRouter,
    BaseProvider,
    RuleEngineProvider,
    narrate,
)
from internal.investigation.investigation_engine import (
    InvestigationResult,
    investigate,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


# ===========================================================================
# Helpers
# ===========================================================================

def make_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
    host: str = "WIN-01",
    severity: int = 85,
    mitre: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=severity,
        host=host,
        user="SYSTEM",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=4821,
            parent_name="svchost.exe",
            parent_pid=812,
        ),
        mitre_techniques=mitre or [],
    )


def make_result(events=None) -> InvestigationResult:
    events = events or [
        make_event(
            event_id="E-1",
            severity=85,
            mitre=["T1546.011"],
        ),
        make_event(
            event_id="E-2",
            offset_seconds=5,
            severity=85,
            mitre=["T1546.011"],
        ),
    ]
    return investigate(
        events,
        title="Test Investigation",
    )


class StubProvider(BaseProvider):
    """Provider palsu untuk menguji router."""
    _name = "stub"

    def __init__(
        self,
        *,
        available: bool = True,
        text: str = "stub narrative",
        raise_on_narrative: Exception | None = None,
        raise_on_available: Exception | None = None,
    ):
        self._available = available
        self._text = text
        self._raise_narrative = raise_on_narrative
        self._raise_available = raise_on_available

    def is_available(self) -> bool:
        if self._raise_available is not None:
            raise self._raise_available
        return self._available

    def generate_narrative(self, result: InvestigationResult) -> str:
        if self._raise_narrative is not None:
            raise self._raise_narrative
        return self._text


# ===========================================================================
# Protocol
# ===========================================================================

def test_rule_engine_implements_ai_provider_protocol():
    provider = RuleEngineProvider()
    assert isinstance(provider, AIProvider)


def test_rule_engine_name():
    provider = RuleEngineProvider()
    assert provider.name() == "rule_engine"


def test_rule_engine_is_available():
    assert RuleEngineProvider().is_available() is True


# ===========================================================================
# RuleEngineProvider narrative
# ===========================================================================

def test_narrative_is_nonempty():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert text
    assert len(text) > 100


def test_narrative_mentions_title():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert "Test Investigation" in text


def test_narrative_mentions_risk_score():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert f"{result.risk_score}/100" in text


def test_narrative_mentions_main_hypothesis():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert "Application Shimming" in text or "persistence" in text.lower()


def test_narrative_mentions_counter_hypothesis():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert "COUNTER" in text or "alternatif" in text.lower()


def test_narrative_mentions_missing_evidence():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    # Template T1546.011 punya missing evidence
    assert "shim" in text.lower() or "missing" in text.lower() or "dibutuhkan" in text.lower()


def test_narrative_mentions_actions():
    result = make_result()
    text = RuleEngineProvider().generate_narrative(result)
    assert "Rekomendasi" in text or "sdbinst" in text


def test_narrative_deterministic():
    result = make_result()
    a = RuleEngineProvider().generate_narrative(result)
    b = RuleEngineProvider().generate_narrative(result)
    assert a == b


def test_narrative_empty_result():
    result = investigate([], title="Empty")
    text = RuleEngineProvider().generate_narrative(result)
    assert text  # masih ada opening


# ===========================================================================
# AIRouter
# ===========================================================================

def test_router_default_includes_rule_engine():
    router = AIRouter()
    assert "rule_engine" in router.all_providers()


def test_router_narrates_with_rule_engine():
    router = AIRouter()
    result = make_result()
    text = router.narrate(result)
    assert text
    assert "Test Investigation" in text


def test_router_available_providers():
    router = AIRouter()
    available = router.available_providers()
    assert "rule_engine" in available


def test_router_custom_provider_takes_precedence():
    """
    Kalau provider custom tersedia dan menghasilkan narrative,
    dipakai. Rule engine tidak dipanggil.
    """
    stub = StubProvider(text="custom narrative")
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate(result)
    assert text == "custom narrative"


def test_router_fallback_when_custom_unavailable():
    stub = StubProvider(available=False)
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate(result)
    # Fallback ke rule engine
    assert "Test Investigation" in text


def test_router_fallback_when_custom_raises():
    stub = StubProvider(raise_on_narrative=RuntimeError("boom"))
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate(result)
    assert "Test Investigation" in text


def test_router_fallback_when_availability_raises():
    stub = StubProvider(raise_on_available=RuntimeError("boom"))
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate(result)
    assert "Test Investigation" in text


def test_router_skips_empty_narrative():
    stub = StubProvider(text="")
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate(result)
    # Empty narrative → fallback
    assert "Test Investigation" in text


def test_router_all_fail_raises():
    stub = StubProvider(raise_on_narrative=RuntimeError("boom"))
    router = AIRouter(
        providers=[stub],
        include_rule_engine=False,
    )
    result = make_result()
    with pytest.raises(RuntimeError, match="all AI providers failed"):
        router.narrate(result)


def test_router_narrate_with_provider():
    stub = StubProvider(text="explicit narrative")
    router = AIRouter(providers=[stub])
    result = make_result()
    text = router.narrate_with_provider(
        result, provider_name="stub"
    )
    assert text == "explicit narrative"


def test_router_narrate_with_provider_unknown():
    router = AIRouter()
    result = make_result()
    with pytest.raises(ValueError, match="not found"):
        router.narrate_with_provider(
            result, provider_name="nonexistent"
        )


def test_router_narrate_with_provider_unavailable():
    stub = StubProvider(available=False)
    router = AIRouter(providers=[stub])
    result = make_result()
    with pytest.raises(RuntimeError, match="not available"):
        router.narrate_with_provider(result, provider_name="stub")


def test_router_requires_at_least_one_provider():
    with pytest.raises(ValueError, match="requires at least one"):
        AIRouter(providers=[], include_rule_engine=False)


# ===========================================================================
# Factory
# ===========================================================================

def test_narrate_convenience():
    result = make_result()
    text = narrate(result)
    assert "Test Investigation" in text


def test_narrate_with_custom_providers():
    stub = StubProvider(text="custom")
    result = make_result()
    text = narrate(result, providers=[stub])
    assert text == "custom"


# ===========================================================================
# Determinism
# ===========================================================================

def test_router_narrative_deterministic():
    router = AIRouter()
    events = [
        make_event("E-1", mitre=["T1546.011"]),
        make_event("E-2", offset_seconds=5, mitre=["T1546.011"]),
    ]
    r1 = investigate(events, title="Det test")
    r2 = investigate(events, title="Det test")
    assert router.narrate(r1) == router.narrate(r2)
