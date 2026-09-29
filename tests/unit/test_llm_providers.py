"""
Contract tests untuk LLM providers.

Tidak butuh network. Test hanya:
- konstruksi & konfigurasi
- is_available() berdasarkan config
- prompt building deterministic
- error handling tanpa network
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.ai.llm import (
    CloudLLMProvider,
    LocalLLMProvider,
)
from internal.ai.llm.prompts import (
    SYSTEM_PROMPT,
    build_narrative_prompt,
)
from internal.ai.provider import AIProvider
from internal.investigation.investigation_engine import (
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


def make_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
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
        host="WIN-01",
        user="SYSTEM",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=4821,
            parent_name="svchost.exe",
            parent_pid=812,
        ),
        mitre_techniques=mitre or [],
    )


def make_result():
    return investigate(
        [
            make_event("E-1", severity=85, mitre=["T1546.011"]),
            make_event("E-2", offset_seconds=5, severity=85, mitre=["T1546.011"]),
        ],
        title="Application Shimming",
    )


# ===========================================================================
# Protocol
# ===========================================================================

def test_local_llm_implements_protocol():
    assert isinstance(LocalLLMProvider(), AIProvider)


def test_cloud_llm_implements_protocol():
    assert isinstance(
        CloudLLMProvider(api_key="dummy"), AIProvider
    )


def test_local_llm_name():
    assert LocalLLMProvider().name() == "ollama"


def test_cloud_llm_name():
    assert (
        CloudLLMProvider(api_key="dummy").name()
        == "openai_compatible"
    )


# ===========================================================================
# LocalLLMProvider
# ===========================================================================

def test_local_llm_defaults():
    p = LocalLLMProvider()
    assert p._host == "http://localhost:11434"
    assert p._model == "llama3.2"


def test_local_llm_env_override(monkeypatch):
    monkeypatch.setenv("OLLAMA_HOST", "http://custom:9999")
    monkeypatch.setenv("OLLAMA_MODEL", "mistral")
    p = LocalLLMProvider()
    assert p._host == "http://custom:9999"
    assert p._model == "mistral"


def test_local_llm_is_available_returns_bool():
    """Tanpa network, is_available() harus return bool, tidak raise."""
    p = LocalLLMProvider(host="http://localhost:1")
    assert p.is_available() is False


# ===========================================================================
# CloudLLMProvider
# ===========================================================================

def test_cloud_llm_unavailable_without_api_key(monkeypatch):
    monkeypatch.delenv("AEGIS_CLOUD_LLM_API_KEY", raising=False)
    p = CloudLLMProvider(api_key="")
    assert p.is_available() is False


def test_cloud_llm_empty_key_overrides_env(monkeypatch):
    """Explicit empty string harus menang atas env."""
    monkeypatch.setenv("AEGIS_CLOUD_LLM_API_KEY", "sk-from-env")
    p = CloudLLMProvider(api_key="")
    assert p.is_available() is False
    assert p._api_key == ""

def test_cloud_llm_available_with_api_key():
    p = CloudLLMProvider(api_key="sk-test")
    assert p.is_available() is True


def test_cloud_llm_defaults():
    p = CloudLLMProvider(api_key="sk-test")
    assert p._base_url == "https://api.openai.com/v1"
    assert p._model == "gpt-4o-mini"


def test_cloud_llm_env_override(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_CLOUD_LLM_BASE_URL", "https://api.example.com/v1"
    )
    monkeypatch.setenv("AEGIS_CLOUD_LLM_API_KEY", "sk-env")
    monkeypatch.setenv("AEGIS_CLOUD_LLM_MODEL", "my-model")
    p = CloudLLMProvider()
    assert p._base_url == "https://api.example.com/v1"
    assert p._api_key == "sk-env"
    assert p._model == "my-model"


def test_cloud_llm_generate_without_key_raises(monkeypatch):
    monkeypatch.delenv("AEGIS_CLOUD_LLM_API_KEY", raising=False)
    p = CloudLLMProvider(api_key="")
    with pytest.raises(RuntimeError, match="not configured"):
        p.generate_narrative(make_result())

def test_cloud_llm_generate_unreachable_raises():
    p = CloudLLMProvider(
        base_url="http://localhost:1",
        api_key="sk-test",
        timeout=1,
    )
    with pytest.raises(RuntimeError):
        p.generate_narrative(make_result())


# ===========================================================================
# Prompt building
# ===========================================================================

def test_system_prompt_is_string():
    assert isinstance(SYSTEM_PROMPT, str)
    assert len(SYSTEM_PROMPT) > 50


def test_build_narrative_prompt_contains_title():
    result = make_result()
    prompt = build_narrative_prompt(result)
    assert "Application Shimming" in prompt


def test_build_narrative_prompt_contains_risk_score():
    result = make_result()
    prompt = build_narrative_prompt(result)
    assert str(result.risk_score) in prompt


def test_build_narrative_prompt_contains_evidence():
    result = make_result()
    prompt = build_narrative_prompt(result)
    assert "Evidence:" in prompt
    assert "sdbinst.exe" in prompt


def test_build_narrative_prompt_contains_hypotheses():
    result = make_result()
    prompt = build_narrative_prompt(result)
    assert "MAIN:" in prompt
    assert "COUNTER:" in prompt


def test_build_narrative_prompt_deterministic():
    result = make_result()
    a = build_narrative_prompt(result)
    b = build_narrative_prompt(result)
    assert a == b


def test_build_narrative_prompt_ends_with_instruction():
    result = make_result()
    prompt = build_narrative_prompt(result)
    assert "Generate a narrative" in prompt
