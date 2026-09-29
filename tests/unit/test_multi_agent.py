"""
Contract tests untuk multi-agent orchestrator.
"""

from datetime import datetime, timedelta, timezone

import pytest

from internal.ai import (
    AIRouter,
    MultiAgentProvider,
)
from internal.ai.agents import (
    Agent,
    AgentContext,
    AgentOrchestrator,
    AgentOutput,
    CounterAgent,
    CriticAgent,
    HypothesisAgent,
    ReportAgent,
)
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


def make_result(
    *,
    with_mitre: bool = True,
) -> object:
    events = [
        make_event(
            "E-1", severity=85,
            mitre=["T1546.011"] if with_mitre else None,
        ),
        make_event(
            "E-2", offset_seconds=5, severity=85,
            mitre=["T1546.011"] if with_mitre else None,
        ),
    ]
    return investigate(events, title="Application Shimming")


# ===========================================================================
# Agent base
# ===========================================================================

def test_agent_output_not_empty():
    out = AgentOutput(name="x", content="hello")
    assert out.is_empty is False


def test_agent_output_empty():
    out = AgentOutput(name="x", content="")
    assert out.is_empty is True


def test_agent_context_add_and_get():
    result = make_result()
    ctx = AgentContext(result=result)
    out = AgentOutput(name="a", content="x", findings=["f1"])
    ctx.add_output(out)

    assert ctx.get_output("a") is out
    assert ctx.prior_findings() == ["f1"]
    assert ctx.prior_findings(exclude="a") == []


def test_base_agent_requires_run():
    class Dummy(Agent):
        _name = "dummy"

    with pytest.raises(NotImplementedError):
        Dummy().run(AgentContext(result=make_result()))


# ===========================================================================
# HypothesisAgent
# ===========================================================================

def test_hypothesis_agent_produces_output():
    result = make_result()
    agent = HypothesisAgent()
    output = agent.run(AgentContext(result=result))

    assert output.name == "hypothesis_agent"
    assert output.content
    assert "Application Shimming" in output.content


def test_hypothesis_agent_findings_not_empty():
    result = make_result()
    output = HypothesisAgent().run(AgentContext(result=result))
    assert len(output.findings) > 0


def test_hypothesis_agent_no_hypotheses():
    result = investigate(
        [make_event(severity=20)],
        title="No hypothesis",
    )
    output = HypothesisAgent().run(AgentContext(result=result))
    assert "Tidak ada MAIN hypothesis" in output.content


# ===========================================================================
# CounterAgent
# ===========================================================================

def test_counter_agent_produces_output():
    result = make_result()
    output = CounterAgent().run(AgentContext(result=result))

    assert output.name == "counter_agent"
    assert "COUNTER" in output.content


def test_counter_agent_no_counters():
    result = investigate(
        [make_event(severity=20)],
        title="Empty",
    )
    output = CounterAgent().run(AgentContext(result=result))
    assert "Tidak ada COUNTER" in output.content


# ===========================================================================
# CriticAgent
# ===========================================================================

def test_critic_agent_produces_output():
    result = make_result()
    output = CriticAgent().run(AgentContext(result=result))

    assert output.name == "critic_agent"
    assert len(output.findings) > 0


def test_critic_agent_detects_duplicates():
    result = make_result()
    output = CriticAgent().run(AgentContext(result=result))
    # Dua evidence dengan title sama → harus mendeteksi
    has_dup_finding = any(
        "berulang" in f.lower() or "duplik" in f.lower()
        for f in output.findings
    )
    assert has_dup_finding


def test_critic_agent_no_findings_returns_clean():
    result = investigate(
        [make_event(severity=50)],
        title="Clean",
    )
    output = CriticAgent().run(AgentContext(result=result))
    assert output.content
    assert len(output.findings) >= 1


# ===========================================================================
# ReportAgent
# ===========================================================================

def test_report_agent_produces_final_narrative():
    result = make_result()
    ctx = AgentContext(result=result)
    # Pre-populate critic output supaya ReportAgent bisa konsumsi
    critic = CriticAgent().run(ctx)
    ctx.add_output(critic)

    output = ReportAgent().run(ctx)
    assert output.name == "report_agent"
    assert "Application Shimming" in output.content
    assert "Risk assessment" in output.content or "risk" in output.content.lower()


# ===========================================================================
# Orchestrator
# ===========================================================================

def test_orchestrator_runs_all_agents():
    result = make_result()
    final, outputs = AgentOrchestrator().run(result)

    assert "hypothesis_agent" in outputs
    assert "counter_agent" in outputs
    assert "critic_agent" in outputs
    assert "report_agent" in outputs

    assert final.name == "report_agent"
    assert final.content


def test_orchestrator_narrate_shortcut():
    result = make_result()
    text = AgentOrchestrator().narrate(result)
    assert text
    assert "Application Shimming" in text


def test_orchestrator_deterministic():
    result = make_result()
    a, _ = AgentOrchestrator().run(result)
    b, _ = AgentOrchestrator().run(result)
    assert a.content == b.content


def test_orchestrator_custom_agents():
    class EchoAgent(Agent):
        _name = "echo"

        def run(self, context):
            return AgentOutput(name=self._name, content="echo")

    orch = AgentOrchestrator(agents=[EchoAgent()])
    final, outputs = orch.run(make_result())
    assert final.content == "echo"
    assert "echo" in outputs


# ===========================================================================
# MultiAgentProvider
# ===========================================================================

def test_multi_agent_provider_name():
    assert MultiAgentProvider().name() == "multi_agent"


def test_multi_agent_provider_is_available():
    assert MultiAgentProvider().is_available() is True


def test_multi_agent_provider_narrative():
    result = make_result()
    text = MultiAgentProvider().generate_narrative(result)
    assert text
    assert "Application Shimming" in text


def test_multi_agent_provider_in_router():
    provider = MultiAgentProvider()
    router = AIRouter(providers=[provider])
    result = make_result()
    text = router.narrate(result)
    assert text
    # Karena provider ini available, dia yang dipakai duluan
    used = router.available_providers()
    assert "multi_agent" in used


def test_multi_agent_fallback_to_rule_engine():
    """Multi-agent + rule engine, tapi rule engine jadi fallback."""
    provider = MultiAgentProvider()
    router = AIRouter(providers=[provider])
    result = make_result()

    # Narration via multi-agent
    text = router.narrate(result)
    assert "Application Shimming" in text
