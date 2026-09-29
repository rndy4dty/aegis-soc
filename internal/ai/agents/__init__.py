"""
Multi-agent orchestrator for AegisSOC.

Agents:
- HypothesisAgent : review & refine MAIN hypothesis
- CounterAgent    : perkuat COUNTER hypothesis
- CriticAgent     : kritik & gap analysis
- ReportAgent     : sintesis narrative final

Orchestrator menjalankan semua agent secara berurutan, saling
melewatkan output via AgentContext.

Semua agent deterministic (rule-based). Integrasi LLM dilakukan
di layer provider, bukan di agent.
"""

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from internal.ai.agents.hypothesis_agent import HypothesisAgent
from internal.ai.agents.counter_agent import CounterAgent
from internal.ai.agents.critic_agent import CriticAgent
from internal.ai.agents.report_agent import ReportAgent
from internal.ai.agents.orchestrator import AgentOrchestrator

__all__ = [
    "Agent",
    "AgentContext",
    "AgentOutput",
    "HypothesisAgent",
    "CounterAgent",
    "CriticAgent",
    "ReportAgent",
    "AgentOrchestrator",
]
