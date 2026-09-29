"""
MultiAgentProvider: bungkus AgentOrchestrator sebagai AIProvider.

Dengan ini, multi-agent bisa langsung dipakai di AIRouter.
"""

from __future__ import annotations

from internal.ai.agents import AgentOrchestrator
from internal.ai.provider import BaseProvider
from internal.investigation.investigation_engine import (
    InvestigationResult,
)


class MultiAgentProvider(BaseProvider):
    """
    AIProvider yang menjalankan 4 agent (hypothesis, counter,
    critic, report) dan mengembalikan narrative final.
    """

    _name = "multi_agent"

    def __init__(
        self,
        orchestrator: AgentOrchestrator | None = None,
    ) -> None:
        self._orchestrator = orchestrator or AgentOrchestrator()

    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        return self._orchestrator.narrate(result)


__all__ = ["MultiAgentProvider"]
