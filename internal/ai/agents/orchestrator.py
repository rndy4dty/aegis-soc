"""
AgentOrchestrator: jalankan semua agent berurutan.
"""

from __future__ import annotations

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from internal.ai.agents.counter_agent import CounterAgent
from internal.ai.agents.critic_agent import CriticAgent
from internal.ai.agents.hypothesis_agent import HypothesisAgent
from internal.ai.agents.report_agent import ReportAgent
from internal.investigation.investigation_engine import (
    InvestigationResult,
)


class AgentOrchestrator:
    """
    Jalankan pipeline agent secara deterministic.
    """

    def __init__(
        self,
        agents: list[Agent] | None = None,
    ) -> None:
        if agents is not None:
            self._agents = list(agents)
        else:
            self._agents = [
                HypothesisAgent(),
                CounterAgent(),
                CriticAgent(),
                ReportAgent(),
            ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run(
        self, result: InvestigationResult
    ) -> tuple[AgentOutput, dict[str, AgentOutput]]:
        """
        Jalankan semua agent.

        Return (final_output, all_outputs).
        """
        context = AgentContext(result=result)
        outputs: dict[str, AgentOutput] = {}

        for agent in self._agents:
            output = agent.run(context)
            context.add_output(output)
            outputs[agent.name()] = output

        # Output final = ReportAgent (kalau ada), else output terakhir
        final = outputs.get("report_agent")
        if final is None:
            final = list(outputs.values())[-1] if outputs else AgentOutput(
                name="empty",
                content="",
            )

        return final, outputs

    def narrate(self, result: InvestigationResult) -> str:
        """
        Shortcut: hasilkan narrative final saja.
        """
        final, _ = self.run(result)
        return final.content


__all__ = ["AgentOrchestrator"]
