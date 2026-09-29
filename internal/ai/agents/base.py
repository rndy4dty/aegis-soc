"""
Base abstractions untuk multi-agent orchestrator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from internal.investigation.investigation_engine import (
    InvestigationResult,
)


@dataclass
class AgentOutput:
    """
    Output satu agent.

    - name          : nama agent
    - content       : narasi/sintesis utama
    - findings      : list temuan terstruktur (string)
    - metadata      : data tambahan (opsional)
    """

    name: str
    content: str
    findings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_empty(self) -> bool:
        return not self.content.strip() and not self.findings


@dataclass
class AgentContext:
    """
    Konteks yang dilewatkan antar agent.

    Attributes:
    - result    : InvestigationResult (immutable view)
    - outputs   : AgentOutput dari agent sebelumnya (keyed by name)
    """

    result: InvestigationResult
    outputs: dict[str, AgentOutput] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def add_output(self, output: AgentOutput) -> None:
        self.outputs[output.name] = output

    def get_output(self, name: str) -> AgentOutput | None:
        return self.outputs.get(name)

    def prior_findings(self, exclude: str | None = None) -> list[str]:
        """
        Gabung semua findings dari agent sebelumnya.
        """
        out: list[str] = []
        for name, output in self.outputs.items():
            if exclude is not None and name == exclude:
                continue
            out.extend(output.findings)
        return out


class Agent:
    """
    Base class agent.

    Subclass wajib implementasi:
    - name() -> str
    - run(context: AgentContext) -> AgentOutput
    """

    _name: str = "base"

    def name(self) -> str:
        return self._name

    def run(self, context: AgentContext) -> AgentOutput:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement run()"
        )


__all__ = ["Agent", "AgentContext", "AgentOutput"]
