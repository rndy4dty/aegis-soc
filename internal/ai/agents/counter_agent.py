"""
CounterAgent: perkuat COUNTER hypothesis.

Deterministic. Untuk setiap MAIN hypothesis, cari COUNTER yang
sesuai. Analisis:
- apakah COUNTER punya dukungan evidence
- penjelasan legitimate apa yang bisa menjelaskan evidence yang sama
- syarat apa yang harus dipenuhi supaya COUNTER benar
"""

from __future__ import annotations

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from pkg.models.hypothesis import HypothesisType


class CounterAgent(Agent):
    _name = "counter_agent"

    def run(self, context: AgentContext) -> AgentOutput:
        result = context.result

        counters = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.COUNTER
        ]

        if not counters:
            return AgentOutput(
                name=self._name,
                content=(
                    "Tidak ada COUNTER hypothesis. Investigasi tidak "
                    "menyediakan hipotesis alternatif."
                ),
                findings=[],
            )

        findings: list[str] = []
        lines: list[str] = []

        for c in counters:
            lines.append(f"COUNTER: {c.statement}")

            if c.supporting_evidence_ids:
                findings.append(
                    f"COUNTER '{c.statement[:40]}...' punya "
                    f"{len(c.supporting_evidence_ids)} supporting "
                    f"evidence."
                )
            else:
                findings.append(
                    "COUNTER belum punya bukti pendukung; "
                    "default netral terhadap MAIN."
                )

            # -- Syarat COUNTER benar -------------------------------
            if c.missing_evidence:
                lines.append("  Untuk membuktikan COUNTER, perlu:")
                for item in c.missing_evidence[:5]:
                    lines.append(f"    - {item}")

            # -- Saran eksplorasi -----------------------------------
            if c.mitre_techniques:
                techs = ", ".join(c.mitre_techniques)
                lines.append(
                    f"  Fokus verifikasi: apakah aktivitas pada "
                    f"{techs} konsisten dengan baseline legitimate?"
                )

        return AgentOutput(
            name=self._name,
            content="\n".join(lines),
            findings=findings,
            metadata={"counter_count": len(counters)},
        )


__all__ = ["CounterAgent"]
