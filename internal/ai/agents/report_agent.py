"""
ReportAgent: sintesis narrative final dari semua agent sebelumnya.

Deterministic. Menggabungkan:
- opening summary
- findings dari HypothesisAgent, CounterAgent, CriticAgent
- risk assessment
- rekomendasi tindak lanjut
"""

from __future__ import annotations

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from pkg.models.hypothesis import HypothesisType


class ReportAgent(Agent):
    _name = "report_agent"

    def run(self, context: AgentContext) -> AgentOutput:
        result = context.result
        sections: list[str] = []

        # -- Opening ------------------------------------------------
        sections.append(self._opening(result))

        # -- Hypothesis summary -------------------------------------
        mains = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.MAIN
        ]
        if mains:
            sections.append(self._hypotheses_section(mains))

        # -- Critical findings --------------------------------------
        critic = context.get_output("critic_agent")
        if critic and critic.findings:
            sections.append(self._critique_section(critic.findings))

        # -- Risk ---------------------------------------------------
        if result.risk:
            sections.append(self._risk_section(result))

        # -- Actions ------------------------------------------------
        actions = self._recommended_actions(result)
        if actions:
            sections.append(self._actions_section(actions))

        # -- Closing -------------------------------------------------
        sections.append(self._closing(result))

        content = "\n\n".join(s for s in sections if s)

        return AgentOutput(
            name=self._name,
            content=content,
            findings=[],
            metadata={"section_count": len(sections)},
        )

    # ------------------------------------------------------------------
    # Sections
    # ------------------------------------------------------------------

    @staticmethod
    def _opening(result) -> str:
        case = result.case
        return (
            f"Investigasi {case.title!r} menganalisis "
            f"{result.graph.events_processed} event, "
            f"mengekstrak {result.evidence_count} evidence, "
            f"dan menghasilkan {result.hypothesis_count} hipotesis. "
            f"Risk score akhir: {result.risk_score}/100 "
            f"(confidence {result.confidence:.2f})."
        )

    @staticmethod
    def _hypotheses_section(mains) -> str:
        lines = ["**Hipotesis utama:**"]
        for h in mains:
            lines.append(
                f"- {h.statement} "
                f"({h.status.value}, confidence {h.confidence:.2f})"
            )
            if h.supporting_evidence_ids:
                lines.append(
                    f"  didukung oleh {len(h.supporting_evidence_ids)} "
                    f"evidence"
                )
            if h.missing_evidence:
                lines.append(
                    f"  {len(h.missing_evidence)} bukti masih dibutuhkan"
                )
        return "\n".join(lines)

    @staticmethod
    def _critique_section(findings: list[str]) -> str:
        lines = ["**Catatan kritis:**"]
        for f in findings[:5]:
            lines.append(f"- {f}")
        return "\n".join(lines)

    @staticmethod
    def _risk_section(result) -> str:
        risk = result.risk
        lines = [f"**Risk assessment ({risk.risk_score}/100):**"]
        for cat, val in risk.breakdown.items():
            sign = "+" if val >= 0 else ""
            lines.append(f"- {cat}: {sign}{val:.1f}")
        return "\n".join(lines)

    @staticmethod
    def _actions_section(actions: list[str]) -> str:
        lines = ["**Rekomendasi tindak lanjut:**"]
        for i, a in enumerate(actions[:6], 1):
            lines.append(f"{i}. {a}")
        return "\n".join(lines)

    @staticmethod
    def _closing(result) -> str:
        if result.risk_score >= 70:
            verdict = "prioritas tinggi, tindak lanjut segera"
        elif result.risk_score >= 40:
            verdict = "prioritas menengah, perlu verifikasi lanjutan"
        else:
            verdict = "prioritas rendah, pantau sebagai konteks"
        return (
            f"**Kesimpulan**: Kasus ini dinilai {verdict}. "
            f"Semua klaim di atas didasarkan pada evidence yang "
            f"tersedia; klaim tanpa evidence tidak disertakan."
        )

    @staticmethod
    def _recommended_actions(result) -> list[str]:
        from internal.reporter.report import InvestigatorReport

        return InvestigatorReport(result)._recommended_actions()


__all__ = ["ReportAgent"]
