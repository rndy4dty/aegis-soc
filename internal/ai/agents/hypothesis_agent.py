"""
HypothesisAgent: review & refine MAIN hypothesis.

Deterministic. Menganalisis:
- dukungan evidence per hypothesis
- kekuatan correlation
- apakah status hypothesis (PROPOSED/SUPPORTED/...) sudah tepat
- gap analysis: bukti apa yang masih kurang
"""

from __future__ import annotations

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from pkg.models.hypothesis import (
    HypothesisStatus,
    HypothesisType,
)


class HypothesisAgent(Agent):
    _name = "hypothesis_agent"

    def run(self, context: AgentContext) -> AgentOutput:
        result = context.result

        mains = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.MAIN
        ]

        if not mains:
            return AgentOutput(
                name=self._name,
                content=(
                    "Tidak ada MAIN hypothesis yang terdeteksi. "
                    "Evidence saat ini belum cukup kuat untuk "
                    "mengangkat hipotesis utama."
                ),
                findings=[],
            )

        findings: list[str] = []
        lines: list[str] = []

        for h in mains:
            support = h.support_count
            contra = h.contradict_count
            conf = h.confidence

            lines.append(
                f"MAIN: {h.statement} "
                f"(status={h.status.value}, confidence={conf:.2f})"
            )

            # -- Evidence assessment ---------------------------------
            if support >= 3:
                finding = (
                    f"Hipotesis didukung kuat oleh {support} evidence."
                )
            elif support >= 2:
                finding = (
                    f"Hipotesis didukung oleh {support} evidence."
                )
            elif support == 1:
                finding = (
                    "Hipotesis hanya didukung 1 evidence; "
                    "perlu verifikasi tambahan."
                )
            else:
                finding = (
                    "Hipotesis belum punya supporting evidence; "
                    "status masih PROPOSED."
                )
            findings.append(finding)

            # -- Counter presence ------------------------------------
            if contra > 0:
                findings.append(
                    f"Ditemukan {contra} contradicting evidence — "
                    f"pertimbangkan downgrade status."
                )

            # -- Status assessment -----------------------------------
            if h.status == HypothesisStatus.PROPOSED and support >= 2:
                findings.append(
                    "Hipotesis punya cukup dukungan untuk naik ke "
                    "SUPPORTED."
                )
            elif h.status == HypothesisStatus.SUPPORTED and conf >= 0.7:
                findings.append(
                    "Confidence tinggi; hipotesis kandidat kuat "
                    "untuk CONFIRMED setelah verifikasi tambahan."
                )

            # -- Missing evidence ------------------------------------
            if h.missing_evidence:
                findings.append(
                    f"{len(h.missing_evidence)} bukti masih dibutuhkan "
                    f"untuk konfirmasi."
                )

        return AgentOutput(
            name=self._name,
            content="\n".join(lines),
            findings=findings,
            metadata={"main_count": len(mains)},
        )


__all__ = ["HypothesisAgent"]
