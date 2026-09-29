"""
CriticAgent: kritik & gap analysis terhadap hasil investigasi.

Deterministic. Mencari:
- evidence yang tampak duplikat (content_hash mirip)
- evidence dengan strength tinggi tapi tidak didukung context lain
- hypothesis tanpa evidence atau tanpa counter
- gap antara MAIN dan COUNTER
"""

from __future__ import annotations

from collections import Counter

from internal.ai.agents.base import (
    Agent,
    AgentContext,
    AgentOutput,
)
from pkg.models.hypothesis import HypothesisType


class CriticAgent(Agent):
    _name = "critic_agent"

    def run(self, context: AgentContext) -> AgentOutput:
        result = context.result

        findings: list[str] = []
        lines: list[str] = ["Kritik terhadap investigasi:"]

        # -- Duplikasi evidence -------------------------------------
        titles = [ev.title for ev in result.evidence]
        title_counts = Counter(titles)
        duplicates = [
            title for title, count in title_counts.items()
            if count > 1
        ]
        if duplicates:
            for dup in duplicates:
                findings.append(
                    f"Terdeteksi observasi berulang: '{dup}' "
                    f"muncul lebih dari sekali. "
                    f"Pertimbangkan dedup sebelum risk scoring."
                )

        # -- Evidence tanpa konteks ---------------------------------
        evidence_without_context = [
            ev for ev in result.evidence
            if not ev.data.get("process")
            and not ev.data.get("network")
            and not ev.data.get("file")
            and not ev.data.get("registry")
            and not ev.data.get("dns")
        ]
        if evidence_without_context:
            findings.append(
                f"{len(evidence_without_context)} evidence tanpa "
                f"context spesifik; sulit dikonfirmasi."
            )

        # -- Hypothesis tanpa counter -------------------------------
        mains = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.MAIN
        ]
        counters = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.COUNTER
        ]
        if mains and not counters:
            findings.append(
                "MAIN hypothesis ada, tapi tidak ada COUNTER "
                "hypothesis. Investigasi tidak seimbang."
            )

        # -- MAIN tanpa evidence ------------------------------------
        for h in mains:
            if not h.supporting_evidence_ids:
                findings.append(
                    f"MAIN '{h.statement[:50]}...' tidak punya "
                    f"supporting evidence."
                )

        # -- Korelasi lemah -----------------------------------------
        weak_corr = [
            c for c in result.correlations
            if getattr(c, "confidence", 0.0) < 0.5
        ]
        if weak_corr:
            findings.append(
                f"{len(weak_corr)} korelasi ber-confidence rendah "
                f"(< 0.5); pertimbangkan untuk diabaikan."
            )

        # -- Risk score tinggi tanpa dukungan -----------------------
        if result.risk_score >= 70 and not mains:
            findings.append(
                "Risk score tinggi tetapi tidak ada MAIN hypothesis. "
                "Periksa apakah scoring proporsional."
            )

        if not findings:
            findings.append(
                "Tidak ditemukan gap signifikan pada investigasi ini."
            )

        lines.extend(f"  - {f}" for f in findings)

        return AgentOutput(
            name=self._name,
            content="\n".join(lines),
            findings=findings,
            metadata={
                "duplicate_titles": duplicates,
                "evidence_without_context_count": len(
                    evidence_without_context
                ),
            },
        )


__all__ = ["CriticAgent"]
