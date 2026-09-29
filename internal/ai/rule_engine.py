"""
Deterministic rule-based narrative provider.

Menghasilkan analyst-style narrative dari InvestigationResult tanpa LLM.
Selalu tersedia. Menjadi fallback utama ketika LLM tidak ada.
"""

from __future__ import annotations

from internal.ai.provider import BaseProvider
from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from pkg.models.evidence import EvidenceStrength
from pkg.models.hypothesis import (
    HypothesisStatus,
    HypothesisType,
)


class RuleEngineProvider(BaseProvider):
    """Deterministic narrative generator."""

    _name = "rule_engine"

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        sections = [
            self._opening(result),
            self._findings(result),
            self._hypotheses(result),
            self._risk(result),
            self._missing_evidence(result),
            self._actions(result),
        ]
        return "\n\n".join(s for s in sections if s)

    def _opening(self, result: InvestigationResult) -> str:
        case = result.case
        title = case.title

        parts = [
            f"Investigasi {title!r} menganalisis "
            f"{result.graph.events_processed} event "
            f"dari host terkait.",
        ]

        if result.evidence_count:
            parts.append(
                f"Sistem mengekstrak {result.evidence_count} evidence "
                f"dan menemukan {result.correlation_count} korelasi "
                f"antar-event."
            )

        if result.hypothesis_count:
            parts.append(
                f"{result.hypothesis_count} hipotesis dibangun dari data ini."
            )

        parts.append(
            f"Risk score akhir: {result.risk_score}/100 "
            f"(confidence {result.confidence:.2f})."
        )

        return " ".join(parts)

    def _findings(self, result: InvestigationResult) -> str:
        if not result.evidence:
            return ""

        lines: list[str] = ["**Temuan utama:**"]

        highlighted = [
            ev for ev in result.evidence
            if ev.strength in (
                EvidenceStrength.CRITICAL,
                EvidenceStrength.STRONG,
            )
        ]
        other = [
            ev for ev in result.evidence
            if ev not in highlighted
        ]

        for ev in highlighted[:3]:
            lines.append(
                f"- [{ev.strength.value.upper()}] {ev.title}"
            )

        if len(highlighted) > 3:
            lines.append(
                f"- ... dan {len(highlighted) - 3} evidence kuat lainnya"
            )

        if not highlighted and other:
            for ev in other[:3]:
                lines.append(
                    f"- [{ev.strength.value}] {ev.title}"
                )

        if result.correlations:
            top = max(
                result.correlations,
                key=lambda c: c.confidence,
            )
            reasons = ", ".join(
                r.value for r in top.reasons
            )
            lines.append(
                f"- Correlation engine mengaitkan event-event ini "
                f"melalui {len(top.reasons)} sinyal "
                f"({reasons}), dengan confidence "
                f"{top.confidence:.2f}."
            )

        return "\n".join(lines)

    def _hypotheses(self, result: InvestigationResult) -> str:
        if not result.hypotheses:
            return ""

        lines: list[str] = ["**Hipotesis:**"]

        mains = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.MAIN
        ]
        counters = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.COUNTER
        ]
        subs = [
            h for h in result.hypotheses
            if h.hypothesis_type == HypothesisType.SUB
        ]

        for h in mains:
            status_label = self._status_label(h.status)
            lines.append(
                f"- [MAIN] {h.statement} "
                f"({status_label}, confidence {h.confidence:.2f})"
            )
            if h.supporting_evidence_ids:
                lines.append(
                    f"  didukung oleh {len(h.supporting_evidence_ids)} "
                    f"evidence"
                )

        for h in counters:
            lines.append(
                f"- [COUNTER] {h.statement} — "
                f"hipotesis alternatif yang belum terbantahkan"
            )

        if subs:
            lines.append(
                f"- {len(subs)} sub-hipotesis turunan dari sinyal "
                f"graph / correlation."
            )

        return "\n".join(lines)

    def _risk(self, result: InvestigationResult) -> str:
        if result.risk is None:
            return ""

        risk = result.risk
        breakdown = risk.breakdown

        lines: list[str] = [
            f"**Risk assessment ({risk.risk_score}/100):**"
        ]

        for category in (
            "evidence", "correlation", "hypothesis", "penalty"
        ):
            value = breakdown.get(category, 0.0)
            sign = "+" if value >= 0 else ""
            lines.append(f"- {category}: {sign}{value:.1f}")

        top = risk.top_contributors[:3]
        if top:
            lines.append("")
            lines.append("**Kontributor terbesar:**")
            for f in top:
                lines.append(
                    f"- {f.contribution:+.1f} — {f.rationale}"
                )

        return "\n".join(lines)

    def _missing_evidence(
        self, result: InvestigationResult
    ) -> str:
        missing: set[str] = set()
        for h in result.hypotheses:
            missing.update(h.missing_evidence)

        if not missing:
            return ""

        lines = [
            f"**Bukti yang masih dibutuhkan ({len(missing)}):**"
        ]
        for item in sorted(missing):
            lines.append(f"- {item}")

        return "\n".join(lines)

    def _actions(self, result: InvestigationResult) -> str:
        from internal.reporter.report import InvestigatorReport

        actions = InvestigatorReport(result)._recommended_actions()
        if not actions:
            return ""

        lines = ["**Rekomendasi tindak lanjut:**"]
        for i, action in enumerate(actions[:5], 1):
            lines.append(f"{i}. {action}")
        return "\n".join(lines)

    @staticmethod
    def _status_label(status: HypothesisStatus) -> str:
        labels = {
            HypothesisStatus.PROPOSED: "proposed",
            HypothesisStatus.SUPPORTED: "didukung",
            HypothesisStatus.WEAKENED: "melemah",
            HypothesisStatus.CONFIRMED: "terkonfirmasi",
            HypothesisStatus.REJECTED: "ditolak",
        }
        return labels.get(status, status.value)


__all__ = ["RuleEngineProvider"]
