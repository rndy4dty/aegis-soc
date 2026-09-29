"""
Deterministic risk engine for AegisSOC.

Tugas:
    (Evidence[], CorrelationResult[], Hypothesis[])  ->  RiskAssessment

Menjawab pertanyaan inti AegisSOC:

    "Kenapa risk score naik dari 42 ke 71?
     Evidence / correlation / hypothesis mana yang menyebabkan?"

Prinsip:
- Deterministik. Tidak ada LLM, tidak ada randomness.
- Setiap kenaikan/penurunan dijelaskan sebagai RiskFactor eksplisit.
- Setiap faktor punya category: evidence, correlation, hypothesis, penalty.
- Skor akhir di [0, 100]. Confidence di [0, 1].
- Tidak mengubah Evidence, CorrelationResult, Hypothesis, atau Case.
- Terintegrasi dengan InvestigationCase.update_risk() via apply_to_case().

Catatan tentang Evidence model AegisSOC:
- Evidence memiliki `strength` dan `confidence`, TIDAK memiliki `weight`.
- Kontribusi evidence dihitung dari `strength` (via EVIDENCE_STRENGTH_SCORES).
- `confidence` di Evidence dipakai untuk RiskAssessment.confidence,
  bukan untuk risk_score itu sendiri.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    model_validator,
)

from pkg.models.evidence import (
    Evidence,
    EvidenceAssessment,
    EvidenceStrength,
)
from pkg.models.hypothesis import Hypothesis, HypothesisStatus


# ===========================================================================
# Constants
# ===========================================================================

RISK_MIN: int = 0
RISK_MAX: int = 100

CONFIDENCE_MIN: float = 0.0
CONFIDENCE_MAX: float = 1.0


# Skor kontribusi evidence berdasarkan strength.
# Dipakai langsung (tanpa multiplier) — bukan dari `weight`.
EVIDENCE_STRENGTH_SCORES: dict[EvidenceStrength, float] = {
    EvidenceStrength.WEAK: 5.0,
    EvidenceStrength.MODERATE: 10.0,
    EvidenceStrength.STRONG: 20.0,
    EvidenceStrength.CRITICAL: 30.0,
}


# Skor kontribusi hypothesis berdasarkan status.
HYPOTHESIS_STATUS_SCORES: dict[HypothesisStatus, float] = {
    HypothesisStatus.PROPOSED: 5.0,
    HypothesisStatus.SUPPORTED: 25.0,
    HypothesisStatus.CONFIRMED: 40.0,
    HypothesisStatus.WEAKENED: 0.0,
    HypothesisStatus.REJECTED: 0.0,
}


RiskCategory = Literal["evidence", "correlation", "hypothesis", "penalty"]


# ===========================================================================
# RiskConfig
# ===========================================================================

class RiskConfig(BaseModel):
    """
    Konfigurasi engine. Bisa di-tune tanpa mengubah logika.
    """

    model_config = ConfigDict(extra="forbid")

    # -- Evidence ---------------------------------------------------------
    evidence_max_contribution: float = Field(default=40.0, ge=0.0)
    evidence_verified_bonus: float = Field(default=3.0, ge=0.0)

    # -- Correlation ------------------------------------------------------
    correlation_max_contribution: float = Field(default=20.0, ge=0.0)
    correlation_per_pair_max: float = Field(default=5.0, ge=0.0)

    # -- Hypothesis -------------------------------------------------------
    hypothesis_max_contribution: float = Field(default=40.0, ge=0.0)

    # -- Penalties --------------------------------------------------------
    missing_evidence_per_item: float = Field(default=2.0, ge=0.0)
    missing_evidence_max_penalty: float = Field(default=15.0, ge=0.0)

    contradicting_evidence_per_item: float = Field(default=3.0, ge=0.0)
    contradicting_evidence_max_penalty: float = Field(default=20.0, ge=0.0)

    # -- Confidence blend -------------------------------------------------
    confidence_evidence_weight: float = Field(default=0.4, ge=0.0, le=1.0)
    confidence_coverage_weight: float = Field(default=0.3, ge=0.0, le=1.0)
    confidence_hypothesis_weight: float = Field(default=0.3, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _check_weights_sum(self) -> "RiskConfig":
        total = (
            self.confidence_evidence_weight
            + self.confidence_coverage_weight
            + self.confidence_hypothesis_weight
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                "confidence weights must sum to 1.0, "
                f"got {total:.4f}"
            )
        return self


DEFAULT_RISK_CONFIG = RiskConfig()


# ===========================================================================
# RiskFactor
# ===========================================================================

class RiskFactor(BaseModel):
    """
    Satu kontributor pada risk score.

    Positif  -> menaikkan risk.
    Negatif  -> menurunkan risk (penalti).
    """

    model_config = ConfigDict(extra="forbid")

    name: str
    category: RiskCategory
    contribution: float
    rationale: str
    source_ids: list[str] = Field(default_factory=list)

    @property
    def is_positive(self) -> bool:
        return self.contribution > 0.0

    @property
    def is_negative(self) -> bool:
        return self.contribution < 0.0


# ===========================================================================
# RiskAssessment
# ===========================================================================

class RiskAssessment(BaseModel):
    """
    Hasil perhitungan risk engine.
    """

    model_config = ConfigDict(extra="forbid")

    risk_score: int = Field(ge=RISK_MIN, le=RISK_MAX)
    confidence: float = Field(ge=CONFIDENCE_MIN, le=CONFIDENCE_MAX)

    factors: list[RiskFactor] = Field(default_factory=list)

    breakdown: dict[str, float] = Field(default_factory=dict)

    summary: str | None = None

    # ==================================================================
    # Helpers
    # ==================================================================

    @property
    def positive_contributors(self) -> list[RiskFactor]:
        return [f for f in self.factors if f.is_positive]

    @property
    def negative_contributors(self) -> list[RiskFactor]:
        return [f for f in self.factors if f.is_negative]

    @property
    def top_contributors(self) -> list[RiskFactor]:
        return sorted(
            self.positive_contributors,
            key=lambda f: -f.contribution,
        )

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 70

    @property
    def is_critical(self) -> bool:
        return self.risk_score >= 85

    def explain(self) -> str:
        """
        Human-readable breakdown.
        """
        lines = [
            f"Risk Score   : {self.risk_score}/100",
            f"Confidence   : {self.confidence:.2f}",
            "",
            "Breakdown:",
        ]
        for cat in ("evidence", "correlation", "hypothesis", "penalty"):
            val = self.breakdown.get(cat, 0.0)
            lines.append(f"  {cat:<12} {val:+.2f}")

        if self.factors:
            lines.append("")
            lines.append("Factors:")
            for f in sorted(self.factors, key=lambda x: -abs(x.contribution)):
                sign = "+" if f.contribution >= 0 else ""
                lines.append(
                    f"  {sign}{f.contribution:6.2f}  "
                    f"[{f.category}] {f.rationale}"
                )

        return "\n".join(lines)

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": "risk-assessment",
            "type": "RiskAssessment",
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "breakdown": dict(self.breakdown),
            "factor_count": len(self.factors),
            "top_contributors": [
                {
                    "name": f.name,
                    "category": f.category,
                    "contribution": f.contribution,
                }
                for f in self.top_contributors[:5]
            ],
        }


# ===========================================================================
# Module-level helpers
# ===========================================================================

def _clamp_float(value: float, lo: float, hi: float) -> float:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def _clamp_int(value: int, lo: int, hi: int) -> int:
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


# ===========================================================================
# RiskEngine
# ===========================================================================

class RiskEngine:
    """
    Stateless risk calculator.
    """

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or DEFAULT_RISK_CONFIG

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def compute(
        self,
        *,
        evidence: list[Evidence] | None = None,
        correlations: list[Any] | None = None,
        hypotheses: list[Hypothesis] | None = None,
    ) -> RiskAssessment:
        evidence = list(evidence or [])
        correlations = list(correlations or [])
        hypotheses = list(hypotheses or [])

        factors: list[RiskFactor] = []

        evidence_score = self._score_evidence(evidence, factors)
        correlation_score = self._score_correlations(correlations, factors)
        hypothesis_score = self._score_hypotheses(hypotheses, factors)
        penalty_score = self._score_penalties(
            evidence, hypotheses, factors,
        )

        raw_total = (
            evidence_score
            + correlation_score
            + hypothesis_score
            + penalty_score
        )
        risk_score = _clamp_int(round(raw_total), RISK_MIN, RISK_MAX)

        confidence = self._compute_confidence(evidence, hypotheses)

        breakdown = {
            "evidence": round(evidence_score, 2),
            "correlation": round(correlation_score, 2),
            "hypothesis": round(hypothesis_score, 2),
            "penalty": round(penalty_score, 2),
        }

        summary = self._build_summary(
            risk_score=risk_score,
            confidence=confidence,
            breakdown=breakdown,
            top=factors,
        )

        return RiskAssessment(
            risk_score=risk_score,
            confidence=confidence,
            factors=factors,
            breakdown=breakdown,
            summary=summary,
        )

    # -------------------------------------------------------------------
    # Evidence scoring
    # -------------------------------------------------------------------
    #
    # Kontribusi evidence = EVIDENCE_STRENGTH_SCORES[strength]
    #                     + verified_bonus (kalau verified)
    #
    # Tidak ada multiplier `weight` — model Evidence tidak punya field itu.
    # `confidence` di Evidence dipakai untuk RiskAssessment.confidence.

    def _score_evidence(
        self,
        evidence: list[Evidence],
        factors: list[RiskFactor],
    ) -> float:
        if not evidence:
            return 0.0

        total = 0.0

        for ev in evidence:
            base = EVIDENCE_STRENGTH_SCORES.get(ev.strength, 0.0)
            contribution = base

            if ev.verification.verified:
                contribution += self.config.evidence_verified_bonus

            total += contribution

            factors.append(RiskFactor(
                name=f"evidence:{ev.evidence_id}",
                category="evidence",
                contribution=round(contribution, 3),
                rationale=(
                    f"{ev.strength.value} {ev.evidence_type.value}: "
                    f"{ev.title}"
                ),
                source_ids=[ev.evidence_id],
            ))

        return min(total, self.config.evidence_max_contribution)

    # -------------------------------------------------------------------
    # Correlation scoring
    # -------------------------------------------------------------------

    def _score_correlations(
        self,
        correlations: list[Any],
        factors: list[RiskFactor],
    ) -> float:
        if not correlations:
            return 0.0

        total = 0.0

        for corr in correlations:
            conf = _clamp_float(
                getattr(corr, "confidence", 0.0), 0.0, 1.0,
            )
            contribution = conf * self.config.correlation_per_pair_max
            total += contribution

            cid = getattr(corr, "correlation_id", None) or "unknown"
            reasons = getattr(corr, "reasons", None) or []
            reason_str = ",".join(
                r.value if isinstance(r, Enum) else str(r)
                for r in reasons
            ) or "n/a"

            factors.append(RiskFactor(
                name=f"correlation:{cid}",
                category="correlation",
                contribution=round(contribution, 3),
                rationale=(
                    f"correlation confidence {conf:.2f} "
                    f"(reasons: {reason_str})"
                ),
                source_ids=[str(cid)],
            ))

        return min(total, self.config.correlation_max_contribution)

    # -------------------------------------------------------------------
    # Hypothesis scoring
    # -------------------------------------------------------------------

    def _score_hypotheses(
        self,
        hypotheses: list[Hypothesis],
        factors: list[RiskFactor],
    ) -> float:
        if not hypotheses:
            return 0.0

        # Ambil kontribusi tertinggi dari hipotesis mana pun.
        # Ini mencegah double-counting saat MAIN dan SUB hypothesis
        # sama-sama menunjuk pada bukti yang sama.
        best_value = 0.0
        best_factor: RiskFactor | None = None

        for hyp in hypotheses:
            base = HYPOTHESIS_STATUS_SCORES.get(hyp.status, 0.0)
            conf = _clamp_float(hyp.confidence, 0.0, 1.0)
            value = base * conf

            if value > best_value:
                best_value = value
                best_factor = RiskFactor(
                    name=f"hypothesis:{hyp.hypothesis_id}",
                    category="hypothesis",
                    contribution=round(value, 3),
                    rationale=(
                        f"{hyp.status.value} hypothesis "
                        f"(confidence {conf:.2f}): {hyp.statement}"
                    ),
                    source_ids=[hyp.hypothesis_id],
                )

        if best_factor is not None:
            factors.append(best_factor)

        return min(best_value, self.config.hypothesis_max_contribution)

    # -------------------------------------------------------------------
    # Penalties
    # -------------------------------------------------------------------

    def _score_penalties(
        self,
        evidence: list[Evidence],
        hypotheses: list[Hypothesis],
        factors: list[RiskFactor],
    ) -> float:
        total_penalty = 0.0

        # -- Missing evidence --------------------------------------------
        missing_count = sum(
            len(hyp.missing_evidence) for hyp in hypotheses
        )
        if missing_count > 0:
            penalty = min(
                missing_count * self.config.missing_evidence_per_item,
                self.config.missing_evidence_max_penalty,
            )
            total_penalty -= penalty
            factors.append(RiskFactor(
                name="penalty:missing_evidence",
                category="penalty",
                contribution=round(-penalty, 3),
                rationale=(
                    f"{missing_count} missing evidence item(s) "
                    f"across hypotheses"
                ),
                source_ids=[
                    h.hypothesis_id for h in hypotheses
                    if h.missing_evidence
                ],
            ))

        # -- Contradicting evidence --------------------------------------
        contradicting_ids: set[str] = set()

        for hyp in hypotheses:
            contradicting_ids.update(hyp.contradicting_evidence_ids)

        for ev in evidence:
            for link in ev.hypothesis_links:
                if link.assessment == EvidenceAssessment.CONTRADICTS:
                    contradicting_ids.add(ev.evidence_id)

        contradicting_count = len(contradicting_ids)
        if contradicting_count > 0:
            penalty = min(
                contradicting_count
                * self.config.contradicting_evidence_per_item,
                self.config.contradicting_evidence_max_penalty,
            )
            total_penalty -= penalty
            factors.append(RiskFactor(
                name="penalty:contradicting_evidence",
                category="penalty",
                contribution=round(-penalty, 3),
                rationale=(
                    f"{contradicting_count} contradicting evidence item(s)"
                ),
                source_ids=sorted(contradicting_ids),
            ))

        return total_penalty

    # -------------------------------------------------------------------
    # Confidence
    # -------------------------------------------------------------------

    def _compute_confidence(
        self,
        evidence: list[Evidence],
        hypotheses: list[Hypothesis],
    ) -> float:
        # 1. Average evidence confidence
        if evidence:
            evidence_confidence = sum(
                _clamp_float(ev.confidence, 0.0, 1.0)
                for ev in evidence
            ) / len(evidence)
        else:
            evidence_confidence = 0.0

        # 2. Coverage: berapa banyak hypothesis yang punya
        #    setidaknya satu supporting evidence.
        if hypotheses:
            covered = sum(
                1 for h in hypotheses if h.supporting_evidence_ids
            )
            coverage = covered / len(hypotheses)
        else:
            coverage = 0.0

        # 3. Hypothesis confidence (max di antara semua hypothesis)
        if hypotheses:
            hypothesis_confidence = max(
                _clamp_float(h.confidence, 0.0, 1.0) for h in hypotheses
            )
        else:
            hypothesis_confidence = 0.0

        confidence = (
            self.config.confidence_evidence_weight * evidence_confidence
            + self.config.confidence_coverage_weight * coverage
            + self.config.confidence_hypothesis_weight
            * hypothesis_confidence
        )

        return _clamp_float(confidence, CONFIDENCE_MIN, CONFIDENCE_MAX)

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------

    @staticmethod
    def _build_summary(
        *,
        risk_score: int,
        confidence: float,
        breakdown: dict[str, float],
        top: list[RiskFactor],
    ) -> str:
        positives = sorted(
            (f for f in top if f.contribution > 0),
            key=lambda f: -f.contribution,
        )
        top_names = ", ".join(f.name for f in positives[:3]) or "none"

        return (
            f"Risk {risk_score}/100 (confidence {confidence:.2f}). "
            f"Breakdown: evidence={breakdown['evidence']:+.1f}, "
            f"correlation={breakdown['correlation']:+.1f}, "
            f"hypothesis={breakdown['hypothesis']:+.1f}, "
            f"penalty={breakdown['penalty']:+.1f}. "
            f"Top contributors: {top_names}."
        )

    # -------------------------------------------------------------------
    # Case integration
    # -------------------------------------------------------------------

    def apply_to_case(
        self,
        case: Any,
        assessment: RiskAssessment,
        *,
        reason: str | None = None,
        evidence_ids: list[str] | None = None,
        hypothesis_ids: list[str] | None = None,
    ) -> None:
        """
        Tulis assessment ke InvestigationCase via update_risk().

        Memodifikasi case in-place lewat method resmi yang sudah
        mencatat RiskEvolution.
        """
        case.update_risk(
            risk_score=assessment.risk_score,
            confidence=assessment.confidence,
            reason=reason or assessment.summary or "risk engine update",
            risk_factors=[f.name for f in assessment.factors],
            evidence_ids=evidence_ids or [],
            hypothesis_ids=hypothesis_ids or [],
        )


# ===========================================================================
# Factory
# ===========================================================================

def compute_risk(
    *,
    evidence: list[Evidence] | None = None,
    correlations: list[Any] | None = None,
    hypotheses: list[Hypothesis] | None = None,
    config: RiskConfig | None = None,
) -> RiskAssessment:
    """Convenience factory."""
    return RiskEngine(config=config).compute(
        evidence=evidence,
        correlations=correlations,
        hypotheses=hypotheses,
    )


__all__ = [
    "RISK_MIN",
    "RISK_MAX",
    "CONFIDENCE_MIN",
    "CONFIDENCE_MAX",
    "EVIDENCE_STRENGTH_SCORES",
    "HYPOTHESIS_STATUS_SCORES",
    "RiskCategory",
    "RiskConfig",
    "DEFAULT_RISK_CONFIG",
    "RiskFactor",
    "RiskAssessment",
    "RiskEngine",
    "compute_risk",
]
