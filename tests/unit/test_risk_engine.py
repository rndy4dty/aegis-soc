"""
Contract tests untuk RiskEngine.

Menguji:
- evidence scoring (strength-based, tanpa weight)
- correlation scoring
- hypothesis scoring
- penalty (missing + contradicting)
- confidence blend
- integration dengan InvestigationCase
- determinisme
- edge cases
"""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from internal.investigation.risk_engine import (
    CONFIDENCE_MAX,
    CONFIDENCE_MIN,
    EVIDENCE_STRENGTH_SCORES,
    HYPOTHESIS_STATUS_SCORES,
    DEFAULT_RISK_CONFIG,
    RISK_MAX,
    RISK_MIN,
    RiskAssessment,
    RiskConfig,
    RiskEngine,
    RiskFactor,
    compute_risk,
)
from pkg.models.evidence import (
    Evidence,
    EvidenceAssessment,
    EvidenceProvenance,
    EvidenceStrength,
    EvidenceType,
    HypothesisLink,
)
from pkg.models.hypothesis import (
    Hypothesis,
    HypothesisStatus,
    HypothesisType,
)


# ===========================================================================
# Helpers
# ===========================================================================

def make_evidence(
    *,
    evidence_id: str = "E-1",
    strength: EvidenceStrength = EvidenceStrength.MODERATE,
    confidence: float = 0.8,
    verified: bool = False,
    contradicts: list[str] | None = None,
) -> Evidence:
    links = []
    for hid in (contradicts or []):
        links.append(HypothesisLink(
            hypothesis_id=hid,
            assessment=EvidenceAssessment.CONTRADICTS,
            weight=0.5,
        ))

    ev = Evidence(
        evidence_type=EvidenceType.PROCESS,
        strength=strength,
        title=f"Evidence {evidence_id}",
        description="test evidence",
        confidence=confidence,
        provenance=EvidenceProvenance(source="test"),
        hypothesis_links=links,
    )
    ev = ev.model_copy(update={"evidence_id": evidence_id})

    if verified:
        ev = ev.mark_verified(
            verified_by="analyst",
            method="manual_review",
        )

    return ev


def make_correlation(
    correlation_id: str = "COR-1",
    confidence: float = 0.7,
) -> object:
    class _Corr:
        pass

    c = _Corr()
    c.correlation_id = correlation_id
    c.confidence = confidence
    c.reasons = []
    return c


def make_hypothesis(
    *,
    hypothesis_id: str = "H-1",
    status: HypothesisStatus = HypothesisStatus.PROPOSED,
    confidence: float = 0.5,
    supporting_evidence_ids: list[str] | None = None,
    contradicting_evidence_ids: list[str] | None = None,
    missing_evidence: list[str] | None = None,
    rationale: str | None = None,
) -> Hypothesis:
    kwargs: dict = {
        "statement": f"Hypothesis {hypothesis_id}",
        "hypothesis_type": HypothesisType.MAIN,
        "status": status,
        "confidence": confidence,
        "supporting_evidence_ids": supporting_evidence_ids or [],
        "contradicting_evidence_ids": contradicting_evidence_ids or [],
        "missing_evidence": missing_evidence or [],
    }
    if status in (
        HypothesisStatus.CONFIRMED, HypothesisStatus.REJECTED,
    ):
        kwargs["rationale"] = rationale or "rationale required"
    h = Hypothesis(**kwargs)
    return h.model_copy(update={"hypothesis_id": hypothesis_id})


# ===========================================================================
# Empty / trivial
# ===========================================================================

def test_empty_input():
    result = compute_risk()
    assert result.risk_score == 0
    assert result.confidence == 0.0
    assert result.factors == []
    assert result.breakdown == {
        "evidence": 0.0,
        "correlation": 0.0,
        "hypothesis": 0.0,
        "penalty": 0.0,
    }


def test_no_factors_returns_zero():
    result = compute_risk(evidence=[], correlations=[], hypotheses=[])
    assert result.risk_score == 0


# ===========================================================================
# Evidence scoring
# ===========================================================================

def test_evidence_weak():
    ev = make_evidence(strength=EvidenceStrength.WEAK)
    result = compute_risk(evidence=[ev])
    assert result.breakdown["evidence"] == 5.0


def test_evidence_moderate():
    ev = make_evidence(strength=EvidenceStrength.MODERATE)
    result = compute_risk(evidence=[ev])
    assert result.breakdown["evidence"] == 10.0


def test_evidence_strong():
    ev = make_evidence(strength=EvidenceStrength.STRONG)
    result = compute_risk(evidence=[ev])
    assert result.breakdown["evidence"] == 20.0


def test_evidence_critical():
    ev = make_evidence(strength=EvidenceStrength.CRITICAL)
    result = compute_risk(evidence=[ev])
    assert result.breakdown["evidence"] == 30.0


def test_evidence_verified_bonus():
    ev = make_evidence(strength=EvidenceStrength.MODERATE, verified=True)
    result = compute_risk(evidence=[ev])
    # 10 (base) + 3 (verified bonus)
    assert result.breakdown["evidence"] == 13.0


def test_evidence_strength_scores_complete():
    for s in EvidenceStrength:
        assert s in EVIDENCE_STRENGTH_SCORES


def test_evidence_summed_and_capped():
    evidence = [
        make_evidence(
            evidence_id=f"E-{i}",
            strength=EvidenceStrength.CRITICAL,
        )
        for i in range(10)
    ]
    result = compute_risk(evidence=evidence)
    # 10 × 30 = 300 -> capped at 40
    assert result.breakdown["evidence"] == 40.0


def test_evidence_factor_created():
    ev = make_evidence(evidence_id="E-42")
    result = compute_risk(evidence=[ev])
    assert len(result.factors) == 1
    f = result.factors[0]
    assert f.name == "evidence:E-42"
    assert f.category == "evidence"
    assert "E-42" in f.source_ids


# ===========================================================================
# Correlation scoring
# ===========================================================================

def test_correlation_scoring():
    corr = make_correlation(confidence=0.8)
    result = compute_risk(correlations=[corr])
    # 0.8 * 5.0 = 4.0
    assert result.breakdown["correlation"] == 4.0


def test_correlation_capped_at_max():
    corr_list = [
        make_correlation(f"COR-{i}", confidence=1.0)
        for i in range(10)
    ]
    result = compute_risk(correlations=corr_list)
    assert result.breakdown["correlation"] == 20.0


def test_correlation_factor_created():
    corr = make_correlation("COR-X", confidence=0.9)
    result = compute_risk(correlations=[corr])
    names = [f.name for f in result.factors]
    assert "correlation:COR-X" in names


# ===========================================================================
# Hypothesis scoring
# ===========================================================================

def test_hypothesis_proposed():
    h = make_hypothesis(
        status=HypothesisStatus.PROPOSED,
        confidence=1.0,
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["hypothesis"] == 5.0


def test_hypothesis_supported():
    h = make_hypothesis(
        status=HypothesisStatus.SUPPORTED,
        confidence=1.0,
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["hypothesis"] == 25.0


def test_hypothesis_confirmed():
    h = make_hypothesis(
        status=HypothesisStatus.CONFIRMED,
        confidence=1.0,
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["hypothesis"] == 40.0


def test_hypothesis_confidence_multiplier():
    h = make_hypothesis(
        status=HypothesisStatus.CONFIRMED,
        confidence=0.5,
    )
    result = compute_risk(hypotheses=[h])
    # 40 * 0.5 = 20
    assert result.breakdown["hypothesis"] == 20.0


def test_hypothesis_takes_max_not_sum():
    h1 = make_hypothesis(
        hypothesis_id="H-1",
        status=HypothesisStatus.SUPPORTED,
        confidence=1.0,
    )
    h2 = make_hypothesis(
        hypothesis_id="H-2",
        status=HypothesisStatus.CONFIRMED,
        confidence=1.0,
    )
    result = compute_risk(hypotheses=[h1, h2])
    # max(25, 40) = 40, bukan sum
    assert result.breakdown["hypothesis"] == 40.0


def test_hypothesis_weakened_no_positive_contribution():
    h = make_hypothesis(
        status=HypothesisStatus.WEAKENED,
        confidence=1.0,
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["hypothesis"] == 0.0


def test_hypothesis_status_scores_complete():
    for s in HypothesisStatus:
        assert s in HYPOTHESIS_STATUS_SCORES


# ===========================================================================
# Penalties
# ===========================================================================

def test_missing_evidence_penalty():
    h = make_hypothesis(
        missing_evidence=["shim_db", "registry", "network"],
    )
    result = compute_risk(hypotheses=[h])
    # 3 * 2.0 = 6.0
    assert result.breakdown["penalty"] == -6.0


def test_missing_evidence_penalty_capped():
    h = make_hypothesis(
        missing_evidence=[f"item-{i}" for i in range(20)],
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["penalty"] == -15.0


def test_contradicting_evidence_penalty():
    h = make_hypothesis(
        contradicting_evidence_ids=["E-1", "E-2"],
    )
    result = compute_risk(hypotheses=[h])
    # 2 * 3.0 = 6.0
    assert result.breakdown["penalty"] == -6.0


def test_contradicting_evidence_penalty_capped():
    h = make_hypothesis(
        contradicting_evidence_ids=[f"E-{i}" for i in range(20)],
    )
    result = compute_risk(hypotheses=[h])
    assert result.breakdown["penalty"] == -20.0


def test_evidence_with_contradicting_link_penalized():
    ev = make_evidence(
        evidence_id="E-1",
        contradicts=["H-1"],
    )
    result = compute_risk(evidence=[ev])
    assert result.breakdown["penalty"] == -3.0


def test_missing_and_contradicting_combined():
    h = make_hypothesis(
        contradicting_evidence_ids=["E-1"],
        missing_evidence=["a", "b"],
    )
    result = compute_risk(hypotheses=[h])
    # -3.0 + -4.0 = -7.0
    assert result.breakdown["penalty"] == -7.0


# ===========================================================================
# Confidence
# ===========================================================================

def test_confidence_empty():
    result = compute_risk()
    assert result.confidence == 0.0


def test_confidence_with_evidence_only():
    ev = make_evidence(confidence=0.9)
    result = compute_risk(evidence=[ev])
    # evidence_confidence=0.9, coverage=0, hypothesis=0
    # 0.4*0.9 = 0.36
    assert abs(result.confidence - 0.36) < 1e-6


def test_confidence_full():
    ev = make_evidence(confidence=1.0)
    h = make_hypothesis(
        confidence=1.0,
        supporting_evidence_ids=["E-1"],
    )
    result = compute_risk(evidence=[ev], hypotheses=[h])
    # 0.4*1 + 0.3*1 + 0.3*1 = 1.0
    assert abs(result.confidence - 1.0) < 1e-6


# ===========================================================================
# Overall scoring
# ===========================================================================

def test_risk_score_clamped_to_100():
    evidence = [
        make_evidence(
            evidence_id=f"E-{i}",
            strength=EvidenceStrength.CRITICAL,
        )
        for i in range(10)
    ]
    h = make_hypothesis(
        status=HypothesisStatus.CONFIRMED,
        confidence=1.0,
    )
    corr_list = [
        make_correlation(f"COR-{i}", confidence=1.0) for i in range(10)
    ]
    result = compute_risk(
        evidence=evidence,
        correlations=corr_list,
        hypotheses=[h],
    )
    assert result.risk_score == RISK_MAX


def test_risk_score_clamped_to_0():
    h = make_hypothesis(
        contradicting_evidence_ids=[f"E-{i}" for i in range(20)],
        missing_evidence=[f"m-{i}" for i in range(20)],
    )
    result = compute_risk(hypotheses=[h])
    assert result.risk_score == 0


def test_complete_scenario():
    ev = make_evidence(
        strength=EvidenceStrength.STRONG,
        confidence=0.8,
        verified=True,
    )
    corr = make_correlation(confidence=0.6)
    h = make_hypothesis(
        status=HypothesisStatus.SUPPORTED,
        confidence=0.7,
        supporting_evidence_ids=["E-1"],
    )
    result = compute_risk(
        evidence=[ev],
        correlations=[corr],
        hypotheses=[h],
    )

    # evidence: 20 + 3 = 23
    # correlation: 0.6 * 5 = 3
    # hypothesis: 25 * 0.7 = 17.5
    # penalty: 0
    # total = 43.5 -> 44
    assert result.risk_score == 44


# ===========================================================================
# RiskAssessment helpers
# ===========================================================================

def test_assessment_properties():
    ev = make_evidence(strength=EvidenceStrength.CRITICAL)
    h = make_hypothesis(
        status=HypothesisStatus.CONFIRMED,
        confidence=1.0,
    )
    result = compute_risk(evidence=[ev], hypotheses=[h])

    assert result.is_high_risk
    assert len(result.positive_contributors) >= 1
    assert len(result.top_contributors) >= 1


def test_assessment_explain():
    ev = make_evidence(evidence_id="E-X")
    result = compute_risk(evidence=[ev])
    text = result.explain()
    assert "Risk Score" in text
    assert "Breakdown" in text
    assert "evidence" in text


def test_assessment_to_graph_node():
    ev = make_evidence()
    result = compute_risk(evidence=[ev])
    node = result.to_graph_node()
    assert node["type"] == "RiskAssessment"
    assert node["risk_score"] == result.risk_score
    assert node["confidence"] == result.confidence


def test_assessment_summary():
    ev = make_evidence()
    result = compute_risk(evidence=[ev])
    assert result.summary is not None
    assert "Risk" in result.summary


def test_assessment_negative_contributors():
    h = make_hypothesis(missing_evidence=["a"])
    result = compute_risk(hypotheses=[h])
    assert len(result.negative_contributors) == 1
    assert result.negative_contributors[0].contribution < 0


# ===========================================================================
# Config
# ===========================================================================

def test_config_weights_must_sum_to_one():
    with pytest.raises(ValidationError, match="sum to 1.0"):
        RiskConfig(
            confidence_evidence_weight=0.5,
            confidence_coverage_weight=0.5,
            confidence_hypothesis_weight=0.5,
        )


def test_config_tunable_evidence_max():
    config = RiskConfig(evidence_max_contribution=10.0)
    ev = make_evidence(strength=EvidenceStrength.CRITICAL)
    result = compute_risk(evidence=[ev], config=config)
    assert result.breakdown["evidence"] == 10.0


def test_config_tunable_missing_penalty():
    config = RiskConfig(missing_evidence_per_item=5.0)
    h = make_hypothesis(missing_evidence=["a", "b"])
    result = compute_risk(hypotheses=[h], config=config)
    assert result.breakdown["penalty"] == -10.0


def test_config_defaults():
    assert DEFAULT_RISK_CONFIG.evidence_max_contribution == 40.0
    assert DEFAULT_RISK_CONFIG.correlation_max_contribution == 20.0
    assert DEFAULT_RISK_CONFIG.hypothesis_max_contribution == 40.0


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic():
    ev = make_evidence()
    h = make_hypothesis(
        status=HypothesisStatus.SUPPORTED,
        confidence=0.6,
    )
    r1 = compute_risk(evidence=[ev], hypotheses=[h])
    r2 = compute_risk(evidence=[ev], hypotheses=[h])
    assert r1.risk_score == r2.risk_score
    assert r1.confidence == r2.confidence
    assert r1.breakdown == r2.breakdown


# ===========================================================================
# Case integration
# ===========================================================================

def test_apply_to_case():
    from pkg.models.investigation import (
        InvestigationCase,
        InvestigationStatus,
    )

    case = InvestigationCase(title="Test case")
    case.transition_to(InvestigationStatus.TRIAGED)

    ev = make_evidence(strength=EvidenceStrength.STRONG, verified=True)
    assessment = compute_risk(evidence=[ev])

    engine = RiskEngine()
    engine.apply_to_case(case, assessment)

    assert case.risk_score == assessment.risk_score
    assert case.confidence == assessment.confidence
    assert len(case.risk_history) == 1


def test_apply_to_case_creates_risk_evolution():
    from pkg.models.investigation import (
        InvestigationCase,
        InvestigationStatus,
    )

    case = InvestigationCase(title="Test case")
    case.transition_to(InvestigationStatus.TRIAGED)

    engine = RiskEngine()

    a1 = compute_risk(evidence=[
        make_evidence(strength=EvidenceStrength.WEAK),
    ])
    engine.apply_to_case(case, a1, reason="initial")

    a2 = compute_risk(
        evidence=[
            make_evidence(strength=EvidenceStrength.STRONG),
            make_evidence(
                evidence_id="E-2",
                strength=EvidenceStrength.STRONG,
            ),
        ],
    )
    engine.apply_to_case(case, a2, reason="after correlation")

    assert len(case.risk_history) == 2
    assert case.risk_history[1].previous_risk_score == a1.risk_score
    assert case.risk_history[1].risk_score == a2.risk_score


def test_apply_to_case_with_reason():
    from pkg.models.investigation import (
        InvestigationCase,
        InvestigationStatus,
    )

    case = InvestigationCase(title="Test case")
    case.transition_to(InvestigationStatus.TRIAGED)

    ev = make_evidence()
    assessment = compute_risk(evidence=[ev])

    engine = RiskEngine()
    engine.apply_to_case(case, assessment, reason="custom reason")

    assert case.risk_history[0].reason == "custom reason"
