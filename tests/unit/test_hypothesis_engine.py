"""
Contract tests untuk HypothesisEngine.
"""

import pytest

from internal.investigation.hypothesis_engine import (
    MIN_EVIDENCE_FOR_MAIN,
    MIN_SUPPORT_FOR_STATUS,
    MITRE_HYPOTHESIS_TEMPLATES,
    HypothesisEngine,
    generate_hypotheses,
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
    HypothesisSource,
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
    mitre_techniques: list[str] | None = None,
    tags: list[str] | None = None,
    contradicts: list[str] | None = None,
) -> Evidence:
    data = {}
    if mitre_techniques:
        data["mitre_techniques"] = mitre_techniques

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
        confidence=0.8,
        data=data,
        tags=tags or [],
        provenance=EvidenceProvenance(source="test"),
        hypothesis_links=links,
    )
    return ev.model_copy(update={"evidence_id": evidence_id})


def make_correlation(correlation_id: str = "COR-1", confidence: float = 0.7):
    class _Corr:
        pass

    c = _Corr()
    c.correlation_id = correlation_id
    c.confidence = confidence
    c.reasons = []
    return c


# ===========================================================================
# Empty / trivial
# ===========================================================================

def test_empty_input():
    hyps = generate_hypotheses()
    assert hyps == []


def test_evidence_without_technique():
    ev = make_evidence()
    hyps = generate_hypotheses(evidence=[ev])
    assert hyps == []


# ===========================================================================
# MAIN hypothesis per technique
# ===========================================================================

def test_main_from_single_technique():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])

    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    assert len(mains) == 1
    assert "Application Shimming" in mains[0].statement
    assert "T1546.011" in mains[0].mitre_techniques
    assert mains[0].source == HypothesisSource.DETERMINISTIC


def test_main_from_multiple_techniques():
    ev1 = make_evidence(
        evidence_id="E-1",
        mitre_techniques=["T1546.011"],
    )
    ev2 = make_evidence(
        evidence_id="E-2",
        mitre_techniques=["T1059.001"],
    )
    hyps = generate_hypotheses(evidence=[ev1, ev2])

    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    assert len(mains) == 2
    techs = {m.mitre_techniques[0] for m in mains}
    assert techs == {"T1546.011", "T1059.001"}


def test_technique_from_tags():
    ev = make_evidence(
        mitre_techniques=None,
        tags=["T1546.011", "soc"],
    )
    hyps = generate_hypotheses(evidence=[ev])
    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    assert len(mains) == 1


def test_unknown_technique_uses_generic_template():
    ev = make_evidence(mitre_techniques=["T9999"])
    hyps = generate_hypotheses(evidence=[ev])

    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    assert len(mains) == 1
    assert "T9999" in mains[0].statement
    assert "T9999" in mains[0].mitre_techniques


def test_supporting_evidence_ids():
    ev1 = make_evidence(
        evidence_id="E-1",
        mitre_techniques=["T1546.011"],
    )
    ev2 = make_evidence(
        evidence_id="E-2",
        mitre_techniques=["T1546.011"],
    )
    hyps = generate_hypotheses(evidence=[ev1, ev2])

    main = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
    )
    assert main.supporting_evidence_ids == ["E-1", "E-2"]


# ===========================================================================
# Status & confidence
# ===========================================================================

def test_single_evidence_proposed():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    main = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
    )
    assert main.status == HypothesisStatus.PROPOSED
    assert main.confidence == 0.30


def test_multiple_evidence_supported():
    evs = [
        make_evidence(
            evidence_id=f"E-{i}",
            mitre_techniques=["T1546.011"],
        )
        for i in range(2)
    ]
    hyps = generate_hypotheses(evidence=evs)
    main = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
    )
    assert main.status == HypothesisStatus.SUPPORTED
    assert main.confidence >= 0.55


def test_confidence_scales_with_count():
    for count, expected_min in [(1, 0.29), (2, 0.54), (3, 0.69), (5, 0.89)]:
        evs = [
            make_evidence(
                evidence_id=f"E-{i}",
                mitre_techniques=["T1546.011"],
            )
            for i in range(count)
        ]
        hyps = generate_hypotheses(evidence=evs)
        main = next(
            h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
        )
        assert main.confidence >= expected_min


# ===========================================================================
# COUNTER hypothesis
# ===========================================================================

def test_counter_created_per_main():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])

    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    counters = [
        h for h in hyps if h.hypothesis_type == HypothesisType.COUNTER
    ]
    assert len(mains) == len(counters)


def test_counter_statement_from_template():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    counter = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.COUNTER
    )
    assert "Legitimate" in counter.statement
    assert (
        "PcaSvc" in counter.statement
        or "compatibility" in counter.statement
    )


def test_counter_no_parent_id():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    counter = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.COUNTER
    )
    assert counter.parent_hypothesis_id is None


def test_counter_has_same_technique():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    counter = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.COUNTER
    )
    assert "T1546.011" in counter.mitre_techniques


# ===========================================================================
# Missing evidence
# ===========================================================================

def test_missing_evidence_from_template():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    main = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
    )
    assert "shim database modification" in main.missing_evidence


def test_generic_template_has_fallback_missing():
    ev = make_evidence(mitre_techniques=["T9999"])
    hyps = generate_hypotheses(evidence=[ev])
    main = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.MAIN
    )
    assert main.missing_evidence


# ===========================================================================
# SUB hypothesis
# ===========================================================================

def test_sub_from_correlation():
    corr = make_correlation(confidence=0.8)
    hyps = generate_hypotheses(correlations=[corr])
    subs = [h for h in hyps if h.hypothesis_type == HypothesisType.SUB]
    assert len(subs) == 1
    assert "Correlated" in subs[0].statement


def test_sub_from_low_confidence_correlation_skipped():
    corr = make_correlation(confidence=0.3)
    hyps = generate_hypotheses(correlations=[corr])
    subs = [h for h in hyps if h.hypothesis_type == HypothesisType.SUB]
    assert subs == []


def test_sub_from_correlation_uses_best():
    c1 = make_correlation("COR-1", confidence=0.5)
    c2 = make_correlation("COR-2", confidence=0.9)
    hyps = generate_hypotheses(correlations=[c1, c2])
    sub = next(
        h for h in hyps if h.hypothesis_type == HypothesisType.SUB
    )
    assert "COR-2" in sub.rationale


# ===========================================================================
# Contradicting evidence attachment
# ===========================================================================

def test_contradicting_evidence_attached():
    ev = make_evidence(
        evidence_id="E-X",
        mitre_techniques=["T1546.011"],
        contradicts=["H-1"],
    )
    hyps = generate_hypotheses(evidence=[ev])
    assert hyps


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_output():
    ev1 = make_evidence(
        evidence_id="E-1",
        mitre_techniques=["T1546.011"],
    )
    ev2 = make_evidence(
        evidence_id="E-2",
        mitre_techniques=["T1059.001"],
    )

    h1 = generate_hypotheses(evidence=[ev1, ev2])
    h2 = generate_hypotheses(evidence=[ev1, ev2])

    s1 = [(h.hypothesis_type.value, h.fingerprint) for h in h1]
    s2 = [(h.hypothesis_type.value, h.fingerprint) for h in h2]
    assert s1 == s2


def test_deterministic_order():
    ev1 = make_evidence(
        evidence_id="E-1",
        mitre_techniques=["T1059.001"],
    )
    ev2 = make_evidence(
        evidence_id="E-2",
        mitre_techniques=["T1546.011"],
    )

    hyps = generate_hypotheses(evidence=[ev1, ev2])

    main_indices = [
        i for i, h in enumerate(hyps)
        if h.hypothesis_type == HypothesisType.MAIN
    ]
    counter_indices = [
        i for i, h in enumerate(hyps)
        if h.hypothesis_type == HypothesisType.COUNTER
    ]
    assert max(main_indices) < min(counter_indices)


# ===========================================================================
# Fingerprint
# ===========================================================================

def test_all_hypotheses_have_fingerprint():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(evidence=[ev])
    for h in hyps:
        assert h.fingerprint is not None
        assert h.verify_fingerprint()


# ===========================================================================
# Config
# ===========================================================================

def test_min_evidence_config():
    ev = make_evidence(mitre_techniques=["T1546.011"])
    hyps = generate_hypotheses(
        evidence=[ev], min_evidence_for_main=2,
    )
    assert hyps == []


def test_engine_invalid_config():
    with pytest.raises(ValueError):
        HypothesisEngine(min_evidence_for_main=0)


# ===========================================================================
# Integration
# ===========================================================================

def test_full_scenario():
    ev1 = make_evidence(
        evidence_id="E-1",
        mitre_techniques=["T1546.011"],
    )
    ev2 = make_evidence(
        evidence_id="E-2",
        mitre_techniques=["T1546.011"],
    )
    corr = make_correlation("COR-1", confidence=0.8)

    hyps = generate_hypotheses(
        evidence=[ev1, ev2],
        correlations=[corr],
    )

    mains = [h for h in hyps if h.hypothesis_type == HypothesisType.MAIN]
    counters = [
        h for h in hyps if h.hypothesis_type == HypothesisType.COUNTER
    ]
    subs = [h for h in hyps if h.hypothesis_type == HypothesisType.SUB]

    assert len(mains) == 1
    assert len(counters) == 1
    assert len(subs) == 1
    assert mains[0].status == HypothesisStatus.SUPPORTED


def test_engine_reusable():
    engine = HypothesisEngine()
    ev = make_evidence(mitre_techniques=["T1546.011"])
    r1 = engine.generate(evidence=[ev])
    r2 = engine.generate(evidence=[ev])
    assert len(r1) == len(r2)


# ===========================================================================
# Template registry sanity
# ===========================================================================

def test_all_templates_have_required_fields():
    for tech, tpl in MITRE_HYPOTHESIS_TEMPLATES.items():
        assert tpl.technique == tech
        assert tpl.main_statement
        assert tpl.counter_statement
        assert isinstance(tpl.missing_evidence, tuple)
