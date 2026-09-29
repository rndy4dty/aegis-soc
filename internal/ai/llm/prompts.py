"""
Prompt templates untuk LLM providers.

Semua fungsi return string, deterministic. Tidak ada I/O.
"""

from __future__ import annotations

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from pkg.models.hypothesis import HypothesisType


SYSTEM_PROMPT = """\
You are a senior SOC analyst assistant. You analyze investigation \
results from AegisSOC, an evidence-grounded investigation engine.

Rules:
- Base every statement on the provided evidence, correlations, and hypotheses.
- Do not invent facts, indicators, or techniques.
- If evidence is insufficient, say so explicitly.
- Structure your output: summary, findings, hypotheses, risk, recommended actions.
- Write in the same language as the case title (Indonesian or English).
- Keep it concise: 200-400 words.
"""


def build_narrative_prompt(result: InvestigationResult) -> str:
    """
    Prompt untuk menghasilkan narrative analyst-style.
    """
    case = result.case

    lines: list[str] = []
    lines.append(SYSTEM_PROMPT)
    lines.append("")
    lines.append("=== INVESTIGATION DATA ===")
    lines.append(f"Title: {case.title}")
    lines.append(f"Status: {case.status.value}")
    lines.append(f"Priority: {case.priority.value}")
    lines.append(f"Risk score: {result.risk_score}/100")
    lines.append(f"Confidence: {result.confidence:.2f}")
    lines.append("")

    # -- Evidence ----------------------------------------------------
    lines.append("Evidence:")
    for ev in result.evidence:
        lines.append(
            f"- [{ev.strength.value}] {ev.evidence_id}: {ev.title}"
        )
    lines.append("")

    # -- Correlation -------------------------------------------------
    if result.correlations:
        lines.append("Correlations:")
        for corr in result.correlations:
            cid = getattr(corr, "correlation_id", "?")
            conf = getattr(corr, "confidence", 0.0)
            reasons = getattr(corr, "reasons", []) or []
            reason_str = ", ".join(r.value for r in reasons)
            lines.append(
                f"- {cid} (confidence {conf:.2f}, reasons: {reason_str})"
            )
        lines.append("")

    # -- Hypotheses --------------------------------------------------
    if result.hypotheses:
        lines.append("Hypotheses:")
        for h in result.hypotheses:
            if h.hypothesis_type == HypothesisType.MAIN:
                lines.append(
                    f"- MAIN: {h.statement} "
                    f"(status={h.status.value}, confidence={h.confidence:.2f})"
                )
            elif h.hypothesis_type == HypothesisType.COUNTER:
                lines.append(f"- COUNTER: {h.statement}")
            elif h.hypothesis_type == HypothesisType.SUB:
                lines.append(f"- SUB: {h.statement}")
        lines.append("")

    # -- Risk breakdown ---------------------------------------------
    if result.risk:
        lines.append("Risk breakdown:")
        for k, v in result.risk.breakdown.items():
            lines.append(f"- {k}: {v:+.1f}")
        lines.append("")

    # -- Missing evidence -------------------------------------------
    missing: set[str] = set()
    for h in result.hypotheses:
        missing.update(h.missing_evidence)
    if missing:
        lines.append("Missing evidence:")
        for item in sorted(missing):
            lines.append(f"- {item}")
        lines.append("")

    lines.append("=== END DATA ===")
    lines.append("")
    lines.append(
        "Generate a narrative analysis report following the rules."
    )

    return "\n".join(lines)


__all__ = [
    "SYSTEM_PROMPT",
    "build_narrative_prompt",
]
