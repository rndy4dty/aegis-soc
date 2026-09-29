"""
UI components untuk dashboard.

Semua fungsi menerima data dan merender via Streamlit.
"""

from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.reporter.report import InvestigatorReport
from pkg.models.hypothesis import HypothesisType


# ===========================================================================
# Header & metrics
# ===========================================================================

def render_header(result: InvestigationResult) -> None:
    case = result.case
    st.title("AegisSOC Investigator")
    st.caption(f"Case: **{case.title}**  ·  `{case.case_id}`")


def render_metrics(result: InvestigationResult) -> None:
    case = result.case
    c1, c2, c3, c4 = st.columns(4)

    c1.metric("Risk Score", f"{result.risk_score}/100")
    c2.metric("Confidence", f"{result.confidence:.2f}")
    c3.metric("Priority", case.priority.value.upper())
    c4.metric("Status", case.status.value)


# ===========================================================================
# Timeline
# ===========================================================================

def render_timeline(result: InvestigationResult) -> None:
    st.subheader("Attack Timeline")

    if not result.evidence:
        st.info("Tidak ada evidence.")
        return

    rows: list[dict[str, Any]] = []
    for ev in sorted(
        result.evidence,
        key=lambda e: (e.observed_at, e.evidence_id)
        if e.observed_at else (None, e.evidence_id),
    ):
        data = ev.data or {}
        rows.append({
            "Time": (
                ev.observed_at.strftime("%Y-%m-%d %H:%M:%S")
                if ev.observed_at else "-"
            ),
            "Category": data.get("category", "-"),
            "Event": data.get("event_type", "-"),
            "Host": data.get("host", "-"),
            "Strength": ev.strength.value,
            "Title": ev.title,
        })

    df = pd.DataFrame(rows)
    st.dataframe(df, width="stretch", hide_index=True)

# ===========================================================================
# Hypotheses
# ===========================================================================

def render_hypotheses(result: InvestigationResult) -> None:
    st.subheader("Hypotheses")

    if not result.hypotheses:
        st.info("Tidak ada hypothesis.")
        return

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
        _render_hyp_card(h, emoji="🔷", label="MAIN", color="blue")
    for h in counters:
        _render_hyp_card(h, emoji="🔶", label="COUNTER", color="orange")
    for h in subs:
        _render_hyp_card(h, emoji="◽", label="SUB", color="gray")


def _render_hyp_card(h, *, emoji: str, label: str, color: str) -> None:
    with st.container(border=True):
        st.markdown(
            f"**{emoji} [{label}]** {h.statement}"
        )
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"Status: `{h.status.value}`")
        c2.markdown(f"Confidence: `{h.confidence:.2f}`")
        c3.markdown(f"Support: `{h.support_count}`")

        if h.mitre_techniques:
            st.markdown(
                "MITRE: " + ", ".join(f"`{t}`" for t in h.mitre_techniques)
            )

        if h.missing_evidence:
            with st.expander("Missing evidence"):
                for item in h.missing_evidence:
                    st.markdown(f"- {item}")

        if h.rationale:
            with st.expander("Rationale"):
                st.markdown(h.rationale)


# ===========================================================================
# Risk breakdown
# ===========================================================================

def render_risk(result: InvestigationResult) -> None:
    st.subheader("Risk Breakdown")

    if result.risk is None:
        st.info("Tidak ada risk assessment.")
        return

    breakdown = result.risk.breakdown
    df = pd.DataFrame(
        [
            {"Category": k, "Contribution": v}
            for k, v in breakdown.items()
        ]
    )
    st.bar_chart(df.set_index("Category"))

    with st.expander("Top contributors"):
        for f in result.risk.top_contributors[:5]:
            st.markdown(
                f"- **{f.contribution:+.1f}** "
                f"`[{f.category}]` {f.rationale}"
            )


# ===========================================================================
# AI Narrative
# ===========================================================================

def render_ai_narrative(result: InvestigationResult) -> None:
    st.subheader("AI Narrative")

    provider = st.radio(
        "Provider",
        options=("rule", "multi_agent"),
        index=0,
        horizontal=True,
        key="narrative_provider",
    )

    if not st.button("Generate narrative"):
        return

    try:
        from internal.ai import (
            AIRouter,
            MultiAgentProvider,
        )

        providers = []
        if provider == "multi_agent":
            providers = [MultiAgentProvider()]

        router = AIRouter(providers=providers)
        narrative = router.narrate(result)

        st.markdown(narrative)
        st.caption(
            f"Providers: {router.available_providers()}"
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"Narrative failed: {exc}")


# ===========================================================================
# Recommended actions
# ===========================================================================

def render_actions(result: InvestigationResult) -> None:
    st.subheader("Recommended Actions")

    report = InvestigatorReport(result)
    actions = report._recommended_actions()

    if not actions:
        st.info("Tidak ada rekomendasi.")
        return

    for i, action in enumerate(actions, 1):
        st.checkbox(action, key=f"action_{i}")


# ===========================================================================
# Download
# ===========================================================================

def render_download(result: InvestigationResult) -> None:
    st.subheader("Export")

    report = InvestigatorReport(result)
    md = report.to_markdown()
    data = report.to_dict()

    import json

    c1, c2 = st.columns(2)

    with c1:
        st.download_button(
            label="Download Markdown",
            data=md,
            file_name=f"{result.case.case_id}.md",
            mime="text/markdown",
        )

    with c2:
        st.download_button(
            label="Download JSON",
            data=json.dumps(data, indent=2, default=str),
            file_name=f"{result.case.case_id}.json",
            mime="application/json",
        )


__all__ = [
    "render_header",
    "render_metrics",
    "render_timeline",
    "render_hypotheses",
    "render_risk",
    "render_ai_narrative",
    "render_actions",
    "render_download",
]
