"""
AegisSOC Streamlit dashboard.

Jalankan:
    streamlit run internal/dashboard/app.py
"""

from __future__ import annotations

import streamlit as st

from internal.dashboard.components import (
    render_actions,
    render_ai_narrative,
    render_download,
    render_header,
    render_hypotheses,
    render_metrics,
    render_risk,
    render_timeline,
)
from internal.dashboard.data import (
    parse_events,
    run_investigation,
)


st.set_page_config(
    page_title="AegisSOC Investigator",
    page_icon="🛡️",
    layout="wide",
)


def main() -> None:
    st.title("🛡️ AegisSOC Investigator")
    st.caption(
        "Evidence-Grounded AI Investigation & Correlation Engine"
    )

    # -- Sidebar: input ------------------------------------------------
    with st.sidebar:
        st.header("Input")

        uploaded = st.file_uploader(
            "Upload events JSON",
            type=["json"],
            help=(
                "File JSON berisi list events atau {'events': [...]}"
            ),
        )

        title = st.text_input(
            "Investigation title",
            value="Investigation",
        )

        analyst = st.text_input(
            "Analyst (optional)",
            value="",
        )

        tenant = st.text_input(
            "Tenant (optional)",
            value="",
        )

        category = st.selectbox(
            "Category",
            options=(
                "unknown", "malware", "phishing", "persistence",
                "execution", "defense_evasion", "lateral_movement",
                "command_and_control", "data_exfiltration",
                "policy_violation",
            ),
            index=0,
        )

        run = st.button(
            "Run investigation",
            type="primary",
            width="stretch",
        )
    # -- Main ---------------------------------------------------------
    if uploaded is None:
        st.info(
            "Upload JSON file di sidebar, lalu klik **Run investigation**."
        )
        st.markdown(
            "Contoh: lihat `examples/application_shimming.json` "
            "di repo."
        )
        return

    if not run:
        st.success(
            f"File **{uploaded.name}** siap. "
            "Klik **Run investigation** di sidebar."
        )
        return

    # -- Run ----------------------------------------------------------
    try:
        events = parse_events(uploaded.getvalue())
    except ValueError as exc:
        st.error(f"Gagal parsing events: {exc}")
        return

    if not events:
        st.warning("File tidak berisi event.")
        return

    st.success(f"Loaded {len(events)} event(s).")

    with st.spinner("Running investigation..."):
        try:
            result = run_investigation(
                events,
                title=title or "Investigation",
                analyst=analyst or None,
                tenant=tenant or None,
                category=category,
            )
        except Exception as exc:  # noqa: BLE001
            st.error(f"Investigation failed: {exc}")
            return

    # -- Render -------------------------------------------------------
    render_header(result)
    render_metrics(result)

    st.divider()

    col_left, col_right = st.columns([2, 1])

    with col_left:
        render_timeline(result)
        render_hypotheses(result)

    with col_right:
        render_risk(result)
        render_actions(result)

    st.divider()

    render_ai_narrative(result)

    st.divider()

    render_download(result)


main()
