"""
Graph visualization untuk AegisSOC dashboard.

Pakai st-cytoscape (render native React, bukan iframe).
- warna node by entity_type
- warna edge by relationship_type
- klik node/edge → detail panel
"""
from __future__ import annotations

from typing import Any

import pandas as pd
import streamlit as st
from st_cytoscape import cytoscape

from internal.investigation.investigation_engine import InvestigationResult


_NODE_COLORS: dict[str, str] = {
    "process":         "#4a90e2",
    "user":            "#50c878",
    "host":            "#e8a33d",
    "hash":            "#9b59b6",
    "file":            "#f1c40f",
    "network":         "#e74c3c",
    "ip":              "#8e44ad",
    "domain":          "#3498db",
    "url":             "#16a085",
    "registry":        "#d35400",
    "mitre_technique": "#c0392b",
    "event":           "#7f8c8d",
    "alert":           "#95a5a6",
    "evidence":        "#bdc3c7",
}
_DEFAULT_NODE_COLOR = "#95a5a6"

_EDGE_COLORS: dict[str, str] = {
    "parent_of": "#7f8c8d", "child_of": "#7f8c8d",
    "part_of": "#7f8c8d",   "contains": "#7f8c8d",
    "spawned": "#4a90e2",   "executed": "#4a90e2",
    "accessed": "#3498db",  "modified": "#e67e22",
    "created": "#27ae60",   "deleted": "#c0392b",
    "run_as": "#50c878",    "logged_on": "#50c878",
    "owned_by": "#50c878",  "member_of": "#50c878",
    "has_hash": "#9b59b6",  "matches_hash": "#9b59b6",
    "connected_to": "#e74c3c", "resolved_to": "#e74c3c",
    "requested": "#e74c3c", "bound_to": "#e74c3c",
}
_DEFAULT_EDGE_COLOR = "#95a5a6"


def render_graph(result: InvestigationResult, *, height: int = 600) -> None:
    """Render investigation graph via Cytoscape."""
    st.subheader("Attack Graph")

    graph = getattr(result, "graph", None)
    if graph is None:
        st.info("Tidak ada graph di investigation result.")
        return

    try:
        payload = graph.to_dict()
    except Exception as exc:  # noqa: BLE001
        st.error(f"Gagal extract graph: {exc}")
        return

    entities = payload.get("entities", [])
    relationships = payload.get("relationships", [])

    if not entities:
        st.info("Graph kosong (tidak ada entity).")
        return

    st.caption(
        f"{len(entities)} entities · {len(relationships)} relationships"
    )

    elements = _build_elements(entities, relationships)
    stylesheet = _build_stylesheet()

    try:
        cytoscape(
            elements,
            stylesheet=stylesheet,
            layout={"name": "cose", "animate": False, "padding": 30},
            height=f"{height}px",
            key="aegis_attack_graph",
        )
    except Exception as exc:  # noqa: BLE001
        st.error(f"Gagal render graph: {exc}")
        return

    with st.expander("Entities (table)"):
        df = pd.DataFrame([
            {
                "type": _str(e.get("entity_type")),
                "value": e.get("value", ""),
                "host": e.get("host") or "",
                "fingerprint": _str(e.get("fingerprint"))[:16],
            }
            for e in entities
        ])
        st.dataframe(df, width="stretch", hide_index=True)


def _build_elements(
    entities: list[dict],
    relationships: list[dict],
) -> list[dict]:
    """Bangun list element cytoscape: nodes + edges."""
    known = {e.get("id") for e in entities if e.get("id")}
    elements: list[dict] = []

    for e in entities:
        eid = e.get("id")
        if not eid:
            continue
        etype = _str(e.get("entity_type"))
        value = e.get("value") or eid[:8]
        host = e.get("host") or "-"
        fp = _str(e.get("fingerprint"))[:16]
        elements.append({
            "data": {
                "id": eid,
                "label": str(value)[:40],
                "type": etype,
                "color": _NODE_COLORS.get(etype, _DEFAULT_NODE_COLOR),
                "host": host,
                "fingerprint": fp,
                "tooltip": f"{etype} · {value} · {host} · fp:{fp}",
            }
        })

    for r in relationships:
        src = r.get("source")
        dst = r.get("target")
        if not src or not dst:
            continue
        if src not in known or dst not in known:
            continue
        rtype = _str(r.get("relationship_type"))
        color = _EDGE_COLORS.get(rtype, _DEFAULT_EDGE_COLOR)
        weight = r.get("weight") or 1.0
        elements.append({
            "data": {
                "id": f"{src}->{dst}:{rtype}",
                "source": src,
                "target": dst,
                "label": rtype,
                "color": color,
                "weight": float(weight),
            }
        })

    return elements


def _build_stylesheet() -> list[dict]:
    """Stylesheet Cytoscape."""
    return [
        {
            "selector": "node",
            "style": {
                "background-color": "data(color)",
                "label": "data(label)",
                "color": "#fafafa",
                "font-size": "12px",
                "font-family": "monospace",
                "text-valign": "bottom",
                "text-halign": "center",
                "text-margin-y": 4,
                "width": 28,
                "height": 28,
                "border-width": 2,
                "border-color": "#fafafa",
            },
        },
        {
            "selector": "node:selected",
            "style": {
                "border-width": 4,
                "border-color": "#f1c40f",
            },
        },
        {
            "selector": "edge",
            "style": {
                "label": "data(label)",
                "width": 2,
                "line-color": "data(color)",
                "target-arrow-color": "data(color)",
                "target-arrow-shape": "triangle",
                "curve-style": "bezier",
                "font-size": "11px",
                "font-family": "monospace",
                "color": "#ddd",
                "text-background-color": "#0e1117",
                "text-background-opacity": 0.85,
                "text-background-padding": "3px",
                "text-rotation": "autorotate",
            },
        },
        {
            "selector": "edge:selected",
            "style": {
                "width": 4,
                "line-color": "#f1c40f",
                "target-arrow-color": "#f1c40f",
            },
        },
    ]


def _str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if hasattr(value, "value"):
        return str(value.value)
    return str(value)


__all__ = ["render_graph"]
