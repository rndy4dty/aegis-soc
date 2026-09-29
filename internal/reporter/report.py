"""
Reporter for AegisSOC investigations.

Tugas:
    InvestigationResult  →  analyst-readable report

Menghasilkan laporan deterministic dari hasil investigation engine
dalam beberapa format:
- dict   : structured (untuk dashboard / API)
- markdown : untuk analyst / dokumentasi
- text   : human-readable executive summary

Prinsip:
- Deterministik. Result sama → report sama.
- Tidak memanggil LLM.
- Tidak mengubah InvestigationResult.
- Semua data diambil dari result yang sudah ada.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from pkg.models.entity import EntityType
from pkg.models.evidence import EvidenceStrength
from pkg.models.hypothesis import (
    HypothesisStatus,
    HypothesisType,
)
from pkg.models.relationship import RelationshipType


# ===========================================================================
# Recommended actions
# ===========================================================================

# Mapping dari MITRE technique → recommended action.
TECHNIQUE_ACTIONS: dict[str, list[str]] = {
    "T1546.011": [
        "Inspect sdbinst.exe command line and parent process",
        "Review Shim Database modifications under HKLM\\...\\AppCompatFlags",
        "Check PcaSvc activity around the same time window",
    ],
    "T1059.001": [
        "Review PowerShell script block logs (event ID 4104)",
        "Check encoded commands and outbound connections",
        "Validate initiating user and logon origin",
    ],
    "T1059.003": [
        "Review cmd.exe command line history",
        "Check parent process lineage for suspicious spawning",
    ],
    "T1105": [
        "Identify downloaded file hash and signature",
        "Check destination endpoint reputation",
    ],
    "T1055": [
        "Inspect target process memory regions",
        "Correlate with Sysmon event ID 8 (CreateRemoteThread)",
    ],
    "T1071": [
        "Analyze beacon interval and destination reputation",
        "Check DNS resolution history for destination host",
    ],
}


GENERIC_ACTIONS: list[str] = [
    "Correlate with adjacent events within the same time window",
    "Validate evidence provenance and source reliability",
]


# ===========================================================================
# Report sections
# ===========================================================================

@dataclass
class ReportSection:
    """Satu bagian report."""
    title: str
    content: str


# ===========================================================================
# InvestigatorReport
# ===========================================================================

class InvestigatorReport:
    """
    Analyst-readable report dari InvestigationResult.
    """

    def __init__(self, result: InvestigationResult) -> None:
        self.result = result

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Structured representation untuk dashboard / API.
        """
        r = self.result
        case = r.case

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "case": {
                "case_id": case.case_id,
                "title": case.title,
                "description": case.description,
                "status": case.status.value,
                "priority": case.priority.value,
                "category": case.category.value,
                "severity": case.severity,
                "analyst": case.analyst,
                "tenant_id": case.tenant_id,
                "created_at": case.created_at.isoformat(),
            },
            "risk": {
                "score": r.risk_score,
                "confidence": r.confidence,
                "breakdown": (
                    dict(r.risk.breakdown) if r.risk else {}
                ),
                "top_contributors": (
                    [
                        {
                            "name": f.name,
                            "category": f.category,
                            "contribution": f.contribution,
                            "rationale": f.rationale,
                        }
                        for f in r.risk.top_contributors[:5]
                    ]
                    if r.risk else []
                ),
                "factors": (
                    [
                        {
                            "name": f.name,
                            "category": f.category,
                            "contribution": f.contribution,
                            "rationale": f.rationale,
                        }
                        for f in r.risk.factors
                    ]
                    if r.risk else []
                ),
            },
            "graph": {
                "entity_count": r.graph.entity_count,
                "relationship_count": r.graph.relationship_count,
                "events_processed": r.graph.events_processed,
                "entity_types": (
                    {
                        t.value: n
                        for t, n in r.graph.entities.type_counts().items()
                    }
                ),
                "relationship_types": (
                    {
                        t.value: n
                        for t, n in r.graph.relationships.type_counts().items()
                    }
                ),
            },
            "timeline": self._timeline_dicts(),
            "hypotheses": [
                self._hypothesis_to_dict(h)
                for h in r.hypotheses
            ],
            "evidence_summary": self._evidence_summary_dict(),
            "recommended_actions": self._recommended_actions(),
        }

    def to_markdown(self) -> str:
        """
        Markdown report untuk analyst / dokumentasi.
        """
        r = self.result
        case = r.case
        lines: list[str] = []

        # -- Header ----------------------------------------------------
        lines.append(f"# Investigation Report: {case.title}")
        lines.append("")
        lines.append(f"- **Case ID**: `{case.case_id}`")
        lines.append(f"- **Status**: `{case.status.value}`")
        lines.append(f"- **Priority**: `{case.priority.value}`")
        lines.append(f"- **Category**: `{case.category.value}`")
        if case.analyst:
            lines.append(f"- **Analyst**: `{case.analyst}`")
        lines.append(f"- **Generated**: {self._now_iso()}")
        lines.append("")

        # -- Risk summary ----------------------------------------------
        lines.append("## Risk Assessment")
        lines.append("")
        lines.append(f"- **Risk Score**: **{r.risk_score}/100**")
        lines.append(f"- **Confidence**: {r.confidence:.2f}")
        lines.append("")

        if r.risk:
            lines.append("### Breakdown")
            lines.append("")
            for cat in ("evidence", "correlation", "hypothesis", "penalty"):
                val = r.risk.breakdown.get(cat, 0.0)
                lines.append(f"- `{cat}`: {val:+.2f}")
            lines.append("")

            if r.risk.top_contributors:
                lines.append("### Top Contributors")
                lines.append("")
                for f in r.risk.top_contributors[:5]:
                    lines.append(
                        f"- **{f.contribution:+.2f}** "
                        f"`[{f.category}]` {f.rationale}"
                    )
                lines.append("")

        # -- Graph stats -----------------------------------------------
        lines.append("## Graph Overview")
        lines.append("")
        lines.append(f"- Entities: **{r.graph.entity_count}**")
        lines.append(f"- Relationships: **{r.graph.relationship_count}**")
        lines.append(f"- Events processed: **{r.graph.events_processed}**")
        lines.append("")

        # -- Timeline --------------------------------------------------
        timeline = self._timeline_rows()
        if timeline:
            lines.append("## Attack Timeline")
            lines.append("")
            lines.append("| # | Time | Category | Event | Host |")
            lines.append("|---|---|---|---|---|")
            for i, row in enumerate(timeline, 1):
                lines.append(
                    f"| {i} | {row['timestamp']} "
                    f"| {row['category']} | {row['event_type']} "
                    f"| {row['host'] or '-'} |"
                )
            lines.append("")

        # -- Hypotheses ------------------------------------------------
        if r.hypotheses:
            lines.append("## Hypotheses")
            lines.append("")
            for h in r.hypotheses:
                lines.append(self._hypothesis_markdown(h))
                lines.append("")

        # -- Evidence summary ------------------------------------------
        if r.evidence:
            lines.append("## Evidence Summary")
            lines.append("")
            for ev in r.evidence:
                lines.append(
                    f"- `{ev.evidence_id}` "
                    f"**{ev.strength.value}** "
                    f"{ev.evidence_type.value}: {ev.title}"
                )
            lines.append("")

        # -- Recommended actions ---------------------------------------
        actions = self._recommended_actions()
        if actions:
            lines.append("## Recommended Actions")
            lines.append("")
            for i, action in enumerate(actions, 1):
                lines.append(f"{i}. {action}")
            lines.append("")

        return "\n".join(lines)

    def to_text(self) -> str:
        """
        Plain-text executive summary.
        """
        r = self.result
        case = r.case
        lines: list[str] = []

        lines.append("=" * 60)
        lines.append("AEGISSOC INVESTIGATION SUMMARY")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Case       : {case.case_id}")
        lines.append(f"Title      : {case.title}")
        lines.append(f"Priority   : {case.priority.value.upper()}")
        lines.append(f"Status     : {case.status.value}")
        lines.append(f"Category   : {case.category.value}")
        lines.append(f"Risk Score : {r.risk_score}/100")
        lines.append(f"Confidence : {r.confidence:.2f}")
        lines.append("")

        # -- Top finding -----------------------------------------------
        if r.hypotheses:
            main = next(
                (h for h in r.hypotheses
                 if h.hypothesis_type == HypothesisType.MAIN),
                None,
            )
            if main:
                lines.append("PRIMARY HYPOTHESIS")
                lines.append(f"  {main.statement}")
                lines.append(
                    f"  Status: {main.status.value} "
                    f"(confidence {main.confidence:.2f})"
                )
                lines.append("")

        # -- Graph overview --------------------------------------------
        lines.append("GRAPH OVERVIEW")
        lines.append(f"  Entities      : {r.graph.entity_count}")
        lines.append(f"  Relationships : {r.graph.relationship_count}")
        lines.append(f"  Events        : {r.graph.events_processed}")
        lines.append("")

        # -- Evidence count --------------------------------------------
        lines.append("EVIDENCE")
        lines.append(f"  Total         : {r.evidence_count}")
        lines.append(f"  Correlations  : {r.correlation_count}")
        lines.append(f"  Hypotheses    : {r.hypothesis_count}")
        lines.append("")

        # -- Recommended actions ---------------------------------------
        actions = self._recommended_actions()
        if actions:
            lines.append("RECOMMENDED ACTIONS")
            for i, action in enumerate(actions[:5], 1):
                lines.append(f"  {i}. {action}")

        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------

    def _now_iso(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _timeline_dicts(self) -> list[dict[str, Any]]:
        # Sort event IDs by chronological order using result.evidence
        entries: list[dict[str, Any]] = []
        for ev in sorted(
            self.result.evidence,
            key=lambda e: (e.observed_at or datetime.min.replace(
                tzinfo=timezone.utc
            ), e.evidence_id),
        ):
            entries.append({
                "evidence_id": ev.evidence_id,
                "event_id": ev.event_id,
                "timestamp": (
                    ev.observed_at.isoformat()
                    if ev.observed_at else None
                ),
                "category": ev.data.get("category") if ev.data else None,
                "event_type": (
                    ev.data.get("event_type") if ev.data else None
                ),
                "host": ev.data.get("host") if ev.data else None,
                "severity": ev.data.get("severity") if ev.data else None,
                "strength": ev.strength.value,
                "title": ev.title,
            })
        return entries

    def _timeline_rows(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for entry in self._timeline_dicts():
            rows.append({
                "timestamp": entry["timestamp"] or "-",
                "category": entry["category"] or "-",
                "event_type": entry["event_type"] or "-",
                "host": entry["host"],
            })
        return rows

    def _hypothesis_to_dict(self, h) -> dict[str, Any]:
        return {
            "hypothesis_id": h.hypothesis_id,
            "type": h.hypothesis_type.value,
            "statement": h.statement,
            "status": h.status.value,
            "confidence": h.confidence,
            "supporting_evidence_ids": list(h.supporting_evidence_ids),
            "contradicting_evidence_ids": list(
                h.contradicting_evidence_ids
            ),
            "missing_evidence": list(h.missing_evidence),
            "mitre_techniques": list(h.mitre_techniques),
            "rationale": h.rationale,
        }

    def _hypothesis_markdown(self, h) -> str:
        lines: list[str] = []
        emoji = {
            HypothesisType.MAIN: "🔷",
            HypothesisType.COUNTER: "🔶",
            HypothesisType.SUB: "◽",
            HypothesisType.UNKNOWN: "❓",
        }.get(h.hypothesis_type, "-")

        lines.append(
            f"### {emoji} {h.hypothesis_type.value.upper()}: "
            f"{h.statement}"
        )
        lines.append("")
        lines.append(
            f"- Status: `{h.status.value}` "
            f"(confidence {h.confidence:.2f})"
        )
        if h.mitre_techniques:
            lines.append(
                f"- MITRE: {', '.join(h.mitre_techniques)}"
            )
        if h.supporting_evidence_ids:
            lines.append(
                f"- Supporting evidence: "
                f"{', '.join(h.supporting_evidence_ids)}"
            )
        if h.contradicting_evidence_ids:
            lines.append(
                f"- Contradicting evidence: "
                f"{', '.join(h.contradicting_evidence_ids)}"
            )
        if h.missing_evidence:
            lines.append("- Missing evidence:")
            for item in h.missing_evidence:
                lines.append(f"  - {item}")
        if h.rationale:
            lines.append(f"- Rationale: {h.rationale}")
        return "\n".join(lines)

    def _evidence_summary_dict(self) -> dict[str, Any]:
        r = self.result
        by_strength: dict[str, int] = {}
        by_type: dict[str, int] = {}

        for ev in r.evidence:
            by_strength[ev.strength.value] = (
                by_strength.get(ev.strength.value, 0) + 1
            )
            by_type[ev.evidence_type.value] = (
                by_type.get(ev.evidence_type.value, 0) + 1
            )

        return {
            "total": len(r.evidence),
            "by_strength": by_strength,
            "by_type": by_type,
        }

    def _recommended_actions(self) -> list[str]:
        """
        Deterministic recommended actions dari hypotheses.
        """
        actions: list[str] = []
        seen: set[str] = set()

        # 1. Technique-specific actions
        for h in self.result.hypotheses:
            if h.hypothesis_type != HypothesisType.MAIN:
                continue
            if not h.is_active:
                continue
            for tech in h.mitre_techniques:
                for action in TECHNIQUE_ACTIONS.get(tech, []):
                    if action not in seen:
                        seen.add(action)
                        actions.append(action)

        # 2. Missing evidence → action
        for h in self.result.hypotheses:
            for item in h.missing_evidence:
                action = f"Collect missing evidence: {item}"
                if action not in seen:
                    seen.add(action)
                    actions.append(action)

        # 3. Generic actions as fallback
        if not actions:
            for action in GENERIC_ACTIONS:
                if action not in seen:
                    seen.add(action)
                    actions.append(action)

        return actions


# ===========================================================================
# Convenience functions
# ===========================================================================

def report_to_dict(result: InvestigationResult) -> dict[str, Any]:
    return InvestigatorReport(result).to_dict()


def report_to_markdown(result: InvestigationResult) -> str:
    return InvestigatorReport(result).to_markdown()


def report_to_text(result: InvestigationResult) -> str:
    return InvestigatorReport(result).to_text()


__all__ = [
    "TECHNIQUE_ACTIONS",
    "GENERIC_ACTIONS",
    "ReportSection",
    "InvestigatorReport",
    "report_to_dict",
    "report_to_markdown",
    "report_to_text",
]
