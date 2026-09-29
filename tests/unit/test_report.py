"""
Contract tests untuk InvestigatorReport.

Menguji:
- to_dict / to_markdown / to_text
- struktur report
- recommended actions
- determinisme
- edge cases (empty, single, complex)
"""

from datetime import datetime, timedelta, timezone

import pytest
import re
from internal.investigation.investigation_engine import (
    InvestigationResult,
    investigate,
)
from internal.reporter.report import (
    TECHNIQUE_ACTIONS,
    InvestigatorReport,
    report_to_dict,
    report_to_markdown,
    report_to_text,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    FileContext,
    Platform,
    ProcessContext,
)
from pkg.models.investigation import InvestigationCategory


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "E-1",
    *,
    offset_seconds: int = 0,
    host: str = "WIN-01",
    user: str | None = "ren",
    process_name: str | None = None,
    pid: int | None = None,
    parent_name: str | None = None,
    parent_pid: int | None = None,
    file_path: str | None = None,
    file_hashes: dict | None = None,
    severity: int = 70,
    mitre: list[str] | None = None,
    rule_id: str | None = None,
) -> Event:
    process = None
    if (
        process_name is not None
        or pid is not None
        or parent_name is not None
    ):
        process = ProcessContext(
            name=process_name,
            pid=pid,
            parent_name=parent_name,
            parent_pid=parent_pid,
        )

    file_ctx = None
    if file_path or file_hashes:
        file_ctx = FileContext(
            path=file_path,
            hashes=file_hashes or {},
        )

    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset_seconds),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=severity,
        host=host,
        user=user,
        process=process,
        file=file_ctx,
        mitre_techniques=mitre or [],
        rule_id=rule_id,
    )


def make_result(events=None) -> InvestigationResult:
    events = events or [
        make_event(
            event_id="E-1",
            host="WIN-01",
            process_name="powershell.exe",
            pid=1234,
            severity=70,
            mitre=["T1546.011"],
        ),
    ]
    return investigate(events, title="Test investigation")


# ===========================================================================
# to_dict
# ===========================================================================

def test_to_dict_structure():
    result = make_result()
    data = report_to_dict(result)

    assert "generated_at" in data
    assert "case" in data
    assert "risk" in data
    assert "graph" in data
    assert "timeline" in data
    assert "hypotheses" in data
    assert "evidence_summary" in data
    assert "recommended_actions" in data


def test_to_dict_case():
    result = make_result()
    data = report_to_dict(result)

    case = data["case"]
    assert case["title"] == "Test investigation"
    assert case["status"] in ("detected", "triaged")
    assert case["case_id"].startswith("CASE-")


def test_to_dict_risk():
    result = make_result()
    data = report_to_dict(result)

    risk = data["risk"]
    assert "score" in risk
    assert "confidence" in risk
    assert "breakdown" in risk
    assert "top_contributors" in risk


def test_to_dict_graph():
    result = make_result()
    data = report_to_dict(result)

    graph = data["graph"]
    assert graph["entity_count"] >= 2
    assert graph["relationship_count"] >= 0


def test_to_dict_hypotheses():
    result = make_result()
    data = report_to_dict(result)

    assert isinstance(data["hypotheses"], list)
    for h in data["hypotheses"]:
        assert "hypothesis_id" in h
        assert "statement" in h
        assert "status" in h


# ===========================================================================
# to_markdown
# ===========================================================================

def test_to_markdown_contains_header():
    result = make_result()
    md = report_to_markdown(result)

    assert "# Investigation Report" in md
    assert "Test investigation" in md
    assert "Case ID" in md


def test_to_markdown_risk_section():
    result = make_result()
    md = report_to_markdown(result)

    assert "## Risk Assessment" in md
    assert "Risk Score" in md
    assert "Confidence" in md


def test_to_markdown_graph_section():
    result = make_result()
    md = report_to_markdown(result)

    assert "## Graph Overview" in md


def test_to_markdown_timeline_section():
    result = make_result([
        make_event(event_id="E-1", severity=70),
    ])
    md = report_to_markdown(result)

    assert "## Attack Timeline" in md
    assert "| # | Time |" in md


def test_to_markdown_hypotheses_section():
    result = make_result([
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ])
    md = report_to_markdown(result)

    assert "## Hypotheses" in md
    assert "MAIN" in md
    assert "COUNTER" in md


def test_to_markdown_recommended_actions():
    result = make_result([
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ])
    md = report_to_markdown(result)

    assert "## Recommended Actions" in md


# ===========================================================================
# to_text
# ===========================================================================

def test_to_text_header():
    result = make_result()
    text = report_to_text(result)

    assert "AEGISSOC INVESTIGATION SUMMARY" in text
    assert "Case" in text
    assert "Priority" in text


def test_to_text_primary_hypothesis():
    result = make_result([
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ])
    text = report_to_text(result)

    assert "PRIMARY HYPOTHESIS" in text
    assert "Application Shimming" in text


def test_to_text_graph_overview():
    result = make_result()
    text = report_to_text(result)

    assert "GRAPH OVERVIEW" in text
    assert "Entities" in text


# ===========================================================================
# Recommended actions
# ===========================================================================

def test_actions_for_shimming():
    result = make_result([
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ])
    report = InvestigatorReport(result)
    actions = report._recommended_actions()

    assert len(actions) > 0
    assert any("sdbinst" in a.lower() for a in actions)


def test_actions_for_powershell():
    result = make_result([
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1059.001"],
        ),
    ])
    report = InvestigatorReport(result)
    actions = report._recommended_actions()

    assert any("powershell" in a.lower() for a in actions)


def test_actions_generic_fallback():
    result = make_result([
        make_event(event_id="E-1", severity=50),
    ])
    report = InvestigatorReport(result)
    actions = report._recommended_actions()

    assert len(actions) > 0


def test_technique_actions_registry():
    assert "T1546.011" in TECHNIQUE_ACTIONS
    assert "T1059.001" in TECHNIQUE_ACTIONS


# ===========================================================================
# Determinism
# ===========================================================================

def test_deterministic_markdown():
    """
    Report markdown deterministik KECUALI:
    - `generated_at` (wall clock)
    - `case_id` (UUID per run)

    Untuk membandingkan dua run, kedua field volatile di-strip dulu.
    """
    events = [
        make_event(
            event_id="E-1",
            severity=70,
            mitre=["T1546.011"],
        ),
    ]
    r1 = investigate(events, title="Det test")
    r2 = investigate(events, title="Det test")

    md1 = report_to_markdown(r1)
    md2 = report_to_markdown(r2)

    assert _strip_volatile(md1) == _strip_volatile(md2)


# Pola ID yang volatile antar run (UUID-based).
_VOLATILE_ID_PATTERNS = [
    re.compile(r"\bE-[a-f0-9]{12}\b"),           # evidence_id
    re.compile(r"\bH-[a-f0-9]{10}\b"),           # hypothesis_id
    re.compile(r"\bCASE-[A-F0-9]{12}\b"),        # case_id
]


def _strip_volatile(md: str) -> str:
    """
    Hapus field yang memang berbeda antar run:
    - generated_at (wall clock)
    - case_id / evidence_id / hypothesis_id (UUID per run)

    Tujuan: menguji determinisme KONTEN, bukan ID instance.
    """
    lines = md.splitlines()
    kept = [
        line for line in lines
        if not line.startswith("- **Generated**")
        and not line.startswith("- **Case ID**")
    ]
    text = "\n".join(kept)
    for pattern in _VOLATILE_ID_PATTERNS:
        text = pattern.sub("<ID>", text)
    return text


def _strip_generated_at(md: str) -> str:
    lines = md.splitlines()
    return "\n".join(
        line for line in lines if not line.startswith("- **Generated**")
    )


# ===========================================================================
# Edge cases
# ===========================================================================

def test_empty_result():
    result = investigate([], title="Empty")
    report = InvestigatorReport(result)

    data = report.to_dict()
    assert data["case"]["title"] == "Empty"
    assert data["evidence_summary"]["total"] == 0

    md = report.to_markdown()
    assert "Empty" in md

    text = report.to_text()
    assert "Empty" in text


def test_complex_result():
    events = [
        make_event(
            event_id="E-1",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            file_path="C:\\tmp\\payload.exe",
            file_hashes={"sha256": "deadbeef"},
            severity=85,
            mitre=["T1546.011", "T1059.001"],
            rule_id="92058",
        ),
        make_event(
            event_id="E-2",
            host="WIN-01",
            user="ren",
            process_name="cmd.exe",
            pid=2000,
            parent_name="powershell.exe",
            parent_pid=1234,
            severity=85,
            mitre=["T1546.011"],
            offset_seconds=10,
        ),
    ]
    result = investigate(
        events,
        title="Complex investigation",
        category=InvestigationCategory.PERSISTENCE,
    )
    report = InvestigatorReport(result)

    data = report.to_dict()
    assert data["case"]["category"] == "persistence"
    assert data["evidence_summary"]["total"] == 2

    md = report.to_markdown()
    assert "## Hypotheses" in md
    assert "## Recommended Actions" in md
    assert "## Attack Timeline" in md


# ===========================================================================
# Report class API
# ===========================================================================

def test_report_class_reusable():
    result = make_result()
    report = InvestigatorReport(result)

    d = report.to_dict()
    md = report.to_markdown()
    txt = report.to_text()

    assert isinstance(d, dict)
    assert isinstance(md, str)
    assert isinstance(txt, str)
