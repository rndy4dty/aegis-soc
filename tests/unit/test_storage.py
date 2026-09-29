"""
Contract tests untuk storage layer.

Pakai SQLite in-memory untuk unit test (cepat, tanpa Postgres).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from internal.investigation.investigation_engine import (
    investigate,
)
from internal.storage.db import Database
from internal.storage.repositories import InvestigationRepository
from internal.storage.service import StorageService
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


@pytest.fixture
def db(tmp_path):
    """Fresh SQLite DB untuk setiap test."""
    url = f"sqlite:///{tmp_path}/test.db"
    return Database(url=url, create_tables=True)


@pytest.fixture
def service(db):
    return StorageService(db=db)


def make_event(
    event_id: str = "E-1",
    *,
    offset: int = 0,
    severity: int = 85,
    mitre: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE + timedelta(seconds=offset),
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=severity,
        host="WIN-01",
        user="SYSTEM",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=4821,
            parent_name="svchost.exe",
            parent_pid=812,
        ),
        mitre_techniques=mitre or [],
    )


def make_result():
    return investigate(
        [
            make_event("E-1", offset=0, mitre=["T1546.011"]),
            make_event("E-2", offset=5, mitre=["T1546.011"]),
        ],
        title="Application Shimming",
        tenant_id="acme",
    )


# ===========================================================================
# Save
# ===========================================================================

def test_save_returns_case_id(service):
    result = make_result()
    case_id = service.save(result)
    assert case_id == result.case.case_id


def test_save_then_load(service):
    result = make_result()
    service.save(result)

    loaded = service.load(result.case.case_id)
    assert loaded is not None
    assert loaded.case.case_id == result.case.case_id
    assert loaded.case.title == result.case.title
    assert loaded.case.tenant_id == "acme"
    assert loaded.risk_score == result.risk_score
    assert loaded.confidence == result.confidence


def test_save_persists_evidence(service):
    result = make_result()
    service.save(result)

    loaded = service.load(result.case.case_id)
    assert len(loaded.evidence) == len(result.evidence)
    assert loaded.evidence_count == result.evidence_count


def test_save_persists_hypotheses(service):
    result = make_result()
    service.save(result)

    loaded = service.load(result.case.case_id)
    assert len(loaded.hypotheses) == len(result.hypotheses)
    assert loaded.hypothesis_count == result.hypothesis_count


def test_save_upsert(service):
    """Save dua kali dengan case_id sama = update."""
    result = make_result()
    service.save(result)

    # Modify result (simulasi update)
    result.case.attach_summary("Updated summary")
    service.save(result)

    loaded = service.load(result.case.case_id)
    assert loaded.case.summary == "Updated summary"


def test_save_updates_indexed_columns(service):
    """Test indexed column update."""
    result = make_result()
    service.save(result)

    # Get row
    row = service.list_cases()[0]
    assert row.risk_score == result.risk_score
    assert row.tenant_id == "acme"


# ===========================================================================
# Load
# ===========================================================================

def test_load_nonexistent(service):
    assert service.load("NON-EXISTENT") is None


def test_load_preserves_status(service):
    result = make_result()
    service.save(result)
    loaded = service.load(result.case.case_id)
    assert loaded.case.status == result.case.status


def test_load_preserves_risk_score(service):
    result = make_result()
    service.save(result)
    loaded = service.load(result.case.case_id)
    assert loaded.risk_score == result.risk_score


def test_load_preserves_hypothesis_statements(service):
    result = make_result()
    service.save(result)
    loaded = service.load(result.case.case_id)

    original_stmts = {h.statement for h in result.hypotheses}
    loaded_stmts = {h.statement for h in loaded.hypotheses}
    assert original_stmts == loaded_stmts


# ===========================================================================
# Query
# ===========================================================================

def test_list_cases_empty(service):
    assert service.list_cases() == []


def test_list_cases_returns_saved(service):
    result = make_result()
    service.save(result)

    cases = service.list_cases()
    assert len(cases) == 1
    assert cases[0].case_id == result.case.case_id


def test_list_by_tenant(service):
    result1 = investigate(
        [make_event("E-1")],
        title="Case 1",
        tenant_id="acme",
    )
    result2 = investigate(
        [make_event("E-2")],
        title="Case 2",
        tenant_id="other",
    )
    service.save(result1)
    service.save(result2)

    acme = service.list_cases(tenant_id="acme")
    assert len(acme) == 1
    assert acme[0].tenant_id == "acme"


def test_list_by_status(service):
    result = make_result()
    service.save(result)

    cases = service.list_cases(status=result.case.status.value)
    assert len(cases) >= 1


def test_list_by_min_risk(service):
    result = make_result()
    service.save(result)

    cases = service.list_cases(min_risk=result.risk_score)
    assert len(cases) == 1

    cases_high = service.list_cases(min_risk=100)
    assert len(cases_high) == 0


def test_count(service):
    assert service.count() == 0
    service.save(make_result())
    assert service.count() == 1
    service.save(make_result())
    assert service.count() == 2


# ===========================================================================
# Delete
# ===========================================================================

def test_delete(service):
    result = make_result()
    service.save(result)
    assert service.load(result.case.case_id) is not None

    deleted = service.delete(result.case.case_id)
    assert deleted is True
    assert service.load(result.case.case_id) is None


def test_delete_nonexistent(service):
    assert service.delete("NON-EXISTENT") is False


# ===========================================================================
# Repository direct access
# ===========================================================================

def test_repository_direct(db):
    with db.session() as session:
        repo = InvestigationRepository(session)
        result = make_result()
        row = repo.save(result)
        assert row.case_id == result.case.case_id

        loaded = repo.load_result(result.case.case_id)
        assert loaded is not None
        assert loaded.case.case_id == result.case.case_id
