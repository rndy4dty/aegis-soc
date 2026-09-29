"""
Contract tests untuk REST API.

Pakai FastAPI TestClient (dari httpx). Tidak butuh server berjalan.
"""

from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

from api.main import create_app


@pytest.fixture(autouse=True)
def _reset_api_key(monkeypatch):
    """Pastikan AEGIS_API_KEY tidak bocor dari env."""
    monkeypatch.delenv("AEGIS_API_KEY", raising=False)
    # Rebuild deps settings
    import importlib
    import api.deps
    importlib.reload(api.deps)


@pytest.fixture
def client() -> TestClient:
    app = create_app()
    return TestClient(app)


# ===========================================================================
# Helpers
# ===========================================================================

def _event_payload(
    event_id: str = "E-1",
    *,
    offset: int = 0,
    severity: int = 85,
    mitre: list[str] | None = None,
) -> dict:
    sec = f"{offset:02d}"
    return {
        "event_id": event_id,
        "timestamp": f"2026-09-26T10:00:{sec}Z",
        "source": "sysmon",
        "platform": "windows",
        "category": "process",
        "event_type": "process_creation",
        "severity": severity,
        "host": "WIN-01",
        "user": "SYSTEM",
        "process": {
            "name": "sdbinst.exe",
            "pid": 4821,
            "parent_name": "svchost.exe",
            "parent_pid": 812,
        },
        "mitre_techniques": mitre or [],
    }


# ===========================================================================
# Health
# ===========================================================================

def test_health(client: TestClient):
    r = client.get("/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_version(client: TestClient):
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


# ===========================================================================
# Meta
# ===========================================================================

def test_meta_providers(client: TestClient):
    r = client.get("/meta/providers")
    assert r.status_code == 200
    data = r.json()
    assert "rule_engine" in data["ai_providers"]
    assert isinstance(data["threat_intel_providers"], list)


def test_meta_categories(client: TestClient):
    r = client.get("/meta/categories")
    assert r.status_code == 200
    cats = r.json()["categories"]
    assert "unknown" in cats
    assert "persistence" in cats


# ===========================================================================
# Investigate
# ===========================================================================

def test_investigate_minimal(client: TestClient):
    payload = {
        "title": "Test case",
        "events": [_event_payload()],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["case_id"].startswith("CASE-")
    assert data["title"] == "Test case"
    assert data["risk_score"] >= 0
    assert data["evidence_count"] >= 1
    assert "report_markdown" in data
    assert "report_dict" in data


def test_investigate_with_mitre(client: TestClient):
    payload = {
        "title": "Shimming case",
        "events": [
            _event_payload("E-1", mitre=["T1546.011"]),
            _event_payload("E-2", offset=5, mitre=["T1546.011"]),
        ],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["hypothesis_count"] >= 2
    assert data["relationship_count"] >= 1


def test_investigate_with_analyst(client: TestClient):
    payload = {
        "title": "Analyst test",
        "analyst": "ren",
        "events": [_event_payload()],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert "Analyst" in data["report_markdown"] or "ren" in str(data)


def test_investigate_with_category(client: TestClient):
    payload = {
        "title": "Persistence case",
        "category": "persistence",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    assert "persistence" in r.json()["report_dict"]["case"]["category"]


def test_investigate_with_priority(client: TestClient):
    payload = {
        "title": "Critical case",
        "priority": "critical",
        "events": [_event_payload(severity=95)],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    assert r.json()["priority"] == "critical"


def test_investigate_with_narrative(client: TestClient):
    payload = {
        "title": "Narrative test",
        "narrative": True,
        "provider": "rule",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    data = r.json()
    assert data["narrative"] is not None
    assert len(data["narrative"]) > 50


def test_investigate_with_multi_agent_narrative(client: TestClient):
    payload = {
        "title": "Multi-agent test",
        "narrative": True,
        "provider": "multi_agent",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 200
    assert r.json()["narrative"] is not None


def test_investigate_empty_events(client: TestClient):
    payload = {"title": "Empty", "events": []}
    r = client.post("/investigations", json=payload)
    assert r.status_code == 422  # min_length=1


def test_investigate_missing_title(client: TestClient):
    payload = {"events": [_event_payload()]}
    r = client.post("/investigations", json=payload)
    assert r.status_code == 422


def test_investigate_invalid_event(client: TestClient):
    payload = {
        "title": "Bad event",
        "events": [{"event_id": "E-1"}],  # missing fields
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 400


def test_investigate_invalid_category(client: TestClient):
    payload = {
        "title": "Bad category",
        "category": "not-a-category",
        "events": [_event_payload()],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 400


def test_investigate_invalid_priority(client: TestClient):
    payload = {
        "title": "Bad priority",
        "priority": "not-a-priority",
        "events": [_event_payload()],
    }
    r = client.post("/investigations", json=payload)
    assert r.status_code == 400


# ===========================================================================
# API key
# ===========================================================================

def test_api_key_required_when_set(
    monkeypatch, client_factory
):
    monkeypatch.setenv("AEGIS_API_KEY", "secret-123")
    import importlib
    import api.deps
    importlib.reload(api.deps)

    client = client_factory()

    # Tanpa header → 401
    r = client.get("/meta/categories")
    assert r.status_code == 401

    # Dengan header salah → 401
    r = client.get(
        "/meta/categories",
        headers={"X-API-Key": "wrong"},
    )
    assert r.status_code == 401

    # Dengan header benar → 200
    r = client.get(
        "/meta/categories",
        headers={"X-API-Key": "secret-123"},
    )
    assert r.status_code == 200


@pytest.fixture
def client_factory():
    def _make() -> TestClient:
        return TestClient(create_app())
    return _make
