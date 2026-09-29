"""
Contract tests untuk REST API.

Semua endpoint investigation butuh auth (JWT).
Fixture `auth_client` menyediakan (client, token).
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


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


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Health
# ===========================================================================

def test_health(auth_client):
    client, _ = auth_client
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"


def test_version(auth_client):
    client, _ = auth_client
    r = client.get("/version")
    assert r.status_code == 200


# ===========================================================================
# Meta
# ===========================================================================

def test_meta_providers(auth_client):
    client, _ = auth_client
    r = client.get("/meta/providers")
    assert r.status_code == 200
    assert "rule_engine" in r.json()["ai_providers"]


def test_meta_categories(auth_client):
    client, _ = auth_client
    r = client.get("/meta/categories")
    assert r.status_code == 200
    cats = r.json()["categories"]
    assert "unknown" in cats
    assert "persistence" in cats


# ===========================================================================
# Create investigation
# ===========================================================================

def test_investigate_minimal(auth_client):
    client, token = auth_client
    payload = {"title": "Test case", "events": [_event_payload()]}
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["case_id"].startswith("CASE-")
    assert data["title"] == "Test case"
    assert data["risk_score"] >= 0
    assert data["evidence_count"] >= 1
    assert "report_markdown" in data


def test_investigate_with_mitre(auth_client):
    client, token = auth_client
    payload = {
        "title": "Shimming case",
        "events": [
            _event_payload("E-1", mitre=["T1546.011"]),
            _event_payload("E-2", offset=5, mitre=["T1546.011"]),
        ],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["hypothesis_count"] >= 2
    assert data["relationship_count"] >= 1


def test_investigate_with_analyst(auth_client):
    client, token = auth_client
    payload = {
        "title": "Analyst test",
        "analyst": "ren",
        "events": [_event_payload()],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text


def test_investigate_with_category(auth_client):
    client, token = auth_client
    payload = {
        "title": "Persistence case",
        "category": "persistence",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text


def test_investigate_with_priority(auth_client):
    client, token = auth_client
    payload = {
        "title": "Critical case",
        "priority": "critical",
        "events": [_event_payload(severity=95)],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["priority"] == "critical"


def test_investigate_with_narrative(auth_client):
    client, token = auth_client
    payload = {
        "title": "Narrative test",
        "narrative": True,
        "provider": "rule",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["narrative"] is not None


def test_investigate_with_multi_agent_narrative(auth_client):
    client, token = auth_client
    payload = {
        "title": "Multi-agent test",
        "narrative": True,
        "provider": "multi_agent",
        "events": [_event_payload(mitre=["T1546.011"])],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["narrative"] is not None


# ===========================================================================
# Validation
# ===========================================================================

def test_investigate_empty_events(auth_client):
    client, token = auth_client
    payload = {"title": "Empty", "events": []}
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 422


def test_investigate_missing_title(auth_client):
    client, token = auth_client
    payload = {"events": [_event_payload()]}
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 422


def test_investigate_invalid_event(auth_client):
    client, token = auth_client
    payload = {
        "title": "Bad event",
        "events": [{"event_id": "E-1"}],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 400


def test_investigate_invalid_category(auth_client):
    client, token = auth_client
    payload = {
        "title": "Bad category",
        "category": "not-a-category",
        "events": [_event_payload()],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 400


def test_investigate_invalid_priority(auth_client):
    client, token = auth_client
    payload = {
        "title": "Bad priority",
        "priority": "not-a-priority",
        "events": [_event_payload()],
    }
    r = client.post(
        "/investigations", json=payload, headers=_auth(token),
    )
    assert r.status_code == 400


# ===========================================================================
# Auth required
# ===========================================================================

def test_investigate_requires_auth(auth_client):
    client, _ = auth_client
    payload = {"title": "Test", "events": [_event_payload()]}
    r = client.post("/investigations", json=payload)
    assert r.status_code == 401


def test_list_requires_auth(auth_client):
    client, _ = auth_client
    r = client.get("/investigations")
    assert r.status_code == 401


def test_get_detail_requires_auth(auth_client):
    client, _ = auth_client
    r = client.get("/investigations/SOME-ID")
    assert r.status_code == 401
