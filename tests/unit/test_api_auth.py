"""
Contract tests untuk API + auth integration.

Verifikasi RBAC + tenant isolation di endpoint investigations.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


# ===========================================================================
# Helpers
# ===========================================================================

def _register_and_login(
    client: TestClient,
    test_db,
    *,
    email: str,
    password: str = "password12345",
    tenant: str = "acme",
    role: str = "analyst",
) -> str:
    """
    Register + promote role + login.
    Return access token.
    """
    from internal.auth import AuthService, UserRole

    r = client.post(
        "/auth/register",
        json={
            "email": email,
            "password": password,
            "tenant_id": tenant,
        },
    )
    assert r.status_code == 201, r.text
    user_id = r.json()["user_id"]

    # Promote role (default viewer → analyst/admin)
    svc = AuthService(db=test_db)
    svc.update_role(user_id, UserRole(role))

    # Login
    r = client.post(
        "/auth/login",
        json={"email": email, "password": password},
    )
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def _event_payload() -> list[dict]:
    return [{
        "event_id": "E-1",
        "timestamp": "2026-09-26T10:00:00Z",
        "source": "sysmon",
        "platform": "windows",
        "category": "process",
        "event_type": "process_creation",
        "severity": 85,
        "host": "WIN-01",
        "mitre_techniques": ["T1546.011"],
    }]


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


# ===========================================================================
# Auth required
# ===========================================================================

def test_list_investigations_requires_auth(auth_client):
    client, _ = auth_client
    r = client.get("/investigations")
    assert r.status_code == 401


def test_create_investigation_requires_auth(auth_client):
    client, _ = auth_client
    r = client.post(
        "/investigations",
        json={"title": "Test", "events": _event_payload()},
    )
    assert r.status_code == 401


# ===========================================================================
# With auth
# ===========================================================================

def test_create_investigation_with_admin(auth_client):
    client, token = auth_client
    r = client.post(
        "/investigations",
        json={"title": "Test Case", "events": _event_payload()},
        headers=_auth(token),
    )
    assert r.status_code == 200, r.text
    assert r.json()["title"] == "Test Case"


def test_list_investigations_with_token(auth_client):
    client, token = auth_client
    r = client.get(
        "/investigations", headers=_auth(token),
    )
    assert r.status_code == 200
    assert isinstance(r.json(), list)


# ===========================================================================
# Tenant isolation
# ===========================================================================

def test_list_isolates_tenants(auth_client, test_db):
    client, _ = auth_client

    token_a = _register_and_login(
        client, test_db,
        email="a@example.com", tenant="tenant-a",
    )
    token_b = _register_and_login(
        client, test_db,
        email="b@example.com", tenant="tenant-b",
    )

    r = client.post(
        "/investigations",
        json={"title": "Case A", "events": _event_payload()},
        headers=_auth(token_a),
    )
    assert r.status_code == 200, r.text

    r = client.get(
        "/investigations", headers=_auth(token_b),
    )
    assert r.status_code == 200
    assert len(r.json()) == 0


def test_get_cross_tenant_denied(auth_client, test_db):
    client, _ = auth_client

    token_a = _register_and_login(
        client, test_db,
        email="a2@example.com", tenant="tenant-a",
    )
    token_b = _register_and_login(
        client, test_db,
        email="b2@example.com", tenant="tenant-b",
    )

    r = client.post(
        "/investigations",
        json={"title": "Case A", "events": _event_payload()},
        headers=_auth(token_a),
    )
    assert r.status_code == 200, r.text
    case_id = r.json()["case_id"]

    r = client.get(
        f"/investigations/{case_id}",
        headers=_auth(token_b),
    )
    assert r.status_code == 403


# ===========================================================================
# Get detail
# ===========================================================================

def test_get_investigation_detail(auth_client):
    client, token = auth_client
    r = client.post(
        "/investigations",
        json={"title": "Detail Test", "events": _event_payload()},
        headers=_auth(token),
    )
    case_id = r.json()["case_id"]

    r = client.get(
        f"/investigations/{case_id}",
        headers=_auth(token),
    )
    assert r.status_code == 200
    assert r.json()["case_id"] == case_id


def test_get_investigation_not_found(auth_client):
    client, token = auth_client
    r = client.get(
        "/investigations/NON-EXISTENT",
        headers=_auth(token),
    )
    assert r.status_code == 404
