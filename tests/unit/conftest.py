"""
Shared fixtures untuk tests.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def test_db(tmp_path: Path, monkeypatch):
    """SQLite temporary + patched global."""
    from internal.storage.db import Database
    import internal.storage.db as db_module

    url = f"sqlite:///{tmp_path}/test.db"
    db = Database(url=url, create_tables=True)

    monkeypatch.setattr(db_module, "_default_db", db)
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "test-secret-key-for-tests-32bytes-minimum-xx",
    )
    return db


@pytest.fixture
def auth_client(test_db):
    """
    Return (client, token) tuple. Token = admin (bootstrap).
    """
    from fastapi.testclient import TestClient
    from api.main import create_app

    client = TestClient(create_app())

    # Register first user -> bootstrap admin
    r = client.post(
        "/auth/register",
        json={
            "email": "admin@test.com",
            "password": "adminpassword123",
            "tenant_id": "acme",
        },
    )
    assert r.status_code == 201, r.text

    # Login
    r = client.post(
        "/auth/login",
        json={
            "email": "admin@test.com",
            "password": "adminpassword123",
        },
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]

    return client, token
