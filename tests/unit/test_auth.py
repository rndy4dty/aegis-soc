"""
Contract tests untuk auth layer.

Pakai SQLite in-memory.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from internal.auth import (
    AuthService,
    UserRole,
    create_token,
    decode_token,
    hash_password,
    verify_password,
)
from internal.auth.models import UserRow
from internal.storage.db import Database


@pytest.fixture
def db(tmp_path: Path):
    url = f"sqlite:///{tmp_path}/auth.db"
    return Database(url=url, create_tables=True)


@pytest.fixture
def service(db):
    return AuthService(db=db)


@pytest.fixture
def jwt_secret(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "test-secret-key-for-unit-tests-only",
    )


# ===========================================================================
# Passwords
# ===========================================================================

def test_hash_password_returns_string():
    h = hash_password("validpassword123")
    assert isinstance(h, str)
    assert len(h) > 20


def test_hash_password_different_each_time():
    h1 = hash_password("validpassword123")
    h2 = hash_password("validpassword123")
    assert h1 != h2  # bcrypt salt berbeda


def test_verify_password_correct():
    h = hash_password("validpassword123")
    assert verify_password("validpassword123", h) is True


def test_verify_password_wrong():
    h = hash_password("validpassword123")
    assert verify_password("wrongpassword", h) is False


def test_password_too_short():
    with pytest.raises(ValueError, match="at least"):
        hash_password("short")


def test_verify_password_invalid_hash():
    assert verify_password("any", "not-a-valid-hash") is False


# ===========================================================================
# JWT Tokens
# ===========================================================================

def test_create_token_basic(jwt_secret):
    token, expires = create_token(
        user_id="U-1",
        email="test@example.com",
        role="analyst",
        tenant_id="acme",
    )
    assert isinstance(token, str)
    assert expires == 3600  # 60 min default


def test_decode_token(jwt_secret):
    token, _ = create_token(
        user_id="U-1",
        email="test@example.com",
        role="analyst",
        tenant_id="acme",
    )
    payload = decode_token(token)
    assert payload.user_id == "U-1"
    assert payload.email == "test@example.com"
    assert payload.role == "analyst"
    assert payload.tenant_id == "acme"


def test_decode_token_invalid(jwt_secret):
    with pytest.raises(ValueError, match="invalid token"):
        decode_token("not-a-token")


def test_decode_token_wrong_secret(monkeypatch):
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "secret-A-" + "x" * 40,
    )
    token, _ = create_token(
        user_id="U-1", email="a@b.com", role="viewer"
    )
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET",
        "secret-B-" + "y" * 40,
    )
    with pytest.raises(ValueError):
        decode_token(token)

def test_decode_token_expired(jwt_secret):
    token, _ = create_token(
        user_id="U-1",
        email="a@b.com",
        role="viewer",
        expires_minutes=-1,  # sudah expired
    )
    with pytest.raises(ValueError, match="expired"):
        decode_token(token)


# ===========================================================================
# AuthService — Register
# ===========================================================================

def test_register_success(service):
    user = service.register(
        email="test@example.com",
        password="validpassword123",
        full_name="Test User",
        tenant_id="acme",
    )
    assert user.user_id.startswith("U-")
    assert user.email == "test@example.com"
    assert user.role == "viewer"
    assert user.tenant_id == "acme"
    assert user.is_active is True


def test_register_normalizes_email(service):
    user = service.register(
        email="  TEST@Example.COM  ",
        password="validpassword123",
    )
    assert user.email == "test@example.com"


def test_register_duplicate_email(service):
    service.register(
        email="test@example.com",
        password="validpassword123",
    )
    with pytest.raises(ValueError, match="already registered"):
        service.register(
            email="test@example.com",
            password="anotherpass123",
        )


def test_register_invalid_email(service):
    with pytest.raises(ValueError, match="invalid email"):
        service.register(
            email="not-an-email",
            password="validpassword123",
        )


def test_register_short_password(service):
    with pytest.raises(ValueError, match="at least"):
        service.register(
            email="test@example.com",
            password="short",
        )


def test_count_users(service):
    assert service.count_users() == 0
    service.register(
        email="a@b.com", password="validpassword123"
    )
    assert service.count_users() == 1


# ===========================================================================
# AuthService — Login
# ===========================================================================

def test_authenticate_success(service):
    service.register(
        email="test@example.com",
        password="validpassword123",
    )
    user = service.authenticate(
        email="test@example.com",
        password="validpassword123",
    )
    assert user is not None
    assert user.email == "test@example.com"


def test_authenticate_wrong_password(service):
    service.register(
        email="test@example.com",
        password="validpassword123",
    )
    user = service.authenticate(
        email="test@example.com",
        password="wrongpass",
    )
    assert user is None


def test_authenticate_unknown_email(service):
    user = service.authenticate(
        email="unknown@example.com",
        password="anypass",
    )
    assert user is None


def test_authenticate_updates_last_login(service):
    service.register(
        email="test@example.com",
        password="validpassword123",
    )
    user = service.authenticate(
        email="test@example.com",
        password="validpassword123",
    )
    assert user.last_login_at is not None


def test_authenticate_inactive_user(service):
    user = service.register(
        email="test@example.com",
        password="validpassword123",
    )
    service.deactivate(user.user_id)

    result = service.authenticate(
        email="test@example.com",
        password="validpassword123",
    )
    assert result is None


# ===========================================================================
# AuthService — Read
# ===========================================================================

def test_get_user(service):
    created = service.register(
        email="test@example.com",
        password="validpassword123",
    )
    user = service.get_user(created.user_id)
    assert user is not None
    assert user.email == "test@example.com"


def test_get_user_nonexistent(service):
    assert service.get_user("NON-EXISTENT") is None


def test_list_users(service):
    service.register(
        email="a@b.com", password="validpassword123"
    )
    service.register(
        email="c@d.com", password="validpassword123"
    )
    users = service.list_users()
    assert len(users) == 2


def test_list_users_by_tenant(service):
    service.register(
        email="a@b.com",
        password="validpassword123",
        tenant_id="acme",
    )
    service.register(
        email="c@d.com",
        password="validpassword123",
        tenant_id="other",
    )
    acme = service.list_users(tenant_id="acme")
    assert len(acme) == 1


# ===========================================================================
# AuthService — Update
# ===========================================================================

def test_update_role(service):
    user = service.register(
        email="test@example.com",
        password="validpassword123",
    )
    assert user.role == "viewer"

    updated = service.update_role(user.user_id, UserRole.ANALYST)
    assert updated is not None
    assert updated.role == "analyst"


def test_update_role_nonexistent(service):
    result = service.update_role("NON-EXISTENT", UserRole.ADMIN)
    assert result is None


def test_deactivate(service):
    user = service.register(
        email="test@example.com",
        password="validpassword123",
    )
    assert service.deactivate(user.user_id) is True

    reloaded = service.get_user(user.user_id)
    assert reloaded is not None
    assert reloaded.is_active is False


# ===========================================================================
# Integration: register → login → token → decode
# ===========================================================================

def test_full_auth_flow(service, jwt_secret):
    # Register
    user = service.register(
        email="alice@example.com",
        password="alicepassword123",
        tenant_id="acme",
    )

    # Login
    authed = service.authenticate(
        email="alice@example.com",
        password="alicepassword123",
    )
    assert authed is not None

    # Create token
    token, expires = create_token(
        user_id=authed.user_id,
        email=authed.email,
        role=authed.role,
        tenant_id=authed.tenant_id,
    )
    assert expires > 0

    # Decode token
    payload = decode_token(token)
    assert payload.user_id == user.user_id
    assert payload.tenant_id == "acme"


# ===========================================================================
# API Tests
# ===========================================================================

def test_api_register_first_user_becomes_admin(tmp_path, monkeypatch):
    """First user bootstrap = admin."""
    from fastapi.testclient import TestClient
    from api.main import create_app
    from internal.storage.db import Database
    import internal.storage.db as db_module

    # Use temp SQLite
    url = f"sqlite:///{tmp_path}/api_auth.db"
    test_db = Database(url=url, create_tables=True)

    # Monkey-patch global get_database
    monkeypatch.setattr(
        db_module, "_default_db", test_db
    )
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET", "test-secret-1234567890-abcdefghijklmnop"
    )

    app = create_app()
    client = TestClient(app)

    r = client.post(
        "/auth/register",
        json={
            "email": "admin@example.com",
            "password": "adminpassword123",
            "tenant_id": "acme",
        },
    )
    assert r.status_code == 201
    data = r.json()
    assert data["role"] == "admin"
    assert data["email"] == "admin@example.com"


def test_api_login_returns_token(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from api.main import create_app
    from internal.storage.db import Database
    import internal.storage.db as db_module

    url = f"sqlite:///{tmp_path}/api_login.db"
    test_db = Database(url=url, create_tables=True)
    monkeypatch.setattr(
        db_module, "_default_db", test_db
    )
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET", "test-secret-1234567890-abcdefghijklmnop"
    )

    app = create_app()
    client = TestClient(app)

    # Register
    client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "userpassword123",
            "tenant_id": "acme",
        },
    )

    # Login
    r = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "userpassword123",
        },
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "user@example.com"


def test_api_login_wrong_password(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from api.main import create_app
    from internal.storage.db import Database
    import internal.storage.db as db_module

    url = f"sqlite:///{tmp_path}/api_wrong.db"
    test_db = Database(url=url, create_tables=True)
    monkeypatch.setattr(
        db_module, "_default_db", test_db
    )
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET", "test-secret-1234567890-abcdefghijklmnop"
    )

    app = create_app()
    client = TestClient(app)

    client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "userpassword123",
        },
    )

    r = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "wrongpassword",
        },
    )
    assert r.status_code == 401


def test_api_me_with_token(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from api.main import create_app
    from internal.storage.db import Database
    import internal.storage.db as db_module

    url = f"sqlite:///{tmp_path}/api_me.db"
    test_db = Database(url=url, create_tables=True)
    monkeypatch.setattr(
        db_module, "_default_db", test_db
    )
    monkeypatch.setenv(
        "AEGIS_JWT_SECRET", "test-secret-1234567890-abcdefghijklmnop"
    )

    app = create_app()
    client = TestClient(app)

    client.post(
        "/auth/register",
        json={
            "email": "user@example.com",
            "password": "userpassword123",
            "tenant_id": "acme",
        },
    )

    r = client.post(
        "/auth/login",
        json={
            "email": "user@example.com",
            "password": "userpassword123",
        },
    )
    token = r.json()["access_token"]

    r = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200
    assert r.json()["email"] == "user@example.com"


def test_api_me_without_token():
    from fastapi.testclient import TestClient
    from api.main import create_app

    app = create_app()
    client = TestClient(app)

    r = client.get("/auth/me")
    assert r.status_code == 401
