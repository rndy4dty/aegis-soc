"""
AuthService: high-level API untuk user management.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import select

from internal.auth.models import UserRow, UserRole
from internal.auth.passwords import (
    hash_password,
    verify_password,
)
from internal.storage.db import Database, get_database


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuthService:
    """Facade untuk user management."""

    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_database()

    # ==================================================================
    # Registration
    # ==================================================================

    def register(
        self,
        *,
        email: str,
        password: str,
        full_name: str | None = None,
        role: UserRole = UserRole.VIEWER,
        tenant_id: str | None = None,
    ) -> UserRow:
        """
        Buat user baru.

        Raise ValueError kalau email sudah dipakai atau password invalid.
        """
        email = email.strip().lower()
        if not email or "@" not in email:
            raise ValueError("invalid email")

        hashed = hash_password(password)

        with self._db.session() as session:
            # Cek duplikat
            existing = session.scalar(
                select(UserRow).where(UserRow.email == email)
            )
            if existing is not None:
                raise ValueError(
                    f"email already registered: {email}"
                )

            user = UserRow(
                user_id=f"U-{uuid4().hex[:12]}",
                email=email,
                hashed_password=hashed,
                full_name=full_name,
                role=role.value,
                tenant_id=tenant_id,
                is_active=True,
            )
            session.add(user)
            session.flush()
            session.refresh(user)
            # Detach
            session.expunge(user)
            return user

    def count_users(self) -> int:
        """Hitung total users (untuk bootstrap check)."""
        from sqlalchemy import func

        with self._db.session() as session:
            return int(
                session.scalar(
                    select(func.count()).select_from(UserRow)
                ) or 0
            )

    # ==================================================================
    # Login
    # ==================================================================

    def authenticate(
        self,
        *,
        email: str,
        password: str,
    ) -> UserRow | None:
        """
        Verify email + password.

        Return UserRow kalau valid, None kalau tidak.
        """
        email = email.strip().lower()

        with self._db.session() as session:
            user = session.scalar(
                select(UserRow).where(UserRow.email == email)
            )
            if user is None:
                return None
            if not user.is_active:
                return None
            if not verify_password(
                password, user.hashed_password
            ):
                return None

            user.last_login_at = _utcnow()
            user.updated_at = _utcnow()
            session.flush()
            session.refresh(user)
            session.expunge(user)
            return user

    # ==================================================================
    # Read
    # ==================================================================

    def get_user(self, user_id: str) -> UserRow | None:
        with self._db.session() as session:
            user = session.get(UserRow, user_id)
            if user is not None:
                session.expunge(user)
            return user

    def get_user_by_email(self, email: str) -> UserRow | None:
        email = email.strip().lower()
        with self._db.session() as session:
            user = session.scalar(
                select(UserRow).where(UserRow.email == email)
            )
            if user is not None:
                session.expunge(user)
            return user

    def list_users(
        self,
        *,
        tenant_id: str | None = None,
        limit: int = 100,
    ) -> list[UserRow]:
        with self._db.session() as session:
            stmt = select(UserRow).order_by(UserRow.email)
            if tenant_id is not None:
                stmt = stmt.where(
                    UserRow.tenant_id == tenant_id
                )
            stmt = stmt.limit(limit)
            users = list(session.scalars(stmt).all())
            for u in users:
                session.expunge(u)
            return users

    # ==================================================================
    # Update
    # ==================================================================

    def update_role(
        self, user_id: str, role: UserRole
    ) -> UserRow | None:
        with self._db.session() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return None
            user.role = role.value
            user.updated_at = _utcnow()
            session.flush()
            session.refresh(user)
            session.expunge(user)
            return user

    def deactivate(self, user_id: str) -> bool:
        with self._db.session() as session:
            user = session.get(UserRow, user_id)
            if user is None:
                return False
            user.is_active = False
            user.updated_at = _utcnow()
            session.flush()
            return True


__all__ = ["AuthService"]
