"""
ORM model untuk user.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean,
    DateTime,
    Index,
    String,
)
from sqlalchemy.orm import Mapped, mapped_column

from internal.storage.db import Base


class UserRole(str, Enum):
    """
    Role user.

    - VIEWER  : read-only
    - ANALYST : read + write investigation
    - ADMIN   : semua akses + user management
    """
    VIEWER = "viewer"
    ANALYST = "analyst"
    ADMIN = "admin"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class UserRow(Base):
    __tablename__ = "users"

    # -- Identity -----------------------------------------------------
    user_id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    email: Mapped[str] = mapped_column(
        String(256), unique=True, index=True
    )
    hashed_password: Mapped[str] = mapped_column(String(256))
    full_name: Mapped[str | None] = mapped_column(
        String(256), nullable=True
    )

    # -- Authorization ------------------------------------------------
    role: Mapped[str] = mapped_column(
        String(32), index=True, default=UserRole.VIEWER.value
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, default=True
    )

    # -- Audit --------------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # -- Indexes ------------------------------------------------------
    __table_args__ = (
        Index(
            "ix_users_tenant_role",
            "tenant_id",
            "role",
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<UserRow user_id={self.user_id!r} "
            f"email={self.email!r} role={self.role!r}>"
        )


__all__ = ["UserRow", "UserRole"]
