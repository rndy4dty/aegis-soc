"""
Database engine and session management.

Configuration via env:
- AEGIS_DATABASE_URL : PostgreSQL connection string
  default: postgresql+psycopg://aegis:aegis@localhost:5432/aegis

Also supports SQLite for testing:
  sqlite:///./aegis.db
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import (
    DeclarativeBase,
    Session,
    sessionmaker,
)


DEFAULT_DATABASE_URL = (
    "postgresql+psycopg://aegis:aegis@localhost:5432/aegis"
)


class Base(DeclarativeBase):
    """Base class untuk semua ORM models."""
    pass


class Database:
    """
    Wrapper untuk SQLAlchemy engine + session factory.
    """

    def __init__(
        self,
        url: str | None = None,
        *,
        echo: bool = False,
        create_tables: bool = True,
    ) -> None:
        if url is not None:
            self._url = url
        else:
            self._url = (
                os.environ.get("AEGIS_DATABASE_URL")
                or DEFAULT_DATABASE_URL
            )

        # SQLite tidak support pool_size, jadi handle berbeda
        if self._url.startswith("sqlite"):
            self._engine = create_engine(
                self._url,
                echo=echo,
                future=True,
            )
        else:
            self._engine = create_engine(
                self._url,
                echo=echo,
                future=True,
                pool_pre_ping=True,
                pool_size=5,
                max_overflow=10,
            )

        self._session_factory = sessionmaker(
            bind=self._engine,
            expire_on_commit=False,
            future=True,
        )

        if create_tables:
            # Import models dulu supaya terdaftar di metadata
            from internal.storage import models  # noqa: F401
            Base.metadata.create_all(self._engine)

    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        # Sembunyikan password kalau ada
        if "@" in self._url:
            scheme, rest = self._url.split("://", 1)
            if "@" in rest:
                creds, host = rest.split("@", 1)
                if ":" in creds:
                    user, _ = creds.split(":", 1)
                    return f"{scheme}://{user}:***@{host}"
        return self._url

    @property
    def engine(self):
        return self._engine

    # ------------------------------------------------------------------

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Context manager: auto commit atau rollback."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def close(self) -> None:
        self._engine.dispose()


# ----------------------------------------------------------------------
# Global singleton (lazy init)
# ----------------------------------------------------------------------

_default_db: Database | None = None


def get_database(
    *,
    create: bool = True,
) -> Database:
    """
    Ambil global database instance (singleton).

    Pertama kali dipanggil: bikin instance baru.
    Selanjutnya: return instance yang sama.

    Parameter `create` -> apakah tabel dibuat otomatis.
    """
    global _default_db
    if _default_db is None:
        _default_db = Database(create_tables=create)
    return _default_db


def reset_database() -> None:
    """Reset singleton (untuk testing)."""
    global _default_db
    if _default_db is not None:
        _default_db.close()
    _default_db = None


__all__ = [
    "Base",
    "Database",
    "get_database",
    "reset_database",
    "DEFAULT_DATABASE_URL",
]
