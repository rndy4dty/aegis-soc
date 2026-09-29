"""
High-level storage service.

Wraps repository + session untuk pemakaian sederhana.
"""

from __future__ import annotations

from datetime import datetime

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.storage.db import Database, get_database
from internal.storage.models import InvestigationRow
from internal.storage.repositories import (
    InvestigationRepository,
)


class StorageService:
    """
    Facade untuk persistence investigation.
    """

    def __init__(self, db: Database | None = None) -> None:
        self._db = db or get_database()

    # ------------------------------------------------------------------
    # Save / Load
    # ------------------------------------------------------------------

    def save(self, result: InvestigationResult) -> str:
        """
        Simpan InvestigationResult.
        Return case_id.
        """
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            row = repo.save(result)
            return row.case_id

    def get(self, case_id: str) -> InvestigationRow | None:
        """Ambil row by case_id."""
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            return repo.get(case_id)

    def load(
        self, case_id: str
    ) -> InvestigationResult | None:
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            return repo.load_result(case_id)

    def delete(self, case_id: str) -> bool:
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            return repo.delete(case_id)

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    def list_cases(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        analyst: str | None = None,
        min_risk: int | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[InvestigationRow]:
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            return repo.list_cases(
                tenant_id=tenant_id,
                status=status,
                priority=priority,
                analyst=analyst,
                min_risk=min_risk,
                since=since,
                limit=limit,
                offset=offset,
            )

    def count(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
    ) -> int:
        with self._db.session() as session:
            repo = InvestigationRepository(session)
            return repo.count(
                tenant_id=tenant_id,
                status=status,
            )


__all__ = ["StorageService"]
