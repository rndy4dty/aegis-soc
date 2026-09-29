"""
AI provider abstraction for AegisSOC.

Setiap provider (rule engine, local LLM, cloud LLM) mengimplementasikan
kontrak yang sama:

    name()              -> str
    is_available()      -> bool
    generate_narrative(InvestigationResult) -> str

Tujuan:
- Router tidak perlu tahu detail provider.
- Menambah provider baru = implement Protocol ini, tanpa ubah router.
- Provider yang tidak tersedia (offline, no API key) otomatis di-skip.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from internal.investigation.investigation_engine import (
    InvestigationResult,
)


@runtime_checkable
class AIProvider(Protocol):
    """
    Protocol untuk semua provider narrative.

    Implementasi wajib menyediakan tiga method ini.
    """

    def name(self) -> str:
        """Nama unik provider (untuk logging & routing)."""
        ...

    def is_available(self) -> bool:
        """Apakah provider siap dipakai saat ini."""
        ...

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        """Hasilkan narrative dari InvestigationResult."""
        ...


class BaseProvider:
    """
    Base class opsional untuk provider.

    Menyediakan implementasi default yang bisa di-override.
    """

    _name: str = "base"

    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        return True

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        raise NotImplementedError(
            f"{self.__class__.__name__} must implement "
            f"generate_narrative()"
        )


__all__ = ["AIProvider", "BaseProvider"]
