"""
Base abstractions untuk collector.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from pkg.models.event import Event


@dataclass
class CollectorResult:
    """
    Hasil dari satu operasi collect.

    Attributes:
    - events        : list[Event] yang berhasil di-normalisasi
    - errors        : list pesan error per item (index + reason)
    - source_name   : nama collector
    - raw_count     : jumlah item mentah yang diproses
    """

    events: list[Event] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    source_name: str = "unknown"
    raw_count: int = 0

    @property
    def success_count(self) -> int:
        return len(self.events)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def success_rate(self) -> float:
        if self.raw_count == 0:
            return 0.0
        return self.success_count / self.raw_count


@runtime_checkable
class Collector(Protocol):
    """
    Protocol untuk semua collector.

    Implementasi mengubah sumber → list[Event].
    """

    def name(self) -> str:
        """Nama unik collector."""
        ...

    def collect(self) -> CollectorResult:
        """
        Baca sumber dan kembalikan CollectorResult.

        Tidak raise untuk error per-item; hanya catch di `errors`.
        Raise hanya untuk error fatal (sumber tidak bisa dibaca).
        """
        ...


__all__ = ["Collector", "CollectorResult"]
