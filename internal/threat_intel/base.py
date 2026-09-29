"""
Base abstractions untuk threat intel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pkg.models.event import Event


class IndicatorType(str, Enum):
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"


@dataclass(frozen=True)
class Indicator:
    """
    Satu indicator yang diekstrak dari event.

    - type    : IndicatorType
    - value   : nilai (normalized)
    - source  : dari mana di event (mis. "process.hashes.sha256")
    """

    type: IndicatorType
    value: str
    source: str = ""

    def __hash__(self) -> int:
        return hash((self.type, self.value))


@dataclass
class IntelResult:
    """
    Hasil lookup satu indicator dari satu provider.

    Attributes:
    - indicator       : indicator yang di-lookup
    - provider        : nama provider ("virustotal", "otx", ...)
    - found           : True kalau provider punya data
    - malicious_count : jumlah engine yang flag malicious
    - total_count     : total engine
    - reputation      : skor reputasi (provider-specific)
    - tags            : kategori / family
    - raw             : respons mentah
    - error           : pesan error kalau gagal
    """

    indicator: Indicator
    provider: str
    found: bool = False
    malicious_count: int = 0
    total_count: int = 0
    reputation: int | None = None
    tags: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    error: str | None = None

    @property
    def is_malicious(self) -> bool:
        return self.malicious_count > 0

    @property
    def detection_ratio(self) -> float:
        if self.total_count <= 0:
            return 0.0
        return self.malicious_count / self.total_count

    @property
    def is_success(self) -> bool:
        return self.error is None


@runtime_checkable
class IntelProvider(Protocol):
    """
    Protocol untuk provider threat intel.
    """

    def name(self) -> str:
        ...

    def is_available(self) -> bool:
        """True kalau provider siap dipakai (API key ada, dsb.)."""
        ...

    def lookup(self, indicator: Indicator) -> IntelResult:
        """
        Query provider untuk satu indicator.

        Raise hanya untuk error fatal; provider sebaiknya return
        IntelResult dengan error field terisi.
        """
        ...


def extract_indicators(event: Event) -> list[Indicator]:
    """
    Ekstrak indicator dari satu Event.

    Sumber:
    - process.hashes (hash)
    - file.hashes (hash)
    - network.source_ip / destination_ip (ip)
    - dns.query (domain)
    - network.url (url)

    Tidak melakukan deduplication di sini; caller yang menangani.
    """
    out: list[Indicator] = []

    # Hash dari process
    if event.process and event.process.hashes:
        for algo, value in event.process.hashes.items():
            if value:
                out.append(Indicator(
                    type=IndicatorType.HASH,
                    value=str(value).lower(),
                    source=f"process.hashes.{algo}",
                ))

    # Hash dari file
    if event.file and event.file.hashes:
        for algo, value in event.file.hashes.items():
            if value:
                out.append(Indicator(
                    type=IndicatorType.HASH,
                    value=str(value).lower(),
                    source=f"file.hashes.{algo}",
                ))

    # Network
    if event.network:
        if event.network.source_ip:
            out.append(Indicator(
                type=IndicatorType.IP,
                value=str(event.network.source_ip),
                source="network.source_ip",
            ))
        if event.network.destination_ip:
            out.append(Indicator(
                type=IndicatorType.IP,
                value=str(event.network.destination_ip),
                source="network.destination_ip",
            ))
        if event.network.url:
            out.append(Indicator(
                type=IndicatorType.URL,
                value=str(event.network.url),
                source="network.url",
            ))

    # DNS
    if event.dns and event.dns.query:
        out.append(Indicator(
            type=IndicatorType.DOMAIN,
            value=str(event.dns.query).lower().rstrip("."),
            source="dns.query",
        ))

    return out


__all__ = [
    "Indicator",
    "IndicatorType",
    "IntelResult",
    "IntelProvider",
    "extract_indicators",
]
