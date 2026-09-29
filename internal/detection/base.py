"""
Base abstractions untuk detection layer.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from pkg.models.event import Event


class Severity(int, Enum):
    """Severity level untuk finding."""
    INFO = 10
    LOW = 30
    MEDIUM = 50
    HIGH = 70
    CRITICAL = 90


@dataclass
class DetectionFinding:
    """
    Hasil deteksi satu rule terhadap satu event.

    Attributes:
    - rule_id         : unique rule identifier
    - rule_name       : human-readable name
    - severity        : Severity (int enum)
    - event_id        : event yang memicu
    - description     : penjelasan singkat
    - mitre_techniques: list teknik yang di-map
    - matched_fields  : detail field yang match (opsional)
    - metadata        : data tambahan
    """

    rule_id: str
    rule_name: str
    severity: Severity
    event_id: str
    description: str = ""
    mitre_techniques: list[str] = field(default_factory=list)
    matched_fields: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_score(self) -> int:
        return int(self.severity)


@runtime_checkable
class DetectionRule(Protocol):
    """
    Protocol rule.

    Implementasi memeriksa satu event dan mengembalikan finding
    (0..N) kalau ada match.
    """

    def id(self) -> str:
        ...

    def name(self) -> str:
        ...

    def evaluate(self, event: Event) -> list[DetectionFinding]:
        ...


__all__ = [
    "Severity",
    "DetectionFinding",
    "DetectionRule",
]
