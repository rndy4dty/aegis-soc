"""
Base abstractions untuk notification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Protocol, runtime_checkable

from internal.investigation.investigation_engine import (
    InvestigationResult,
)


class NotificationLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class NotificationResult:
    """Hasil satu percobaan notifikasi."""
    channel: str
    success: bool
    level: NotificationLevel
    error: str | None = None
    timestamp: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )


@runtime_checkable
class Notifier(Protocol):
    """Protocol untuk semua notifier."""

    def name(self) -> str:
        ...

    def is_available(self) -> bool:
        ...

    def send(
        self,
        result: InvestigationResult,
        *,
        level: NotificationLevel,
        message: str | None = None,
    ) -> NotificationResult:
        ...


# ===========================================================================
# Formatting helper
# ===========================================================================

def format_investigation(
    result: InvestigationResult,
    *,
    level: NotificationLevel,
) -> dict[str, Any]:
    """
    Format InvestigationResult menjadi dict siap kirim.
    """
    case = result.case
    emoji = {
        NotificationLevel.INFO: ":information_source:",
        NotificationLevel.WARNING: ":warning:",
        NotificationLevel.CRITICAL: ":rotating_light:",
    }.get(level, ":bell:")

    return {
        "emoji": emoji,
        "level": level.value,
        "case_id": case.case_id,
        "title": case.title,
        "status": case.status.value,
        "priority": case.priority.value,
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "evidence_count": result.evidence_count,
        "hypothesis_count": result.hypothesis_count,
        "top_hypotheses": [
            h.statement for h in result.hypotheses[:3]
        ],
    }


def render_text(
    payload: dict[str, Any],
    *,
    message: str | None = None,
) -> str:
    """
    Render payload menjadi plain text.
    """
    lines: list[str] = []
    if message:
        lines.append(message)
        lines.append("")

    lines.append(
        f"{payload['emoji']} [{payload['level'].upper()}] "
        f"{payload['title']}"
    )
    lines.append(f"Case: {payload['case_id']}")
    lines.append(
        f"Risk: {payload['risk_score']}/100 "
        f"(confidence {payload['confidence']:.2f})"
    )
    lines.append(
        f"Priority: {payload['priority']} | "
        f"Status: {payload['status']}"
    )
    lines.append(
        f"Evidence: {payload['evidence_count']} | "
        f"Hypotheses: {payload['hypothesis_count']}"
    )

    if payload["top_hypotheses"]:
        lines.append("")
        lines.append("Top hypotheses:")
        for h in payload["top_hypotheses"]:
            lines.append(f"  - {h}")

    return "\n".join(lines)


__all__ = [
    "Notifier",
    "NotificationLevel",
    "NotificationResult",
    "format_investigation",
    "render_text",
]
