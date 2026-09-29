"""
NotificationRouter: evaluasi rules + dispatch ke notifier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.notifications.base import (
    NotificationLevel,
    NotificationResult,
    Notifier,
)


@dataclass
class NotificationRule:
    """
    Rule: kalau predicate True, kirim ke level tertentu.
    """
    name: str
    predicate: Callable[[InvestigationResult], bool]
    level: NotificationLevel


def _default_rules() -> list[NotificationRule]:
    return [
        NotificationRule(
            name="critical",
            predicate=lambda r: r.risk_score >= 85,
            level=NotificationLevel.CRITICAL,
        ),
        NotificationRule(
            name="high",
            predicate=lambda r: r.risk_score >= 70,
            level=NotificationLevel.WARNING,
        ),
        NotificationRule(
            name="medium",
            predicate=lambda r: r.risk_score >= 40,
            level=NotificationLevel.INFO,
        ),
    ]


class NotificationRouter:
    """
    Evaluasi rules terhadap InvestigationResult, lalu dispatch
    ke semua notifier yang available.
    """

    def __init__(
        self,
        notifiers: list[Notifier] | None = None,
        *,
        rules: list[NotificationRule] | None = None,
    ) -> None:
        self._notifiers = list(notifiers or [])
        self._rules = list(rules) if rules is not None else _default_rules()

    # ------------------------------------------------------------------

    @property
    def notifiers(self) -> list[Notifier]:
        return list(self._notifiers)

    @property
    def rules(self) -> list[NotificationRule]:
        return list(self._rules)

    def available_notifiers(self) -> list[str]:
        return [
            n.name() for n in self._notifiers if n.is_available()
        ]

    # ------------------------------------------------------------------

    def dispatch(
        self,
        result: InvestigationResult,
        *,
        message: str | None = None,
    ) -> list[NotificationResult]:
        """
        Evaluasi rules + kirim ke notifier.

        Return list NotificationResult (satu per notifier yang dicoba).
        """
        level = self._evaluate_level(result)
        if level is None:
            return []  # tidak ada rule yang match

        results: list[NotificationResult] = []
        for notifier in self._notifiers:
            if not notifier.is_available():
                continue
            try:
                r = notifier.send(
                    result, level=level, message=message
                )
            except Exception as exc:  # noqa: BLE001
                r = NotificationResult(
                    channel=notifier.name(),
                    success=False,
                    level=level,
                    error=str(exc),
                )
            results.append(r)
        return results

    def _evaluate_level(
        self, result: InvestigationResult
    ) -> NotificationLevel | None:
        """Return level dari rule pertama yang match, else None."""
        for rule in self._rules:
            try:
                if rule.predicate(result):
                    return rule.level
            except Exception:  # noqa: BLE001
                continue
        return None


__all__ = ["NotificationRouter", "NotificationRule"]
