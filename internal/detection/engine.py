"""
DetectionEngine: orkestrasi semua detection rule.
"""

from __future__ import annotations

from internal.detection.base import (
    DetectionFinding,
    DetectionRule,
)
from internal.detection.lolbin import LOLBinDetector
from internal.detection.sigma_loader import SigmaRuleLoader
from pkg.models.event import Event


class DetectionEngine:
    """
    Jalankan semua rule terhadap event.

    Deterministic. Urutan finding di-sort by
    (severity desc, rule_id, event_id).
    """

    def __init__(
        self,
        rules: list[DetectionRule] | None = None,
        *,
        sigma_loader: SigmaRuleLoader | None = None,
    ) -> None:
        self._rules: list[DetectionRule] = list(rules or [])
        self._sigma = sigma_loader

        # Default: kalau tidak ada rule, pakai LOLBin
        if not self._rules and self._sigma is None:
            self._rules = [LOLBinDetector()]

    # ------------------------------------------------------------------

    def detect(self, event: Event) -> list[DetectionFinding]:
        findings: list[DetectionFinding] = []

        for rule in self._rules:
            findings.extend(rule.evaluate(event))

        if self._sigma is not None:
            findings.extend(self._sigma.evaluate(event))

        return self._sort(findings)

    def detect_many(
        self, events: list[Event]
    ) -> list[DetectionFinding]:
        out: list[DetectionFinding] = []
        for ev in events:
            out.extend(self.detect(ev))
        return self._sort(out)

    # ------------------------------------------------------------------

    @staticmethod
    def _sort(
        findings: list[DetectionFinding],
    ) -> list[DetectionFinding]:
        return sorted(
            findings,
            key=lambda f: (
                -f.severity.value,
                f.rule_id,
                f.event_id,
            ),
        )

    # ------------------------------------------------------------------

    def stats(
        self, findings: list[DetectionFinding]
    ) -> dict:
        by_rule: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for f in findings:
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
            by_severity[f.severity.name] = (
                by_severity.get(f.severity.name, 0) + 1
            )
        return {
            "total": len(findings),
            "by_rule": by_rule,
            "by_severity": by_severity,
        }


__all__ = ["DetectionEngine"]
