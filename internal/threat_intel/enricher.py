"""
ThreatIntelEnricher: orkestrasi enrichment dari beberapa provider.
"""

from __future__ import annotations

from typing import Iterable

from internal.threat_intel.base import (
    Indicator,
    IntelProvider,
    IntelResult,
    extract_indicators,
)
from pkg.models.event import Event


class ThreatIntelEnricher:
    """
    Enrich indicator dari event dengan query ke provider.

    Deterministic. Provider yang tidak available di-skip.
    """

    def __init__(
        self,
        providers: list[IntelProvider] | None = None,
    ) -> None:
        self._providers = list(providers or [])

    # ------------------------------------------------------------------

    def available_providers(self) -> list[str]:
        return [p.name() for p in self._providers if p.is_available()]

    def all_providers(self) -> list[str]:
        return [p.name() for p in self._providers]

    def has_available(self) -> bool:
        return any(p.is_available() for p in self._providers)

    # ------------------------------------------------------------------

    def enrich_indicator(
        self, indicator: Indicator
    ) -> list[IntelResult]:
        """
        Query semua provider yang available untuk satu indicator.
        """
        results: list[IntelResult] = []
        for p in self._providers:
            if not p.is_available():
                continue
            try:
                result = p.lookup(indicator)
            except Exception as exc:  # noqa: BLE001
                result = IntelResult(
                    indicator=indicator,
                    provider=p.name(),
                    error=str(exc),
                )
            results.append(result)
        return results

    def enrich_event(
        self, event: Event
    ) -> dict[str, list[IntelResult]]:
        """
        Extract indicator dari event dan query tiap provider.

        Return dict: indicator_value → list[IntelResult].
        """
        indicators = self._dedup(extract_indicators(event))
        out: dict[str, list[IntelResult]] = {}
        for ind in indicators:
            results = self.enrich_indicator(ind)
            if results:
                out[ind.value] = results
        return out

    def enrich_events(
        self, events: list[Event]
    ) -> dict[str, list[IntelResult]]:
        """
        Enrich banyak event, merge hasilnya (dedup indicator).
        """
        merged: dict[str, list[IntelResult]] = {}
        for ev in events:
            for value, results in self.enrich_event(ev).items():
                if value not in merged:
                    merged[value] = results
                else:
                    # Merge results tanpa duplikat (provider sama)
                    existing_providers = {
                        r.provider for r in merged[value]
                    }
                    for r in results:
                        if r.provider not in existing_providers:
                            merged[value].append(r)
        return merged

    # ------------------------------------------------------------------

    @staticmethod
    def _dedup(indicators: Iterable[Indicator]) -> list[Indicator]:
        seen: set[tuple[str, str]] = set()
        out: list[Indicator] = []
        for ind in indicators:
            key = (ind.type.value, ind.value)
            if key in seen:
                continue
            seen.add(key)
            out.append(ind)
        return out

    # ------------------------------------------------------------------

    def summary(
        self, results: dict[str, list[IntelResult]]
    ) -> dict:
        """
        Ringkasan hasil enrichment.
        """
        malicious = 0
        suspicious = 0
        clean = 0
        errors = 0

        for value, res_list in results.items():
            for r in res_list:
                if r.error:
                    errors += 1
                elif r.malicious_count > 0:
                    malicious += 1
                elif r.found:
                    suspicious += 1
                else:
                    clean += 1

        return {
            "indicator_count": len(results),
            "malicious": malicious,
            "suspicious": suspicious,
            "clean": clean,
            "errors": errors,
        }


__all__ = ["ThreatIntelEnricher"]
