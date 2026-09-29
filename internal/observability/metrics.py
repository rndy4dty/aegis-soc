"""
Metrics collection (Prometheus-compatible format).

Tidak butuh dependency eksternal. Format output kompatibel
dengan Prometheus text exposition format.
"""

from __future__ import annotations

import threading
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any


# ===========================================================================
# Metric primitives
# ===========================================================================

@dataclass
class Counter:
    """
    Monotonically increasing counter.
    """
    name: str
    help: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    _value: float = 0.0

    def inc(self, amount: float = 1.0) -> None:
        if amount < 0:
            raise ValueError("counter cannot decrease")
        self._value += amount

    @property
    def value(self) -> float:
        return self._value

    def reset(self) -> None:
        self._value = 0.0


@dataclass
class Gauge:
    """
    Value that can go up and down.
    """
    name: str
    help: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    _value: float = 0.0

    def set(self, value: float) -> None:
        self._value = value

    def inc(self, amount: float = 1.0) -> None:
        self._value += amount

    def dec(self, amount: float = 1.0) -> None:
        self._value -= amount

    @property
    def value(self) -> float:
        return self._value


@dataclass
class Histogram:
    """
    Distribution of values with buckets.
    """
    name: str
    help: str = ""
    labels: dict[str, str] = field(default_factory=dict)
    buckets: tuple[float, ...] = (
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
        0.5, 1.0, 2.5, 5.0, 10.0,
    )
    _counts: list[int] = field(default_factory=list)
    _sum: float = 0.0
    _count: int = 0

    def __post_init__(self) -> None:
        if not self._counts:
            self._counts = [0] * (len(self.buckets) + 1)

    def observe(self, value: float) -> None:
        self._sum += value
        self._count += 1
        for i, bound in enumerate(self.buckets):
            if value <= bound:
                self._counts[i] += 1
                return
        self._counts[-1] += 1

    @property
    def count(self) -> int:
        return self._count

    @property
    def sum(self) -> float:
        return self._sum

    def bucket_counts(self) -> list[tuple[float, int]]:
        return list(zip(self.buckets, self._counts))


# ===========================================================================
# Registry
# ===========================================================================

class MetricsRegistry:
    """
    Thread-safe registry.
    """

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._counters: dict[tuple, Counter] = {}
        self._gauges: dict[tuple, Gauge] = {}
        self._histograms: dict[tuple, Histogram] = {}

    # ------------------------------------------------------------------

    def counter(
        self,
        name: str,
        *,
        help: str = "",
        labels: dict[str, str] | None = None,
    ) -> Counter:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            if key not in self._counters:
                self._counters[key] = Counter(
                    name=name, help=help, labels=labels or {},
                )
            return self._counters[key]

    def gauge(
        self,
        name: str,
        *,
        help: str = "",
        labels: dict[str, str] | None = None,
    ) -> Gauge:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            if key not in self._gauges:
                self._gauges[key] = Gauge(
                    name=name, help=help, labels=labels or {},
                )
            return self._gauges[key]

    def histogram(
        self,
        name: str,
        *,
        help: str = "",
        labels: dict[str, str] | None = None,
        buckets: tuple[float, ...] | None = None,
    ) -> Histogram:
        key = (name, tuple(sorted((labels or {}).items())))
        with self._lock:
            if key not in self._histograms:
                kwargs: dict[str, Any] = {
                    "name": name,
                    "help": help,
                    "labels": labels or {},
                }
                if buckets is not None:
                    kwargs["buckets"] = buckets
                self._histograms[key] = Histogram(**kwargs)
            return self._histograms[key]

    # ------------------------------------------------------------------

    def render(self) -> str:
        """
        Render dalam Prometheus text exposition format.
        """
        lines: list[str] = []

        with self._lock:
            # Counters
            for (name, _), counter in sorted(
                self._counters.items(),
                key=lambda x: x[0][0],
            ):
                if counter.help:
                    lines.append(f"# HELP {name} {counter.help}")
                lines.append(f"# TYPE {name} counter")
                labels = _format_labels(counter.labels)
                lines.append(f"{name}{labels} {counter.value}")

            # Gauges
            for (name, _), gauge in sorted(
                self._gauges.items(),
                key=lambda x: x[0][0],
            ):
                if gauge.help:
                    lines.append(f"# HELP {name} {gauge.help}")
                lines.append(f"# TYPE {name} gauge")
                labels = _format_labels(gauge.labels)
                lines.append(f"{name}{labels} {gauge.value}")

            # Histograms
            for (name, _), hist in sorted(
                self._histograms.items(),
                key=lambda x: x[0][0],
            ):
                if hist.help:
                    lines.append(f"# HELP {name} {hist.help}")
                lines.append(f"# TYPE {name} histogram")
                cumulative = 0
                for bound, count in hist.bucket_counts():
                    cumulative += count
                    labels = _format_labels(
                        hist.labels,
                        extra={"le": str(bound)},
                    )
                    lines.append(
                        f"{name}_bucket{labels} {cumulative}"
                    )
                # +Inf bucket
                labels = _format_labels(
                    hist.labels, extra={"le": "+Inf"},
                )
                lines.append(
                    f"{name}_bucket{labels} {hist.count}"
                )
                base = _format_labels(hist.labels)
                lines.append(f"{name}_sum{base} {hist.sum}")
                lines.append(f"{name}_count{base} {hist.count}")

        return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters.clear()
            self._gauges.clear()
            self._histograms.clear()


def _format_labels(
    labels: dict[str, str],
    *,
    extra: dict[str, str] | None = None,
) -> str:
    merged = dict(labels)
    if extra:
        merged.update(extra)
    if not merged:
        return ""
    parts = [
        f'{k}="{_escape(v)}"'
        for k, v in sorted(merged.items())
    ]
    return "{" + ",".join(parts) + "}"


def _escape(value: str) -> str:
    return (
        value.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
    )


# ===========================================================================
# Global registry
# ===========================================================================

_GLOBAL = MetricsRegistry()


def get_registry() -> MetricsRegistry:
    return _GLOBAL


__all__ = [
    "Counter",
    "Gauge",
    "Histogram",
    "MetricsRegistry",
    "get_registry",
]
