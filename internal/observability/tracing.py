"""
Lightweight trace context.

Kompatibel dengan konsep OpenTelemetry (trace_id, span_id)
tanpa dependency eksternal.

Kalau opentelemetry-sdk terinstall, module ini tetap bekerja
secara independen — tidak ada conflict.
"""

from __future__ import annotations

import contextvars
import secrets
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterator


@dataclass(frozen=True)
class TraceContext:
    """
    Satu trace context.
    """
    trace_id: str
    span_id: str
    parent_span_id: str | None = None
    started_at: datetime = field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    tags: dict[str, Any] = field(default_factory=dict)

    def with_tag(self, key: str, value: Any) -> "TraceContext":
        new_tags = {**self.tags, key: value}
        return TraceContext(
            trace_id=self.trace_id,
            span_id=self.span_id,
            parent_span_id=self.parent_span_id,
            started_at=self.started_at,
            tags=new_tags,
        )


_current_trace: contextvars.ContextVar[TraceContext | None] = (
    contextvars.ContextVar("aegis_trace", default=None)
)


def _gen_id(length: int = 16) -> str:
    return secrets.token_hex(length // 2)


def get_current_trace() -> TraceContext | None:
    return _current_trace.get()


def new_trace(
    *,
    trace_id: str | None = None,
    tags: dict[str, Any] | None = None,
) -> TraceContext:
    """
    Buat trace baru. Otomatis set sebagai current.
    """
    ctx = TraceContext(
        trace_id=trace_id or _gen_id(32),
        span_id=_gen_id(16),
        tags=tags or {},
    )
    _current_trace.set(ctx)
    return ctx


@contextmanager
def trace(
    *,
    name: str,
    tags: dict[str, Any] | None = None,
) -> Iterator[TraceContext]:
    """
    Context manager untuk span.
    """
    parent = _current_trace.get()

    if parent is None:
        ctx = new_trace(tags=tags)
    else:
        ctx = TraceContext(
            trace_id=parent.trace_id,
            span_id=_gen_id(16),
            parent_span_id=parent.span_id,
            tags={**parent.tags, **(tags or {}), "span_name": name},
        )
        _current_trace.set(ctx)

    try:
        yield ctx
    finally:
        # Restore parent
        _current_trace.set(parent)


def clear() -> None:
    """Reset current trace (berguna untuk testing)."""
    _current_trace.set(None)


__all__ = [
    "TraceContext",
    "get_current_trace",
    "new_trace",
    "trace",
    "clear",
]
