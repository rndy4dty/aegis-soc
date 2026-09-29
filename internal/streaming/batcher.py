"""
Event batcher: group events dalam window waktu sebelum investigation.

Logic flush (yang mana duluan tercapai):
1. WINDOW   : event pertama di batch sudah lewat `window_seconds`
2. IDLE     : tidak ada event baru selama `idle_seconds`
3. MAX_SIZE : batch sudah mencapai `max_batch_size`

Grouping opsional (group_by):
- None        : satu batch untuk semua event
- "tenant_id" : satu batch per tenant
- "host"      : satu batch per host

Batcher pure-Python: tidak butuh Redis, deterministic, mudah di-test.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from pkg.models.event import Event


# ===========================================================================
# Config & state
# ===========================================================================

@dataclass
class BatcherConfig:
    window_seconds: int = 30
    idle_seconds: int = 5
    max_batch_size: int = 100

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        if self.idle_seconds <= 0:
            raise ValueError("idle_seconds must be > 0")
        if self.max_batch_size <= 0:
            raise ValueError("max_batch_size must be > 0")


@dataclass
class _BatchState:
    """State internal satu batch."""
    events: list[Event] = field(default_factory=list)
    first_at: datetime | None = None
    last_at: datetime | None = None


# ===========================================================================
# Grouping helpers
# ===========================================================================

def _default_group_key(event: Event) -> str:
    """Default: satu batch untuk semua."""
    return "__all__"


def _make_grouper(field_name: str) -> Callable[[Event], str]:
    """Return fungsi group key dari event attribute."""
    if field_name == "tenant_id":
        return lambda e: str(getattr(e, "tenant_id", None) or "__no_tenant__")
    if field_name == "host":
        return lambda e: str(getattr(e, "host", None) or "__no_host__")
    raise ValueError(
        f"unsupported group_by: {field_name!r} "
        f"(use None, 'tenant_id', or 'host')"
    )


# ===========================================================================
# EventBatcher
# ===========================================================================

class EventBatcher:
    """
    Accumulate events, flush dalam batch siap investigate.
    """

    def __init__(
        self,
        *,
        window_seconds: int = 30,
        idle_seconds: int = 5,
        max_batch_size: int = 100,
        group_by: str | None = None,
    ) -> None:
        self.config = BatcherConfig(
            window_seconds=window_seconds,
            idle_seconds=idle_seconds,
            max_batch_size=max_batch_size,
        )
        self.group_by = group_by

        if group_by is None:
            self._grouper = _default_group_key
        else:
            self._grouper = _make_grouper(group_by)

        self._batches: dict[str, _BatchState] = {}

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def group_count(self) -> int:
        return len(self._batches)

    @property
    def event_count(self) -> int:
        return sum(len(s.events) for s in self._batches.values())

    def is_empty(self) -> bool:
        return self.event_count == 0

    def pending_groups(self) -> list[str]:
        return sorted(self._batches.keys())

    # ------------------------------------------------------------------
    # Add
    # ------------------------------------------------------------------

    def add(
        self,
        event: Event,
        *,
        now: datetime | None = None,
    ) -> None:
        """Tambah event ke batch yang sesuai."""
        ts = _normalize_now(now)
        key = self._grouper(event)

        state = self._batches.get(key)
        if state is None:
            state = _BatchState(first_at=ts)
            self._batches[key] = state

        state.events.append(event)
        state.last_at = ts

    def add_many(
        self,
        events: list[Event],
        *,
        now: datetime | None = None,
    ) -> None:
        for ev in events:
            self.add(ev, now=now)

    # ------------------------------------------------------------------
    # Flush
    # ------------------------------------------------------------------

    def flush_ready(
        self,
        *,
        now: datetime | None = None,
    ) -> list[list[Event]]:
        """
        Return batch yang sudah ready untuk di-investigate.

        Batch yang di-flush akan dihapus dari state.
        """
        ts = _normalize_now(now)
        ready_keys: list[str] = []

        for key, state in self._batches.items():
            if self._should_flush(state, ts):
                ready_keys.append(key)

        batches: list[list[Event]] = []
        for key in ready_keys:
            state = self._batches.pop(key)
            if state.events:
                batches.append(state.events)

        return batches

    def flush_all(self) -> list[list[Event]]:
        """Force flush semua batch. Berguna saat shutdown."""
        batches: list[list[Event]] = []
        for state in self._batches.values():
            if state.events:
                batches.append(state.events)
        self._batches.clear()
        return batches

    def flush_group(self, key: str) -> list[Event]:
        """Force flush batch dengan key tertentu."""
        state = self._batches.pop(key, None)
        if state is None or not state.events:
            return []
        return state.events

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _should_flush(self, state: _BatchState, now: datetime) -> bool:
        if not state.events:
            return False

        # 1. Max size
        if len(state.events) >= self.config.max_batch_size:
            return True

        # 2. Window
        if state.first_at is not None:
            age = (now - state.first_at).total_seconds()
            if age >= self.config.window_seconds:
                return True

        # 3. Idle
        if state.last_at is not None:
            idle = (now - state.last_at).total_seconds()
            if idle >= self.config.idle_seconds:
                return True

        return False


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def _normalize_now(now: datetime | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    if now.tzinfo is None:
        return now.replace(tzinfo=timezone.utc)
    return now.astimezone(timezone.utc)


__all__ = [
    "EventBatcher",
    "BatcherConfig",
]
