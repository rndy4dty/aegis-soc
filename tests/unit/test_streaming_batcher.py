"""
Contract tests untuk EventBatcher.

Pure logic: tidak butuh Redis.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from internal.streaming import BatcherConfig, EventBatcher
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
)


BASE = datetime(2026, 9, 26, 10, 0, tzinfo=timezone.utc)


def make_event(
    event_id: str = "E-1",
    *,
    host: str = "WIN-01",
    tenant_id: str | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE,
        source=EventSource.SYSMON,
        platform=Platform.WINDOWS,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=85,
        host=host,
        tenant_id=tenant_id,
    )


# ===========================================================================
# Config validation
# ===========================================================================

def test_config_defaults():
    cfg = BatcherConfig()
    assert cfg.window_seconds == 30
    assert cfg.idle_seconds == 5
    assert cfg.max_batch_size == 100


def test_config_rejects_invalid():
    with pytest.raises(ValueError):
        BatcherConfig(window_seconds=0)
    with pytest.raises(ValueError):
        BatcherConfig(idle_seconds=-1)
    with pytest.raises(ValueError):
        BatcherConfig(max_batch_size=0)


# ===========================================================================
# Basic add
# ===========================================================================

def test_empty_batcher():
    b = EventBatcher()
    assert b.is_empty()
    assert b.event_count == 0
    assert b.group_count == 0


def test_add_single_event():
    b = EventBatcher()
    b.add(make_event(), now=BASE)
    assert b.event_count == 1
    assert b.group_count == 1


def test_add_many_events():
    b = EventBatcher()
    b.add_many(
        [make_event(f"E-{i}") for i in range(5)],
        now=BASE,
    )
    assert b.event_count == 5


# ===========================================================================
# Flush: max size
# ===========================================================================

def test_flush_on_max_size():
    b = EventBatcher(max_batch_size=3, window_seconds=999, idle_seconds=999)
    b.add_many([make_event(f"E-{i}") for i in range(3)], now=BASE)

    batches = b.flush_ready(now=BASE)
    assert len(batches) == 1
    assert len(batches[0]) == 3
    assert b.event_count == 0


def test_no_flush_below_max_size():
    b = EventBatcher(max_batch_size=5, window_seconds=999, idle_seconds=999)
    b.add_many([make_event(f"E-{i}") for i in range(3)], now=BASE)

    batches = b.flush_ready(now=BASE)
    assert batches == []
    assert b.event_count == 3


# ===========================================================================
# Flush: window
# ===========================================================================

def test_flush_on_window_elapsed():
    b = EventBatcher(window_seconds=30, idle_seconds=999, max_batch_size=999)
    b.add(make_event(), now=BASE)

    # 15 detik: belum flush
    batches = b.flush_ready(now=BASE + timedelta(seconds=15))
    assert batches == []

    # 35 detik: sudah flush
    batches = b.flush_ready(now=BASE + timedelta(seconds=35))
    assert len(batches) == 1
    assert b.event_count == 0


def test_window_uses_first_event_time():
    b = EventBatcher(window_seconds=30, idle_seconds=999, max_batch_size=999)
    b.add(make_event("E-1"), now=BASE)

    # Event kedua masuk 20 detik kemudian (batch age = 20s)
    b.add(make_event("E-2"), now=BASE + timedelta(seconds=20))

    # 25 detik dari event pertama: belum flush (age = 25s)
    batches = b.flush_ready(now=BASE + timedelta(seconds=25))
    assert batches == []

    # 31 detik dari event pertama: flush (age = 31s)
    batches = b.flush_ready(now=BASE + timedelta(seconds=31))
    assert len(batches) == 1
    assert len(batches[0]) == 2


# ===========================================================================
# Flush: idle
# ===========================================================================

def test_flush_on_idle():
    b = EventBatcher(window_seconds=999, idle_seconds=5, max_batch_size=999)
    b.add(make_event(), now=BASE)

    # 3 detik: belum idle
    batches = b.flush_ready(now=BASE + timedelta(seconds=3))
    assert batches == []

    # 6 detik: idle tercapai
    batches = b.flush_ready(now=BASE + timedelta(seconds=6))
    assert len(batches) == 1


def test_idle_resets_on_new_event():
    b = EventBatcher(window_seconds=999, idle_seconds=5, max_batch_size=999)
    b.add(make_event("E-1"), now=BASE)

    # Event baru masuk setelah 3 detik -> idle counter reset
    b.add(make_event("E-2"), now=BASE + timedelta(seconds=3))

    # Cek 6 detik dari event pertama (3 detik dari event kedua): belum flush
    batches = b.flush_ready(now=BASE + timedelta(seconds=6))
    assert batches == []

    # Cek 9 detik dari event pertama (6 detik dari event kedua): flush
    batches = b.flush_ready(now=BASE + timedelta(seconds=9))
    assert len(batches) == 1


# ===========================================================================
# Grouping
# ===========================================================================

def test_group_by_host():
    b = EventBatcher(
        group_by="host",
        max_batch_size=999, window_seconds=999, idle_seconds=999,
    )
    b.add(make_event("E-1", host="WIN-01"), now=BASE)
    b.add(make_event("E-2", host="WIN-02"), now=BASE)
    b.add(make_event("E-3", host="WIN-01"), now=BASE)

    assert b.group_count == 2
    assert b.event_count == 3


def test_group_by_host_flush_separate():
    b = EventBatcher(
        group_by="host",
        max_batch_size=2, window_seconds=999, idle_seconds=999,
    )
    b.add(make_event("E-1", host="WIN-01"), now=BASE)
    b.add(make_event("E-2", host="WIN-02"), now=BASE)
    b.add(make_event("E-3", host="WIN-01"), now=BASE)

    batches = b.flush_ready(now=BASE)
    # WIN-01 punya 2 events -> flush
    # WIN-02 punya 1 event -> belum
    assert len(batches) == 1
    assert len(batches[0]) == 2
    assert all(e.host == "WIN-01" for e in batches[0])
    assert b.event_count == 1


def test_group_by_tenant():
    b = EventBatcher(
        group_by="tenant_id",
        max_batch_size=999, window_seconds=999, idle_seconds=999,
    )
    b.add(make_event("E-1", tenant_id="acme"), now=BASE)
    b.add(make_event("E-2", tenant_id="other"), now=BASE)
    b.add(make_event("E-3", tenant_id="acme"), now=BASE)

    assert b.group_count == 2


def test_group_by_invalid_field():
    with pytest.raises(ValueError, match="unsupported group_by"):
        EventBatcher(group_by="invalid_field")


# ===========================================================================
# Flush all / flush group
# ===========================================================================

def test_flush_all():
    b = EventBatcher(
        group_by="host",
        max_batch_size=999, window_seconds=999, idle_seconds=999,
    )
    b.add(make_event("E-1", host="WIN-01"), now=BASE)
    b.add(make_event("E-2", host="WIN-02"), now=BASE)

    batches = b.flush_all()
    assert len(batches) == 2
    assert b.event_count == 0


def test_flush_group():
    b = EventBatcher(
        group_by="host",
        max_batch_size=999, window_seconds=999, idle_seconds=999,
    )
    b.add(make_event("E-1", host="WIN-01"), now=BASE)
    b.add(make_event("E-2", host="WIN-02"), now=BASE)

    events = b.flush_group("WIN-01")
    assert len(events) == 1
    assert events[0].host == "WIN-01"
    assert b.event_count == 1
    assert b.group_count == 1


def test_flush_group_nonexistent():
    b = EventBatcher()
    assert b.flush_group("nonexistent") == []


# ===========================================================================
# Deterministic (no `now` arg)
# ===========================================================================

def test_add_without_now_uses_utcnow():
    b = EventBatcher()
    b.add(make_event())
    assert b.event_count == 1


def test_now_naive_datetime_treated_as_utc():
    b = EventBatcher()
    naive = datetime(2026, 9, 26, 10, 0)
    b.add(make_event(), now=naive)
    assert b.event_count == 1
