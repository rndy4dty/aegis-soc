"""
Contract tests untuk Redis Streams bus.

Skip otomatis kalau Redis tidak tersedia.
"""

from __future__ import annotations

from uuid import uuid4

import pytest

from internal.streaming import (
    StreamBus,
    StreamMessage,
    get_bus,
    reset_bus,
)


def _redis_available() -> bool:
    try:
        bus = StreamBus(url="redis://localhost:6379/15")
        return bus.is_available()
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _redis_available(),
    reason="Redis not available. Start with: docker compose up -d redis",
)


@pytest.fixture
def bus():
    reset_bus()
    b = StreamBus(url="redis://localhost:6379/15")
    b.client.flushdb()
    yield b
    b.client.flushdb()
    reset_bus()


@pytest.fixture
def stream_name() -> str:
    return f"test-stream-{uuid4().hex[:8]}"


# ===========================================================================
# Health
# ===========================================================================

def test_bus_is_available(bus):
    assert bus.is_available() is True


def test_bus_url(bus):
    assert "redis" in bus.url


# ===========================================================================
# Publish
# ===========================================================================

def test_publish_returns_message_id(bus, stream_name):
    msg_id = bus.publish(stream_name, {"event_id": "E-1"})
    assert isinstance(msg_id, str)
    assert "-" in msg_id


def test_publish_increases_stream_length(bus, stream_name):
    assert bus.stream_length(stream_name) == 0
    bus.publish(stream_name, {"event_id": "E-1"})
    bus.publish(stream_name, {"event_id": "E-2"})
    assert bus.stream_length(stream_name) == 2


def test_publish_handles_complex_values(bus, stream_name):
    bus.publish(stream_name, {
        "event_id": "E-1",
        "tags": ["soc", "critical"],
        "process": {"name": "x", "pid": 1},
        "severity": 85,
        "active": True,
    })
    assert bus.stream_length(stream_name) == 1


# ===========================================================================
# Consumer groups
# ===========================================================================

def test_ensure_group_creates_group(bus, stream_name):
    bus.ensure_group(stream_name, "investigators")


def test_ensure_group_idempotent(bus, stream_name):
    bus.ensure_group(stream_name, "investigators")
    bus.ensure_group(stream_name, "investigators")


def test_consume_empty_returns_empty(bus, stream_name):
    bus.ensure_group(stream_name, "g1")
    messages = bus.consume(
        stream_name, "g1", "worker-1", block_ms=100
    )
    assert messages == []


def test_consume_returns_published_messages(bus, stream_name):
    bus.publish(stream_name, {"event_id": "E-1"})
    bus.publish(stream_name, {"event_id": "E-2"})
    bus.ensure_group(stream_name, "g1", start_id="0")

    messages = bus.consume(
        stream_name, "g1", "worker-1", block_ms=100
    )
    assert len(messages) == 2
    assert all(isinstance(m, StreamMessage) for m in messages)
    assert messages[0].data["event_id"] == "E-1"


def test_ack_removes_from_pending(bus, stream_name):
    bus.publish(stream_name, {"event_id": "E-1"})
    bus.ensure_group(stream_name, "g1", start_id="0")

    messages = bus.consume(
        stream_name, "g1", "w1", block_ms=100
    )
    assert len(messages) == 1
    assert bus.pending_count(stream_name, "g1") == 1

    acked = bus.ack(
        stream_name, "g1", messages[0].message_id
    )
    assert acked == 1
    assert bus.pending_count(stream_name, "g1") == 0


def test_multiple_consumers_share_load(bus, stream_name):
    for i in range(4):
        bus.publish(stream_name, {"event_id": f"E-{i}"})

    bus.ensure_group(stream_name, "g1", start_id="0")

    w1 = bus.consume(
        stream_name, "g1", "w1", count=2, block_ms=100
    )
    w2 = bus.consume(
        stream_name, "g1", "w2", count=10, block_ms=100
    )

    assert len(w1) == 2
    assert len(w2) == 2
    ids = {m.message_id for m in w1 + w2}
    assert len(ids) == 4


# ===========================================================================
# Monitoring
# ===========================================================================

def test_stream_length(bus, stream_name):
    assert bus.stream_length(stream_name) == 0
    for i in range(5):
        bus.publish(stream_name, {"event_id": f"E-{i}"})
    assert bus.stream_length(stream_name) == 5


def test_delete_stream(bus, stream_name):
    bus.publish(stream_name, {"event_id": "E-1"})
    assert bus.stream_length(stream_name) == 1
    bus.delete_stream(stream_name)
    assert bus.stream_length(stream_name) == 0
