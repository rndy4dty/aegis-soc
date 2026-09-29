"""
Contract tests untuk StreamWorker.

Skip otomatis kalau Redis tidak tersedia.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from internal.streaming import (
    EventBatcher,
    EventProducer,
    StreamBus,
    StreamWorker,
)
from internal.storage import StorageService
from internal.storage.db import Database
from internal.storage.repositories import InvestigationRepository


def _redis_available() -> bool:
    try:
        bus = StreamBus(url="redis://localhost:6379/13")
        return bus.is_available()
    except Exception:  # noqa: BLE001
        return False


pytestmark = pytest.mark.skipif(
    not _redis_available(),
    reason="Redis not available",
)


# ===========================================================================
# Fixtures
# ===========================================================================

@pytest.fixture
def bus():
    b = StreamBus(url="redis://localhost:6379/13")
    b.client.flushdb()
    yield b
    b.client.flushdb()


@pytest.fixture
def storage(tmp_path: Path) -> StorageService:
    url = f"sqlite:///{tmp_path}/worker.db"
    db = Database(url=url, create_tables=True)
    return StorageService(db=db)


@pytest.fixture
def stream() -> str:
    return f"test-worker-{uuid4().hex[:8]}"


@pytest.fixture
def worker(bus, storage, stream) -> StreamWorker:
    batcher = EventBatcher(
        window_seconds=999,
        idle_seconds=999,
        max_batch_size=2,  # kecil supaya test cepet flush
    )
    return StreamWorker(
        bus=bus,
        storage=storage,
        batcher=batcher,
        stream=stream,
        group="g-test",
        consumer="w-test",
    )


def _events_file(tmp_path: Path) -> Path:
    import json

    path = tmp_path / "events.json"
    path.write_text(json.dumps([
        {
            "event_id": f"E-{i}",
            "timestamp": f"2026-09-26T10:00:0{i}Z",
            "source": "sysmon",
            "platform": "windows",
            "category": "process",
            "event_type": "process_creation",
            "severity": 85,
            "host": "WIN-01",
            "mitre_techniques": ["T1546.011"],
        }
        for i in range(4)
    ]), encoding="utf-8")
    return path


# ===========================================================================
# Init & setup
# ===========================================================================

def test_worker_init(worker):
    assert worker.stream.startswith("test-worker-")
    assert worker.group == "g-test"
    assert worker.consumer == "w-test"
    assert worker.stats.iterations == 0


def test_worker_ensure_group(worker):
    worker.ensure_group()
    # Tidak raise = OK


def test_worker_run_once_empty_stream(worker):
    """Tanpa event, run_once tidak crash, return 0."""
    worker.ensure_group()
    created = worker.run_once(block_ms=100)
    assert created == 0
    assert worker.stats.messages_consumed == 0


# ===========================================================================
# Process single batch
# ===========================================================================

def test_worker_investigates_batch(
    worker, bus, storage, stream, tmp_path
):
    worker.ensure_group()

    # Publish 2 events -> max_batch_size=2 -> flush on 2nd add
    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(_events_file(tmp_path))  # publish 4
    # Note: publisher uses different bus instance but same Redis

    # Consume via worker
    created = worker.run_once(block_ms=500, count=100)

    # 4 events / max_batch_size=2 -> 2 batches -> 2 investigations
    assert created >= 1
    assert worker.stats.messages_consumed == 4
    assert worker.stats.investigations_created >= 1

    # Verify saved to storage
    with storage._db.session() as session:  # noqa: SLF001
        repo = InvestigationRepository(session)
        rows = repo.list_cases()
        assert len(rows) >= 1


def test_worker_acks_messages(
    worker, bus, storage, stream, tmp_path
):
    worker.ensure_group()

    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(_events_file(tmp_path))

    worker.run_once(block_ms=500, count=100)

    # Semua message harus di-ack
    assert worker.stats.messages_acked == 4
    assert bus.pending_count(stream, "g-test") == 0


def test_worker_stats_accumulate(
    worker, bus, storage, stream, tmp_path
):
    worker.ensure_group()

    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(_events_file(tmp_path))

    worker.run_once(block_ms=500)
    worker.run_once(block_ms=100)

    assert worker.stats.iterations == 2
    assert worker.stats.messages_consumed == 4


# ===========================================================================
# Group by tenant
# ===========================================================================

def test_worker_group_by_host(bus, storage, stream, tmp_path):
    import json

    batcher = EventBatcher(
        window_seconds=999,
        idle_seconds=999,
        max_batch_size=999,
        group_by="host",
    )
    worker = StreamWorker(
        bus=bus,
        storage=storage,
        batcher=batcher,
        stream=stream,
        group="g-host",
        consumer="w-host",
    )
    worker.ensure_group()

    # Events dari dua host
    path = tmp_path / "multi-host.json"
    path.write_text(json.dumps([
        {
            "event_id": "E-1", "timestamp": "2026-09-26T10:00:00Z",
            "source": "sysmon", "platform": "windows",
            "category": "process", "event_type": "process_creation",
            "severity": 85, "host": "WIN-01",
        },
        {
            "event_id": "E-2", "timestamp": "2026-09-26T10:00:01Z",
            "source": "sysmon", "platform": "windows",
            "category": "process", "event_type": "process_creation",
            "severity": 85, "host": "WIN-02",
        },
    ]), encoding="utf-8")

    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(path)

    # Force flush all
    worker.run_once(block_ms=500)
    worker.flush_pending()

    # 2 hosts -> 2 investigations
    with storage._db.session() as session:  # noqa: SLF001
        repo = InvestigationRepository(session)
        rows = repo.list_cases()
        assert len(rows) >= 2


# ===========================================================================
# Flush pending
# ===========================================================================

def test_worker_flush_pending(bus, storage, stream, tmp_path):
    """Force-flush pending batches."""
    import json

    batcher = EventBatcher(
        window_seconds=999,
        idle_seconds=999,
        max_batch_size=100,
    )
    worker = StreamWorker(
        bus=bus,
        storage=storage,
        batcher=batcher,
        stream=stream,
        group="g-flush",
        consumer="w-flush",
    )
    worker.ensure_group()

    path = tmp_path / "three.json"
    path.write_text(json.dumps([
        {
            "event_id": f"E-{i}",
            "timestamp": f"2026-09-26T10:00:0{i}Z",
            "source": "sysmon", "platform": "windows",
            "category": "process", "event_type": "process_creation",
            "severity": 85, "host": "WIN-01",
        }
        for i in range(3)
    ]), encoding="utf-8")

    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(path)

    worker.run_once(block_ms=500)

    # 3 events sudah masuk batcher, belum auto-flush
    assert worker._batcher.event_count == 3
    assert worker.stats.batches_flushed == 0

    # Force flush
    flushed = worker.flush_pending()
    assert flushed == 1
    assert worker._batcher.event_count == 0


def test_worker_deserialize_event(worker, bus, stream, tmp_path):
    worker.ensure_group()

    producer = EventProducer(bus=bus, stream=stream)
    producer.publish_from_file(_events_file(tmp_path))

    bus.ensure_group(stream, worker.group, start_id="0")
    messages = bus.consume(stream, worker.group, "w-x", block_ms=100)
    assert len(messages) == 4

    event = worker._deserialize(messages[0])
    assert event.event_id == "E-0"
    assert event.host == "WIN-01"
    assert event.mitre_techniques == ["T1546.011"]
