"""
Real-time streaming ingestion.

Komponen:
- StreamBus        : Redis Streams wrapper
- EventProducer    : publish events ke stream
- EventBatcher     : group events dalam window waktu
- StreamWorker     : consume + investigate + save
"""

from internal.streaming.batcher import (
    BatcherConfig,
    EventBatcher,
)
from internal.streaming.bus import (
    StreamBus,
    StreamMessage,
    get_bus,
    reset_bus,
)
from internal.streaming.producer import (
    DEFAULT_STREAM,
    EventProducer,
    load_events_from_file,
)
from internal.streaming.worker import (
    DEFAULT_CONSUMER,
    DEFAULT_GROUP,
    StreamWorker,
    WorkerStats,
)

__all__ = [
    "StreamBus",
    "StreamMessage",
    "EventProducer",
    "EventBatcher",
    "BatcherConfig",
    "StreamWorker",
    "WorkerStats",
    "load_events_from_file",
    "DEFAULT_STREAM",
    "DEFAULT_GROUP",
    "DEFAULT_CONSUMER",
    "get_bus",
    "reset_bus",
]
