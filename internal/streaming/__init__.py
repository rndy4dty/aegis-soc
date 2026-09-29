"""
Real-time streaming ingestion.

Komponen:
- StreamBus        : Redis Streams wrapper
- EventProducer    : publish events ke stream
- EventBatcher     : group events dalam window waktu
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

__all__ = [
    "StreamBus",
    "StreamMessage",
    "EventProducer",
    "EventBatcher",
    "BatcherConfig",
    "load_events_from_file",
    "DEFAULT_STREAM",
    "get_bus",
    "reset_bus",
]
