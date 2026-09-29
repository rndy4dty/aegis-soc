"""
Redis Streams bus wrapper.

Usage:
    bus = StreamBus()
    bus.publish("alerts", {"event_id": "E-1"})
    msgs = bus.consume("alerts", group="g", consumer="w-1")
    bus.ack("alerts", "g", msgs[0].message_id)

Config via env:
- AEGIS_REDIS_URL : redis://localhost:6379/0
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import redis


DEFAULT_REDIS_URL = "redis://localhost:6379/0"
DEFAULT_BLOCK_MS = 1000
DEFAULT_COUNT = 10


@dataclass
class StreamMessage:
    """Satu message dari Redis Stream."""
    message_id: str
    stream: str
    data: dict[str, Any]

    def to_json(self) -> str:
        return json.dumps(self.data, default=str)


class StreamBus:
    """Wrapper untuk Redis Streams."""

    def __init__(
        self,
        *,
        url: str | None = None,
        client: redis.Redis | None = None,
    ) -> None:
        if client is not None:
            self._client = client
            self._url = "injected"
        else:
            self._url = url or os.environ.get(
                "AEGIS_REDIS_URL", DEFAULT_REDIS_URL
            )
            self._client = redis.Redis.from_url(
                self._url,
                decode_responses=True,
                socket_connect_timeout=3,
                socket_timeout=5,
            )

    # ------------------------------------------------------------------
    # Health
    # ------------------------------------------------------------------

    @property
    def url(self) -> str:
        return self._url

    @property
    def client(self) -> redis.Redis:
        return self._client

    def is_available(self) -> bool:
        try:
            return bool(self._client.ping())
        except Exception:  # noqa: BLE001
            return False

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish(
        self,
        stream: str,
        data: dict[str, Any],
        *,
        maxlen: int | None = 10_000,
    ) -> str:
        """Publish message ke stream. Return message_id."""
        flat: dict[str, str] = {}
        for key, value in data.items():
            if isinstance(value, (str, int, float, bool)) or value is None:
                flat[key] = "" if value is None else str(value)
            else:
                flat[key] = json.dumps(value, default=str)

        msg_id = self._client.xadd(
            stream,
            flat,
            maxlen=maxlen,
            approximate=True,
        )
        return str(msg_id)

    # ------------------------------------------------------------------
    # Consumer groups
    # ------------------------------------------------------------------

    def ensure_group(
        self,
        stream: str,
        group: str,
        *,
        start_id: str = "$",
    ) -> None:
        try:
            self._client.xgroup_create(
                stream, group, id=start_id, mkstream=True
            )
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    def consume(
        self,
        stream: str,
        group: str,
        consumer: str,
        *,
        count: int = DEFAULT_COUNT,
        block_ms: int = DEFAULT_BLOCK_MS,
    ) -> list[StreamMessage]:
        response = self._client.xreadgroup(
            groupname=group,
            consumername=consumer,
            streams={stream: ">"},
            count=count,
            block=block_ms,
        )

        if not response:
            return []

        messages: list[StreamMessage] = []
        for stream_name, entries in response:
            for msg_id, fields in entries:
                messages.append(
                    StreamMessage(
                        message_id=str(msg_id),
                        stream=str(stream_name),
                        data=dict(fields),
                    )
                )
        return messages

    def ack(
        self,
        stream: str,
        group: str,
        *message_ids: str,
    ) -> int:
        if not message_ids:
            return 0
        return int(
            self._client.xack(stream, group, *message_ids)
        )

    # ------------------------------------------------------------------
    # Monitoring
    # ------------------------------------------------------------------

    def stream_length(self, stream: str) -> int:
        try:
            return int(self._client.xlen(stream))
        except Exception:  # noqa: BLE001
            return 0

    def pending_count(self, stream: str, group: str) -> int:
        try:
            info = self._client.xpending(stream, group)
            return int(info["pending"])
        except Exception:  # noqa: BLE001
            return 0

    def delete_stream(self, stream: str) -> None:
        self._client.delete(stream)


# ----------------------------------------------------------------------
# Global singleton
# ----------------------------------------------------------------------

_default_bus: StreamBus | None = None


def get_bus() -> StreamBus:
    global _default_bus
    if _default_bus is None:
        _default_bus = StreamBus()
    return _default_bus


def reset_bus() -> None:
    global _default_bus
    _default_bus = None


__all__ = [
    "StreamBus",
    "StreamMessage",
    "get_bus",
    "reset_bus",
    "DEFAULT_REDIS_URL",
    "DEFAULT_BLOCK_MS",
]
