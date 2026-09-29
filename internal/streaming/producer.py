"""
Event Producer: baca events dari file/sumber dan publish ke Redis Stream.

Supported input formats (auto-detect):
- Canonical Event (list atau {"events": [...]})
- Wazuh alert
- Sysmon event
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from internal.streaming.bus import StreamBus, get_bus
from pkg.models.event import Event


DEFAULT_STREAM = "aegis.alerts"


class EventProducer:
    """Publish Event ke Redis Stream."""

    def __init__(
        self,
        *,
        bus: StreamBus | None = None,
        stream: str = DEFAULT_STREAM,
    ) -> None:
        self._bus = bus or get_bus()
        self._stream = stream

    @property
    def stream(self) -> str:
        return self._stream

    @property
    def bus(self) -> StreamBus:
        return self._bus

    # ------------------------------------------------------------------
    # Publish
    # ------------------------------------------------------------------

    def publish_event(self, event: Event) -> str:
        """Publish single Event. Return message_id."""
        payload = event.model_dump(mode="json")
        return self._bus.publish(self._stream, payload)

    def publish_events(self, events: list[Event]) -> int:
        """Publish many events. Return count."""
        count = 0
        for ev in events:
            self.publish_event(ev)
            count += 1
        return count

    def publish_from_file(self, path: str | Path) -> int:
        """Read + convert + publish. Return count."""
        events = load_events_from_file(Path(path))
        return self.publish_events(events)


# ----------------------------------------------------------------------
# Loader: auto-detect format
# ----------------------------------------------------------------------

def _looks_like_wazuh_alert(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    if "rule" in item and ("agent" in item or "manager" in item):
        return True
    if "rule" in item and "id" in item and "timestamp" in item:
        return True
    return False


def _looks_like_sysmon_event(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    if "EventID" in item and ("UtcTime" in item or "Image" in item):
        return True
    return False


def _looks_like_canonical_event(item: dict) -> bool:
    if not isinstance(item, dict):
        return False
    return (
        "event_id" in item
        and "source" in item
        and "event_type" in item
    )


def load_events_from_file(path: Path) -> list[Event]:
    """
    Baca file, auto-detect format, return list[Event].

    Raise FileNotFoundError kalau file tidak ada.
    Raise ValueError kalau format tidak dikenali.
    """
    if not path.exists():
        raise FileNotFoundError(f"file not found: {path}")

    text = path.read_text(encoding="utf-8")
    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg}") from exc

    if isinstance(data, dict):
        if "events" in data:
            data = data["events"]
        else:
            data = [data]

    if not isinstance(data, list):
        raise ValueError("payload must be list or {'events': [...]}")

    if not data:
        return []

    first = data[0]
    if not isinstance(first, dict):
        raise ValueError("event at index 0 is not object")

    if _looks_like_canonical_event(first):
        return [Event.model_validate(item) for item in data]

    if _looks_like_wazuh_alert(first):
        from internal.collector import WazuhCollector
        return WazuhCollector(data).collect().events

    if _looks_like_sysmon_event(first):
        from internal.collector import SysmonCollector
        return SysmonCollector(data).collect().events

    raise ValueError(
        f"unrecognized event format. Keys: {sorted(first.keys())}"
    )


__all__ = [
    "EventProducer",
    "load_events_from_file",
    "DEFAULT_STREAM",
]
