"""
Wazuh poller: poll alerts dari API, publish ke Redis Stream.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from internal.collector.wazuh import WazuhCollector
from internal.collector.wazuh_api import (
    WazuhAPIClient,
    WazuhAlert,
)
from internal.streaming.bus import StreamBus, get_bus
from internal.streaming.producer import DEFAULT_STREAM, EventProducer


DEFAULT_POLL_INTERVAL = 30
DEFAULT_INITIAL_LOOKBACK = 300
DEFAULT_PAGE_SIZE = 100
MAX_SEEN_IDS = 10_000


@dataclass
class PollerStats:
    iterations: int = 0
    alerts_fetched: int = 0
    alerts_published: int = 0
    alerts_skipped: int = 0
    errors: list[str] = field(default_factory=list)


class WazuhPoller:
    """Poll Wazuh API, publish alerts ke Redis Stream."""

    def __init__(
        self,
        *,
        api: WazuhAPIClient | None = None,
        bus: StreamBus | None = None,
        stream: str = DEFAULT_STREAM,
        poll_interval: int = DEFAULT_POLL_INTERVAL,
        initial_lookback: int = DEFAULT_INITIAL_LOOKBACK,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> None:
        self._api = api or WazuhAPIClient()
        self._bus = bus or get_bus()
        self._producer = EventProducer(bus=self._bus, stream=stream)
        self._poll_interval = poll_interval
        self._initial_lookback = initial_lookback
        self._page_size = page_size

        self._last_seen: datetime | None = None
        self._seen_ids: set[str] = set()
        self._seen_order: list[str] = []
        self._stats = PollerStats()
        self._stop = False

    @property
    def stats(self) -> PollerStats:
        return self._stats

    @property
    def stream(self) -> str:
        return self._producer.stream

    def stop(self) -> None:
        self._stop = True

    # ------------------------------------------------------------------
    # Dedup
    # ------------------------------------------------------------------

    def _is_seen(self, alert_id: str) -> bool:
        return alert_id in self._seen_ids

    def _mark_seen(self, alert_id: str) -> None:
        if alert_id in self._seen_ids:
            return
        self._seen_ids.add(alert_id)
        self._seen_order.append(alert_id)
        while len(self._seen_order) > MAX_SEEN_IDS:
            old = self._seen_order.pop(0)
            self._seen_ids.discard(old)

    # ------------------------------------------------------------------
    # Poll
    # ------------------------------------------------------------------

    def poll_once(self) -> int:
        self._stats.iterations += 1

        since = self._last_seen
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(
                seconds=self._initial_lookback
            )

        try:
            alerts = self._api.get_alerts(
                limit=self._page_size,
                since=since,
            )
        except Exception as exc:  # noqa: BLE001
            self._stats.errors.append(f"fetch: {exc}")
            return 0

        self._stats.alerts_fetched += len(alerts)

        alerts_sorted = sorted(
            alerts, key=lambda a: (a.timestamp, a.alert_id)
        )

        published = 0
        for alert in alerts_sorted:
            if self._is_seen(alert.alert_id):
                self._stats.alerts_skipped += 1
                continue

            try:
                event = self._convert_alert(alert)
            except Exception as exc:  # noqa: BLE001
                self._stats.errors.append(
                    f"convert {alert.alert_id}: {exc}"
                )
                self._mark_seen(alert.alert_id)
                continue

            try:
                self._producer.publish_event(event)
                published += 1
                self._stats.alerts_published += 1
            except Exception as exc:  # noqa: BLE001
                self._stats.errors.append(
                    f"publish {alert.alert_id}: {exc}"
                )

            if (
                self._last_seen is None
                or alert.timestamp > self._last_seen
            ):
                self._last_seen = alert.timestamp

            self._mark_seen(alert.alert_id)

        return published

    def _convert_alert(self, alert: WazuhAlert) -> Any:
        result = WazuhCollector(alert.raw).collect()
        if result.error_count > 0 and result.success_count == 0:
            raise ValueError(
                "conversion failed: " + "; ".join(result.errors[:2])
            )
        if not result.events:
            raise ValueError("no events produced")
        event = result.events[0]
        return event.model_copy(
            update={"event_id": f"wazuh-{alert.alert_id}"}
        )

    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    def run_forever(
        self,
        *,
        max_iterations: int | None = None,
    ) -> None:
        import signal

        def _handler(signum, frame):  # noqa: ANN001
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):
            pass

        iterations = 0
        while not self._stop:
            self.poll_once()
            iterations += 1
            if (
                max_iterations is not None
                and iterations >= max_iterations
            ):
                break
            for _ in range(self._poll_interval):
                if self._stop:
                    break
                time.sleep(1)


__all__ = [
    "WazuhPoller",
    "PollerStats",
    "DEFAULT_POLL_INTERVAL",
    "DEFAULT_INITIAL_LOOKBACK",
]
