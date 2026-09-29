"""
Stream Worker: consume events dari Redis Stream, batch, investigate, save.

Loop utama:
    1. Consume messages dari Redis Stream (via consumer group)
    2. Deserialize Event dari message
    3. Add ke EventBatcher
    4. Flush batcher yang ready
    5. Untuk tiap batch: jalankan investigate() + save
    6. Ack messages yang sudah diproses

Design:
- Worker bisa jalan sekali (run_once) atau loop (run_forever).
- Kalau Redis tidak tersedia, worker raise RuntimeError.
- Kalau investigate/save gagal, message tetap di-pending (tidak ack)
  supaya bisa di-retry.
"""

from __future__ import annotations

import os
import signal
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from internal.investigation.investigation_engine import (
    InvestigationResult,
    investigate,
)
from internal.streaming.batcher import EventBatcher
from internal.streaming.bus import StreamBus, StreamMessage, get_bus
from internal.notifications import NotificationRouter
from internal.storage import StorageService
from pkg.models.event import Event


DEFAULT_STREAM = "aegis.alerts"
DEFAULT_GROUP = "investigators"
DEFAULT_CONSUMER = "worker-1"
DEFAULT_TITLE_PREFIX = "Stream investigation"


# ===========================================================================
# Stats
# ===========================================================================

@dataclass
class WorkerStats:
    """Statistik worker (untuk logging / monitoring)."""
    iterations: int = 0
    messages_consumed: int = 0
    messages_acked: int = 0
    messages_failed: int = 0
    batches_flushed: int = 0
    investigations_created: int = 0
    errors: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.__init__()  # type: ignore[misc]


# ===========================================================================
# StreamWorker
# ===========================================================================

class StreamWorker:
    """
    Worker yang consume dari Redis Stream + investigate + save.
    """

    def __init__(
        self,
        *,
        bus: StreamBus | None = None,
        storage: StorageService | None = None,
        batcher: EventBatcher | None = None,
        notifier: NotificationRouter | None = None,
        stream: str = DEFAULT_STREAM,
        group: str = DEFAULT_GROUP,
        consumer: str = DEFAULT_CONSUMER,
        title_prefix: str = DEFAULT_TITLE_PREFIX,
    ) -> None:
        self._bus = bus or get_bus()
        self._storage = storage or StorageService()
        self._batcher = batcher or EventBatcher()
        self._notifier = notifier
        self._stream = stream
        self._group = group
        self._consumer = consumer
        self._title_prefix = title_prefix
        self._stats = WorkerStats()
        self._stop = False
        self._graph_enabled = (
            os.environ.get("AEGIS_WORKER_GRAPH", "1") != "0"
        )
        self._graph_service: Any = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def stats(self) -> WorkerStats:
        return self._stats

    @property
    def stream(self) -> str:
        return self._stream

    @property
    def group(self) -> str:
        return self._group

    @property
    def consumer(self) -> str:
        return self._consumer

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def ensure_group(self) -> None:
        """Bikin consumer group kalau belum ada."""
        self._bus.ensure_group(
            self._stream, self._group, start_id="$"
        )

    # ------------------------------------------------------------------
    # Single iteration
    # ------------------------------------------------------------------

    def run_once(
        self,
        *,
        block_ms: int = 1000,
        count: int = 100,
        now: datetime | None = None,
    ) -> int:
        """
        Satu iterasi:
        - consume sampai `count` messages
        - add ke batcher
        - flush yang ready, investigate, save
        - ack yang berhasil

        Return jumlah investigasi yang dibuat di iterasi ini.
        """
        self._stats.iterations += 1

        # 1. Consume
        messages = self._bus.consume(
            self._stream,
            self._group,
            self._consumer,
            count=count,
            block_ms=block_ms,
        )
        if not messages:
            # Tidak ada message masuk; tetap coba flush batcher
            # (untuk kasus idle flush dari batch sebelumnya)
            return self._flush_and_investigate(now=now)

        # 2. Deserialize + add ke batcher
        processed: list[StreamMessage] = []
        for msg in messages:
            try:
                event = self._deserialize(msg)
                self._batcher.add(event, now=now)
                processed.append(msg)
                self._stats.messages_consumed += 1
            except Exception as exc:  # noqa: BLE001
                self._stats.messages_failed += 1
                self._stats.errors.append(
                    f"deserialize {msg.message_id}: {exc}"
                )
                # Skip; tidak ack supaya bisa di-inspect

        # 3. Flush + investigate
        investigations = self._flush_and_investigate(now=now)

        # 4. Ack messages yang sudah masuk batcher
        if processed:
            acked = self._bus.ack(
                self._stream,
                self._group,
                *[m.message_id for m in processed],
            )
            self._stats.messages_acked += acked

        return investigations

    # ------------------------------------------------------------------
    # Flush + investigate
    # ------------------------------------------------------------------

    def _save_to_graph(
        self,
        batch: list[Event],
        result: InvestigationResult,
    ) -> None:
        """Push graph hasil investigation ke Neo4j. Fail-soft, opt-out via env."""
        if not self._graph_enabled:
            return
        try:
            from internal.storage.graph import GraphService
        except ImportError as exc:
            self._stats.errors.append(f"graph import: {exc}")
            return
        try:
            if self._graph_service is None:
                self._graph_service = GraphService()

            # case_id & tenant_id diambil dari result.case
            case_id = getattr(result.case, "case_id", None)
            tenant_id = getattr(result.case, "tenant_id", None)

            # Pakai graph yang sudah dibangun investigation engine
            # (bukan build_graph ulang)
            self._graph_service.save_graph(
                result.graph,
                case_id=case_id,
                tenant_id=tenant_id,
            )
        except Exception as exc:  # noqa: BLE001
            self._stats.errors.append(f"graph save: {exc}")

    def _flush_and_investigate(
        self,
        *,
        now: datetime | None = None,
    ) -> int:
        batches = self._batcher.flush_ready(now=now)
        if not batches:
            return 0

        created = 0
        for batch in batches:
            self._stats.batches_flushed += 1
            try:
                result = self._investigate_batch(batch)
                self._storage.save(result)
                self._save_to_graph(batch, result)
                self._stats.investigations_created += 1
                created += 1

                # Notifikasi (opsional, fail-soft)
                if self._notifier is not None:
                    try:
                        self._notifier.dispatch(result)
                    except Exception:  # noqa: BLE001
                        pass

            except Exception as exc:  # noqa: BLE001
                self._stats.errors.append(
                    f"investigate batch: {exc}"
                )

        return created

    def _investigate_batch(
        self, events: list[Event]
    ) -> InvestigationResult:
        """Jalankan investigate() pada satu batch."""
        # Title: prefix + timestamp + host (kalau konsisten)
        hosts = {e.host for e in events if e.host}
        host_label = (
            f" [{sorted(hosts)[0]}]"
            if len(hosts) == 1 else ""
        )
        # Tenant: dari event pertama (kalau semua konsisten)
        tenants = {e.tenant_id for e in events if e.tenant_id}
        tenant_id = tenants.pop() if len(tenants) == 1 else None

        title = (
            f"{self._title_prefix}{host_label} "
            f"({len(events)} events)"
        )

        return investigate(
            events,
            title=title,
            tenant_id=tenant_id,
        )

    # ------------------------------------------------------------------
    # Deserialize
    # ------------------------------------------------------------------

    @staticmethod
    def _deserialize(msg: StreamMessage) -> Event:
        """
        Convert StreamMessage.data -> Event.

        Bus.publish() mengubah None -> "" (string kosong).
        Di sini kita kembalikan "" -> None supaya Pydantic valid.
        Field list/dict di-serialize sebagai JSON string.
        """
        import json

        data: dict[str, Any] = {}

        for key, value in msg.data.items():
            # Empty string -> None (bus mengganti None jadi "")
            if value == "":
                data[key] = None
                continue

            # Coba JSON decode untuk complex values
            if isinstance(value, str) and value.startswith(("[", "{")):
                try:
                    data[key] = json.loads(value)
                    continue
                except json.JSONDecodeError:
                    pass

            data[key] = value

        return Event.model_validate(data)
    # ------------------------------------------------------------------
    # Loop
    # ------------------------------------------------------------------

    def stop(self) -> None:
        self._stop = True

    def run_forever(
        self,
        *,
        block_ms: int = 1000,
        count: int = 100,
        max_iterations: int | None = None,
        install_signal_handlers: bool = True,
    ) -> None:
        """
        Loop sampai di-stop (via .stop() atau SIGINT/SIGTERM).
        """
        if install_signal_handlers:
            self._install_signal_handlers()

        iterations = 0
        while not self._stop:
            self.run_once(block_ms=block_ms, count=count)
            iterations += 1
            if (
                max_iterations is not None
                and iterations >= max_iterations
            ):
                break

    def _install_signal_handlers(self) -> None:
        def _handler(signum, frame):  # noqa: ANN001
            self.stop()

        try:
            signal.signal(signal.SIGINT, _handler)
            signal.signal(signal.SIGTERM, _handler)
        except (ValueError, OSError):
            # Bukan main thread, skip
            pass

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def flush_pending(self) -> int:
        """
        Force-flush sisa batch (untuk shutdown).
        Return jumlah investigasi yang dibuat.
        """
        batches = self._batcher.flush_all()
        created = 0
        for batch in batches:
            try:
                result = self._investigate_batch(batch)
                self._storage.save(result)
                self._save_to_graph(batch, result)
                self._stats.investigations_created += 1
                created += 1
            except Exception as exc:  # noqa: BLE001
                self._stats.errors.append(
                    f"flush pending: {exc}"
                )
        return created


__all__ = [
    "StreamWorker",
    "WorkerStats",
    "DEFAULT_STREAM",
    "DEFAULT_GROUP",
    "DEFAULT_CONSUMER",
]
