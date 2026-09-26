from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Protocol, runtime_checkable


# ============================================================================
# Constants
# ============================================================================

DEFAULT_HIGH_SEVERITY: int = 70

SEVERITY_MIN: int = 0
SEVERITY_MAX: int = 100

VALID_DUPLICATE_POLICIES = frozenset(
    {
        "error",
        "first",
        "last",
    }
)


# ============================================================================
# Structural contracts
# ============================================================================


@runtime_checkable
class ProcessLike(Protocol):
    """
    Structural contract untuk process context.

    Timeline tidak bergantung langsung pada ProcessContext dari
    pkg.models.event sehingga dapat menerima object yang kompatibel.
    """

    name: str | None
    pid: int | None
    parent_pid: int | None


@runtime_checkable
class EventLike(Protocol):
    """
    Structural contract untuk security event.

    Timeline menggunakan duck typing sehingga event dapat berasal dari:

    - pkg.models.event.Event
    - object kompatibel
    - dictionary hasil parsing JSON
    """

    event_id: str
    timestamp: datetime
    category: Any
    event_type: str
    severity: int
    host: str | None
    user: str | None
    process: ProcessLike | dict[str, Any] | None
    mitre_techniques: Iterable[Any] | None
    rule_id: str | None
    rule_name: str | None


# ============================================================================
# Internal helpers
# ============================================================================


def _normalize_timestamp(value: Any) -> datetime:
    """
    Normalisasi timestamp menjadi timezone-aware UTC.

    Naive datetime diasumsikan UTC.

    Raises:
        TypeError: jika value bukan datetime.
    """

    if not isinstance(value, datetime):
        raise TypeError(
            f"timestamp must be datetime, got {type(value).__name__}"
        )

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """
    Mengambil attribute dari object atau key dari dictionary.
    """

    if obj is None:
        return default

    if isinstance(obj, dict):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _enum_value(value: Any, default: str = "unknown") -> str:
    """
    Mengubah enum atau value biasa menjadi string.
    """

    if value is None:
        return default

    if hasattr(value, "value"):
        return str(value.value)

    return str(value)


def _validate_event_id(
    event: Any,
    *,
    index: int,
) -> str:
    """
    Validasi dan normalisasi event_id.

    Contract:

    - harus berupa string
    - tidak boleh None
    - tidak boleh kosong
    - whitespace di awal/akhir dihapus
    """

    event_id = _attr(event, "event_id")

    if not isinstance(event_id, str):
        raise ValueError(
            f"non-string event_id at index {index}: "
            f"got {type(event_id).__name__}"
        )

    event_id = event_id.strip()

    if not event_id:
        raise ValueError(
            f"empty event_id at index {index}"
        )

    return event_id


def _normalize_severity(
    value: Any,
    *,
    index: int,
) -> int:
    """
    Normalisasi severity dan memastikan nilainya berada pada 0..100.
    """

    if value is None:
        severity = 0
    else:
        try:
            severity = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"invalid severity at index {index}: {value!r}"
            ) from exc

    if not SEVERITY_MIN <= severity <= SEVERITY_MAX:
        raise ValueError(
            f"severity at index {index} must be between "
            f"{SEVERITY_MIN} and {SEVERITY_MAX}, got {severity}"
        )

    return severity


def _normalize_pid(value: Any) -> int | None:
    """
    PID hanya dianggap valid apabila berupa integer.

    bool secara eksplisit ditolak karena bool merupakan subclass int.
    """

    if isinstance(value, bool):
        return None

    if isinstance(value, int):
        return value

    return None


def _normalize_optional_string(value: Any) -> str | None:
    """
    Normalisasi optional string.

    Empty string diperlakukan sebagai None.
    """

    if value is None:
        return None

    if not isinstance(value, str):
        return str(value)

    value = value.strip()

    return value or None


def _normalize_mitre_techniques(value: Any) -> tuple[str, ...]:
    """
    Normalisasi MITRE techniques:

    - None -> ()
    - deduplicate
    - remove empty values
    - sort deterministically
    """

    if not value:
        return ()

    try:
        values = value
        normalized = {
            str(item).strip()
            for item in values
            if item is not None and str(item).strip()
        }
    except TypeError:
        return ()

    return tuple(sorted(normalized))


# ============================================================================
# TimelineEvent
# ============================================================================


@dataclass(frozen=True, slots=True)
class TimelineEvent:
    """
    Representasi kronologis dari satu security event.

    TimelineEvent merupakan snapshot data untuk kebutuhan investigasi.
    Timeline tidak menyimpan referensi terhadap object Event asli.
    """

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------

    event_id: str
    timestamp: datetime

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------

    category: str
    event_type: str
    severity: int

    # ------------------------------------------------------------------
    # Actor
    # ------------------------------------------------------------------

    host: str | None
    user: str | None

    # ------------------------------------------------------------------
    # Process
    # ------------------------------------------------------------------

    process_name: str | None
    process_pid: int | None
    parent_pid: int | None

    # ------------------------------------------------------------------
    # Detection
    # ------------------------------------------------------------------

    mitre_techniques: tuple[str, ...]
    rule_id: str | None
    rule_name: str | None

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    summary: str

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def is_high_severity(self) -> bool:
        """
        True jika severity >= DEFAULT_HIGH_SEVERITY.
        """

        return self.severity >= DEFAULT_HIGH_SEVERITY

    def to_dict(self) -> dict[str, Any]:
        """
        Serialize TimelineEvent menjadi dictionary.
        """

        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat(),
            "category": self.category,
            "event_type": self.event_type,
            "severity": self.severity,
            "host": self.host,
            "user": self.user,
            "process_name": self.process_name,
            "process_pid": self.process_pid,
            "parent_pid": self.parent_pid,
            "mitre_techniques": list(self.mitre_techniques),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "summary": self.summary,
        }


# ============================================================================
# Timeline
# ============================================================================


class Timeline:
    """
    Chronological view over a collection of security events.

    Timeline bersifat immutable setelah construction.

    Sorting deterministic:

        1. timestamp ascending
        2. event_id ascending

    Duplicate event_id policy:

        error
            Tolak duplicate event_id.

        first
            Pertahankan event pertama.

        last
            Pertahankan event terakhir.
    """

    def __init__(
        self,
        events: Iterable[Any] = (),
        *,
        on_duplicate: str = "error",
    ) -> None:

        self._validate_duplicate_policy(on_duplicate)

        raw_events = list(events)

        built: list[TimelineEvent] = []
        seen: dict[str, int] = {}

        for index, event in enumerate(raw_events):
            event_id = _validate_event_id(
                event,
                index=index,
            )

            previous_index = seen.get(event_id)

            if previous_index is not None:
                if on_duplicate == "error":
                    raise ValueError(
                        f"duplicate event_id '{event_id}' "
                        f"at index {index}; "
                        f"first seen at index {previous_index}"
                    )

                if on_duplicate == "first":
                    continue

                if on_duplicate == "last":
                    built = [
                        existing
                        for existing in built
                        if existing.event_id != event_id
                    ]

            seen[event_id] = index

            built.append(
                self._build_event(
                    event,
                    index=index,
                    event_id=event_id,
                )
            )

        self._events: tuple[TimelineEvent, ...] = tuple(
            sorted(
                built,
                key=lambda event: (
                    event.timestamp,
                    event.event_id,
                ),
            )
        )

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_duplicate_policy(
        on_duplicate: str,
    ) -> None:
        if on_duplicate not in VALID_DUPLICATE_POLICIES:
            allowed = ", ".join(
                sorted(VALID_DUPLICATE_POLICIES)
            )

            raise ValueError(
                f"on_duplicate must be one of: {allowed}; "
                f"got {on_duplicate!r}"
            )

    # ------------------------------------------------------------------
    # Builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_event(
        event: Any,
        *,
        index: int,
        event_id: str | None = None,
    ) -> TimelineEvent:
        """
        Convert arbitrary EventLike-compatible object menjadi
        TimelineEvent.
        """

        if event_id is None:
            event_id = _validate_event_id(
                event,
                index=index,
            )

        timestamp = _normalize_timestamp(
            _attr(event, "timestamp")
        )

        severity = _normalize_severity(
            _attr(event, "severity", 0),
            index=index,
        )

        process = _attr(
            event,
            "process",
        )

        process_name = _normalize_optional_string(
            _attr(process, "name")
        )

        process_pid = _normalize_pid(
            _attr(process, "pid")
        )

        parent_pid = _normalize_pid(
            _attr(process, "parent_pid")
        )

        category = _enum_value(
            _attr(event, "category"),
            default="other",
        )

        event_type = _normalize_optional_string(
            _attr(event, "event_type")
        ) or "unknown"

        techniques = _normalize_mitre_techniques(
            _attr(event, "mitre_techniques")
        )

        host = _normalize_optional_string(
            _attr(event, "host")
        )

        user = _normalize_optional_string(
            _attr(event, "user")
        )

        rule_id = _normalize_optional_string(
            _attr(event, "rule_id")
        )

        rule_name = _normalize_optional_string(
            _attr(event, "rule_name")
        )

        summary = Timeline._build_summary(
            event_type=event_type,
            category=category,
            process_name=process_name,
            process_pid=process_pid,
        )

        return TimelineEvent(
            event_id=event_id,
            timestamp=timestamp,
            category=category,
            event_type=event_type,
            severity=severity,
            host=host,
            user=user,
            process_name=process_name,
            process_pid=process_pid,
            parent_pid=parent_pid,
            mitre_techniques=techniques,
            rule_id=rule_id,
            rule_name=rule_name,
            summary=summary,
        )

    @staticmethod
    def _build_summary(
        *,
        event_type: str,
        category: str,
        process_name: str | None,
        process_pid: int | None,
    ) -> str:
        """
        Generate human-readable summary.
        """

        if category == "process" and process_name:
            if process_pid is not None:
                return (
                    f"{event_type}: "
                    f"{process_name} "
                    f"(PID {process_pid})"
                )

            return f"{event_type}: {process_name}"

        return event_type

    # ------------------------------------------------------------------
    # Access
    # ------------------------------------------------------------------

    @property
    def events(self) -> tuple[TimelineEvent, ...]:
        """
        Immutable tuple berisi seluruh TimelineEvent.
        """

        return self._events

    @property
    def size(self) -> int:
        return len(self._events)

    @property
    def is_empty(self) -> bool:
        return not self._events

    @property
    def earliest(self) -> TimelineEvent | None:
        if not self._events:
            return None

        return self._events[0]

    @property
    def latest(self) -> TimelineEvent | None:
        if not self._events:
            return None

        return self._events[-1]

    @property
    def duration_seconds(self) -> float:
        if len(self._events) < 2:
            return 0.0

        return (
            self._events[-1].timestamp
            - self._events[0].timestamp
        ).total_seconds()

    def __len__(self) -> int:
        return len(self._events)

    def __iter__(self) -> Iterator[TimelineEvent]:
        return iter(self._events)

    def __getitem__(
        self,
        index: int,
    ) -> TimelineEvent:
        return self._events[index]

    # ------------------------------------------------------------------
    # Filters — time
    # ------------------------------------------------------------------

    def between(
        self,
        start: datetime,
        end: datetime,
    ) -> list[TimelineEvent]:
        """
        Return events pada inclusive time range.

        start <= timestamp <= end
        """

        normalized_start = _normalize_timestamp(start)
        normalized_end = _normalize_timestamp(end)

        if normalized_end < normalized_start:
            raise ValueError(
                "end must be greater than or equal to start"
            )

        return [
            event
            for event in self._events
            if normalized_start
            <= event.timestamp
            <= normalized_end
        ]

    def since(
        self,
        since: datetime,
    ) -> list[TimelineEvent]:
        """
        Return events dengan timestamp >= since.
        """

        normalized_since = _normalize_timestamp(since)

        return [
            event
            for event in self._events
            if event.timestamp >= normalized_since
        ]

    def until(
        self,
        until: datetime,
    ) -> list[TimelineEvent]:
        """
        Return events dengan timestamp <= until.
        """

        normalized_until = _normalize_timestamp(until)

        return [
            event
            for event in self._events
            if event.timestamp <= normalized_until
        ]

    # ------------------------------------------------------------------
    # Filters — host
    # ------------------------------------------------------------------

    def for_host(
        self,
        host: str,
    ) -> list[TimelineEvent]:
        """
        Return events dengan host yang sama persis.

        host kosong menghasilkan [].
        """

        if not host:
            return []

        return [
            event
            for event in self._events
            if event.host == host
        ]

    # ------------------------------------------------------------------
    # Filters — process
    # ------------------------------------------------------------------

    def for_process(
        self,
        pid: int | None,
    ) -> list[TimelineEvent]:
        """
        Return events dengan process PID yang sama.

        Child process tidak termasuk.
        Gunakan related_to_process() untuk parent-child relation.
        """

        if pid is None:
            return []

        return [
            event
            for event in self._events
            if event.process_pid == pid
        ]

    def related_to_process(
        self,
        pid: int | None,
    ) -> list[TimelineEvent]:
        """
        Return events yang:

        - process_pid == pid
        - atau parent_pid == pid
        """

        if pid is None:
            return []

        return [
            event
            for event in self._events
            if (
                event.process_pid == pid
                or event.parent_pid == pid
            )
        ]

    # ------------------------------------------------------------------
    # Filters — severity
    # ------------------------------------------------------------------

    def high_severity(
        self,
        minimum: int = DEFAULT_HIGH_SEVERITY,
    ) -> list[TimelineEvent]:
        """
        Return events dengan severity >= minimum.
        """

        if not SEVERITY_MIN <= minimum <= SEVERITY_MAX:
            raise ValueError(
                f"minimum severity must be between "
                f"{SEVERITY_MIN} and {SEVERITY_MAX}"
            )

        return [
            event
            for event in self._events
            if event.severity >= minimum
        ]

    # ------------------------------------------------------------------
    # Serialization
    # ------------------------------------------------------------------

    def to_list(self) -> list[TimelineEvent]:
        """
        Return shallow list copy dari TimelineEvent.
        """

        return list(self._events)

    def to_dicts(self) -> list[dict[str, Any]]:
        """
        Return seluruh timeline sebagai list dictionary.
        """

        return [
            event.to_dict()
            for event in self._events
        ]

    def to_json(
        self,
        indent: int | None = None,
    ) -> str:
        """
        Serialize timeline ke deterministic JSON.
        """

        return json.dumps(
            self.to_dicts(),
            indent=indent,
            sort_keys=True,
            default=str,
        )


# ============================================================================
# Factory
# ============================================================================


def build_timeline(
    events: Iterable[Any],
    *,
    on_duplicate: str = "error",
) -> Timeline:
    """
    Convenience factory untuk membangun Timeline.
    """

    return Timeline(
        events,
        on_duplicate=on_duplicate,
    )
