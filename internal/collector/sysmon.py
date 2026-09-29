"""
Sysmon collector.

Mengubah Sysmon event (Windows Event Log JSON export) menjadi
canonical Event. Support format:

    {
      "EventID": 1,
      "UtcTime": "2026-09-26 10:00:00.000",
      "Computer": "WIN-01",
      "User": "NT AUTHORITY\\SYSTEM",
      "Image": "C:\\Windows\\System32\\sdbinst.exe",
      "ProcessId": 4821,
      "ParentProcessId": 812,
      "ParentImage": "C:\\Windows\\System32\\svchost.exe",
      "CommandLine": "sdbinst.exe -m -bg",
      "Hashes": "SHA256=abc123"
    }
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from internal.collector.base import CollectorResult
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    Platform,
    ProcessContext,
    SourceReliability,
)


# Mapping Sysmon EventID → EventCategory
SYSMON_EVENT_CATEGORY: dict[int, EventCategory] = {
    1: EventCategory.PROCESS,          # Process Create
    2: EventCategory.FILE,             # File creation time changed
    3: EventCategory.NETWORK,          # Network connection
    5: EventCategory.PROCESS,          # Process terminated
    6: EventCategory.OTHER,            # Driver loaded
    7: EventCategory.OTHER,            # Image loaded
    8: EventCategory.PROCESS,          # CreateRemoteThread
    10: EventCategory.PROCESS,         # Process access
    11: EventCategory.FILE,            # File created
    12: EventCategory.REGISTRY,        # Registry create/delete
    13: EventCategory.REGISTRY,        # Registry set value
    14: EventCategory.REGISTRY,        # Registry rename
    15: EventCategory.FILE,            # FileCreateStreamHash
    17: EventCategory.NETWORK,         # Pipe created
    18: EventCategory.NETWORK,         # Pipe connected
    19: EventCategory.OTHER,           # WMI filter
    20: EventCategory.OTHER,           # WMI consumer
    21: EventCategory.OTHER,           # WMI consumer to filter
    22: EventCategory.DNS,             # DNS query
    23: EventCategory.FILE,            # File delete
    24: EventCategory.OTHER,           # Clipboard change
    25: EventCategory.PROCESS,         # Process tampering
    26: EventCategory.FILE,            # File delete logged
}


SYSMON_EVENT_NAME: dict[int, str] = {
    1: "process_creation",
    2: "file_creation_time_changed",
    3: "network_connection",
    5: "process_terminated",
    6: "driver_loaded",
    7: "image_loaded",
    8: "create_remote_thread",
    10: "process_access",
    11: "file_created",
    12: "registry_create_delete",
    13: "registry_set_value",
    14: "registry_rename",
    15: "file_create_stream_hash",
    22: "dns_query",
    23: "file_delete",
    25: "process_tampering",
    26: "file_delete_logged",
}


def _parse_sysmon_timestamp(value: Any) -> datetime:
    if isinstance(value, str):
        # Format umum: "2026-09-26 10:00:00.000"
        candidates = [
            value,
            value.replace(" ", "T"),
            value.replace("Z", "+00:00"),
        ]
        for cand in candidates:
            try:
                dt = datetime.fromisoformat(cand)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


def _coerce_int(v: Any) -> int | None:
    if v is None:
        return None
    try:
        if isinstance(v, str) and v.startswith("0x"):
            return int(v, 16)
        return int(v)
    except (ValueError, TypeError):
        return None


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    p = str(path).replace("/", "\\")
    return p.rsplit("\\", 1)[-1]


def _parse_hashes(raw: Any) -> dict[str, str]:
    """
    Parse Sysmon Hashes string: "MD5=abc,SHA256=def".
    """
    if not isinstance(raw, str):
        return {}

    out: dict[str, str] = {}
    for chunk in raw.split(","):
        chunk = chunk.strip()
        if "=" not in chunk:
            continue
        algo, value = chunk.split("=", 1)
        algo_norm = algo.strip().lower()
        value_norm = value.strip().lower()
        if algo_norm and value_norm:
            out[algo_norm] = value_norm
    return out


# ===========================================================================
# SysmonCollector
# ===========================================================================

class SysmonCollector:
    """
    Collector untuk Sysmon events.

    Bisa dari:
    - file tunggal (JSON list atau NDJSON)
    - list[dict]
    - dict tunggal
    """

    def __init__(self, source: Any) -> None:
        self._source = source

    def name(self) -> str:
        return "sysmon"

    def collect(self) -> CollectorResult:
        result = CollectorResult(source_name=self.name())

        try:
            items = self._load_items()
        except (FileNotFoundError, ValueError) as exc:
            result.errors.append(str(exc))
            return result

        result.raw_count = len(items)

        for index, item in enumerate(items):
            if not isinstance(item, dict):
                result.errors.append(
                    f"item {index}: not an object"
                )
                continue
            try:
                event = self._convert(item, index=index)
                result.events.append(event)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"item {index}: {exc}")

        return result

    # -------------------------------------------------------------------

    def _load_items(self) -> list[dict]:
        src = self._source

        if isinstance(src, dict):
            return [src]
        if isinstance(src, list):
            return src
        if isinstance(src, (str, Path)):
            path = Path(src)
            if not path.exists():
                raise FileNotFoundError(
                    f"sysmon source not found: {path}"
                )
            return self._load_from_file(path)

        raise ValueError(
            f"unsupported source type: {type(src).__name__}"
        )

    @staticmethod
    def _load_from_file(path: Path) -> list[dict]:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []

        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                if "events" in data and isinstance(data["events"], list):
                    return data["events"]
                return [data]
        except json.JSONDecodeError:
            pass

        # NDJSON fallback
        out: list[dict] = []
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    out.append(obj)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON at line {line_no}: {exc.msg}"
                ) from exc
        return out

    # -------------------------------------------------------------------

    def _convert(self, item: dict, *, index: int) -> Event:
        event_id_num = _coerce_int(item.get("EventID"))
        category = SYSMON_EVENT_CATEGORY.get(
            event_id_num or -1, EventCategory.OTHER
        )
        event_type = SYSMON_EVENT_NAME.get(
            event_id_num or -1, "sysmon_event"
        )

        ts = _parse_sysmon_timestamp(
            item.get("UtcTime") or item.get("TimeCreated")
        )
        host = item.get("Computer")
        user = item.get("User")

        process: ProcessContext | None = None
        if event_id_num == 1 or item.get("Image"):
            hashes = _parse_hashes(item.get("Hashes"))
            process = ProcessContext(
                name=_basename(item.get("Image")),
                pid=_coerce_int(item.get("ProcessId")),
                parent_pid=_coerce_int(item.get("ParentProcessId")),
                parent_name=_basename(item.get("ParentImage")),
                command_line=item.get("CommandLine"),
                image_path=item.get("Image"),
                user=str(user) if user else None,
                hashes=hashes,
            )

        # severity: Sysmon sendiri tidak punya severity; default 50
        # (bisa di-override oleh detection layer)
        severity = 50

        return Event(
            event_id=f"sysmon-{index}-{event_id_num or 'unknown'}",
            timestamp=ts,
            source=EventSource.SYSMON,
            source_reliability=SourceReliability.A,
            platform=Platform.WINDOWS,
            category=category,
            event_type=event_type,
            severity=severity,
            host=str(host) if host else None,
            user=str(user) if user else None,
            process=process,
            raw_data=item,
        )


__all__ = [
    "SysmonCollector",
    "SYSMON_EVENT_CATEGORY",
    "SYSMON_EVENT_NAME",
]
