"""
Data adapter untuk dashboard.

Auto-detect format file:
- Canonical Event (list atau {"events": [...]})
- Wazuh alert (raw)
- Sysmon event (raw)
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import ValidationError

from internal.investigation.investigation_engine import (
    InvestigationResult,
    investigate,
)
from pkg.models.event import Event
from pkg.models.investigation import InvestigationCategory


def _looks_like_wazuh_alert(item: dict) -> bool:
    """Wazuh alert punya field 'rule' + 'agent' atau 'manager'."""
    if not isinstance(item, dict):
        return False
    if "rule" in item and ("agent" in item or "manager" in item):
        return True
    if "rule" in item and "id" in item and "timestamp" in item:
        return True
    return False


def _looks_like_sysmon_event(item: dict) -> bool:
    """Sysmon event punya field 'EventID' + 'UtcTime' atau 'Image'."""
    if not isinstance(item, dict):
        return False
    if "EventID" in item and ("UtcTime" in item or "Image" in item):
        return True
    return False


def _looks_like_canonical_event(item: dict) -> bool:
    """Canonical Event punya 'event_id', 'source', 'event_type'."""
    if not isinstance(item, dict):
        return False
    return (
        "event_id" in item
        and "source" in item
        and "event_type" in item
    )


def parse_events(raw_bytes: bytes) -> list[Event]:
    """
    Parse uploaded file bytes menjadi list[Event].

    Auto-detect format:
    - Canonical Event (list atau {"events": [...]})
    - Wazuh alert (raw)
    - Sysmon event (raw)
    """
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"file must be UTF-8: {exc}") from exc

    try:
        data: Any = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid JSON: {exc.msg} "
            f"(line {exc.lineno}, col {exc.colno})"
        ) from exc

    # -- Normalize to list ----------------------------------------------
    if isinstance(data, dict):
        if "events" in data:
            data = data["events"]
        else:
            data = [data]

    if not isinstance(data, list):
        raise ValueError(
            "payload must be a list or {'events': [...]}"
        )

    if not data:
        return []

    # -- Detect format from first item ---------------------------------
    first = data[0]
    if not isinstance(first, dict):
        raise ValueError("event at index 0 is not an object")

    if _looks_like_canonical_event(first):
        return _parse_canonical(data)

    if _looks_like_wazuh_alert(first):
        return _parse_wazuh(data)

    if _looks_like_sysmon_event(first):
        return _parse_sysmon(data)

    # -- Fallback: coba canonical, tapi mungkin gagal ------------------
    raise ValueError(
        "Unrecognized event format. Supported formats:\n"
        "- Canonical Event (list or {'events': [...]})\n"
        "- Wazuh alert (with 'rule' and 'agent' fields)\n"
        "- Sysmon event (with 'EventID' and 'UtcTime' fields)\n"
        f"Detected keys: {sorted(first.keys())}"
    )


def _parse_canonical(data: list[dict]) -> list[Event]:
    events: list[Event] = []
    for index, item in enumerate(data):
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            raise ValueError(
                f"event at index {index} is invalid: {exc}"
            ) from exc
    return events


def _parse_wazuh(data: list[dict]) -> list[Event]:
    from internal.collector import WazuhCollector

    result = WazuhCollector(data).collect()
    if result.error_count > 0 and result.success_count == 0:
        raise ValueError(
            "failed to convert Wazuh alerts: "
            + "; ".join(result.errors[:3])
        )
    return result.events


def _parse_sysmon(data: list[dict]) -> list[Event]:
    from internal.collector import SysmonCollector

    result = SysmonCollector(data).collect()
    if result.error_count > 0 and result.success_count == 0:
        raise ValueError(
            "failed to convert Sysmon events: "
            + "; ".join(result.errors[:3])
        )
    return result.events


def run_investigation(
    events: list[Event],
    *,
    title: str,
    analyst: str | None = None,
    tenant: str | None = None,
    category: str = InvestigationCategory.UNKNOWN.value,
) -> InvestigationResult:
    return investigate(
        events,
        title=title,
        tenant_id=tenant,
        analyst=analyst,
        category=InvestigationCategory(category),
    )


__all__ = ["parse_events", "run_investigation"]
