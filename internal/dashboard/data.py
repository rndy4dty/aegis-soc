"""
Data adapter untuk dashboard.

Tugas:
- Load events dari uploaded file (bytes)
- Jalankan investigate()
- Return InvestigationResult
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


def parse_events(raw_bytes: bytes) -> list[Event]:
    """
    Parse uploaded file bytes menjadi list[Event].

    Raise ValueError kalau format invalid.
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

    if isinstance(data, dict):
        if "events" not in data:
            raise ValueError(
                "JSON object must contain 'events' key "
                "or be a list of events"
            )
        data = data["events"]

    if not isinstance(data, list):
        raise ValueError(
            "events payload must be a list or {'events': [...]}"
        )

    events: list[Event] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise ValueError(
                f"event at index {index} is not an object"
            )
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            raise ValueError(
                f"event at index {index} is invalid: {exc}"
            ) from exc

    return events


def run_investigation(
    events: list[Event],
    *,
    title: str,
    analyst: str | None = None,
    tenant: str | None = None,
    category: str = InvestigationCategory.UNKNOWN.value,
) -> InvestigationResult:
    """
    Jalankan investigate() dengan parameter dari UI.
    """
    return investigate(
        events,
        title=title,
        tenant_id=tenant,
        analyst=analyst,
        category=InvestigationCategory(category),
    )


__all__ = ["parse_events", "run_investigation"]
