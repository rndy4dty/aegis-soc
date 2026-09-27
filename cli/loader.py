"""
Event loader untuk AegisSOC CLI.

Input:
- Path ke file JSON
- Format: list[dict] ATAU {"events": [dict, ...]}

Output:
- list[Event] (Pydantic model)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from pkg.models.event import Event


def load_events(path: Path) -> list[Event]:
    if not path.exists():
        raise FileNotFoundError(f"events file not found: {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read events file: {exc}") from exc

    try:
        data: Any = json.loads(raw_text)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"invalid JSON in {path}: {exc.msg} "
            f"(line {exc.lineno}, column {exc.colno})"
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
            raise ValueError(f"event at index {index} is not an object")
        try:
            events.append(Event.model_validate(item))
        except ValidationError as exc:
            raise ValueError(
                f"event at index {index} is invalid: {exc}"
            ) from exc

    return events


__all__ = ["load_events"]
