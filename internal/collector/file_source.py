"""
Generic file source.

Baca satu file atau directory berisi file JSON. Setiap file
di-parse sebagai list[Event] canonical (dengan schema kita).

Berguna untuk: file export, backup, replay, testing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from internal.collector.base import CollectorResult
from pkg.models.event import Event


class FileSource:
    """
    Baca events dari file / directory.

    Setiap file harus berisi:
    - list[dict] schema Event, atau
    - {"events": [dict, ...]}
    """

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    def name(self) -> str:
        return "file_source"

    def collect(self) -> CollectorResult:
        result = CollectorResult(source_name=self.name())

        if not self._path.exists():
            result.errors.append(
                f"path not found: {self._path}"
            )
            return result

        files: list[Path] = []
        if self._path.is_dir():
            files = sorted(self._path.glob("*.json"))
        else:
            files = [self._path]

        for file_path in files:
            try:
                events = self._read_file(file_path)
            except (OSError, ValueError) as exc:
                result.errors.append(
                    f"{file_path.name}: {exc}"
                )
                continue

            result.raw_count += len(events)
            result.events.extend(events)

        return result

    # -------------------------------------------------------------------

    @staticmethod
    def _read_file(path: Path) -> list[Event]:
        text = path.read_text(encoding="utf-8").strip()
        if not text:
            return []

        try:
            data: Any = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON: {exc.msg} "
                f"(line {exc.lineno})"
            ) from exc

        if isinstance(data, dict):
            if "events" in data:
                data = data["events"]
            else:
                data = [data]

        if not isinstance(data, list):
            raise ValueError("payload must be list or {'events': []}")

        events: list[Event] = []
        for i, item in enumerate(data):
            if not isinstance(item, dict):
                raise ValueError(f"item {i}: not an object")
            try:
                events.append(Event.model_validate(item))
            except ValidationError as exc:
                raise ValueError(
                    f"item {i}: {exc}"
                ) from exc

        return events


__all__ = ["FileSource"]
