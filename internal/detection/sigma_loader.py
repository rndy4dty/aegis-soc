"""
Sigma-like rule loader & matcher.

Simplified Sigma: mendukung subset kondisi umum:

    {
      "id": "aegis-001",
      "title": "Suspicious sdbinst execution",
      "level": "high",
      "logsource": {
        "category": "process_creation"
      },
      "detection": {
        "selection": {
          "process.name": "sdbinst.exe",
          "process.parent_name": "svchost.exe"
        },
        "condition": "selection"
      },
      "tags": ["attack.persistence", "attack.t1546.011"]
    }

Kondisi yang didukung:
- `selection`           : AND semua field
- `selection and other` : AND antar selection
- `selection or other`  : OR antar selection
- `1 of selection*`     : minimal 1 match dari wildcard
- `all of selection*`   : semua match

Field mapping:
- `process.name`        → event.process.name (case-insensitive)
- `process.parent_name` → event.process.parent_name
- `process.command_line`→ event.process.command_line (substring match)
- `host`                → event.host
- `user`                → event.user
- `rule.id`             → event.rule_id
- dst.

Value match:
- String  : exact (case-insensitive), atau substring untuk command_line
- List    : OR antar value
- Wildcard: `*` di awal/akhir
"""

from __future__ import annotations

import fnmatch
import json
from pathlib import Path
from typing import Any

from internal.detection.base import (
    DetectionFinding,
    Severity,
)
from pkg.models.event import Event


# Sigma level → Severity
_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


# Sigma field → resolver
def _resolve_field(event: Event, field: str) -> Any:
    """
    Ambil nilai field dari event via dotted path.
    """
    if field == "host":
        return event.host
    if field == "user":
        return event.user
    if field == "domain":
        return event.domain
    if field == "rule.id":
        return event.rule_id
    if field == "rule.name":
        return event.rule_name
    if field == "event.type":
        return event.event_type
    if field == "category":
        return event.category.value

    if field.startswith("process."):
        if event.process is None:
            return None
        sub = field[len("process."):]
        return getattr(event.process, sub, None)

    if field.startswith("network."):
        if event.network is None:
            return None
        sub = field[len("network."):]
        return getattr(event.network, sub, None)

    if field.startswith("file."):
        if event.file is None:
            return None
        sub = field[len("file."):]
        return getattr(event.file, sub, None)

    if field.startswith("registry."):
        if event.registry is None:
            return None
        sub = field[len("registry."):]
        return getattr(event.registry, sub, None)

    if field.startswith("dns."):
        if event.dns is None:
            return None
        sub = field[len("dns."):]
        return getattr(event.dns, sub, None)

    return event.metadata.get(field)


# ===========================================================================
# Match helpers
# ===========================================================================

def _is_command_field(field: str) -> bool:
    """Field yang match substring, bukan exact."""
    return field in (
        "process.command_line",
        "process.image_path",
        "file.path",
        "registry.key",
        "dns.query",
        "network.url",
    )


def _match_value(
    actual: Any,
    expected: Any,
    *,
    substring: bool,
) -> bool:
    if actual is None:
        return False

    actual_str = str(actual)

    # List value → OR
    if isinstance(expected, list):
        return any(
            _match_value(actual, v, substring=substring)
            for v in expected
        )

    expected_str = str(expected)

    # Wildcard
    if "*" in expected_str or "?" in expected_str:
        return fnmatch.fnmatchcase(
            actual_str.lower(), expected_str.lower()
        )

    if substring:
        return expected_str.lower() in actual_str.lower()

    return actual_str.lower() == expected_str.lower()


def _match_selection(
    event: Event,
    selection: dict[str, Any],
) -> bool:
    """AND semua field dalam selection."""
    if not isinstance(selection, dict):
        return False
    for field, expected in selection.items():
        actual = _resolve_field(event, field)
        substring = _is_command_field(field)
        if not _match_value(actual, expected, substring=substring):
            return False
    return True


def _match_condition(
    event: Event,
    detection: dict[str, Any],
    condition: str,
) -> bool:
    """
    Evaluate condition sederhana.
    """
    if not condition:
        return False

    cond = condition.strip().lower()

    # -- "1 of selection*" ------------------------------------------
    if cond.startswith("1 of "):
        pattern = cond[len("1 of "):].rstrip("*")
        for key, val in detection.items():
            if key == "condition":
                continue
            if key.lower().startswith(pattern):
                if _match_selection(event, val):
                    return True
        return False

    # -- "all of selection*" ----------------------------------------
    if cond.startswith("all of "):
        pattern = cond[len("all of "):].rstrip("*")
        found_any = False
        for key, val in detection.items():
            if key == "condition":
                continue
            if key.lower().startswith(pattern):
                found_any = True
                if not _match_selection(event, val):
                    return False
        return found_any

    # -- "A and B and ..." ------------------------------------------
    if " and " in cond:
        parts = [p.strip() for p in cond.split(" and ")]
        return all(
            _match_condition(event, detection, p) for p in parts
        )

    # -- "A or B or ..." --------------------------------------------
    if " or " in cond:
        parts = [p.strip() for p in cond.split(" or ")]
        return any(
            _match_condition(event, detection, p) for p in parts
        )

    # -- Single selection name --------------------------------------
    selection = detection.get(cond)
    if selection is None:
        return False
    return _match_selection(event, selection)


# ===========================================================================
# SigmaRule
# ===========================================================================

class SigmaRule:
    """Satu Sigma-like rule."""

    def __init__(self, data: dict[str, Any]) -> None:
        self._data = data

    def id(self) -> str:
        return str(self._data.get("id", "sigma-unknown"))

    def name(self) -> str:
        return str(self._data.get("title", self.id()))

    def level(self) -> Severity:
        level = str(self._data.get("level", "medium")).lower()
        return _LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM)

    def tags(self) -> list[str]:
        raw = self._data.get("tags") or []
        if isinstance(raw, str):
            return [raw]
        return [str(t) for t in raw]

    def mitre_techniques(self) -> list[str]:
        """Ekstrak teknik dari tags: 'attack.t1546.011'."""
        out: list[str] = []
        for tag in self.tags():
            if tag.lower().startswith("attack.t"):
                tech = tag[len("attack."):].upper()
                # Format: t1546.011 → T1546.011
                if tech.startswith("T") and len(tech) >= 5:
                    out.append(tech)
        return sorted(set(out))

    def evaluate(self, event: Event) -> list[DetectionFinding]:
        detection = self._data.get("detection")
        if not isinstance(detection, dict):
            return []

        condition = detection.get("condition", "")
        if not condition:
            return []

        if not _match_condition(event, detection, condition):
            return []

        description = str(
            self._data.get("description", "")
        ) or f"Rule {self.name()} matched"

        return [
            DetectionFinding(
                rule_id=self.id(),
                rule_name=self.name(),
                severity=self.level(),
                event_id=event.event_id,
                description=description,
                mitre_techniques=self.mitre_techniques(),
                metadata={"tags": self.tags()},
            )
        ]


# ===========================================================================
# Loader
# ===========================================================================

class SigmaRuleLoader:
    """
    Load Sigma-like rules dari file JSON.
    """

    def __init__(
        self,
        rules: list[dict[str, Any]] | None = None,
    ) -> None:
        self._rules_data = list(rules or [])

    def load_file(self, path: str | Path) -> int:
        """
        Load dari file JSON (list rules) atau directory.
        Return jumlah rule yang di-load.
        """
        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"rules path not found: {p}")

        count = 0
        if p.is_dir():
            for f in sorted(p.glob("*.json")):
                count += self._load_one(f)
        else:
            count += self._load_one(p)
        return count

    def _load_one(self, path: Path) -> int:
        text = path.read_text(encoding="utf-8")
        data = json.loads(text)
        if isinstance(data, list):
            self._rules_data.extend(data)
            return len(data)
        if isinstance(data, dict):
            self._rules_data.append(data)
            return 1
        return 0

    def add_rule(self, rule: dict[str, Any]) -> None:
        self._rules_data.append(rule)

    def rules(self) -> list[SigmaRule]:
        return [SigmaRule(r) for r in self._rules_data]

    def evaluate(self, event: Event) -> list[DetectionFinding]:
        """Jalankan semua rule terhadap event."""
        findings: list[DetectionFinding] = []
        for rule in self.rules():
            findings.extend(rule.evaluate(event))
        return findings


__all__ = [
    "SigmaRule",
    "SigmaRuleLoader",
]
