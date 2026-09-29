"""
Wazuh collector.

Mengubah Wazuh alert JSON menjadi canonical Event.

Format Wazuh alert yang didukung:
    {
      "id": "1606484225.12345",
      "timestamp": "2026-09-26T10:00:00.000+0000",
      "rule": {
        "id": "92058",
        "level": 10,
        "description": "Application Shimming",
        "mitre": {
          "id": ["T1546.011"],
          "tactic": ["Persistence"]
        }
      },
      "agent": {
        "id": "001",
        "name": "WIN-01"
      },
      "data": {
        "win": {
          "system": {...},
          "eventdata": {...}
        }
      },
      "full_log": "...",
      "location": "..."
    }

Kita ekstrak yang tersedia, tidak semua field wajib ada.
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


# Severity mapping: Wazuh rule.level (0-15) → Event.severity (0-100)
WAZUH_LEVEL_TO_SEVERITY: dict[int, int] = {
    0: 0, 1: 5, 2: 10, 3: 15, 4: 25, 5: 30,
    6: 40, 7: 50, 8: 60, 9: 65, 10: 75,
    11: 80, 12: 85, 13: 90, 14: 95, 15: 100,
}


def wazuh_level_to_severity(level: int) -> int:
    if level <= 0:
        return 0
    if level >= 15:
        return 100
    return WAZUH_LEVEL_TO_SEVERITY.get(level, 0)


def _parse_wazuh_timestamp(value: Any) -> datetime:
    """
    Parse timestamp Wazuh. Fallback ke now() UTC kalau gagal.
    """
    if isinstance(value, str):
        candidates = [
            value,
            value.replace("+0000", "+00:00"),
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


def _detect_platform(alert: dict[str, Any]) -> Platform:
    """
    Coba tebak platform dari isi alert.
    """
    data = alert.get("data") or {}
    if isinstance(data, dict):
        if "win" in data:
            return Platform.WINDOWS
        if "audit" in data or "unix" in data:
            return Platform.LINUX

    location = str(alert.get("location", "")).lower()
    if "windows" in location or "win" in location:
        return Platform.WINDOWS
    if "linux" in location or "ubuntu" in location:
        return Platform.LINUX

    return Platform.UNKNOWN


def _detect_category(alert: dict[str, Any]) -> EventCategory:
    """
    Tebak EventCategory dari isi alert.
    """
    data = alert.get("data") or {}
    win = data.get("win") if isinstance(data, dict) else None
    if isinstance(win, dict):
        system = win.get("system") or {}
        event_id = str(system.get("eventID", ""))
        # Sysmon event IDs
        if event_id == "1":
            return EventCategory.PROCESS
        if event_id == "3":
            return EventCategory.NETWORK
        if event_id == "11":
            return EventCategory.FILE
        if event_id in ("12", "13", "14"):
            return EventCategory.REGISTRY
        if event_id == "22":
            return EventCategory.DNS

        event_data = win.get("eventdata") or {}
        if isinstance(event_data, dict):
            if "image" in {k.lower() for k in event_data}:
                return EventCategory.PROCESS

    # Fallback heuristik
    groups = alert.get("rule", {}).get("groups", [])
    if isinstance(groups, list):
        groups_lower = {str(g).lower() for g in groups}
        if "process" in groups_lower or "sysmon" in groups_lower:
            return EventCategory.PROCESS
        if "network" in groups_lower or "firewall" in groups_lower:
            return EventCategory.NETWORK
        if "authentication" in groups_lower or "auth" in groups_lower:
            return EventCategory.AUTHENTICATION
        if "registry" in groups_lower:
            return EventCategory.REGISTRY

    return EventCategory.OTHER


def _extract_process(alert: dict[str, Any]) -> ProcessContext | None:
    """
    Ekstrak process context dari Sysmon event di Wazuh alert.
    """
    data = alert.get("data") or {}
    win = data.get("win") if isinstance(data, dict) else None
    if not isinstance(win, dict):
        return None

    event_data = win.get("eventdata") or {}
    if not isinstance(event_data, dict):
        return None

    # Normalize keys ke lowercase untuk lookup case-insensitive
    lower = {str(k).lower(): v for k, v in event_data.items()}

    def _get(*keys: str) -> Any:
        for k in keys:
            if k in lower:
                return lower[k]
        return None

    name = _get("image", "processname", "newprocessname")
    if not name:
        return None

    # Ambil basename
    name_str = str(name).replace("/", "\\")
    if "\\" in name_str:
        name_str = name_str.rsplit("\\", 1)[-1]

    pid = _get("processid", "newprocessid", "pid")
    ppid = _get("parentprocessid", "parentpid", "ppid")
    parent_name = _get("parentimage", "parentprocessname")
    if parent_name:
        pn = str(parent_name).replace("/", "\\")
        if "\\" in pn:
            parent_name = pn.rsplit("\\", 1)[-1]

    cmd = _get("commandline", "command_line")
    user = _get("user", "username")

    def _coerce_int(v: Any) -> int | None:
        if v is None:
            return None
        try:
            # Sysmon kadang beri hex: "0x1234"
            if isinstance(v, str) and v.startswith("0x"):
                return int(v, 16)
            return int(v)
        except (ValueError, TypeError):
            return None

    return ProcessContext(
        name=str(name_str),
        pid=_coerce_int(pid),
        parent_pid=_coerce_int(ppid),
        parent_name=str(parent_name) if parent_name else None,
        command_line=str(cmd) if cmd else None,
        user=str(user) if user else None,
        image_path=str(name) if name else None,
    )


# Mapping MITRE tactic name → tactic ID.
# Dipakai kalau Wazuh hanya memberi nama (bukan ID).
MITRE_TACTIC_NAME_TO_ID: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource development": "TA0042",
    "initial access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege escalation": "TA0004",
    "defense evasion": "TA0005",
    "credential access": "TA0006",
    "discovery": "TA0007",
    "lateral movement": "TA0008",
    "collection": "TA0009",
    "command and control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


def _normalize_tactic(value: str) -> str | None:
    """
    Konversi tactic name atau ID menjadi ID canonical (TAxxxx).
    Return None kalau tidak bisa di-normalisasi.
    """
    s = str(value).strip()
    if not s:
        return None

    # Sudah ID? (TAxxxx)
    if s.upper().startswith("TA") and s[2:].isdigit():
        return s.upper()

    # Nama tactic? coba mapping
    key = s.lower().replace("_", " ").strip()
    mapped = MITRE_TACTIC_NAME_TO_ID.get(key)
    if mapped:
        return mapped

    return None

def _extract_mitre(alert: dict[str, Any]) -> tuple[list[str], list[str]]:
    """
    Ekstrak MITRE technique + tactic dari rule.mitre.

    Technique: harus format Txxxx (optional .yyy).
    Tactic: name atau ID, di-normalisasi ke TAxxxx.
    Tactic yang tidak bisa di-normalisasi → di-skip (tidak raise).
    """
    rule = alert.get("rule") or {}
    mitre = rule.get("mitre") if isinstance(rule, dict) else None
    if not isinstance(mitre, dict):
        return [], []

    raw_ids = mitre.get("id") or []
    raw_tactics = mitre.get("tactic") or []

    if isinstance(raw_ids, str):
        raw_ids = [raw_ids]
    if isinstance(raw_tactics, str):
        raw_tactics = [raw_tactics]

    # -- Techniques: validasi format Txxxx ---------------------------
    techs: list[str] = []
    for t in raw_ids:
        t_str = str(t).strip().upper()
        if t_str.startswith("T") and t_str[1:].replace(".", "").isdigit():
            techs.append(t_str)

    # -- Tactics: normalisasi nama / ID → TAxxxx ---------------------
    tactics: list[str] = []
    for raw in raw_tactics:
        tid = _normalize_tactic(raw)
        if tid:
            tactics.append(tid)

    return sorted(set(techs)), sorted(set(tactics))

# ===========================================================================
# WazuhCollector
# ===========================================================================

class WazuhCollector:
    """
    Collector untuk Wazuh alert JSON.

    Bisa dari:
    - file tunggal (JSON list atau NDJSON)
    - string (single alert)
    - sudah-parsed dict
    """

    def __init__(self, source: Any) -> None:
        self._source = source

    def name(self) -> str:
        return "wazuh"

    def collect(self) -> CollectorResult:
        result = CollectorResult(source_name=self.name())

        try:
            alerts = self._load_alerts()
        except (FileNotFoundError, ValueError) as exc:
            result.errors.append(str(exc))
            return result

        result.raw_count = len(alerts)

        for index, alert in enumerate(alerts):
            if not isinstance(alert, dict):
                result.errors.append(
                    f"item {index}: not an object"
                )
                continue
            try:
                event = self._convert(alert, index=index)
                result.events.append(event)
            except Exception as exc:  # noqa: BLE001
                result.errors.append(f"item {index}: {exc}")

        return result

    # -------------------------------------------------------------------
    # Loading
    # -------------------------------------------------------------------

    def _load_alerts(self) -> list[dict]:
        src = self._source

        if isinstance(src, dict):
            return [src]

        if isinstance(src, list):
            return src

        if isinstance(src, (str, Path)):
            path = Path(src)
            if not path.exists():
                raise FileNotFoundError(
                    f"wazuh source not found: {path}"
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

        # Coba JSON array dulu
        try:
            data = json.loads(text)
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                # Mungkin {"alerts": [...]}
                if "alerts" in data and isinstance(data["alerts"], list):
                    return data["alerts"]
                return [data]
        except json.JSONDecodeError:
            pass

        # Fallback: NDJSON (newline-delimited JSON)
        alerts: list[dict] = []
        for line_no, line in enumerate(text.splitlines(), 1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    alerts.append(item)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"invalid JSON at line {line_no}: {exc.msg}"
                ) from exc

        return alerts

    # -------------------------------------------------------------------
    # Conversion
    # -------------------------------------------------------------------

    def _convert(
        self, alert: dict, *, index: int
    ) -> Event:
        rule = alert.get("rule") or {}
        agent = alert.get("agent") or {}

        rule_id = str(rule.get("id", "")) or None
        rule_name = str(rule.get("description", "")) or None
        rule_level = rule.get("level")
        try:
            rule_level_int = int(rule_level) if rule_level is not None else None
        except (ValueError, TypeError):
            rule_level_int = None

        severity = wazuh_level_to_severity(rule_level_int or 0)

        platform = _detect_platform(alert)
        category = _detect_category(alert)

        # event_type: gunakan deskripsi rule kalau ada
        event_type = (
            rule_name
            or f"wazuh_event_{rule_id or 'unknown'}"
        ).lower().replace(" ", "_")

        mitre_techniques, mitre_tactics = _extract_mitre(alert)

        host = None
        if isinstance(agent, dict):
            host = agent.get("name") or agent.get("id")

        user = None
        process = _extract_process(alert)
        if process and process.user:
            user = process.user

        # event_id: pakai alert id atau fallback
        event_id = str(
            alert.get("id") or f"wazuh-{index}"
        )

        ts = _parse_wazuh_timestamp(alert.get("timestamp"))

        # Tags: rule groups
        tags: list[str] = []
        groups = rule.get("groups") if isinstance(rule, dict) else None
        if isinstance(groups, list):
            tags = [str(g).lower() for g in groups if g]

        return Event(
            event_id=event_id,
            timestamp=ts,
            source=EventSource.WAZUH,
            source_reliability=SourceReliability.B,
            platform=platform,
            category=category,
            event_type=event_type,
            severity=severity,
            host=str(host) if host else None,
            user=str(user) if user else None,
            process=process,
            rule_id=rule_id,
            rule_name=rule_name,
            rule_level=rule_level_int,
            mitre_techniques=mitre_techniques,
            mitre_tactics=mitre_tactics,
            tags=tags,
            raw_data=alert,
        )


__all__ = [
    "WazuhCollector",
    "wazuh_level_to_severity",
    "WAZUH_LEVEL_TO_SEVERITY",
]
