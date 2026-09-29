"""
LOLBin detection.

Living-off-the-land binaries: binary bawaan Windows yang sering
disalahgunakan untuk eksekusi, download, atau bypass.

Referensi: https://lolbas-project.github.io/
"""

from __future__ import annotations

from internal.detection.base import (
    DetectionFinding,
    Severity,
)
from pkg.models.event import Event, EventCategory


# Mapping LOLBin name → (severity, description, techniques)
LOLBIN_REGISTRY: dict[str, tuple[Severity, str, list[str]]] = {
    "certutil.exe": (
        Severity.HIGH,
        "certutil can download files or decode payloads",
        ["T1140", "T1105"],
    ),
    "bitsadmin.exe": (
        Severity.HIGH,
        "bitsadmin can download files via BITS",
        ["T1197", "T1105"],
    ),
    "mshta.exe": (
        Severity.CRITICAL,
        "mshta executes HTA payloads",
        ["T1218.005"],
    ),
    "wscript.exe": (
        Severity.MEDIUM,
        "wscript executes VBS/JS scripts",
        ["T1059.005"],
    ),
    "cscript.exe": (
        Severity.MEDIUM,
        "cscript executes VBS/JS scripts via console",
        ["T1059.005"],
    ),
    "regsvr32.exe": (
        Severity.CRITICAL,
        "regsvr32 can bypass application whitelisting",
        ["T1218.010"],
    ),
    "rundll32.exe": (
        Severity.HIGH,
        "rundll32 can execute DLL exports",
        ["T1218.011"],
    ),
    "msiexec.exe": (
        Severity.HIGH,
        "msiexec can install MSI packages from remote",
        ["T1218.007"],
    ),
    "installutil.exe": (
        Severity.HIGH,
        "installutil can execute .NET assemblies",
        ["T1218.004"],
    ),
    "msbuild.exe": (
        Severity.HIGH,
        "msbuild can execute inline tasks",
        ["T1127.001"],
    ),
    "csc.exe": (
        Severity.MEDIUM,
        "csc compiles C# on target",
        ["T1027.004"],
    ),
    "regasm.exe": (
        Severity.HIGH,
        "regasm can execute .NET assemblies",
        ["T1218.009"],
    ),
    "regsvcs.exe": (
        Severity.HIGH,
        "regsvcs can execute .NET assemblies",
        ["T1218.009"],
    ),
    "forfiles.exe": (
        Severity.MEDIUM,
        "forfiles can execute arbitrary commands",
        ["T1202"],
    ),
    "pcalua.exe": (
        Severity.HIGH,
        "pcalua can launch executables via compatibility",
        ["T1202"],
    ),
    "wmic.exe": (
        Severity.HIGH,
        "wmic can execute and query WMI",
        ["T1047"],
    ),
    "at.exe": (
        Severity.MEDIUM,
        "at schedules commands",
        ["T1053.002"],
    ),
    "schtasks.exe": (
        Severity.MEDIUM,
        "schtasks schedules tasks",
        ["T1053.005"],
    ),
    "sdbinst.exe": (
        Severity.HIGH,
        "sdbinst installs shim databases",
        ["T1546.011"],
    ),
    "xwizard.exe": (
        Severity.MEDIUM,
        "xwizard can run custom class registration",
        ["T1218"],
    ),
    "expand.exe": (
        Severity.LOW,
        "expand decompresses CAB files",
        ["T1140"],
    ),
    "extrac32.exe": (
        Severity.MEDIUM,
        "extrac32 extracts CAB or downloads via IE",
        ["T1105", "T1140"],
    ),
    "findstr.exe": (
        Severity.LOW,
        "findstr can read files via regex",
        ["T1552.001"],
    ),
    "ftp.exe": (
        Severity.MEDIUM,
        "ftp can transfer files",
        ["T1105"],
    ),
    "replace.exe": (
        Severity.LOW,
        "replace can copy files",
        ["T1105"],
    ),
}


def _basename(path: str | None) -> str | None:
    if not path:
        return None
    p = str(path).replace("/", "\\")
    return p.rsplit("\\", 1)[-1].lower()


class LOLBinDetector:
    """
    Detector untuk LOLBin.
    """

    def __init__(
        self,
        registry: dict | None = None,
        *,
        min_severity: Severity = Severity.LOW,
    ) -> None:
        # Pakai `is not None` supaya registry={} dihormati
        # (tidak jatuh ke default).
        if registry is not None:
            self._registry = registry
        else:
            self._registry = LOLBIN_REGISTRY
        self._min_severity = min_severity

    def id(self) -> str:
        return "lolbin"

    def name(self) -> str:
        return "LOLBin Detector"

    def evaluate(self, event: Event) -> list[DetectionFinding]:
        if event.category != EventCategory.PROCESS:
            return []
        if event.process is None:
            return []

        name = _basename(event.process.name)
        if not name:
            return []

        entry = self._registry.get(name)
        if entry is None:
            return []

        severity, description, techniques = entry
        if severity.value < self._min_severity.value:
            return []

        return [
            DetectionFinding(
                rule_id=f"lolbin.{name}",
                rule_name=f"LOLBin execution: {name}",
                severity=severity,
                event_id=event.event_id,
                description=description,
                mitre_techniques=list(techniques),
                matched_fields={
                    "process.name": name,
                    "process.command_line": (
                        event.process.command_line
                    ),
                },
                metadata={"lolbin": name},
            )
        ]


__all__ = ["LOLBinDetector", "LOLBIN_REGISTRY"]
