from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


# ===========================================================================
# Constants
# ===========================================================================

SCHEMA_VERSION: str = "1.0"

SEVERITY_MIN: int = 0
SEVERITY_MAX: int = 100


# ===========================================================================
# Enums — Telemetry Source (bukan platform)
# ===========================================================================

class EventSource(str, Enum):
    """
    Sumber telemetry. Menjawab: 'dari mana event ini datang?'

    Bukan platform/OS. Lihat Platform untuk dimensi OS.
    """
    WAZUH = "wazuh"
    SYSMON = "sysmon"
    EDR = "edr"
    CLOUD = "cloud"           # CloudTrail, Azure Activity, GCP Audit
    NETWORK = "network"       # Zeek, Suricata, firewall
    IDENTITY = "identity"     # AD, Okta, Entra ID
    APPLICATION = "application"
    MANUAL = "manual"         # input analis


# ===========================================================================
# Enums — Platform / OS
# ===========================================================================

class Platform(str, Enum):
    """
    Platform/OS. Menjawab: 'sistem apa yang menghasilkan event ini?'

    Kombinasikan dengan EventSource.

    Contoh:
        source=sysmon, platform=windows
        source=wazuh,  platform=linux
        source=edr,    platform=macos
        source=cloud,  platform=cloud
    """
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    CLOUD = "cloud"
    NETWORK = "network"
    UNKNOWN = "unknown"


# ===========================================================================
# Enums — Category (isi event, bukan tactic)
# ===========================================================================

class EventCategory(str, Enum):
    """
    Kategori event: menjawab 'event ini tentang apa?'

    Ini BUKAN MITRE tactic. Tactic menjawab tahap attack lifecycle,
    category menjawab jenis objek/aktivitas.

    Contoh:
        category = PROCESS
        mitre_technique = T1059.001
        mitre_tactic = TA0002

    Tiga layer ini independen dan bisa berbeda.
    """
    PROCESS = "process"
    FILE = "file"
    REGISTRY = "registry"
    NETWORK = "network"
    DNS = "dns"
    HTTP = "http"
    AUTHENTICATION = "authentication"
    ACCOUNT = "account"
    CONFIGURATION = "configuration"
    OTHER = "other"


# ===========================================================================
# Enums — Reliability
# ===========================================================================

class SourceReliability(str, Enum):
    """
    NATO Admiralty Code — keandalan sumber.
    Dipakai untuk confidence scoring, bukan dari LLM.
    """
    A = "completely_reliable"
    B = "usually_reliable"
    C = "fairly_reliable"
    D = "not_usually_reliable"
    E = "unreliable"
    F = "cannot_be_judged"


# ===========================================================================
# Enums — Detail konteks
# ===========================================================================

class IntegrityLevel(str, Enum):
    UNTRUSTED = "Untrusted"
    LOW = "Low"
    MEDIUM = "Medium"
    MEDIUM_PLUS = "Medium Plus"
    HIGH = "High"
    SYSTEM = "System"
    PROTECTED = "Protected"
    UNKNOWN = "Unknown"


class NetworkDirection(str, Enum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"
    LATERAL = "lateral"
    UNKNOWN = "unknown"


class RegistryOperation(str, Enum):
    CREATE = "create"
    MODIFY = "modify"
    DELETE = "delete"
    READ = "read"
    RENAME = "rename"
    UNKNOWN = "unknown"


# ===========================================================================
# Sub-models — Context
# ===========================================================================

class UserContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    domain: str | None = None
    sid: str | None = None
    logon_id: str | None = None
    logon_type: int | None = None
    session_id: int | None = None
    integrity_level: IntegrityLevel | None = None
    is_admin: bool | None = None
    is_service_account: bool | None = None


class ProcessContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    name: str | None = None
    pid: int | None = None
    ppid: int | None = None
    guid: str | None = None

    parent_name: str | None = None
    parent_pid: int | None = None
    parent_guid: str | None = None

    command_line: str | None = None
    image_path: str | None = None

    user: str | None = None
    integrity_level: IntegrityLevel | None = None

    hashes: dict[str, str] = Field(default_factory=dict)

    signed: bool | None = None
    signer: str | None = None
    company: str | None = None
    product: str | None = None
    description: str | None = None

    is_lolbin: bool | None = None
    is_elevated: bool | None = None

    @field_validator("hashes")
    @classmethod
    def _normalize_hashes(cls, v: dict[str, str]) -> dict[str, str]:
        return {k.lower(): val.lower() for k, val in v.items() if val}


class NetworkContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    source_ip: str | None = None
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    direction: NetworkDirection | None = None

    hostname: str | None = None
    url: str | None = None
    user_agent: str | None = None

    bytes_sent: int | None = None
    bytes_received: int | None = None

    geo_country: str | None = None
    asn: str | None = None

    @field_validator("protocol")
    @classmethod
    def _normalize_protocol(cls, v: str | None) -> str | None:
        return v.upper() if v else v


class FileContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    path: str | None = None
    name: str | None = None
    extension: str | None = None
    size: int | None = None

    hashes: dict[str, str] = Field(default_factory=dict)

    signed: bool | None = None
    signer: str | None = None

    created_at: datetime | None = None
    modified_at: datetime | None = None
    accessed_at: datetime | None = None

    operation: Literal["create", "modify", "delete", "read", "rename"] | None = None

    @field_validator("hashes")
    @classmethod
    def _normalize_hashes(cls, v: dict[str, str]) -> dict[str, str]:
        return {k.lower(): val.lower() for k, val in v.items() if val}


class RegistryContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    key: str | None = None
    value_name: str | None = None
    value_data: str | None = None
    value_type: str | None = None
    operation: RegistryOperation | None = None

    is_persistence_key: bool | None = None


class DnsContext(BaseModel):
    model_config = ConfigDict(extra="allow")

    query: str | None = None
    query_type: str | None = None
    response: list[str] = Field(default_factory=list)
    response_code: str | None = None
    is_dga: bool | None = None
    is_tunneling: bool | None = None


# ===========================================================================
# Main Event
# ===========================================================================

class Event(BaseModel):
    """
    Canonical security event AegisSOC.

    Blok field:
    - Identity
    - Time
    - Classification (source, platform, category, event_type)
    - Severity
    - Actor (host, user, domain)
    - Context (user, process, network, file, registry, dns)
    - Detection (rule, MITRE)
    - Extensibility (raw_data, metadata)

    Catatan:
    - TIDAK ADA field ledger (evidence_id, prev_hash, hash).
      Itu tanggung jawab Evidence & Evidence Ledger.
    - TIDAK ADA risk_score. Itu milik Investigation Case.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    schema_version: str = Field(default=SCHEMA_VERSION)

    tenant_id: str | None = None
    investigation_id: str | None = None
    correlation_id: str | None = None

    # -----------------------------------------------------------------------
    # Time
    # -----------------------------------------------------------------------
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    # -----------------------------------------------------------------------
    # Classification
    # -----------------------------------------------------------------------
    source: EventSource                              # telemetry
    platform: Platform = Platform.UNKNOWN            # OS / environment
    category: EventCategory = EventCategory.OTHER    # isi event, bukan tactic
    event_type: str
    tags: list[str] = Field(default_factory=list)

    source_reliability: SourceReliability = SourceReliability.C

    # -----------------------------------------------------------------------
    # Severity (raw from source, bukan risk score)
    # -----------------------------------------------------------------------
    severity: int = Field(default=0, ge=SEVERITY_MIN, le=SEVERITY_MAX)

    # -----------------------------------------------------------------------
    # Actor
    # -----------------------------------------------------------------------
    host: str | None = None
    user: str | None = None
    domain: str | None = None

    # -----------------------------------------------------------------------
    # Context
    # -----------------------------------------------------------------------
    user_context: UserContext | None = None
    process: ProcessContext | None = None
    network: NetworkContext | None = None
    file: FileContext | None = None
    registry: RegistryContext | None = None
    dns: DnsContext | None = None

    # -----------------------------------------------------------------------
    # Detection
    # -----------------------------------------------------------------------
    rule_id: str | None = None
    rule_name: str | None = None
    rule_level: int | None = None

    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)

    # -----------------------------------------------------------------------
    # Extensibility
    # -----------------------------------------------------------------------
    raw_data: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # =======================================================================
    # Validators
    # =======================================================================

    @field_validator("timestamp", "ingested_at")
    @classmethod
    def _ensure_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            return v.replace(tzinfo=timezone.utc)
        return v.astimezone(timezone.utc)

    @field_validator("mitre_techniques")
    @classmethod
    def _validate_mitre_techniques(cls, v: list[str]) -> list[str]:
        for t in v:
            if not t.startswith("T") or not t[1:].replace(".", "").isdigit():
                raise ValueError(f"Invalid MITRE technique ID: {t}")
        return sorted(set(v))

    @field_validator("mitre_tactics")
    @classmethod
    def _validate_mitre_tactics(cls, v: list[str]) -> list[str]:
        for t in v:
            if not t.startswith("TA") or not t[2:].isdigit():
                raise ValueError(f"Invalid MITRE tactic ID: {t}")
        return sorted(set(v))

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, v: list[str]) -> list[str]:
        return sorted({t.strip().lower() for t in v if t.strip()})

    @model_validator(mode="after")
    def _infer_category(self) -> "Event":
        """
        Jika category = OTHER tapi ada context spesifik, infer otomatis.
        Ini hanya default — bukan source of truth.
        Urutan penting: HTTP sebelum NETWORK.
        """
        if self.category == EventCategory.OTHER:
            if self.process is not None:
                object.__setattr__(self, "category", EventCategory.PROCESS)
            elif self.registry is not None:
                object.__setattr__(self, "category", EventCategory.REGISTRY)
            elif self.dns is not None:
                object.__setattr__(self, "category", EventCategory.DNS)
            elif self.network is not None and (
                self.network.url or self.network.user_agent
            ):
                object.__setattr__(self, "category", EventCategory.HTTP)
            elif self.file is not None:
                object.__setattr__(self, "category", EventCategory.FILE)
            elif self.network is not None:
                object.__setattr__(self, "category", EventCategory.NETWORK)
        return self

    # =======================================================================
    # Serializers
    # =======================================================================

    @field_serializer("timestamp", "ingested_at")
    def _serialize_dt(self, v: datetime) -> str:
        return v.isoformat()

    # =======================================================================
    # Properties
    # =======================================================================

    @property
    def is_process_event(self) -> bool:
        return self.category == EventCategory.PROCESS

    @property
    def is_network_event(self) -> bool:
        return self.category in (
            EventCategory.NETWORK,
            EventCategory.DNS,
            EventCategory.HTTP,
        )

    @property
    def is_windows(self) -> bool:
        return self.platform == Platform.WINDOWS

    @property
    def is_linux(self) -> bool:
        return self.platform == Platform.LINUX

    @property
    def is_high_severity(self) -> bool:
        return self.severity >= 70

    # =======================================================================
    # Helper Methods
    # =======================================================================

    def fingerprint(self) -> str:
        """
        Fingerprint stabil untuk deduplikasi.

        Tidak termasuk:
        - event_id
        - timestamp
        - ingested_at

        TODO v2: pisahkan menjadi dua konsep:
            - content_fingerprint(): identitas substantif event
            - dedup_fingerprint(): content + temporal/context window
        """
        payload = {
            "source": self.source.value,
            "platform": self.platform.value,
            "category": self.category.value,
            "event_type": self.event_type,
            "host": self.host,
            "user": self.user,
            "process_name": self.process.name if self.process else None,
            "process_pid": self.process.pid if self.process else None,
            "parent_name": self.process.parent_name if self.process else None,
            "command_line": self.process.command_line if self.process else None,
            "file_path": self.file.path if self.file else None,
            "registry_key": self.registry.key if self.registry else None,
            "src_ip": self.network.source_ip if self.network else None,
            "dst_ip": self.network.destination_ip if self.network else None,
            "rule_id": self.rule_id,
        }
        blob = json.dumps(payload, sort_keys=True, default=str)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def to_graph_node(self) -> dict[str, Any]:
        """Representasi node Event untuk Investigation Graph."""
        return {
            "id": self.event_id,
            "type": "Event",
            "source": self.source.value,
            "platform": self.platform.value,
            "category": self.category.value,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "host": self.host,
            "user": self.user,
            "severity": self.severity,
            "mitre_techniques": list(self.mitre_techniques),
            "mitre_tactics": list(self.mitre_tactics),
            "tags": list(self.tags),
        }

    def to_entities(self) -> list[dict[str, Any]]:
        """
        Convenience helper: ekstrak entitas dari event.

        CATATAN ARSITEKTUR:
        Ini BUKAN source of truth graph. Entity resmi dibangun oleh
        internal/graph/entity_extractor.py, karena entity juga bisa
        berasal dari:
            - Threat Intelligence
            - DNS enrichment
            - WHOIS
            - VirusTotal
            - Analyst input
            - Previous investigation

        Method ini hanya dipakai untuk kebutuhan lokal / debug / test.
        """
        entities: list[dict[str, Any]] = []

        if self.host:
            entities.append({
                "type": "Host",
                "value": self.host,
                "properties": {"platform": self.platform.value},
            })

        if self.user:
            entities.append({
                "type": "User",
                "value": self.user,
                "properties": {
                    "domain": self.domain,
                    "integrity_level": (
                        self.user_context.integrity_level.value
                        if self.user_context and self.user_context.integrity_level
                        else None
                    ),
                },
            })

        if self.process:
            if self.process.name:
                entities.append({
                    "type": "Process",
                    "value": self.process.name,
                    "properties": {
                        "pid": self.process.pid,
                        "ppid": self.process.ppid,
                        "path": self.process.image_path,
                        "hashes": dict(self.process.hashes),
                        "is_lolbin": self.process.is_lolbin,
                    },
                })
            if self.process.parent_name:
                entities.append({
                    "type": "Process",
                    "value": self.process.parent_name,
                    "properties": {
                        "pid": self.process.parent_pid,
                        "role": "parent",
                    },
                })

        if self.file and self.file.path:
            entities.append({
                "type": "File",
                "value": self.file.path,
                "properties": {
                    "hashes": dict(self.file.hashes),
                    "size": self.file.size,
                    "signed": self.file.signed,
                },
            })

        if self.registry and self.registry.key:
            entities.append({
                "type": "Registry",
                "value": self.registry.key,
                "properties": {
                    "value_name": self.registry.value_name,
                    "value_data": self.registry.value_data,
                    "operation": (
                        self.registry.operation.value
                        if self.registry.operation
                        else None
                    ),
                    "is_persistence_key": self.registry.is_persistence_key,
                },
            })

        if self.network:
            if self.network.source_ip:
                entities.append({
                    "type": "IP",
                    "value": self.network.source_ip,
                    "properties": {
                        "port": self.network.source_port,
                        "role": "source",
                    },
                })
            if self.network.destination_ip:
                entities.append({
                    "type": "IP",
                    "value": self.network.destination_ip,
                    "properties": {
                        "port": self.network.destination_port,
                        "role": "destination",
                        "country": self.network.geo_country,
                        "asn": self.network.asn,
                    },
                })

        if self.dns and self.dns.query:
            entities.append({
                "type": "Domain",
                "value": self.dns.query,
                "properties": {"response": list(self.dns.response)},
            })

        for tech in self.mitre_techniques:
            entities.append({"type": "MITRE", "value": tech, "properties": {}})

        return entities


# ===========================================================================
# Type alias
# ===========================================================================

EventList = list[Event]
