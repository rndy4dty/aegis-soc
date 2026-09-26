from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


SCHEMA_VERSION: str = "1.0"

CONFIDENCE_MIN: float = 0.0
CONFIDENCE_MAX: float = 1.0

WEIGHT_MIN: float = 0.0
WEIGHT_MAX: float = 10.0


# ===========================================================================
# Enums — Tipe Evidence
# ===========================================================================

class EvidenceType(str, Enum):
    """
    Jenis bukti. Menjawab: 'bukti ini berasal dari domain apa?'
    """
    EVENT = "event"
    ALERT = "alert"
    PROCESS = "process"
    NETWORK = "network"
    FILE = "file"
    REGISTRY = "registry"
    DNS = "dns"
    AUTHENTICATION = "authentication"
    THREAT_INTEL = "threat_intel"
    ENRICHMENT = "enrichment"
    ANALYST = "analyst"
    DERIVED = "derived"
    MEMORY = "memory"


class EvidenceStrength(str, Enum):
    """
    Kekuatan evidence secara kualitatif.
    Ini penilaian taksonomi, bukan skor.
    """
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CRITICAL = "critical"


class EvidenceAssessment(str, Enum):
    """
    Arah hubungan evidence terhadap hipotesis.
    """
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    NEUTRAL = "neutral"


class SourceReliability(str, Enum):
    """
    NATO Admiralty Code. Dipakai untuk confidence scoring.
    """
    A = "completely_reliable"
    B = "usually_reliable"
    C = "fairly_reliable"
    D = "not_usually_reliable"
    E = "unreliable"
    F = "cannot_be_judged"


# ===========================================================================
# Sub-model — Provenance
# ===========================================================================

class EvidenceProvenance(BaseModel):
    """
    Menjelaskan dari mana evidence berasal, bagaimana diperoleh,
    dan oleh komponen mana.
    """

    model_config = ConfigDict(extra="allow")

    # -- Asal -------------------------------------------------------------
    source: str
    source_reliability: SourceReliability = SourceReliability.C

    # -- Pengumpul --------------------------------------------------------
    collector: str | None = None
    collector_version: str | None = None

    # -- Derivasi ---------------------------------------------------------
    parent_event_id: str | None = None
    derived_from: list[str] = Field(default_factory=list)
    # evidence_id lain yang menjadi dasar evidence ini
    transformation: str | None = None
    # misal: "Event correlation", "Risk scoring", "MITRE mapping"

    # -- Waktu ------------------------------------------------------------
    collected_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # -- Referensi eksternal ---------------------------------------------
    external_ref: str | None = None
    external_hash: str | None = None

    # ====================================================================
    # Validators
    # ====================================================================

    @field_validator("collected_at")
    @classmethod
    def _normalize_collected_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("collected_at")
    def _serialize_collected_at(self, value: datetime) -> str:
        return value.isoformat()


# ===========================================================================
# Sub-model — Hypothesis Link
# ===========================================================================

class HypothesisLink(BaseModel):
    """
    Hubungan eksplisit antara Evidence dan Hypothesis.

    Satu Evidence bisa:
    - mendukung Hypothesis A
    - menentang Hypothesis B
    - netral terhadap Hypothesis C

    Karena itu assessment disimpan per-link, bukan global di Evidence.
    """

    model_config = ConfigDict(extra="forbid")

    hypothesis_id: str
    assessment: EvidenceAssessment
    weight: float = Field(default=1.0, ge=WEIGHT_MIN, le=WEIGHT_MAX)
    rationale: str | None = None

    @field_validator("hypothesis_id")
    @classmethod
    def _validate_hypothesis_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("hypothesis_id cannot be empty")
        return value.strip()


# ===========================================================================
# Sub-model — Verification
# ===========================================================================

class EvidenceVerification(BaseModel):
    """
    Status verifikasi analis.
    """

    model_config = ConfigDict(extra="forbid")

    verified: bool = False
    verified_by: str | None = None
    verified_at: datetime | None = None
    method: str | None = None
    notes: str | None = None

    @field_validator("verified_at")
    @classmethod
    def _normalize_verified_at(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("verified_at")
    def _serialize_verified_at(
        self, value: datetime | None
    ) -> str | None:
        return value.isoformat() if value else None

    @model_validator(mode="after")
    def _consistency(self) -> "EvidenceVerification":
        if self.verified:
            if not self.verified_by:
                raise ValueError(
                    "verified=True requires verified_by"
                )
            if self.verified_at is None:
                raise ValueError(
                    "verified=True requires verified_at"
                )
        return self


# ===========================================================================
# Sub-model — Integrity
# ===========================================================================

class EvidenceIntegrity(BaseModel):
    """
    Integrity metadata untuk evidence.
    content_hash dihitung dari isi evidence, bukan identitas.
    """

    model_config = ConfigDict(extra="forbid")

    content_hash: str | None = None
    hash_algorithm: str = "sha256"


# ===========================================================================
# Main Evidence
# ===========================================================================

class Evidence(BaseModel):
    """
    Canonical investigation evidence AegisSOC.

    Struktur:
    - Identity
    - Classification
    - Observation
    - Data
    - References
    - Hypothesis Links
    - Verification
    - Provenance
    - Integrity
    - Graph
    - Extensibility
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
    )

    # --------------------------------------------------------------------
    # Identity
    # --------------------------------------------------------------------
    evidence_id: str = Field(default_factory=lambda: f"E-{uuid4().hex[:12]}")
    schema_version: str = SCHEMA_VERSION

    tenant_id: str | None = None
    case_id: str | None = None

    # --------------------------------------------------------------------
    # Classification
    # --------------------------------------------------------------------
    evidence_type: EvidenceType
    strength: EvidenceStrength = EvidenceStrength.MODERATE

    # --------------------------------------------------------------------
    # Observation
    # --------------------------------------------------------------------
    title: str = Field(min_length=1)
    description: str | None = None

    observed_at: datetime | None = None

    confidence: float = Field(
        default=0.0,
        ge=CONFIDENCE_MIN,
        le=CONFIDENCE_MAX,
    )

    # --------------------------------------------------------------------
    # Data (structured observation)
    # --------------------------------------------------------------------
    data: dict[str, Any] = Field(default_factory=dict)

    # --------------------------------------------------------------------
    # References
    # --------------------------------------------------------------------
    event_id: str | None = None
    alert_id: str | None = None

    # --------------------------------------------------------------------
    # Hypothesis Links
    # --------------------------------------------------------------------
    hypothesis_links: list[HypothesisLink] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Verification
    # --------------------------------------------------------------------
    verification: EvidenceVerification = Field(
        default_factory=EvidenceVerification
    )

    # --------------------------------------------------------------------
    # Provenance
    # --------------------------------------------------------------------
    provenance: EvidenceProvenance

    # --------------------------------------------------------------------
    # Integrity
    # --------------------------------------------------------------------
    integrity: EvidenceIntegrity = Field(
        default_factory=EvidenceIntegrity
    )

    # --------------------------------------------------------------------
    # Graph
    # --------------------------------------------------------------------
    entity_ids: list[str] = Field(default_factory=list)
    relationship_ids: list[str] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Extensibility
    # --------------------------------------------------------------------
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ====================================================================
    # Validators
    # ====================================================================

    @field_validator("observed_at")
    @classmethod
    def _normalize_observed_at(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("entity_ids", "relationship_ids")
    @classmethod
    def _normalize_ids(cls, values: list[str]) -> list[str]:
        return sorted({v.strip() for v in values if v and v.strip()})

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, values: list[str]) -> list[str]:
        return sorted({v.strip().lower() for v in values if v and v.strip()})

    @field_serializer("observed_at")
    def _serialize_observed_at(
        self, value: datetime | None
    ) -> str | None:
        return value.isoformat() if value else None

    # ====================================================================
    # Properties
    # ====================================================================

    @property
    def is_verified(self) -> bool:
        return self.verification.verified

    @property
    def is_strong(self) -> bool:
        return self.strength in (
            EvidenceStrength.STRONG,
            EvidenceStrength.CRITICAL,
        )

    @property
    def is_critical(self) -> bool:
        return self.strength == EvidenceStrength.CRITICAL

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    @property
    def is_derived(self) -> bool:
        return self.evidence_type == EvidenceType.DERIVED

    @property
    def supports_hypotheses(self) -> list[str]:
        return [
            link.hypothesis_id
            for link in self.hypothesis_links
            if link.assessment == EvidenceAssessment.SUPPORTS
        ]

    @property
    def contradicts_hypotheses(self) -> list[str]:
        return [
            link.hypothesis_id
            for link in self.hypothesis_links
            if link.assessment == EvidenceAssessment.CONTRADICTS
        ]

    # ====================================================================
    # Integrity
    # ====================================================================

    def canonical_payload(self) -> dict[str, Any]:
        """
        Payload deterministik untuk integrity hashing.

        Dikecualikan:
        - evidence_id            (identity, bukan content)
        - tenant_id, case_id     (routing)
        - verification           (analyst metadata)
        - integrity              (output)
        - tags, metadata         (decorative / extensibility)
        - entity_ids,
          relationship_ids       (graph projection)
        """
        return {
            "schema_version": self.schema_version,
            "evidence_type": self.evidence_type.value,
            "strength": self.strength.value,
            "title": self.title,
            "description": self.description,
            "observed_at": (
                self.observed_at.isoformat()
                if self.observed_at is not None
                else None
            ),
            "confidence": self.confidence,
            "data": self.data,
            "event_id": self.event_id,
            "alert_id": self.alert_id,
            "hypothesis_links": [
                link.model_dump(mode="json")
                for link in self.hypothesis_links
            ],
            "provenance": {
                "source": self.provenance.source,
                "source_reliability": self.provenance.source_reliability.value,
                "collector": self.provenance.collector,
                "collector_version": self.provenance.collector_version,
                "parent_event_id": self.provenance.parent_event_id,
                "derived_from": list(self.provenance.derived_from),
                "transformation": self.provenance.transformation,
                "external_ref": self.provenance.external_ref,
                "external_hash": self.provenance.external_hash,
            },
        }

    def calculate_content_hash(self) -> str:
        """
        SHA-256 dari canonical payload.

        Deterministik: urutan key sama, tanpa spasi, ASCII-only.
        """
        payload = self.canonical_payload()
        blob = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def with_content_hash(self) -> "Evidence":
        """
        Kembalikan Evidence baru dengan integrity.content_hash terisi.
        """
        return self.model_copy(
            update={
                "integrity": self.integrity.model_copy(
                    update={
                        "content_hash": self.calculate_content_hash(),
                    }
                )
            }
        )

    def verify_content_hash(self) -> bool:
        """
        Cek apakah integrity.content_hash masih sesuai isi evidence.
        """
        if not self.integrity.content_hash:
            return False
        return self.integrity.content_hash == self.calculate_content_hash()

    # ====================================================================
    # Verification Helper
    # ====================================================================

    def mark_verified(
        self,
        *,
        verified_by: str,
        method: str | None = None,
        notes: str | None = None,
    ) -> "Evidence":
        """
        Tandai evidence sebagai terverifikasi oleh analis.
        """
        return self.model_copy(
            update={
                "verification": EvidenceVerification(
                    verified=True,
                    verified_by=verified_by,
                    verified_at=datetime.now(timezone.utc),
                    method=method,
                    notes=notes,
                )
            }
        )

    # ====================================================================
    # Hypothesis Helpers
    # ====================================================================

    def get_hypothesis_link(
        self, hypothesis_id: str
    ) -> HypothesisLink | None:
        for link in self.hypothesis_links:
            if link.hypothesis_id == hypothesis_id:
                return link
        return None

    # ====================================================================
    # Graph Helpers
    # ====================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.evidence_id,
            "type": "Evidence",
            "evidence_type": self.evidence_type.value,
            "strength": self.strength.value,
            "title": self.title,
            "confidence": self.confidence,
            "verified": self.verification.verified,
            "case_id": self.case_id,
            "tags": list(self.tags),
        }

    def to_hypothesis_edges(self) -> list[dict[str, Any]]:
        """
        Edge Evidence → Hypothesis.

        Format konsisten dengan test:
            {
                "source": evidence_id,
                "target": hypothesis_id,
                "relationship": "SUPPORTS" | "CONTRADICTS" | "NEUTRAL",
                "properties": {"weight": ..., "rationale": ...},
            }
        """
        edges: list[dict[str, Any]] = []

        for link in self.hypothesis_links:
            edges.append({
                "source": self.evidence_id,
                "source_type": "Evidence",
                "target": link.hypothesis_id,
                "target_type": "Hypothesis",
                "relationship": link.assessment.value.upper(),
                "properties": {
                    "weight": link.weight,
                    "rationale": link.rationale,
                },
            })

        return edges

    def to_reference_edges(self) -> list[dict[str, Any]]:
        """
        Edge Evidence → Event / Alert / Entity / Evidence.
        """
        edges: list[dict[str, Any]] = []

        if self.event_id:
            edges.append({
                "source": self.evidence_id,
                "source_type": "Evidence",
                "target": self.event_id,
                "target_type": "Event",
                "relationship": "REFERENCES",
                "properties": {},
            })

        if self.alert_id:
            edges.append({
                "source": self.evidence_id,
                "source_type": "Evidence",
                "target": self.alert_id,
                "target_type": "Alert",
                "relationship": "REFERENCES",
                "properties": {},
            })

        for parent_id in self.provenance.derived_from:
            edges.append({
                "source": self.evidence_id,
                "source_type": "Evidence",
                "target": parent_id,
                "target_type": "Evidence",
                "relationship": "DERIVED_FROM",
                "properties": {},
            })

        for entity_id in self.entity_ids:
            edges.append({
                "source": self.evidence_id,
                "source_type": "Evidence",
                "target": entity_id,
                "target_type": "Entity",
                "relationship": "ABOUT",
                "properties": {},
            })

        return edges

    # ====================================================================
    # Factory
    # ====================================================================

    @classmethod
    def from_event(
        cls,
        event: Any,
        *,
        title: str,
        description: str | None = None,
        evidence_type: EvidenceType,
        strength: EvidenceStrength = EvidenceStrength.MODERATE,
        confidence: float | None = None,
        observed_at: datetime | None = None,
        data: dict[str, Any] | None = None,
        provenance: EvidenceProvenance | None = None,
    ) -> "Evidence":
        """
        Konstruksi Evidence dari Event.

        `event` boleh berupa objek Event atau dict yang punya
        setidaknya `event_id` dan (opsional) `source`.

        Catatan:
        - `confidence` masuk sebagai field Evidence, bukan ke `data`.
        - `observed_at` default = timestamp event jika tersedia.
        """

        # -- Extract event fields (duck typing) ---------------------------
        if isinstance(event, dict):
            event_id = event.get("event_id")
            event_source = event.get("source")
            event_timestamp = event.get("timestamp")
        else:
            event_id = getattr(event, "event_id", None)
            event_source = getattr(event, "source", None)
            event_timestamp = getattr(event, "timestamp", None)

        if not event_id:
            raise ValueError("event must provide event_id")

        # -- Normalize source ---------------------------------------------
        if hasattr(event_source, "value"):
            source_str = event_source.value
        elif event_source is not None:
            source_str = str(event_source)
        else:
            source_str = "unknown"

        # -- Normalize observed_at ----------------------------------------
        if observed_at is None:
            if isinstance(event_timestamp, datetime):
                observed_at = event_timestamp
            elif isinstance(event_timestamp, str):
                try:
                    observed_at = datetime.fromisoformat(
                        event_timestamp.replace("Z", "+00:00")
                    )
                except ValueError:
                    observed_at = None

        # -- Build provenance ---------------------------------------------
        if provenance is None:
            provenance = EvidenceProvenance(
                source=source_str,
                collector="event_bridge",
                parent_event_id=str(event_id),
                transformation="Event to Evidence",
            )

        # -- Confidence ---------------------------------------------------
        if confidence is None:
            confidence = 0.0

        return cls(
            evidence_id=f"E-{event_id}",
            event_id=str(event_id),
            evidence_type=evidence_type,
            strength=strength,
            title=title,
            description=description,
            observed_at=observed_at,
            confidence=confidence,
            data=data or {},
            provenance=provenance,
        )


# ===========================================================================
# Type alias
# ===========================================================================

EvidenceList = list[Evidence]
