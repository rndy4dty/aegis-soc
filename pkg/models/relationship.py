"""
Canonical relationship (graph edge) model for the AegisSOC Investigation Graph.

Relationship merepresentasikan edge berarah antar node graph.

    Entity   --HAS_HASH-->      Entity(Hash)
    Process  --SPAWNED-->       Process
    Entity   --OBSERVED_IN-->   Event
    Evidence --SUPPORTS-->      Hypothesis

Prinsip:
- Relationship adalah source of truth untuk graph edges.
- Identity substantif:
      (source_type, source_id, relationship_type, target_type, target_id)
  Fingerprint dihitung dari identity ini, BUKAN dari properties.
- Dua relationship dengan identity sama di-merge:
  provenance di-union, temporal di-extend, properties di-merge.
- Berarah. reverse() hanya boleh kalau ada inverse eksplisit.
- weight / confidence di [0, 1].
- Relationship TIDAK memutasi Entity, Event, atau Evidence.

Catatan cakupan:
- NodeType sengaja luas (Entity, Event, Evidence, Alert, dst.) karena
  graph AegisSOC mencakup lebih dari sekadar Entity.
- Model ini TIDAK memvalidasi kombinasi endpoint (misalnya
  "Investigation --HAS_HASH--> IP" ditolak). Validasi endpoint adalah
  tanggung jawab relationship builder / schema layer.
"""

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
    field_validator,
    model_validator,
)


# ===========================================================================
# Constants
# ===========================================================================

SCHEMA_VERSION: str = "1.0"

WEIGHT_MIN: float = 0.0
WEIGHT_MAX: float = 1.0

DEFAULT_WEIGHT: float = 1.0
DEFAULT_CONFIDENCE: float = 1.0

ConflictPolicy = Literal["left", "right", "raise"]
DEFAULT_CONFLICT_POLICY: ConflictPolicy = "left"

StrengthCombinePolicy = Literal["max", "avg", "left", "right"]
DEFAULT_STRENGTH_COMBINE_POLICY: StrengthCombinePolicy = "max"


# ===========================================================================
# Node type
# ===========================================================================

class NodeType(str, Enum):
    """
    Jenis node yang boleh menjadi endpoint relationship.

    Keanggotaan sengaja luas karena graph AegisSOC mencakup lebih
    dari sekadar Entity. Validasi kombinasi endpoint dilakukan di
    relationship builder, bukan di model ini.
    """
    ENTITY = "entity"
    EVENT = "event"
    EVIDENCE = "evidence"
    ALERT = "alert"
    INVESTIGATION = "investigation"
    HYPOTHESIS = "hypothesis"
    CORRELATION = "correlation"
    LEDGER_ENTRY = "ledger_entry"


# ===========================================================================
# Relationship type
# ===========================================================================

class RelationshipType(str, Enum):
    """
    Jenis edge canonical untuk Investigation Graph.
    """
    # -- Structure --------------------------------------------------------
    PARENT_OF = "parent_of"
    CHILD_OF = "child_of"
    PART_OF = "part_of"
    CONTAINS = "contains"

    # -- Process ----------------------------------------------------------
    SPAWNED = "spawned"
    EXECUTED = "executed"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    CREATED = "created"
    DELETED = "deleted"

    # -- File / Hash ------------------------------------------------------
    HAS_HASH = "has_hash"
    MATCHES_HASH = "matches_hash"

    # -- Network ----------------------------------------------------------
    CONNECTED_TO = "connected_to"
    RESOLVED_TO = "resolved_to"
    REQUESTED = "requested"
    BOUND_TO = "bound_to"

    # -- Identity ---------------------------------------------------------
    LOGGED_ON = "logged_on"
    RUN_AS = "run_as"
    OWNED_BY = "owned_by"
    MEMBER_OF = "member_of"

    # -- Investigation ----------------------------------------------------
    OBSERVED_IN = "observed_in"
    CITED_BY = "cited_by"
    REFERENCES = "references"
    DERIVED_FROM = "derived_from"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"
    TRIGGERED_BY = "triggered_by"
    INVESTIGATES = "investigates"


# ---------------------------------------------------------------------------
# Category mapping
# ---------------------------------------------------------------------------

RELATIONSHIP_CATEGORY: dict[RelationshipType, str] = {
    # -- Structure --------------------------------------------------------
    RelationshipType.PARENT_OF: "structure",
    RelationshipType.CHILD_OF: "structure",
    RelationshipType.PART_OF: "structure",
    RelationshipType.CONTAINS: "structure",

    # -- Process ----------------------------------------------------------
    RelationshipType.SPAWNED: "process",
    RelationshipType.EXECUTED: "process",
    RelationshipType.ACCESSED: "process",
    RelationshipType.MODIFIED: "process",
    RelationshipType.CREATED: "process",
    RelationshipType.DELETED: "process",

    # -- File -------------------------------------------------------------
    RelationshipType.HAS_HASH: "file",
    RelationshipType.MATCHES_HASH: "file",

    # -- Network ----------------------------------------------------------
    RelationshipType.CONNECTED_TO: "network",
    RelationshipType.RESOLVED_TO: "network",
    RelationshipType.REQUESTED: "network",
    RelationshipType.BOUND_TO: "network",

    # -- Identity ---------------------------------------------------------
    RelationshipType.LOGGED_ON: "identity",
    RelationshipType.RUN_AS: "identity",
    RelationshipType.OWNED_BY: "identity",
    RelationshipType.MEMBER_OF: "identity",

    # -- Investigation ----------------------------------------------------
    RelationshipType.OBSERVED_IN: "investigation",
    RelationshipType.CITED_BY: "investigation",
    RelationshipType.REFERENCES: "investigation",
    RelationshipType.DERIVED_FROM: "investigation",
    RelationshipType.SUPPORTS: "investigation",
    RelationshipType.CONTRADICTS: "investigation",
    RelationshipType.TRIGGERED_BY: "investigation",
    RelationshipType.INVESTIGATES: "investigation",
}


# ---------------------------------------------------------------------------
# Inverse mapping
# ---------------------------------------------------------------------------
# Eksplisit. Kalau tipe relationship tidak ada di sini, `reverse()` akan
# raise. Ini mencegah pembalikan edge yang secara semantik tidak valid.
#
# Aturan:
# - Untuk pasangan asimetris, daftarkan kedua arah:
#       PARENT_OF <-> CHILD_OF
#       CONTAINS  <-> PART_OF
# - Untuk relasi simetris, daftarkan self-inverse:
#       CONNECTED_TO <-> CONNECTED_TO
#       MATCHES_HASH <-> MATCHES_HASH
#       CONTRADICTS  <-> CONTRADICTS

INVERSE_RELATIONSHIP: dict[RelationshipType, RelationshipType] = {
    # -- Asymmetric pairs ------------------------------------------------
    RelationshipType.PARENT_OF: RelationshipType.CHILD_OF,
    RelationshipType.CHILD_OF: RelationshipType.PARENT_OF,
    RelationshipType.CONTAINS: RelationshipType.PART_OF,
    RelationshipType.PART_OF: RelationshipType.CONTAINS,

    # -- Symmetric (self-inverse) ---------------------------------------
    RelationshipType.CONNECTED_TO: RelationshipType.CONNECTED_TO,
    RelationshipType.MATCHES_HASH: RelationshipType.MATCHES_HASH,
    RelationshipType.CONTRADICTS: RelationshipType.CONTRADICTS,
}


# Sanity check: mapping harus bidirectional.
# Kalau tidak, raise RuntimeError di import time.
for _src, _dst in INVERSE_RELATIONSHIP.items():
    if INVERSE_RELATIONSHIP.get(_dst) != _src:
        raise RuntimeError(
            "INVERSE_RELATIONSHIP is not bidirectional: "
            f"{_src.value} -> {_dst.value}"
        )
del _src, _dst


# Symmetric relationships = tipe yang inverse-nya dirinya sendiri.
SYMMETRIC_RELATIONSHIPS: frozenset[RelationshipType] = frozenset(
    rt for rt, inv in INVERSE_RELATIONSHIP.items() if rt == inv
)


# ===========================================================================
# Helper functions
# ===========================================================================

def category_of(relationship_type: RelationshipType) -> str | None:
    """Kategori high-level sebuah relationship type."""
    return RELATIONSHIP_CATEGORY.get(relationship_type)


def inverse_of(
    relationship_type: RelationshipType,
) -> RelationshipType | None:
    """Inverse eksplisit, atau None kalau tidak didefinisikan."""
    return INVERSE_RELATIONSHIP.get(relationship_type)


def is_symmetric(relationship_type: RelationshipType) -> bool:
    """True kalau relationship simetris (inverse = dirinya sendiri)."""
    return relationship_type in SYMMETRIC_RELATIONSHIPS


# ===========================================================================
# Internal helpers
# ===========================================================================

def _normalize_ts(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_node_id(value: Any) -> str:
    """
    Untuk field validator: harus string non-empty, raise kalau tidak.
    """
    if not isinstance(value, str):
        raise ValueError("node id must be a string")
    stripped = value.strip()
    if not stripped:
        raise ValueError("node id cannot be empty")
    return stripped


def _normalize_id_string(value: Any) -> str | None:
    """
    Untuk helper mutation: None kalau tidak valid.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


# ===========================================================================
# Relationship
# ===========================================================================

class Relationship(BaseModel):
    """
    Canonical graph edge.

    Identity substantif:
        source_type + source_id + relationship_type + target_type + target_id

    Fingerprint dihitung dari identity ini.
    Properties, tags, provenance, temporal, weight, dan confidence
    TIDAK memengaruhi fingerprint.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    relationship_id: str = Field(default_factory=lambda: str(uuid4()))
    schema_version: str = Field(default=SCHEMA_VERSION)
    tenant_id: str | None = None

    # ------------------------------------------------------------------
    # Edge endpoints
    # ------------------------------------------------------------------
    source_type: NodeType
    source_id: str

    target_type: NodeType
    target_id: str

    relationship_type: RelationshipType

    # ------------------------------------------------------------------
    # Strength
    # ------------------------------------------------------------------
    # weight     : kekuatan hubungan secara model/graph
    # confidence : keyakinan AegisSOC terhadap hubungan tersebut
    #
    # Keduanya terpisah, tapi saat merge di-combine dengan policy
    # yang sama via parameter `on_strength`.
    weight: float = Field(default=DEFAULT_WEIGHT, ge=WEIGHT_MIN, le=WEIGHT_MAX)
    confidence: float = Field(
        default=DEFAULT_CONFIDENCE, ge=WEIGHT_MIN, le=WEIGHT_MAX
    )

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------
    source_event_ids: list[str] = Field(default_factory=list)
    source_evidence_ids: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Temporal
    # ------------------------------------------------------------------
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # ------------------------------------------------------------------
    # Extensibility
    # ------------------------------------------------------------------
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Deterministic identity
    # ------------------------------------------------------------------
    fingerprint: str | None = None

    # ==================================================================
    # Field validators
    # ==================================================================

    @field_validator("source_id", "target_id")
    @classmethod
    def _validate_node_ids(cls, v: str) -> str:
        return _normalize_node_id(v)

    @field_validator("source_event_ids", "source_evidence_ids")
    @classmethod
    def _normalize_source_ids(cls, v: list[str]) -> list[str]:
        return sorted({
            item.strip()
            for item in v
            if item and item.strip()
        })

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, v: list[str]) -> list[str]:
        return sorted({
            item.strip().lower()
            for item in v
            if item and item.strip()
        })

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _ensure_utc(cls, v: datetime | None) -> datetime | None:
        return _normalize_ts(v)

    # ==================================================================
    # Model validator
    # ==================================================================

    @model_validator(mode="after")
    def _finalize(self) -> "Relationship":
        # Self-loop tidak diizinkan untuk semua relationship.
        if (
            self.source_type == self.target_type
            and self.source_id == self.target_id
        ):
            raise ValueError(
                "self-loop relationship is not allowed"
            )

        # Temporal consistency
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError(
                "first_seen cannot be later than last_seen"
            )

        return self

    # ==================================================================
    # Classification properties
    # ==================================================================

    @property
    def category(self) -> str | None:
        return category_of(self.relationship_type)

    @property
    def is_symmetric(self) -> bool:
        return is_symmetric(self.relationship_type)

    @property
    def is_investigation_edge(self) -> bool:
        return self.category == "investigation"

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    @property
    def is_high_weight(self) -> bool:
        return self.weight >= 0.75

    @property
    def has_provenance(self) -> bool:
        return bool(self.source_event_ids or self.source_evidence_ids)

    @property
    def event_count(self) -> int:
        return len(self.source_event_ids)

    @property
    def evidence_count(self) -> int:
        return len(self.source_evidence_ids)

    # ==================================================================
    # Fingerprint
    # ==================================================================

    def canonical_payload(self) -> dict[str, Any]:
        """
        Identity substantif dari edge.

        Termasuk:
        - schema_version, tenant_id
        - source_type, source_id
        - relationship_type
        - target_type, target_id

        Dikecualikan:
        - relationship_id
        - weight, confidence
        - provenance, temporal
        - properties, tags, metadata
        - fingerprint
        """
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "relationship_type": self.relationship_type.value,
            "target_type": self.target_type.value,
            "target_id": self.target_id,
        }

    def calculate_fingerprint(self) -> str:
        """
        SHA-256 dari canonical_payload().

        Identity fingerprint, bukan integrity hash.
        """
        blob = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def with_fingerprint(self) -> "Relationship":
        return self.model_copy(
            update={"fingerprint": self.calculate_fingerprint()}
        )

    def verify_fingerprint(self) -> bool:
        """
        Verifikasi identity fingerprint edge.

        Ini BUKAN integrity check.

        Field yang TIDAK memengaruhi fingerprint: relationship_id,
        weight, confidence, source_event_ids, source_evidence_ids,
        first_seen, last_seen, properties, tags, metadata.

        Field yang MEMENGARUHI fingerprint: schema_version,
        tenant_id, source_type, source_id, relationship_type,
        target_type, target_id.
        """
        if not self.fingerprint:
            return False
        return self.fingerprint == self.calculate_fingerprint()

    # ==================================================================
    # Identity comparison
    # ==================================================================

    def same_identity(self, other: "Relationship") -> bool:
        if not isinstance(other, Relationship):
            return False
        return (
            self.calculate_fingerprint()
            == other.calculate_fingerprint()
        )

    # ==================================================================
    # Reverse
    # ==================================================================

    def can_reverse(self) -> bool:
        """True kalau relationship_type punya inverse eksplisit."""
        return self.relationship_type in INVERSE_RELATIONSHIP

    def reverse(self) -> "Relationship":
        """
        Kembalikan edge terbalik.

        Hanya diizinkan kalau relationship_type punya inverse
        eksplisit di INVERSE_RELATIONSHIP.

        Raise ValueError kalau tidak ada inverse.

        Contoh:
            PARENT_OF(A, B)    -> CHILD_OF(B, A)
            CONTAINS(A, B)     -> PART_OF(B, A)
            CONNECTED_TO(A, B) -> CONNECTED_TO(B, A)   (symmetric)
            EXECUTED(A, B)     -> ValueError
        """
        inverse_type = INVERSE_RELATIONSHIP.get(self.relationship_type)
        if inverse_type is None:
            raise ValueError(
                f"relationship type {self.relationship_type.value!r} "
                f"has no defined inverse; reverse() is not allowed"
            )

        return self.model_copy(update={
            "source_type": self.target_type,
            "source_id": self.target_id,
            "target_type": self.source_type,
            "target_id": self.source_id,
            "relationship_type": inverse_type,
            "relationship_id": str(uuid4()),
            "fingerprint": None,
        }).with_fingerprint()

    # ==================================================================
    # Temporal
    # ==================================================================

    def touch(self, timestamp: datetime) -> "Relationship":
        """
        Return copy dengan first_seen/last_seen diperluas oleh timestamp.
        """
        ts = _normalize_ts(timestamp)
        if ts is None:
            return self

        first = self.first_seen
        last = self.last_seen

        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts

        return self.model_copy(
            update={"first_seen": first, "last_seen": last}
        )

    # ==================================================================
    # Merge
    # ==================================================================

    @staticmethod
    def _merge_dict(
        left: dict[str, Any],
        right: dict[str, Any],
        *,
        on_conflict: ConflictPolicy,
        label: str,
    ) -> dict[str, Any]:
        merged = dict(left)
        for key, value in right.items():
            if key not in merged:
                merged[key] = value
                continue
            if merged[key] == value:
                continue
            if on_conflict == "left":
                continue
            if on_conflict == "right":
                merged[key] = value
                continue
            # on_conflict == "raise"
            raise ValueError(
                f"{label} conflict for key {key!r}: "
                f"left={merged[key]!r}, right={value!r}"
            )
        return merged

    @staticmethod
    def _combine_strength(
        left: float,
        right: float,
        *,
        policy: StrengthCombinePolicy,
    ) -> float:
        if policy == "max":
            return max(left, right)
        if policy == "avg":
            return (left + right) / 2.0
        if policy == "left":
            return left
        return right  # "right"

    def merge(
        self,
        other: "Relationship",
        *,
        on_property_conflict: ConflictPolicy = DEFAULT_CONFLICT_POLICY,
        on_metadata_conflict: ConflictPolicy = DEFAULT_CONFLICT_POLICY,
        on_strength: StrengthCombinePolicy = DEFAULT_STRENGTH_COMBINE_POLICY,
    ) -> "Relationship":
        """
        Gabungkan dua relationship dengan identity sama.

        Parameter:
        - on_property_conflict : policy konflik untuk `properties`
        - on_metadata_conflict : policy konflik untuk `metadata`
        - on_strength          : policy kombinasi untuk edge strength,
                                 yaitu `weight` dan `confidence`.
                                 Karena keduanya merepresentasikan kekuatan
                                 edge, mereka di-combine dengan policy yang
                                 sama.

        Aturan:
        - fingerprint harus sama.
        - weight & confidence: default max (lihat `on_strength`).
        - first_seen = min, last_seen = max.
        - source_event_ids / source_evidence_ids = union.
        - tags = union.
        - properties = merge dengan on_property_conflict.
        - metadata   = merge dengan on_metadata_conflict.
        - fingerprint dihitung ulang.
        """
        if not self.same_identity(other):
            raise ValueError(
                "cannot merge relationships with different fingerprint"
            )

        merged_event_ids = sorted(
            set(self.source_event_ids) | set(other.source_event_ids)
        )
        merged_evidence_ids = sorted(
            set(self.source_evidence_ids) | set(other.source_evidence_ids)
        )
        merged_tags = sorted(set(self.tags) | set(other.tags))

        merged_properties = self._merge_dict(
            self.properties,
            other.properties,
            on_conflict=on_property_conflict,
            label="property",
        )
        merged_metadata = self._merge_dict(
            self.metadata,
            other.metadata,
            on_conflict=on_metadata_conflict,
            label="metadata",
        )

        merged_weight = self._combine_strength(
            self.weight, other.weight, policy=on_strength
        )
        merged_confidence = self._combine_strength(
            self.confidence, other.confidence, policy=on_strength
        )

        def _min_ts(
            a: datetime | None, b: datetime | None
        ) -> datetime | None:
            if a is None:
                return b
            if b is None:
                return a
            return a if a <= b else b

        def _max_ts(
            a: datetime | None, b: datetime | None
        ) -> datetime | None:
            if a is None:
                return b
            if b is None:
                return a
            return a if a >= b else b

        merged = self.model_copy(update={
            "weight": merged_weight,
            "confidence": merged_confidence,
            "first_seen": _min_ts(self.first_seen, other.first_seen),
            "last_seen": _max_ts(self.last_seen, other.last_seen),
            "source_event_ids": merged_event_ids,
            "source_evidence_ids": merged_evidence_ids,
            "properties": merged_properties,
            "tags": merged_tags,
            "metadata": merged_metadata,
            "fingerprint": None,
        })

        return merged.with_fingerprint()

    # ==================================================================
    # Provenance helpers
    # ==================================================================

    def add_event(self, event_id: Any) -> "Relationship":
        """
        Tambah event_id ke source_event_ids.

        Input dinormalisasi: harus string, di-strip, non-empty.
        Kalau tidak valid → return self tanpa perubahan.
        """
        normalized = _normalize_id_string(event_id)
        if normalized is None:
            return self
        return self.model_copy(update={
            "source_event_ids": sorted(
                set(self.source_event_ids) | {normalized}
            )
        })

    def add_evidence(self, evidence_id: Any) -> "Relationship":
        """
        Tambah evidence_id ke source_evidence_ids.

        Input dinormalisasi: harus string, di-strip, non-empty.
        Kalau tidak valid → return self tanpa perubahan.
        """
        normalized = _normalize_id_string(evidence_id)
        if normalized is None:
            return self
        return self.model_copy(update={
            "source_evidence_ids": sorted(
                set(self.source_evidence_ids) | {normalized}
            )
        })

    def add_tag(self, tag: Any) -> "Relationship":
        """
        Tambah tag (dinormalisasi lowercase).

        Input dinormalisasi: harus string, di-strip, non-empty.
        """
        normalized = _normalize_id_string(tag)
        if normalized is None:
            return self
        return self.model_copy(update={
            "tags": sorted(set(self.tags) | {normalized.lower()})
        })

    # ==================================================================
    # Graph
    # ==================================================================

    def to_graph_edge(self) -> dict[str, Any]:
        """
        Representasi edge untuk Investigation Graph.
        """
        return {
            "id": self.relationship_id,
            "type": "Relationship",
            "source": self.source_id,
            "source_type": self.source_type.value,
            "target": self.target_id,
            "target_type": self.target_type.value,
            "relationship_type": self.relationship_type.value,
            "category": self.category,
            "is_symmetric": self.is_symmetric,
            "weight": self.weight,
            "confidence": self.confidence,
            "fingerprint": self.fingerprint,
            "first_seen": (
                self.first_seen.isoformat()
                if self.first_seen else None
            ),
            "last_seen": (
                self.last_seen.isoformat()
                if self.last_seen else None
            ),
            "tags": list(self.tags),
            "properties": dict(self.properties),
        }


# ===========================================================================
# Type alias
# ===========================================================================

RelationshipList = list[Relationship]


__all__ = [
    "SCHEMA_VERSION",
    "WEIGHT_MIN",
    "WEIGHT_MAX",
    "DEFAULT_WEIGHT",
    "DEFAULT_CONFIDENCE",
    "ConflictPolicy",
    "DEFAULT_CONFLICT_POLICY",
    "StrengthCombinePolicy",
    "DEFAULT_STRENGTH_COMBINE_POLICY",
    "NodeType",
    "RelationshipType",
    "RELATIONSHIP_CATEGORY",
    "INVERSE_RELATIONSHIP",
    "SYMMETRIC_RELATIONSHIPS",
    "category_of",
    "inverse_of",
    "is_symmetric",
    "Relationship",
    "RelationshipList",
]
