"""
Canonical hypothesis model for AegisSOC investigations.

Hypothesis adalah klaim yang bisa didukung atau dibantah oleh Evidence.

    Evidence  ──SUPPORTS────►  Hypothesis
    Evidence  ──CONTRADICTS─►  Hypothesis

Hypothesis juga bisa punya Counter-Hypothesis: hipotesis alternatif yang
menjelaskan evidence yang sama dengan cara yang berbeda.

Prinsip:
- Hypothesis adalah derived object: dibuat dari Evidence, bukan sebaliknya.
- Hypothesis TIDAK mengubah Evidence.
- Hubungan ke Evidence disimpan sebagai ID; link canonical dibangun
  oleh relationship layer.
- Status lifecycle jelas: PROPOSED → SUPPORTED/WEAKENED → CONFIRMED/REJECTED.
- Confidence dan status adalah dua dimensi terpisah.
- Fingerprint deterministik dari (tenant, type, normalized statement).
- Merge by fingerprint: union evidence, min/max temporal, merge properties.
"""

from __future__ import annotations

import hashlib
import json
import re
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

CONFIDENCE_MIN: float = 0.0
CONFIDENCE_MAX: float = 1.0

DEFAULT_CONFIDENCE: float = 0.0

STATEMENT_MIN_LENGTH: int = 3
STATEMENT_MAX_LENGTH: int = 2000

ConflictPolicy = Literal["left", "right", "raise"]
DEFAULT_CONFLICT_POLICY: ConflictPolicy = "left"


# ===========================================================================
# Enums
# ===========================================================================

class HypothesisType(str, Enum):
    """
    Jenis hypothesis.

    - MAIN     : hipotesis utama untuk sebuah investigation.
    - COUNTER  : hipotesis alternatif yang membantah MAIN.
    - SUB      : sub-hipotesis yang mendukung decomposition MAIN.
    - UNKNOWN  : default, belum diklasifikasi.
    """
    MAIN = "main"
    COUNTER = "counter"
    SUB = "sub"
    UNKNOWN = "unknown"


class HypothesisStatus(str, Enum):
    """
    Lifecycle status hypothesis.

        PROPOSED ──► SUPPORTED ──► CONFIRMED
            │            │
            │            └──► WEAKENED ──► REJECTED
            │
            └──► WEAKENED ──► REJECTED
    """
    PROPOSED = "proposed"
    SUPPORTED = "supported"
    WEAKENED = "weakened"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class HypothesisSource(str, Enum):
    """
    Asal hypothesis.
    """
    DETERMINISTIC = "deterministic"   # rule engine / correlation
    AI = "ai"                         # dihasilkan LLM
    ANALYST = "analyst"               # dibuat manual oleh analis
    IMPORTED = "imported"             # dari sistem eksternal


# ===========================================================================
# State machine
# ===========================================================================

_ALLOWED_TRANSITIONS: dict[HypothesisStatus, set[HypothesisStatus]] = {
    HypothesisStatus.PROPOSED: {
        HypothesisStatus.SUPPORTED,
        HypothesisStatus.WEAKENED,
        HypothesisStatus.REJECTED,
    },
    HypothesisStatus.SUPPORTED: {
        HypothesisStatus.CONFIRMED,
        HypothesisStatus.WEAKENED,
    },
    HypothesisStatus.WEAKENED: {
        HypothesisStatus.SUPPORTED,
        HypothesisStatus.REJECTED,
    },
    HypothesisStatus.CONFIRMED: set(),   # terminal
    HypothesisStatus.REJECTED: set(),    # terminal
}


# ===========================================================================
# Internal helpers
# ===========================================================================

def _normalize_ts(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


_WHITESPACE_RE = re.compile(r"\s+")


def _normalize_statement(value: str) -> str:
    """
    Normalisasi statement untuk fingerprint:
    - strip
    - lowercase
    - collapse whitespace
    """
    return _WHITESPACE_RE.sub(" ", value.strip().lower())


def _normalize_id_list(values: list[str]) -> list[str]:
    return sorted({
        v.strip()
        for v in values
        if isinstance(v, str) and v.strip()
    })


def _normalize_tag_list(values: list[str]) -> list[str]:
    return sorted({
        v.strip().lower()
        for v in values
        if isinstance(v, str) and v.strip()
    })


# ===========================================================================
# Hypothesis
# ===========================================================================

class Hypothesis(BaseModel):
    """
    Canonical hypothesis untuk AegisSOC Investigation.

    Identity substantif:
        (tenant_id, hypothesis_type, normalized statement)

    Fingerprint TIDAK bergantung pada:
    - hypothesis_id
    - evidence links
    - confidence, status
    - properties, tags, metadata
    - temporal
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
    hypothesis_id: str = Field(
        default_factory=lambda: f"H-{uuid4().hex[:10]}"
    )
    schema_version: str = Field(default=SCHEMA_VERSION)
    tenant_id: str | None = None
    investigation_id: str | None = None

    # ------------------------------------------------------------------
    # Classification
    # ------------------------------------------------------------------
    hypothesis_type: HypothesisType = HypothesisType.UNKNOWN
    parent_hypothesis_id: str | None = None

    # ------------------------------------------------------------------
    # Statement
    # ------------------------------------------------------------------
    statement: str = Field(
        min_length=STATEMENT_MIN_LENGTH,
        max_length=STATEMENT_MAX_LENGTH,
    )
    description: str | None = None

    # ------------------------------------------------------------------
    # MITRE
    # ------------------------------------------------------------------
    mitre_techniques: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    status: HypothesisStatus = HypothesisStatus.PROPOSED
    confidence: float = Field(
        default=DEFAULT_CONFIDENCE,
        ge=CONFIDENCE_MIN,
        le=CONFIDENCE_MAX,
    )

    # ------------------------------------------------------------------
    # Evidence links (ID-only)
    # ------------------------------------------------------------------
    supporting_evidence_ids: list[str] = Field(default_factory=list)
    contradicting_evidence_ids: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Missing evidence (bukan ID, tapi deskripsi)
    # ------------------------------------------------------------------
    missing_evidence: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------
    source: HypothesisSource = HypothesisSource.DETERMINISTIC
    rationale: str | None = None
    created_by: str | None = None     # agent ID / analyst ID

    # ------------------------------------------------------------------
    # Temporal
    # ------------------------------------------------------------------
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

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

    @field_validator("statement")
    @classmethod
    def _validate_statement(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("statement cannot be empty")
        return v

    @field_validator("mitre_techniques")
    @classmethod
    def _validate_techniques(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for t in v:
            if not isinstance(t, str):
                continue
            t = t.strip().upper()
            if not t:
                continue
            if not t.startswith("T") or not t[1:].replace(".", "").isdigit():
                raise ValueError(f"Invalid MITRE technique ID: {t}")
            out.append(t)
        return sorted(set(out))

    @field_validator("mitre_tactics")
    @classmethod
    def _validate_tactics(cls, v: list[str]) -> list[str]:
        out: list[str] = []
        for t in v:
            if not isinstance(t, str):
                continue
            t = t.strip().upper()
            if not t:
                continue
            if not t.startswith("TA") or not t[2:].isdigit():
                raise ValueError(f"Invalid MITRE tactic ID: {t}")
            out.append(t)
        return sorted(set(out))

    @field_validator(
        "supporting_evidence_ids",
        "contradicting_evidence_ids",
    )
    @classmethod
    def _normalize_evidence_ids(cls, v: list[str]) -> list[str]:
        return _normalize_id_list(v)

    @field_validator("missing_evidence")
    @classmethod
    def _normalize_missing_evidence(cls, v: list[str]) -> list[str]:
        return sorted({
            m.strip()
            for m in v
            if isinstance(m, str) and m.strip()
        })

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, v: list[str]) -> list[str]:
        return _normalize_tag_list(v)

    @field_validator(
        "first_seen", "last_seen", "created_at", "updated_at"
    )
    @classmethod
    def _normalize_dt(cls, v: datetime | None) -> datetime | None:
        return _normalize_ts(v)

    # ==================================================================
    # Model validator
    # ==================================================================

    @model_validator(mode="after")
    def _finalize(self) -> "Hypothesis":
        # Temporal consistency
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError(
                "first_seen cannot be later than last_seen"
            )

        if self.updated_at < self.created_at:
            raise ValueError(
                "updated_at cannot be earlier than created_at"
            )

        # Evidence link conflict: tidak boleh jadi supporting dan
        # contradicting sekaligus.
        overlap = (
            set(self.supporting_evidence_ids)
            & set(self.contradicting_evidence_ids)
        )
        if overlap:
            raise ValueError(
                f"evidence IDs cannot be both supporting and "
                f"contradicting: {sorted(overlap)}"
            )

        # SUB hypothesis wajib punya parent
        # SUB hypothesis BERPOTENSI punya parent, tapi tidak wajib.
        # SUB tanpa parent adalah sinyal turunan mandiri
        # (mis. dari correlation engine).
        if (
            self.hypothesis_type == HypothesisType.SUB
            and self.parent_hypothesis_id
            and self.parent_hypothesis_id == self.hypothesis_id
        ):
            raise ValueError(
                "SUB hypothesis cannot have itself as parent"
            )
        # COUNTER tidak boleh punya parent (langsung ke MAIN)
        if (
            self.hypothesis_type == HypothesisType.COUNTER
            and self.parent_hypothesis_id is not None
        ):
            raise ValueError(
                "COUNTER hypothesis cannot have parent_hypothesis_id"
            )

        # CONFIRMED/REJECTED harus punya rationale
        if self.status in (
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.REJECTED,
        ):
            if not self.rationale:
                raise ValueError(
                    f"{self.status.value} hypothesis requires rationale"
                )

        return self

    # ==================================================================
    # Properties
    # ==================================================================

    @property
    def is_main(self) -> bool:
        return self.hypothesis_type == HypothesisType.MAIN

    @property
    def is_counter(self) -> bool:
        return self.hypothesis_type == HypothesisType.COUNTER

    @property
    def is_sub(self) -> bool:
        return self.hypothesis_type == HypothesisType.SUB

    @property
    def is_terminal(self) -> bool:
        return self.status in (
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.REJECTED,
        )

    @property
    def is_active(self) -> bool:
        return not self.is_terminal

    @property
    def is_supported(self) -> bool:
        return self.status == HypothesisStatus.SUPPORTED

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    @property
    def has_evidence(self) -> bool:
        return bool(
            self.supporting_evidence_ids
            or self.contradicting_evidence_ids
        )

    @property
    def has_missing_evidence(self) -> bool:
        return bool(self.missing_evidence)

    @property
    def support_count(self) -> int:
        return len(self.supporting_evidence_ids)

    @property
    def contradict_count(self) -> int:
        return len(self.contradicting_evidence_ids)

    @property
    def evidence_balance(self) -> int:
        """
        Selisih supporting - contradicting.

        Positif : lebih banyak yang mendukung.
        Negatif : lebih banyak yang membantah.
        """
        return self.support_count - self.contradict_count

    # ==================================================================
    # Fingerprint
    # ==================================================================

    def canonical_payload(self) -> dict[str, Any]:
        """
        Identity substantif dari hypothesis.

        Termasuk:
        - schema_version
        - tenant_id
        - hypothesis_type
        - normalized statement

        Dikecualikan:
        - hypothesis_id
        - parent_hypothesis_id (structural, bukan identity)
        - evidence links, confidence, status
        - properties, tags, metadata
        - temporal
        - fingerprint
        """
        return {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "hypothesis_type": self.hypothesis_type.value,
            "statement": _normalize_statement(self.statement),
        }

    def calculate_fingerprint(self) -> str:
        blob = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def with_fingerprint(self) -> "Hypothesis":
        return self.model_copy(
            update={"fingerprint": self.calculate_fingerprint()}
        )

    def verify_fingerprint(self) -> bool:
        """
        Verifikasi identity fingerprint hypothesis.
        Ini BUKAN integrity check.
        """
        if not self.fingerprint:
            return False
        return self.fingerprint == self.calculate_fingerprint()

    # ==================================================================
    # Identity comparison
    # ==================================================================

    def same_identity(self, other: "Hypothesis") -> bool:
        if not isinstance(other, Hypothesis):
            return False
        return (
            self.calculate_fingerprint()
            == other.calculate_fingerprint()
        )

    # ==================================================================
    # Lifecycle
    # ==================================================================

    def touch(self) -> "Hypothesis":
        return self.model_copy(update={
            "updated_at": datetime.now(timezone.utc),
        })

    def can_transition_to(self, status: HypothesisStatus) -> bool:
        if status == self.status:
            return True
        return status in _ALLOWED_TRANSITIONS.get(self.status, set())

    def transition_to(
        self,
        status: HypothesisStatus,
        *,
        rationale: str | None = None,
    ) -> "Hypothesis":
        if status == self.status:
            return self
        if not self.can_transition_to(status):
            raise ValueError(
                f"illegal transition: {self.status.value} -> "
                f"{status.value}"
            )

        update: dict[str, Any] = {
            "status": status,
            "updated_at": datetime.now(timezone.utc),
        }
        if rationale is not None:
            update["rationale"] = rationale.strip() or None

        # Validator akan memaksa rationale untuk CONFIRMED/REJECTED.
        if status in (
            HypothesisStatus.CONFIRMED,
            HypothesisStatus.REJECTED,
        ):
            if not (rationale or self.rationale):
                raise ValueError(
                    f"transition to {status.value} requires rationale"
                )
            if not update.get("rationale"):
                update["rationale"] = self.rationale

        return self.model_copy(update=update)

    # ==================================================================
    # Confidence
    # ==================================================================

    def with_confidence(self, confidence: float) -> "Hypothesis":
        if not CONFIDENCE_MIN <= confidence <= CONFIDENCE_MAX:
            raise ValueError(
                f"confidence must be between {CONFIDENCE_MIN} "
                f"and {CONFIDENCE_MAX}"
            )
        return self.model_copy(update={
            "confidence": confidence,
            "updated_at": datetime.now(timezone.utc),
        })

    # ==================================================================
    # Evidence helpers
    # ==================================================================

    def add_supporting_evidence(
        self, evidence_id: str
    ) -> "Hypothesis":
        evidence_id = str(evidence_id).strip()
        if not evidence_id:
            return self
        if evidence_id in self.contradicting_evidence_ids:
            raise ValueError(
                f"evidence {evidence_id} already contradicts this hypothesis"
            )
        return self.model_copy(update={
            "supporting_evidence_ids": sorted(
                set(self.supporting_evidence_ids) | {evidence_id}
            ),
            "updated_at": datetime.now(timezone.utc),
        })

    def add_contradicting_evidence(
        self, evidence_id: str
    ) -> "Hypothesis":
        evidence_id = str(evidence_id).strip()
        if not evidence_id:
            return self
        if evidence_id in self.supporting_evidence_ids:
            raise ValueError(
                f"evidence {evidence_id} already supports this hypothesis"
            )
        return self.model_copy(update={
            "contradicting_evidence_ids": sorted(
                set(self.contradicting_evidence_ids) | {evidence_id}
            ),
            "updated_at": datetime.now(timezone.utc),
        })

    def add_missing_evidence(self, description: str) -> "Hypothesis":
        description = str(description).strip()
        if not description:
            return self
        return self.model_copy(update={
            "missing_evidence": sorted(
                set(self.missing_evidence) | {description}
            ),
            "updated_at": datetime.now(timezone.utc),
        })

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
            raise ValueError(
                f"{label} conflict for key {key!r}: "
                f"left={merged[key]!r}, right={value!r}"
            )
        return merged

    def merge(
        self,
        other: "Hypothesis",
        *,
        on_property_conflict: ConflictPolicy = DEFAULT_CONFLICT_POLICY,
        on_metadata_conflict: ConflictPolicy = DEFAULT_CONFLICT_POLICY,
    ) -> "Hypothesis":
        """
        Gabungkan dua hypothesis dengan identity sama.

        Aturan:
        - fingerprint harus sama.
        - confidence: max.
        - supporting_evidence_ids / contradicting_evidence_ids: union.
        - missing_evidence: union.
        - mitre_techniques / mitre_tactics: union.
        - first_seen = min, last_seen = max.
        - status: prefer yang paling maju (CONFIRMED > SUPPORTED > ...).
        - properties / metadata: per conflict policy.
        - fingerprint dihitung ulang.
        """
        if not self.same_identity(other):
            raise ValueError(
                "cannot merge hypotheses with different fingerprint"
            )

        merged_support = sorted(
            set(self.supporting_evidence_ids)
            | set(other.supporting_evidence_ids)
        )
        merged_contradict = sorted(
            set(self.contradicting_evidence_ids)
            | set(other.contradicting_evidence_ids)
        )

        # Sanity: hasil merge tidak boleh overlap
        overlap = set(merged_support) & set(merged_contradict)
        if overlap:
            raise ValueError(
                f"merge produced conflicting evidence links: "
                f"{sorted(overlap)}"
            )

        merged_missing = sorted(
            set(self.missing_evidence) | set(other.missing_evidence)
        )
        merged_techniques = sorted(
            set(self.mitre_techniques) | set(other.mitre_techniques)
        )
        merged_tactics = sorted(
            set(self.mitre_tactics) | set(other.mitre_tactics)
        )
        merged_tags = sorted(set(self.tags) | set(other.tags))

        merged_properties = self._merge_dict(
            self.properties, other.properties,
            on_conflict=on_property_conflict,
            label="property",
        )
        merged_metadata = self._merge_dict(
            self.metadata, other.metadata,
            on_conflict=on_metadata_conflict,
            label="metadata",
        )

        # Status: pilih yang paling maju
        status_rank = {
            HypothesisStatus.PROPOSED: 0,
            HypothesisStatus.WEAKENED: 1,
            HypothesisStatus.SUPPORTED: 2,
            HypothesisStatus.REJECTED: 3,
            HypothesisStatus.CONFIRMED: 4,
        }
        merged_status = (
            self.status
            if status_rank[self.status] >= status_rank[other.status]
            else other.status
        )

        # Rationale: prefer self, fallback other
        merged_rationale = self.rationale or other.rationale

        def _min_ts(a, b):
            if a is None:
                return b
            if b is None:
                return a
            return a if a <= b else b

        def _max_ts(a, b):
            if a is None:
                return b
            if b is None:
                return a
            return a if a >= b else b

        merged = self.model_copy(update={
            "supporting_evidence_ids": merged_support,
            "contradicting_evidence_ids": merged_contradict,
            "missing_evidence": merged_missing,
            "mitre_techniques": merged_techniques,
            "mitre_tactics": merged_tactics,
            "tags": merged_tags,
            "properties": merged_properties,
            "metadata": merged_metadata,
            "confidence": max(self.confidence, other.confidence),
            "status": merged_status,
            "rationale": merged_rationale,
            "first_seen": _min_ts(self.first_seen, other.first_seen),
            "last_seen": _max_ts(self.last_seen, other.last_seen),
            "updated_at": datetime.now(timezone.utc),
            "fingerprint": None,
        })

        return merged.with_fingerprint()

    # ==================================================================
    # Graph
    # ==================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.hypothesis_id,
            "type": "Hypothesis",
            "tenant_id": self.tenant_id,
            "investigation_id": self.investigation_id,
            "hypothesis_type": self.hypothesis_type.value,
            "parent_hypothesis_id": self.parent_hypothesis_id,
            "statement": self.statement,
            "status": self.status.value,
            "confidence": self.confidence,
            "source": self.source.value,
            "support_count": self.support_count,
            "contradict_count": self.contradict_count,
            "evidence_balance": self.evidence_balance,
            "mitre_techniques": list(self.mitre_techniques),
            "mitre_tactics": list(self.mitre_tactics),
            "missing_evidence": list(self.missing_evidence),
            "tags": list(self.tags),
            "first_seen": (
                self.first_seen.isoformat()
                if self.first_seen else None
            ),
            "last_seen": (
                self.last_seen.isoformat()
                if self.last_seen else None
            ),
            "fingerprint": self.fingerprint,
        }

    def debug_relationships(self) -> list[dict[str, Any]]:
        """
        DEBUG ONLY.

        Bukan source of truth. Hubungan canonical dibangun oleh
        relationship layer.
        """
        edges: list[dict[str, Any]] = []

        for ev_id in self.supporting_evidence_ids:
            edges.append({
                "source": ev_id,
                "source_type": "Evidence",
                "target": self.hypothesis_id,
                "target_type": "Hypothesis",
                "relationship": "SUPPORTS",
                "properties": {"_debug": True},
            })

        for ev_id in self.contradicting_evidence_ids:
            edges.append({
                "source": ev_id,
                "source_type": "Evidence",
                "target": self.hypothesis_id,
                "target_type": "Hypothesis",
                "relationship": "CONTRADICTS",
                "properties": {"_debug": True},
            })

        return edges


# ===========================================================================
# Type alias
# ===========================================================================

HypothesisList = list[Hypothesis]


__all__ = [
    "SCHEMA_VERSION",
    "CONFIDENCE_MIN",
    "CONFIDENCE_MAX",
    "DEFAULT_CONFIDENCE",
    "STATEMENT_MIN_LENGTH",
    "STATEMENT_MAX_LENGTH",
    "ConflictPolicy",
    "DEFAULT_CONFLICT_POLICY",
    "HypothesisType",
    "HypothesisStatus",
    "HypothesisSource",
    "Hypothesis",
    "HypothesisList",
]
