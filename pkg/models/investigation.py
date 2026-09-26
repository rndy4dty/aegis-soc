from __future__ import annotations

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


# ===========================================================================
# Constants
# ===========================================================================

SCHEMA_VERSION: str = "1.0"

SEVERITY_MIN: int = 0
SEVERITY_MAX: int = 100

RISK_SCORE_MIN: int = 0
RISK_SCORE_MAX: int = 100

CONFIDENCE_MIN: float = 0.0
CONFIDENCE_MAX: float = 1.0


# ===========================================================================
# Enums
# ===========================================================================

class InvestigationStatus(str, Enum):
    """
    Lifecycle status investigasi.
    Urutan umum: DETECTED → TRIAGED → CORRELATING → INVESTIGATING
    → (EVIDENCE_REQUIRED | REASSESSING) → CONFIRMED → RESOLVED.
    """
    DETECTED = "detected"
    TRIAGED = "triaged"
    CORRELATING = "correlating"
    INVESTIGATING = "investigating"
    EVIDENCE_REQUIRED = "evidence_required"
    REASSESSING = "reassessing"
    CONFIRMED = "confirmed"
    RESOLVED = "resolved"


class InvestigationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class InvestigationCategory(str, Enum):
    """
    Kategori kasus tingkat SOC. Ini bukan MITRE tactic.
    Tactic melekat pada Event / Hypothesis.
    """
    MALWARE = "malware"
    PHISHING = "phishing"
    CREDENTIAL_ACCESS = "credential_access"
    PERSISTENCE = "persistence"
    EXECUTION = "execution"
    DEFENSE_EVASION = "defense_evasion"
    LATERAL_MOVEMENT = "lateral_movement"
    COMMAND_AND_CONTROL = "command_and_control"
    DATA_EXFILTRATION = "data_exfiltration"
    POLICY_VIOLATION = "policy_violation"
    UNKNOWN = "unknown"


class ResolutionOutcome(str, Enum):
    """
    Hasil akhir sebuah kasus.
    """
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    BENIGN = "benign"
    DUPLICATE = "duplicate"
    INCONCLUSIVE = "inconclusive"


# ===========================================================================
# State machine — transisi yang diizinkan
# ===========================================================================

_ALLOWED_TRANSITIONS: dict[InvestigationStatus, set[InvestigationStatus]] = {
    InvestigationStatus.DETECTED: {
        InvestigationStatus.TRIAGED,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.TRIAGED: {
        InvestigationStatus.CORRELATING,
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.CORRELATING: {
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.EVIDENCE_REQUIRED,
        InvestigationStatus.REASSESSING,
    },
    InvestigationStatus.INVESTIGATING: {
        InvestigationStatus.EVIDENCE_REQUIRED,
        InvestigationStatus.REASSESSING,
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.EVIDENCE_REQUIRED: {
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.REASSESSING,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.REASSESSING: {
        InvestigationStatus.INVESTIGATING,
        InvestigationStatus.CONFIRMED,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.CONFIRMED: {
        InvestigationStatus.REASSESSING,
        InvestigationStatus.RESOLVED,
    },
    InvestigationStatus.RESOLVED: set(),
}


# ===========================================================================
# Sub-model — Risk Evolution
# ===========================================================================

class RiskEvolution(BaseModel):
    """
    Satu titik perubahan risk score.

    Ini menjawab pertanyaan:
        "Risk Score naik dari 42 → 71 karena evidence apa?"
    """

    model_config = ConfigDict(extra="forbid")

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    risk_score: int = Field(ge=RISK_SCORE_MIN, le=RISK_SCORE_MAX)
    confidence: float = Field(ge=CONFIDENCE_MIN, le=CONFIDENCE_MAX)

    previous_risk_score: int | None = None
    previous_confidence: float | None = None

    delta: int = 0
    reason: str

    evidence_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)

    @field_validator("timestamp")
    @classmethod
    def _normalize_ts(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_validator("evidence_ids", "hypothesis_ids")
    @classmethod
    def _normalize_ids(cls, values: list[str]) -> list[str]:
        return sorted({v.strip() for v in values if v and v.strip()})

    @field_serializer("timestamp")
    def _serialize_ts(self, value: datetime) -> str:
        return value.isoformat()


# ===========================================================================
# Main — InvestigationCase
# ===========================================================================

class InvestigationCase(BaseModel):
    """
    Root object representing one SOC investigation.
    """

    model_config = ConfigDict(
        extra="forbid",
        # validate_assignment sengaja dimatikan pada aggregate root ini.
        # Alasan: lifecycle consistency (closed_at ↔ resolved, outcome
        # di resolved) membutuhkan transisi multi-field yang tidak bisa
        # dijamin per-field. Mutasi state harus lewat:
        #   - transition_to()
        #   - mark_resolved()
        #   - update_risk()
        #   - assign_analyst()
        #   - attach_summary() / attach_notes()
        #   - add_alert() / add_event() / add_evidence() / ...
        validate_assignment=False,
        str_strip_whitespace=True,
    )

    # --------------------------------------------------------------------
    # Identity
    # --------------------------------------------------------------------
    case_id: str = Field(
        default_factory=lambda: f"CASE-{uuid4().hex[:12].upper()}"
    )
    schema_version: str = SCHEMA_VERSION
    tenant_id: str | None = None

    # --------------------------------------------------------------------
    # Classification
    # --------------------------------------------------------------------
    title: str = Field(min_length=1)
    description: str | None = None
    category: InvestigationCategory = InvestigationCategory.UNKNOWN
    severity: int = Field(default=0, ge=SEVERITY_MIN, le=SEVERITY_MAX)
    priority: InvestigationPriority = InvestigationPriority.LOW
    tags: list[str] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Lifecycle
    # --------------------------------------------------------------------
    status: InvestigationStatus = InvestigationStatus.DETECTED

    # --------------------------------------------------------------------
    # References — hanya ID
    # --------------------------------------------------------------------
    alert_ids: list[str] = Field(default_factory=list)
    event_ids: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    hypothesis_ids: list[str] = Field(default_factory=list)
    entity_ids: list[str] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Risk
    # --------------------------------------------------------------------
    risk_score: int = Field(default=0, ge=RISK_SCORE_MIN, le=RISK_SCORE_MAX)
    confidence: float = Field(default=0.0, ge=CONFIDENCE_MIN, le=CONFIDENCE_MAX)
    risk_factors: list[str] = Field(default_factory=list)
    risk_history: list[RiskEvolution] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Ownership
    # --------------------------------------------------------------------
    analyst: str | None = None
    analyst_notes: str | None = None

    # --------------------------------------------------------------------
    # Resolution
    # --------------------------------------------------------------------
    outcome: ResolutionOutcome | None = None
    summary: str | None = None

    # --------------------------------------------------------------------
    # Timeline
    # --------------------------------------------------------------------
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    closed_at: datetime | None = None

    # --------------------------------------------------------------------
    # Metadata
    # --------------------------------------------------------------------
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ====================================================================
    # Validators
    # ====================================================================

    @field_validator(
        "alert_ids",
        "event_ids",
        "evidence_ids",
        "hypothesis_ids",
        "entity_ids",
    )
    @classmethod
    def _normalize_reference_ids(cls, values: list[str]) -> list[str]:
        return sorted({v.strip() for v in values if v and v.strip()})

    @field_validator("risk_factors")
    @classmethod
    def _normalize_risk_factors(cls, values: list[str]) -> list[str]:
        return sorted({v.strip() for v in values if v and v.strip()})

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, values: list[str]) -> list[str]:
        return sorted({v.strip().lower() for v in values if v and v.strip()})

    @field_validator("tenant_id", "analyst")
    @classmethod
    def _validate_optional_str(cls, value: str | None) -> str | None:
        if value is None:
            return None
        value = value.strip()
        return value or None

    @field_validator("created_at", "updated_at", "closed_at")
    @classmethod
    def _normalize_timestamps(
        cls, value: datetime | None
    ) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("created_at", "updated_at", "closed_at")
    def _serialize_timestamps(
        self, value: datetime | None
    ) -> str | None:
        return value.isoformat() if value else None

    @model_validator(mode="after")
    def _validate_lifecycle(self) -> "InvestigationCase":
        # closed_at ↔ resolved
        if self.status == InvestigationStatus.RESOLVED:
            if self.closed_at is None:
                raise ValueError(
                    "resolved case requires closed_at"
                )
        if self.closed_at is not None:
            if self.status != InvestigationStatus.RESOLVED:
                raise ValueError(
                    "closed_at requires status=resolved"
                )

        # resolved case harus punya outcome
        if self.status == InvestigationStatus.RESOLVED:
            if self.outcome is None:
                raise ValueError(
                    "resolved case requires outcome"
                )

        # updated_at tidak boleh mendahului created_at
        if self.updated_at < self.created_at:
            raise ValueError(
                "updated_at cannot be earlier than created_at"
            )

        return self

    # ====================================================================
    # Properties
    # ====================================================================

    @property
    def is_open(self) -> bool:
        return self.status != InvestigationStatus.RESOLVED

    @property
    def is_closed(self) -> bool:
        return self.status == InvestigationStatus.RESOLVED

    @property
    def has_evidence(self) -> bool:
        return bool(self.evidence_ids)

    @property
    def has_hypotheses(self) -> bool:
        return bool(self.hypothesis_ids)

    @property
    def has_analyst(self) -> bool:
        return self.analyst is not None

    @property
    def is_high_risk(self) -> bool:
        return self.risk_score >= 70

    @property
    def is_high_confidence(self) -> bool:
        return self.confidence >= 0.75

    @property
    def is_critical(self) -> bool:
        return self.priority == InvestigationPriority.CRITICAL

    @property
    def age_seconds(self) -> float:
        end = self.closed_at or datetime.now(timezone.utc)
        return (end - self.created_at).total_seconds()

    @property
    def duration_seconds(self) -> float | None:
        if self.closed_at is None:
            return None
        return (self.closed_at - self.created_at).total_seconds()

    # ====================================================================
    # Reference helpers
    # ====================================================================

    def _add_id(self, target: list[str], value: str) -> None:
        value = value.strip()
        if value and value not in target:
            target.append(value)
            target.sort()
        self.touch()

    def add_alert(self, alert_id: str) -> None:
        self._add_id(self.alert_ids, alert_id)

    def add_event(self, event_id: str) -> None:
        self._add_id(self.event_ids, event_id)

    def add_evidence(self, evidence_id: str) -> None:
        self._add_id(self.evidence_ids, evidence_id)

    def add_hypothesis(self, hypothesis_id: str) -> None:
        self._add_id(self.hypothesis_ids, hypothesis_id)

    def add_entity(self, entity_id: str) -> None:
        self._add_id(self.entity_ids, entity_id)

    # ====================================================================
    # Lifecycle
    # ====================================================================

    def touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def can_transition_to(self, status: InvestigationStatus) -> bool:
        if status == self.status:
            return True
        return status in _ALLOWED_TRANSITIONS.get(self.status, set())

    def transition_to(self, status: InvestigationStatus) -> None:
        """
        Transisi status dengan validasi state machine.
        """
        if status == self.status:
            return

        if not self.can_transition_to(status):
            raise ValueError(
                f"illegal transition: {self.status.value} -> {status.value}"
            )

        self.status = status

        if status == InvestigationStatus.RESOLVED:
            self.closed_at = datetime.now(timezone.utc)
        else:
            self.closed_at = None

        self.touch()

    def mark_resolved(
        self,
        *,
        outcome: ResolutionOutcome,
        summary: str | None = None,
    ) -> None:
        """
        Selesaikan kasus dengan outcome tertentu.
        """
        self.outcome = outcome
        if summary is not None:
            self.summary = summary
        self.transition_to(InvestigationStatus.RESOLVED)

    # ====================================================================
    # Risk helpers
    # ====================================================================

    def update_risk(
        self,
        *,
        risk_score: int,
        confidence: float,
        reason: str,
        risk_factors: list[str] | None = None,
        evidence_ids: list[str] | None = None,
        hypothesis_ids: list[str] | None = None,
    ) -> None:
        """
        Update risk score DAN catat evolusinya.
        """
        if not RISK_SCORE_MIN <= risk_score <= RISK_SCORE_MAX:
            raise ValueError(
                f"risk_score must be between "
                f"{RISK_SCORE_MIN} and {RISK_SCORE_MAX}"
            )

        if not CONFIDENCE_MIN <= confidence <= CONFIDENCE_MAX:
            raise ValueError(
                f"confidence must be between "
                f"{CONFIDENCE_MIN} and {CONFIDENCE_MAX}"
            )

        previous_risk = self.risk_score
        previous_conf = self.confidence
        delta = risk_score - previous_risk

        evolution = RiskEvolution(
            risk_score=risk_score,
            confidence=confidence,
            previous_risk_score=previous_risk,
            previous_confidence=previous_conf,
            delta=delta,
            reason=reason,
            evidence_ids=evidence_ids or [],
            hypothesis_ids=hypothesis_ids or [],
        )
        self.risk_history.append(evolution)

        self.risk_score = risk_score
        self.confidence = confidence

        if risk_factors is not None:
            self.risk_factors = sorted(
                {f.strip() for f in risk_factors if f and f.strip()}
            )

        self.touch()

    # ====================================================================
    # Analyst / Summary
    # ====================================================================

    def attach_summary(self, summary: str) -> None:
        self.summary = summary.strip() or None
        self.touch()

    def attach_notes(self, notes: str) -> None:
        self.analyst_notes = notes.strip() or None
        self.touch()

    def assign_analyst(self, analyst: str) -> None:
        value = analyst.strip()
        if not value:
            raise ValueError("analyst cannot be empty")
        self.analyst = value
        self.touch()

    # ====================================================================
    # Graph
    # ====================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.case_id,
            "type": "InvestigationCase",
            "tenant_id": self.tenant_id,
            "title": self.title,
            "status": self.status.value,
            "priority": self.priority.value,
            "category": self.category.value,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "analyst": self.analyst,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "closed_at": (
                self.closed_at.isoformat() if self.closed_at else None
            ),
            "tags": list(self.tags),
        }

    def to_relationships(self) -> list[dict[str, Any]]:
        """
        Edge dari InvestigationCase ke sub-object.
        """
        edges: list[dict[str, Any]] = []

        def _edge(target: str, target_type: str, rel: str) -> dict[str, Any]:
            return {
                "source": self.case_id,
                "source_type": "InvestigationCase",
                "target": target,
                "target_type": target_type,
                "relationship": rel,
                "properties": {},
            }

        for alert_id in self.alert_ids:
            edges.append(_edge(alert_id, "Alert", "TRIGGERED_BY"))

        for event_id in self.event_ids:
            edges.append(_edge(event_id, "Event", "OBSERVED"))

        for evidence_id in self.evidence_ids:
            edges.append(_edge(evidence_id, "Evidence", "CONTAINS"))

        for hypothesis_id in self.hypothesis_ids:
            edges.append(_edge(hypothesis_id, "Hypothesis", "EXPLORES"))

        for entity_id in self.entity_ids:
            edges.append(_edge(entity_id, "Entity", "INVOLVES"))

        if self.analyst:
            edges.append(_edge(self.analyst, "Analyst", "OWNED_BY"))

        return edges


# ===========================================================================
# Type alias
# ===========================================================================

InvestigationCaseList = list[InvestigationCase]
