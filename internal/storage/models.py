"""
ORM models untuk persistence.

Design:
- Indexed columns untuk query/filter.
- JSONB `snapshot` untuk full InvestigationResult (reconstruction).
- Child tables untuk evidence & hypotheses (queryable).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import (
    Mapped,
    mapped_column,
    relationship,
)
from sqlalchemy.types import JSON

from internal.storage.db import Base


# JSON type yang portable: JSONB untuk Postgres, JSON untuk SQLite
JSONType = JSON().with_variant(JSONB(), "postgresql")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# Investigation
# ===========================================================================

class InvestigationRow(Base):
    """
    Root row untuk satu investigation.

    Indexed columns -> untuk query cepat.
    `snapshot`      -> full InvestigationResult (JSON).
    """

    __tablename__ = "investigations"

    # -- Identity -----------------------------------------------------
    case_id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )

    # -- Classification -----------------------------------------------
    title: Mapped[str] = mapped_column(String(256), index=True)
    description: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    category: Mapped[str] = mapped_column(
        String(64), default="unknown"
    )
    severity: Mapped[int] = mapped_column(Integer, default=0)
    priority: Mapped[str] = mapped_column(
        String(32), index=True, default="low"
    )
    status: Mapped[str] = mapped_column(
        String(32), index=True, default="detected"
    )

    # -- Risk ---------------------------------------------------------
    risk_score: Mapped[int] = mapped_column(
        Integer, index=True, default=0
    )
    confidence: Mapped[float] = mapped_column(
        Float, default=0.0
    )

    # -- Ownership ----------------------------------------------------
    analyst: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )

    # -- Resolution ---------------------------------------------------
    outcome: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )
    summary: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )

    # -- Timeline -----------------------------------------------------
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        default=_utcnow,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=_utcnow,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # -- Payload ------------------------------------------------------
    snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONType, default=dict
    )
    extra_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONType, default=dict
    )

    # -- Relationships ------------------------------------------------
    evidence: Mapped[list["EvidenceRow"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    hypotheses: Mapped[list["HypothesisRow"]] = relationship(
        back_populates="investigation",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    # -- Indexes ------------------------------------------------------
    __table_args__ = (
        Index(
            "ix_investigations_tenant_status",
            "tenant_id",
            "status",
        ),
        Index(
            "ix_investigations_tenant_risk",
            "tenant_id",
            "risk_score",
        ),
        Index(
            "ix_investigations_created_desc",
            created_at.desc(),
        ),
    )

    def __repr__(self) -> str:
        return (
            f"<InvestigationRow case_id={self.case_id!r} "
            f"status={self.status!r} risk={self.risk_score}>"
        )


# ===========================================================================
# Evidence
# ===========================================================================

class EvidenceRow(Base):
    """Child row: satu evidence."""

    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.case_id", ondelete="CASCADE"),
        index=True,
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )

    evidence_type: Mapped[str] = mapped_column(
        String(32), index=True
    )
    strength: Mapped[str] = mapped_column(
        String(32), index=True
    )
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )
    confidence: Mapped[float] = mapped_column(
        Float, default=0.0
    )
    observed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        index=True,
        nullable=True,
    )
    event_id: Mapped[str | None] = mapped_column(
        String(64), index=True, nullable=True
    )

    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONType, default=dict
    )

    investigation: Mapped[InvestigationRow] = relationship(
        back_populates="evidence"
    )

    def __repr__(self) -> str:
        return (
            f"<EvidenceRow evidence_id={self.evidence_id!r} "
            f"type={self.evidence_type!r}>"
        )


# ===========================================================================
# Hypothesis
# ===========================================================================

class HypothesisRow(Base):
    """Child row: satu hypothesis."""

    __tablename__ = "hypotheses"

    hypothesis_id: Mapped[str] = mapped_column(
        String(64), primary_key=True
    )
    case_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.case_id", ondelete="CASCADE"),
        index=True,
    )
    tenant_id: Mapped[str | None] = mapped_column(
        String(128), index=True, nullable=True
    )

    hypothesis_type: Mapped[str] = mapped_column(
        String(32), index=True
    )
    statement: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(32), index=True
    )
    confidence: Mapped[float] = mapped_column(
        Float, default=0.0
    )
    parent_hypothesis_id: Mapped[str | None] = mapped_column(
        String(64), nullable=True
    )

    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONType, default=dict
    )

    investigation: Mapped[InvestigationRow] = relationship(
        back_populates="hypotheses"
    )

    def __repr__(self) -> str:
        return (
            f"<HypothesisRow hypothesis_id={self.hypothesis_id!r} "
            f"type={self.hypothesis_type!r}>"
        )


__all__ = [
    "InvestigationRow",
    "EvidenceRow",
    "HypothesisRow",
    "JSONType",
]
