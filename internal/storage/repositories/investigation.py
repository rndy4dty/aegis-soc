"""
Repository untuk Investigation.

Task:
- Save InvestigationResult ke DB (upsert)
- Load InvestigationResult dari DB
- Query list investigation
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.orm import Session

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.storage.models import (
    EvidenceRow,
    HypothesisRow,
    InvestigationRow,
)
from pkg.models.evidence import Evidence
from pkg.models.hypothesis import Hypothesis
from pkg.models.investigation import InvestigationCase


class InvestigationRepository:
    """Repository untuk aggregate root Investigation."""

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, result: InvestigationResult) -> InvestigationRow:
        """
        Upsert investigation + evidence + hypotheses.

        Kalau case_id sudah ada, update. Kalau belum, insert baru.
        """
        case = result.case

        row = self._session.get(InvestigationRow, case.case_id)

        if row is None:
            row = InvestigationRow(case_id=case.case_id)
            self._session.add(row)

        # -- Update indexed columns -----------------------------------
        row.tenant_id = case.tenant_id
        row.title = case.title
        row.description = case.description
        row.category = case.category.value
        row.severity = case.severity
        row.priority = case.priority.value
        row.status = case.status.value
        row.risk_score = result.risk_score
        row.confidence = result.confidence
        row.analyst = case.analyst
        row.outcome = (
            case.outcome.value if case.outcome is not None else None
        )
        row.summary = case.summary

        row.created_at = case.created_at
        row.updated_at = datetime.now(timezone.utc)
        row.closed_at = case.closed_at

        # -- Snapshot: full InvestigationResult -----------------------
        row.snapshot = self._serialize_result(result)

        # -- Evidence -------------------------------------------------
        existing_ev = {e.evidence_id for e in row.evidence}
        incoming_ev = {e.evidence_id for e in result.evidence}

        # Delete removed
        for ev_row in list(row.evidence):
            if ev_row.evidence_id not in incoming_ev:
                self._session.delete(ev_row)

        # Add/update
        for ev in result.evidence:
            if ev.evidence_id in existing_ev:
                ev_row = self._session.get(
                    EvidenceRow, ev.evidence_id
                )
                self._update_evidence_row(ev_row, ev, case.case_id)
            else:
                ev_row = self._new_evidence_row(ev, case.case_id)
                self._session.add(ev_row)

        # -- Hypotheses -----------------------------------------------
        existing_h = {h.hypothesis_id for h in row.hypotheses}
        incoming_h = {h.hypothesis_id for h in result.hypotheses}

        for h_row in list(row.hypotheses):
            if h_row.hypothesis_id not in incoming_h:
                self._session.delete(h_row)

        for h in result.hypotheses:
            if h.hypothesis_id in existing_h:
                h_row = self._session.get(
                    HypothesisRow, h.hypothesis_id
                )
                self._update_hypothesis_row(h_row, h, case.case_id)
            else:
                h_row = self._new_hypothesis_row(h, case.case_id)
                self._session.add(h_row)

        self._session.flush()
        return row

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def get(self, case_id: str) -> InvestigationRow | None:
        """Ambil row by case_id."""
        return self._session.get(InvestigationRow, case_id)

    def load_result(
        self, case_id: str
    ) -> InvestigationResult | None:
        """
        Load full InvestigationResult dari DB.

        Reconstruction dari `snapshot` + child rows.
        Return None kalau tidak ketemu.
        """
        row = self.get(case_id)
        if row is None:
            return None

        return self._deserialize_result(row)

    def list_cases(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
        priority: str | None = None,
        analyst: str | None = None,
        min_risk: int | None = None,
        since: datetime | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[InvestigationRow]:
        """
        Query list investigation dengan filter.
        """
        stmt = select(InvestigationRow)

        if tenant_id is not None:
            stmt = stmt.where(
                InvestigationRow.tenant_id == tenant_id
            )
        if status is not None:
            stmt = stmt.where(
                InvestigationRow.status == status
            )
        if priority is not None:
            stmt = stmt.where(
                InvestigationRow.priority == priority
            )
        if analyst is not None:
            stmt = stmt.where(
                InvestigationRow.analyst == analyst
            )
        if min_risk is not None:
            stmt = stmt.where(
                InvestigationRow.risk_score >= min_risk
            )
        if since is not None:
            stmt = stmt.where(
                InvestigationRow.created_at >= since
            )

        stmt = stmt.order_by(
            desc(InvestigationRow.created_at)
        ).limit(limit).offset(offset)

        return list(self._session.scalars(stmt).all())

    def count(
        self,
        *,
        tenant_id: str | None = None,
        status: str | None = None,
    ) -> int:
        from sqlalchemy import func

        stmt = select(func.count()).select_from(InvestigationRow)
        if tenant_id is not None:
            stmt = stmt.where(
                InvestigationRow.tenant_id == tenant_id
            )
        if status is not None:
            stmt = stmt.where(
                InvestigationRow.status == status
            )
        return int(self._session.scalar(stmt) or 0)

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def delete(self, case_id: str) -> bool:
        row = self.get(case_id)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True

    # ------------------------------------------------------------------
    # Serialization helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _serialize_result(
        result: InvestigationResult,
    ) -> dict[str, Any]:
        """Serialize InvestigationResult ke dict (JSON-safe)."""
        return {
            "case": result.case.model_dump(mode="json"),
            "evidence": [
                e.model_dump(mode="json") for e in result.evidence
            ],
            "hypotheses": [
                h.model_dump(mode="json")
                for h in result.hypotheses
            ],
            "correlations": [
                InvestigationRepository._safe_dump(c)
                for c in result.correlations
            ],
            "risk": (
                result.risk.model_dump(mode="json")
                if result.risk else None
            ),
            "graph": {
                "entity_count": result.graph.entity_count,
                "relationship_count": result.graph.relationship_count,
                "events_processed": result.graph.events_processed,
            },
        }

    @staticmethod
    def _safe_dump(obj: Any) -> dict[str, Any]:
        """model_dump kalau Pydantic, else dict."""
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        if isinstance(obj, dict):
            return obj
        return {"repr": repr(obj)}

    @staticmethod
    def _deserialize_result(
        row: InvestigationRow,
    ) -> InvestigationResult:
        """
        Reconstruct InvestigationResult dari row + snapshot.
        """
        snapshot = row.snapshot or {}

        case_data = snapshot.get("case")
        if case_data is None:
            raise ValueError(
                f"missing 'case' in snapshot for {row.case_id}"
            )
        case = InvestigationCase.model_validate(case_data)

        evidence_data = snapshot.get("evidence") or []
        evidence = [
            Evidence.model_validate(e) for e in evidence_data
        ]

        hypothesis_data = snapshot.get("hypotheses") or []
        hypotheses = [
            Hypothesis.model_validate(h) for h in hypothesis_data
        ]

        # Graph hanya statistik (tidak reconstruct full graph)
        # Karena graph butuh object kompleks, kita skip dulu.
        from internal.graph.graph_store import InvestigationGraph
        from internal.graph.entity_resolver import EntityStore
        from internal.graph.relationship_resolver import RelationshipStore

        graph_stats = snapshot.get("graph") or {}
        graph = InvestigationGraph(
            entity_store=EntityStore([]),
            relationship_store=RelationshipStore([]),
            events_processed=graph_stats.get("events_processed", 0),
        )

        # Risk
        risk_data = snapshot.get("risk")
        risk = None
        if risk_data is not None:
            from internal.investigation.risk_engine import RiskAssessment
            risk = RiskAssessment.model_validate(risk_data)

        # Correlations: optional, skip reconstruction
        correlations: list = []

        return InvestigationResult(
            case=case,
            graph=graph,
            evidence=evidence,
            correlations=correlations,
            hypotheses=hypotheses,
            risk=risk,
        )

    # ------------------------------------------------------------------
    # Row helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _new_evidence_row(
        ev: Evidence, case_id: str
    ) -> EvidenceRow:
        return EvidenceRow(
            evidence_id=ev.evidence_id,
            case_id=case_id,
            tenant_id=ev.tenant_id,
            evidence_type=ev.evidence_type.value,
            strength=ev.strength.value,
            title=ev.title,
            description=ev.description,
            confidence=ev.confidence,
            observed_at=ev.observed_at,
            event_id=ev.event_id,
            payload=ev.model_dump(mode="json"),
        )

    @staticmethod
    def _update_evidence_row(
        row: EvidenceRow, ev: Evidence, case_id: str
    ) -> None:
        row.tenant_id = ev.tenant_id
        row.evidence_type = ev.evidence_type.value
        row.strength = ev.strength.value
        row.title = ev.title
        row.description = ev.description
        row.confidence = ev.confidence
        row.observed_at = ev.observed_at
        row.event_id = ev.event_id
        row.payload = ev.model_dump(mode="json")

    @staticmethod
    def _new_hypothesis_row(
        h: Hypothesis, case_id: str
    ) -> HypothesisRow:
        return HypothesisRow(
            hypothesis_id=h.hypothesis_id,
            case_id=case_id,
            tenant_id=h.tenant_id,
            hypothesis_type=h.hypothesis_type.value,
            statement=h.statement,
            status=h.status.value,
            confidence=h.confidence,
            parent_hypothesis_id=h.parent_hypothesis_id,
            payload=h.model_dump(mode="json"),
        )

    @staticmethod
    def _update_hypothesis_row(
        row: HypothesisRow, h: Hypothesis, case_id: str
    ) -> None:
        row.tenant_id = h.tenant_id
        row.hypothesis_type = h.hypothesis_type.value
        row.statement = h.statement
        row.status = h.status.value
        row.confidence = h.confidence
        row.parent_hypothesis_id = h.parent_hypothesis_id
        row.payload = h.model_dump(mode="json")


__all__ = ["InvestigationRepository"]
