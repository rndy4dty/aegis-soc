"""
Investigation endpoints.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import ValidationError

from api.deps import require_api_key
from api.schemas import (
    ErrorResponse,
    InvestigateRequest,
    InvestigateResponse,
)
from internal.investigation.investigation_engine import (
    investigate,
)
from internal.reporter.report import InvestigatorReport
from pkg.models.event import Event
from pkg.models.investigation import (
    InvestigationCategory,
    InvestigationPriority,
)


router = APIRouter(
    prefix="/investigations",
    tags=["investigations"],
    dependencies=[Depends(require_api_key)],
)


@router.post(
    "",
    response_model=InvestigateResponse,
    responses={
        400: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def create_investigation(
    request: InvestigateRequest,
) -> InvestigateResponse:
    # -- Parse events -------------------------------------------------
    events: list[Event] = []
    for index, raw in enumerate(request.events):
        try:
            events.append(Event.model_validate(raw))
        except ValidationError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"event at index {index} invalid: {exc}",
            ) from exc

    # -- Category / priority -----------------------------------------
    try:
        category = InvestigationCategory(request.category)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"invalid category: {request.category}",
        ) from exc

    priority: InvestigationPriority | None = None
    if request.priority:
        try:
            priority = InvestigationPriority(request.priority)
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"invalid priority: {request.priority}",
            ) from exc

    # -- Run ----------------------------------------------------------
    try:
        result = investigate(
            events,
            title=request.title,
            tenant_id=request.tenant,
            analyst=request.analyst,
            category=category,
            priority=priority,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"investigation failed: {exc}",
        ) from exc

    # -- AI narrative (opsional) --------------------------------------
    narrative: str | None = None
    if request.narrative:
        narrative = _generate_narrative(
            result, provider=request.provider
        )

    # -- Build response -----------------------------------------------
    report = InvestigatorReport(result)
    case = result.case

    return InvestigateResponse(
        case_id=case.case_id,
        title=case.title,
        status=case.status.value,
        priority=case.priority.value,
        risk_score=result.risk_score,
        confidence=result.confidence,
        evidence_count=result.evidence_count,
        correlation_count=result.correlation_count,
        hypothesis_count=result.hypothesis_count,
        entity_count=result.graph.entity_count,
        relationship_count=result.graph.relationship_count,
        narrative=narrative,
        report_markdown=report.to_markdown(),
        report_dict=report.to_dict(),
    )


# ===========================================================================
# Helpers
# ===========================================================================

def _generate_narrative(
    result, *, provider: str
) -> str | None:
    try:
        from internal.ai import (
            AIRouter,
            MultiAgentProvider,
        )
    except ImportError:
        return None

    providers = []
    if provider == "multi_agent":
        providers = [MultiAgentProvider()]
    # provider == "rule" (default) → rule engine

    try:
        router = AIRouter(providers=providers)
        return router.narrate(result)
    except Exception:  # noqa: BLE001
        return None


__all__ = ["router"]
