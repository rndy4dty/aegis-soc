"""
Investigation endpoints with auth.

Auth rules:
- POST   /investigations         : analyst or admin
- GET    /investigations         : any authenticated user
- GET    /investigations/{id}    : any authenticated user
- DELETE /investigations/{id}    : admin only

Tenant isolation:
- tenant_id auto-injected from JWT
- user hanya bisa akses investigation milik tenant-nya
"""

from __future__ import annotations

from typing import Annotated

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from pydantic import ValidationError

from api.schemas import (
    ErrorResponse,
    InvestigateRequest,
    InvestigateResponse,
)
from internal.auth.deps import (
    get_current_user,
    require_role,
)
from internal.auth.models import UserRow, UserRole
from internal.investigation.investigation_engine import (
    investigate,
)
from internal.reporter.report import InvestigatorReport
from internal.storage import StorageService
from internal.storage.models import InvestigationRow
from pkg.models.event import Event
from pkg.models.investigation import (
    InvestigationCategory,
    InvestigationPriority,
)


router = APIRouter(
    prefix="/investigations",
    tags=["investigations"],
)


# ===========================================================================
# Helpers
# ===========================================================================

def _row_to_summary(row: InvestigationRow) -> dict:
    """Ringkas row jadi dict untuk list response."""
    return {
        "case_id": row.case_id,
        "title": row.title,
        "status": row.status,
        "priority": row.priority,
        "category": row.category,
        "severity": row.severity,
        "risk_score": row.risk_score,
        "confidence": row.confidence,
        "analyst": row.analyst,
        "tenant_id": row.tenant_id,
        "created_at": row.created_at.isoformat(),
        "updated_at": row.updated_at.isoformat(),
    }


def _check_tenant_access(
    user: UserRow | None,
    tenant_id: str | None,
) -> None:
    """
    Kalau user punya tenant_id, tidak boleh akses tenant lain.
    """
    if user is None or user.tenant_id is None:
        return
    if tenant_id is not None and tenant_id != user.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="access denied: tenant mismatch",
        )


# ===========================================================================
# Create Investigation
# ===========================================================================

@router.post(
    "",
    response_model=InvestigateResponse,
    responses={
        400: {"model": ErrorResponse},
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        500: {"model": ErrorResponse},
    },
)
async def create_investigation(
    request: InvestigateRequest,
    user: Annotated[
        UserRow,
        Depends(require_role(UserRole.ANALYST, UserRole.ADMIN)),
    ],
) -> InvestigateResponse:
    """
    Jalankan investigation baru.

    Tenant ID diambil dari JWT user (auto-inject), tidak dari request.
    """
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

    # -- Tenant override check ---------------------------------------
    # User bisa request tenant hanya kalau dia admin atau tenant-nya None
    effective_tenant = user.tenant_id
    if request.tenant and user.tenant_id is not None:
        if user.tenant_id != request.tenant and user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="cannot create investigation for other tenant",
            )
        effective_tenant = request.tenant
    elif request.tenant:
        effective_tenant = request.tenant

    # -- Run ----------------------------------------------------------
    try:
        result = investigate(
            events,
            title=request.title,
            tenant_id=effective_tenant,
            analyst=request.analyst or user.email,
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

    # -- Persist to DB (optional, fail-soft) --------------------------
    try:
        StorageService().save(result)
    except Exception:  # noqa: BLE001
        # Persistence gagal tidak boleh gagalkan investigation
        pass

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
# List Investigations
# ===========================================================================

@router.get("")
async def list_investigations(
    user: Annotated[
        UserRow, Depends(get_current_user)
    ],
    *,
    status_filter: str | None = Query(
        None, alias="status",
        description="Filter by status",
    ),
    priority: str | None = Query(None),
    analyst: str | None = Query(None),
    min_risk: int | None = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
) -> list[dict]:
    """
    List investigations.

    Tenant otomatis di-scope berdasarkan JWT user.
    """
    tenant_id = user.tenant_id if user else None

    rows = StorageService().list_cases(
        tenant_id=tenant_id,
        status=status_filter,
        priority=priority,
        analyst=analyst,
        min_risk=min_risk,
        limit=limit,
        offset=offset,
    )
    return [_row_to_summary(r) for r in rows]


# ===========================================================================
# Get Investigation Detail
# ===========================================================================


@router.get("/{case_id}")
async def get_investigation(
    case_id: str,
    user: Annotated[
        UserRow, Depends(get_current_user)
    ],
) -> dict:
    """
    Ambil detail investigation.

    Tenant check: user hanya bisa akses investigation milik tenant-nya.
    """
    svc = StorageService()
    row = svc.get(case_id) if hasattr(svc, "get") else None

    # Fallback: load via repository
    if row is None:
        with svc._db.session() as session:  # noqa: SLF001
            from internal.storage.repositories import (
                InvestigationRepository,
            )
            repo = InvestigationRepository(session)
            row = repo.get(case_id)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"investigation not found: {case_id}",
        )

    _check_tenant_access(user, row.tenant_id)

    return _row_to_summary(row)


# ===========================================================================
# Delete Investigation
# ===========================================================================

@router.delete(
    "/{case_id}",
    responses={
        401: {"model": ErrorResponse},
        403: {"model": ErrorResponse},
        404: {"model": ErrorResponse},
    },
)
async def delete_investigation(
    case_id: str,
    user: Annotated[
        UserRow,
        Depends(require_role(UserRole.ADMIN)),
    ],
) -> dict:
    """
    Hapus investigation. Admin only.
    """
    svc = StorageService()

    # Cek dulu ada atau tidak
    with svc._db.session() as session:  # noqa: SLF001
        from internal.storage.repositories import (
            InvestigationRepository,
        )
        repo = InvestigationRepository(session)
        row = repo.get(case_id)

    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"investigation not found: {case_id}",
        )

    _check_tenant_access(user, row.tenant_id)

    deleted = svc.delete(case_id)
    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"delete failed for case_id: {case_id}",
        )

    return {"deleted": True, "case_id": case_id}


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

    try:
        router = AIRouter(providers=providers)
        return router.narrate(result)
    except Exception:  # noqa: BLE001
        return None


__all__ = ["router"]
