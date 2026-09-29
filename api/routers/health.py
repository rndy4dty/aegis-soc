"""
Health & version endpoints.
"""

from fastapi import APIRouter

from api import __version__
from api.schemas import HealthResponse


router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def health() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


@router.get("/version", response_model=HealthResponse)
async def version() -> HealthResponse:
    return HealthResponse(status="ok", version=__version__)


__all__ = ["router"]
