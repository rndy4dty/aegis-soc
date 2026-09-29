"""
Metadata endpoints: provider, kategori, dll.
"""

from fastapi import APIRouter, Depends

from api.deps import require_api_key
from api.schemas import (
    MetaCategoriesResponse,
    MetaProvidersResponse,
)
from pkg.models.investigation import InvestigationCategory


router = APIRouter(
    prefix="/meta",
    tags=["meta"],
    dependencies=[Depends(require_api_key)],
)


@router.get(
    "/providers",
    response_model=MetaProvidersResponse,
)
async def providers() -> MetaProvidersResponse:
    """
    Daftar provider yang tersedia (AI + threat intel).

    Provider dianggap "tersedia" berdasarkan konfigurasi env.
    """
    ai_providers: list[str] = ["rule_engine"]

    # Cek multi-agent
    try:
        from internal.ai import MultiAgentProvider  # noqa: F401
        ai_providers.append("multi_agent")
    except ImportError:
        pass

    # Cek ollama
    try:
        from internal.ai.llm import LocalLLMProvider
        if LocalLLMProvider().is_available():
            ai_providers.append("ollama")
    except Exception:  # noqa: BLE001
        pass

    # Cek cloud
    try:
        from internal.ai.llm import CloudLLMProvider
        if CloudLLMProvider().is_available():
            ai_providers.append("cloud")
    except Exception:  # noqa: BLE001
        pass

    # Cek threat intel
    ti_providers: list[str] = []
    try:
        from internal.threat_intel import (
            MISPProvider,
            OTXProvider,
            VirusTotalProvider,
        )
        if VirusTotalProvider().is_available():
            ti_providers.append("virustotal")
        if OTXProvider().is_available():
            ti_providers.append("otx")
        if MISPProvider().is_available():
            ti_providers.append("misp")
    except ImportError:
        pass

    return MetaProvidersResponse(
        ai_providers=ai_providers,
        threat_intel_providers=ti_providers,
    )


@router.get(
    "/categories",
    response_model=MetaCategoriesResponse,
)
async def categories() -> MetaCategoriesResponse:
    return MetaCategoriesResponse(
        categories=[c.value for c in InvestigationCategory],
    )


__all__ = ["router"]
