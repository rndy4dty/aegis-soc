"""
Pydantic schemas untuk API request/response.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ===========================================================================
# Requests
# ===========================================================================

class EventPayload(BaseModel):
    """Satu event input (schema Event canonical)."""
    model_config = ConfigDict(extra="allow")


class InvestigateRequest(BaseModel):
    """
    Body untuk POST /investigations.

    - events    : list event (schema Event canonical)
    - title     : judul investigation
    - analyst   : nama analis (opsional)
    - tenant    : tenant ID (opsional)
    - category  : kategori investigation (default: unknown)
    - priority  : priority override (opsional)
    - narrative : generate AI narrative (default: False)
    - provider  : rule | multi_agent (default: rule)
    """

    events: list[dict[str, Any]] = Field(min_length=1)
    title: str = Field(min_length=1, max_length=200)
    analyst: str | None = None
    tenant: str | None = None
    category: str = "unknown"
    priority: str | None = None
    narrative: bool = False
    provider: str = "rule"


# ===========================================================================
# Responses
# ===========================================================================

class HealthResponse(BaseModel):
    status: str = "ok"
    version: str


class InvestigateResponse(BaseModel):
    """
    Response dari POST /investigations.

    - case_id          : ID kasus
    - title            : judul
    - status           : status case
    - priority         : priority
    - risk_score       : 0-100
    - confidence       : 0-1
    - evidence_count   : jumlah evidence
    - correlation_count: jumlah korelasi
    - hypothesis_count : jumlah hypothesis
    - entity_count     : jumlah entity di graph
    - relationship_count: jumlah relationship di graph
    - narrative        : AI narrative (kalau diminta)
    - report_markdown  : laporan lengkap markdown
    - report_dict      : laporan terstruktur (dict)
    """

    case_id: str
    title: str
    status: str
    priority: str
    risk_score: int
    confidence: float
    evidence_count: int
    correlation_count: int
    hypothesis_count: int
    entity_count: int
    relationship_count: int
    narrative: str | None = None
    report_markdown: str
    report_dict: dict[str, Any]


class ProviderInfo(BaseModel):
    name: str
    description: str = ""


class MetaProvidersResponse(BaseModel):
    ai_providers: list[str]
    threat_intel_providers: list[str]
    correlation_available: bool = True


class MetaCategoriesResponse(BaseModel):
    categories: list[str]


class ErrorResponse(BaseModel):
    error: str
    detail: str | None = None


__all__ = [
    "InvestigateRequest",
    "InvestigateResponse",
    "HealthResponse",
    "ProviderInfo",
    "MetaProvidersResponse",
    "MetaCategoriesResponse",
    "ErrorResponse",
]
