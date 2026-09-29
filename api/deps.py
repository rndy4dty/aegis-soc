"""
Dependency injection untuk API.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Annotated

from fastapi import Header, HTTPException, status


@dataclass(frozen=True)
class Settings:
    """API settings."""
    app_name: str = "AegisSOC API"
    version: str = "1.0.0"
    api_key: str | None = None

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            api_key=os.environ.get("AEGIS_API_KEY") or None,
        )


_SETTINGS = Settings.from_env()


def get_settings() -> Settings:
    return _SETTINGS


async def require_api_key(
    x_api_key: Annotated[str | None, Header()] = None,
) -> None:
    """
    Opsional: kalau AEGIS_API_KEY diset, header X-API-Key wajib cocok.
    Kalau tidak diset, endpoint terbuka.
    """
    settings = get_settings()
    if settings.api_key is None:
        return
    if x_api_key != settings.api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or missing X-API-Key header",
        )


__all__ = ["Settings", "get_settings", "require_api_key"]
