"""
FastAPI dependencies untuk auth.

- get_auth_service    : AuthService instance
- get_current_user    : required user (401 kalau tidak ada)
- get_optional_user   : optional user
- require_role        : factory untuk cek role
"""

from __future__ import annotations

import os
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBearer,
)

from internal.auth.models import UserRow, UserRole
from internal.auth.service import AuthService
from internal.auth.tokens import decode_token


security = HTTPBearer(auto_error=False)


def _auth_required() -> bool:
    """Apakah auth wajib? Env: AEGIS_AUTH_REQUIRED=true"""
    val = os.environ.get("AEGIS_AUTH_REQUIRED", "false").lower()
    return val in ("1", "true", "yes", "on")


def get_auth_service() -> AuthService:
    return AuthService()


async def get_optional_user(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(security),
    ] = None,
    service: Annotated[
        AuthService, Depends(get_auth_service)
    ] = None,  # type: ignore[assignment]
) -> UserRow | None:
    """
    Return user kalau token valid, None kalau tidak ada token.

    Kalau AEGIS_AUTH_REQUIRED=true dan tidak ada user → 401.
    """
    if credentials is None:
        if _auth_required():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return None

    try:
        payload = decode_token(credentials.credentials)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(exc),
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    user = service.get_user(payload.user_id)
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="user not found or inactive",
        )
    return user


async def get_current_user(
    user: Annotated[
        UserRow | None, Depends(get_optional_user)
    ],
) -> UserRow:
    """
    Wajib ada user. Raise 401 kalau tidak ada.
    """
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_role(*allowed: UserRole):
    """
    Factory: return dependency yang cek user.role ∈ allowed.
    """
    allowed_values = {r.value for r in allowed}

    async def _check(
        user: Annotated[
            UserRow, Depends(get_current_user)
        ],
    ) -> UserRow:
        if user.role not in allowed_values:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"role {user.role!r} not allowed; "
                    f"requires one of {sorted(allowed_values)}"
                ),
            )
        return user

    return _check


__all__ = [
    "get_auth_service",
    "get_optional_user",
    "get_current_user",
    "require_role",
]
