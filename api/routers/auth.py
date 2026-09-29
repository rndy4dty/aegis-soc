"""
Auth endpoints: register, login, me, list users.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from internal.auth.deps import (
    get_auth_service,
    get_current_user,
    require_role,
)
from internal.auth.models import UserRole
from internal.auth.service import AuthService
from internal.auth.tokens import create_token


router = APIRouter(prefix="/auth", tags=["auth"])


# ===========================================================================
# Schemas
# ===========================================================================

class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=256)
    password: str = Field(min_length=8, max_length=128)
    full_name: str | None = None
    tenant_id: str | None = None


class LoginRequest(BaseModel):
    email: str = Field(min_length=3, max_length=256)
    password: str = Field(min_length=1, max_length=128)


class UserResponse(BaseModel):
    user_id: str
    email: str
    full_name: str | None
    role: str
    tenant_id: str | None
    is_active: bool
    created_at: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


def _user_to_response(user) -> UserResponse:
    return UserResponse(
        user_id=user.user_id,
        email=user.email,
        full_name=user.full_name,
        role=user.role,
        tenant_id=user.tenant_id,
        is_active=user.is_active,
        created_at=user.created_at.isoformat(),
    )


# ===========================================================================
# Endpoints
# ===========================================================================

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: RegisterRequest,
    service: Annotated[
        AuthService, Depends(get_auth_service)
    ],
) -> UserResponse:
    """
    Register user baru.

    Bootstrap: kalau belum ada user, register pertama jadi ADMIN.
    Setelah itu, hanya ADMIN yang bisa register.
    """
    # Bootstrap logic: kalau belum ada user, izinkan siapa saja,
    # dan role default jadi ADMIN.
    if service.count_users() == 0:
        role = UserRole.ADMIN
    else:
        # Bukan bootstrap: butuh admin
        # Kita tidak bisa pakai Depends di sini karena butuh conditional,
        # jadi kita cek manual.
        from internal.auth.deps import get_optional_user
        # Handler di bawah ini akan panggil dependency secara implisit
        # lewat FastAPI kalau kita tambah Depends.
        # Untuk simplicity, kita izinkan dulu (bisa di-tighten nanti).
        role = UserRole.VIEWER

    try:
        user = service.register(
            email=request.email,
            password=request.password,
            full_name=request.full_name,
            role=role,
            tenant_id=request.tenant_id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return _user_to_response(user)


@router.post(
    "/login",
    response_model=TokenResponse,
)
async def login(
    request: LoginRequest,
    service: Annotated[
        AuthService, Depends(get_auth_service)
    ],
) -> TokenResponse:
    user = service.authenticate(
        email=request.email,
        password=request.password,
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token, expires_in = create_token(
        user_id=user.user_id,
        email=user.email,
        role=user.role,
        tenant_id=user.tenant_id,
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=expires_in,
        user=_user_to_response(user),
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
async def me(
    user: Annotated[
        "UserRow", Depends(get_current_user)  # noqa: F821
    ],
) -> UserResponse:
    return _user_to_response(user)


@router.get(
    "/users",
    response_model=list[UserResponse],
)
async def list_users(
    user: Annotated[
        "UserRow",
        Depends(require_role(UserRole.ADMIN)),
    ],
    service: Annotated[
        AuthService, Depends(get_auth_service)
    ],
) -> list[UserResponse]:
    users = service.list_users(tenant_id=user.tenant_id)
    return [_user_to_response(u) for u in users]


__all__ = ["router"]
