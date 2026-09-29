"""
JWT token generation & verification.

Config via env:
- AEGIS_JWT_SECRET      (wajib di production)
- AEGIS_JWT_ALGORITHM   (default: HS256)
- AEGIS_JWT_EXPIRE_MIN  (default: 60 menit)
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from jwt import ExpiredSignatureError, InvalidTokenError


DEFAULT_ALGORITHM = "HS256"
DEFAULT_EXPIRE_MINUTES = 60
TOKEN_ISSUER = "aegis-soc"


def _get_secret() -> str:
    secret = os.environ.get("AEGIS_JWT_SECRET")
    if secret:
        return secret

    # Fallback: generate per-process secret (warning!)
    # Ini OK untuk dev/test, tapi token tidak valid setelah restart.
    if not hasattr(_get_secret, "_cache"):
        _get_secret._cache = secrets.token_urlsafe(64)  # type: ignore[attr-defined]
    return _get_secret._cache  # type: ignore[attr-defined]


def _get_algorithm() -> str:
    return os.environ.get("AEGIS_JWT_ALGORITHM", DEFAULT_ALGORITHM)


def _get_expire_minutes() -> int:
    try:
        return int(
            os.environ.get(
                "AEGIS_JWT_EXPIRE_MIN", DEFAULT_EXPIRE_MINUTES
            )
        )
    except (ValueError, TypeError):
        return DEFAULT_EXPIRE_MINUTES


@dataclass(frozen=True)
class TokenPayload:
    """Decoded JWT payload."""
    user_id: str
    email: str
    role: str
    tenant_id: str | None
    issued_at: datetime
    expires_at: datetime


def create_token(
    *,
    user_id: str,
    email: str,
    role: str,
    tenant_id: str | None = None,
    expires_minutes: int | None = None,
) -> tuple[str, int]:
    """
    Buat JWT token.

    Return (token, expires_in_seconds).
    """
    minutes = (
        expires_minutes
        if expires_minutes is not None
        else _get_expire_minutes()
    )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=minutes)

    payload: dict[str, Any] = {
        "sub": user_id,
        "email": email,
        "role": role,
        "tenant_id": tenant_id or "",
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": TOKEN_ISSUER,
    }

    token = jwt.encode(
        payload, _get_secret(), algorithm=_get_algorithm()
    )
    return token, minutes * 60


def decode_token(token: str) -> TokenPayload:
    """
    Decode & verify JWT token.

    Raise ValueError kalau token tidak valid atau expired.
    """
    try:
        data = jwt.decode(
            token,
            _get_secret(),
            algorithms=[_get_algorithm()],
            issuer=TOKEN_ISSUER,
        )
    except ExpiredSignatureError as exc:
        raise ValueError("token expired") from exc
    except InvalidTokenError as exc:
        raise ValueError(f"invalid token: {exc}") from exc

    try:
        user_id = data["sub"]
        email = data.get("email", "")
        role = data.get("role", "viewer")
        tenant_id = data.get("tenant_id") or None
        iat = data["iat"]
        exp = data["exp"]
    except KeyError as exc:
        raise ValueError(f"missing claim: {exc}") from exc

    return TokenPayload(
        user_id=user_id,
        email=email,
        role=role,
        tenant_id=tenant_id,
        issued_at=datetime.fromtimestamp(iat, tz=timezone.utc),
        expires_at=datetime.fromtimestamp(exp, tz=timezone.utc),
    )


__all__ = [
    "create_token",
    "decode_token",
    "TokenPayload",
    "TOKEN_ISSUER",
    "DEFAULT_ALGORITHM",
    "DEFAULT_EXPIRE_MINUTES",
]
