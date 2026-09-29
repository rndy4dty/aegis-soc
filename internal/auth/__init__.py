"""
Authentication & authorization layer.

Komponen:
- UserRow         : ORM model untuk users
- UserRole        : viewer, analyst, admin
- hash_password   : bcrypt hash
- verify_password : bcrypt verify
- create_token    : JWT encode
- decode_token    : JWT decode
- AuthService     : register, login, get user
"""

from internal.auth.models import UserRow, UserRole
from internal.auth.passwords import (
    hash_password,
    verify_password,
)
from internal.auth.service import AuthService
from internal.auth.tokens import (
    TokenPayload,
    create_token,
    decode_token,
)

__all__ = [
    "UserRow",
    "UserRole",
    "AuthService",
    "hash_password",
    "verify_password",
    "create_token",
    "decode_token",
    "TokenPayload",
]
