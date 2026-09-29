"""
Password hashing dengan bcrypt.

Password pre-hash dengan SHA-256 + base64 supaya tidak kena
bcrypt 72-byte limit. Ini pattern standar untuk password panjang.
"""

from __future__ import annotations

import base64
import hashlib

import bcrypt


MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


def _prehash(password: str) -> bytes:
    """SHA-256 → base64. Hasil ~44 char, di bawah 72-byte limit."""
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def validate_password(password: str) -> None:
    """
    Raise ValueError kalau password tidak memenuhi syarat.
    """
    if not isinstance(password, str):
        raise ValueError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at least "
            f"{MIN_PASSWORD_LENGTH} characters"
        )
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(
            f"password must be at most "
            f"{MAX_PASSWORD_LENGTH} characters"
        )


def hash_password(password: str) -> str:
    """Hash password, return bcrypt hash string."""
    validate_password(password)
    hashed = bcrypt.hashpw(_prehash(password), bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    """Verify password. Return False kalau mismatch atau hash invalid."""
    if not isinstance(password, str) or not isinstance(hashed, str):
        return False
    try:
        return bcrypt.checkpw(
            _prehash(password),
            hashed.encode("utf-8"),
        )
    except (ValueError, TypeError):
        return False


__all__ = [
    "hash_password",
    "verify_password",
    "validate_password",
    "MIN_PASSWORD_LENGTH",
    "MAX_PASSWORD_LENGTH",
]
