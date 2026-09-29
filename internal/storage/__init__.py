"""
Persistence layer for AegisSOC.

Komponen:
- db              : SQLAlchemy engine + session
- models          : ORM models
- repositories    : query methods per entity
- service         : high-level API (save/load investigation)
"""

from internal.storage.db import (
    Base,
    Database,
    get_database,
)
from internal.storage.service import StorageService

__all__ = [
    "Base",
    "Database",
    "get_database",
    "StorageService",
]
