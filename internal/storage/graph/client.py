"""
Neo4j client wrapper.

Configuration via env:
- AEGIS_NEO4J_URI       (default: bolt://localhost:7687)
- AEGIS_NEO4J_USER      (default: neo4j)
- AEGIS_NEO4J_PASSWORD  (default: aegispassword)
- AEGIS_NEO4J_DATABASE  (default: neo4j)
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

from neo4j import (
    Driver,
    GraphDatabase,
    Session,
    Transaction,
)


DEFAULT_URI = "bolt://localhost:7687"
DEFAULT_USER = "neo4j"
DEFAULT_PASSWORD = "aegispassword"
DEFAULT_DATABASE = "neo4j"


class Neo4jClient:
    """
    Wrapper untuk Neo4j driver.
    """

    def __init__(
        self,
        *,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        create_indexes: bool = True,
    ) -> None:
        self._uri = uri or os.environ.get(
            "AEGIS_NEO4J_URI", DEFAULT_URI
        )
        self._user = user or os.environ.get(
            "AEGIS_NEO4J_USER", DEFAULT_USER
        )
        self._password = password or os.environ.get(
            "AEGIS_NEO4J_PASSWORD", DEFAULT_PASSWORD
        )
        self._database = database or os.environ.get(
            "AEGIS_NEO4J_DATABASE", DEFAULT_DATABASE
        )

        self._driver: Driver = GraphDatabase.driver(
            self._uri,
            auth=(self._user, self._password),
        )

        if create_indexes:
            self._ensure_indexes()

    # ------------------------------------------------------------------

    @property
    def uri(self) -> str:
        return self._uri

    @property
    def database(self) -> str:
        return self._database

    @property
    def driver(self) -> Driver:
        return self._driver

    # ------------------------------------------------------------------

    def verify_connectivity(self) -> bool:
        try:
            self._driver.verify_connectivity()
            return True
        except Exception:  # noqa: BLE001
            return False

    @contextmanager
    def session(self) -> Iterator[Session]:
        with self._driver.session(database=self._database) as s:
            yield s

    # ------------------------------------------------------------------

    def run(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Run a query, return list of record dicts.
        """
        with self.session() as session:
            result = session.run(
                query, parameters or {}
            )
            return [record.data() for record in result]

    def run_write(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Run a write query, return summary.
        """
        with self.session() as session:
            result = session.run(
                query, parameters or {}
            )
            summary = result.consume()
            return {
                "nodes_created": summary.counters.nodes_created,
                "relationships_created": (
                    summary.counters.relationships_created
                ),
                "properties_set": (
                    summary.counters.properties_set
                ),
            }

    # ------------------------------------------------------------------

    def _ensure_indexes(self) -> None:
        """
        Buat indexes & constraints (idempotent).
        """
        statements = [
            # Entity: unique on entity_id
            (
                "CREATE CONSTRAINT entity_id_unique IF NOT EXISTS "
                "FOR (e:Entity) REQUIRE e.entity_id IS UNIQUE"
            ),
            # Entity: lookup by fingerprint
            (
                "CREATE INDEX entity_fingerprint IF NOT EXISTS "
                "FOR (e:Entity) ON (e.fingerprint)"
            ),
            # Entity: lookup by type
            (
                "CREATE INDEX entity_type IF NOT EXISTS "
                "FOR (e:Entity) ON (e.entity_type)"
            ),
            # Entity: lookup by tenant
            (
                "CREATE INDEX entity_tenant IF NOT EXISTS "
                "FOR (e:Entity) ON (e.tenant_id)"
            ),
            # Entity: lookup by host
            (
                "CREATE INDEX entity_host IF NOT EXISTS "
                "FOR (e:Entity) ON (e.host)"
            ),
            # InvestigationCase nodes (for linking)
            (
                "CREATE CONSTRAINT case_id_unique IF NOT EXISTS "
                "FOR (c:Case) REQUIRE c.case_id IS UNIQUE"
            ),
        ]
        try:
            with self.session() as session:
                for stmt in statements:
                    session.run(stmt)
        except Exception:  # noqa: BLE001
            # Neo4j mungkin belum ready saat init; skip quietly
            pass

    def close(self) -> None:
        self._driver.close()


# ----------------------------------------------------------------------
# Global singleton
# ----------------------------------------------------------------------

_default_client: Neo4jClient | None = None


def get_neo4j(
    *,
    create_indexes: bool = True,
) -> Neo4jClient:
    global _default_client
    if _default_client is None:
        _default_client = Neo4jClient(
            create_indexes=create_indexes
        )
    return _default_client


def reset_neo4j() -> None:
    global _default_client
    if _default_client is not None:
        _default_client.close()
    _default_client = None


__all__ = [
    "Neo4jClient",
    "get_neo4j",
    "reset_neo4j",
    "DEFAULT_URI",
    "DEFAULT_USER",
    "DEFAULT_DATABASE",
]
