from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


# ===========================================================================
# Constants
# ===========================================================================

SCHEMA_VERSION: str = "1.0"

ENTITY_VALUE_MAX_LENGTH: int = 4096

MetadataConflictPolicy = Literal["left", "right", "raise"]
DEFAULT_METADATA_CONFLICT_POLICY: MetadataConflictPolicy = "left"

VALID_USER_IDENTITY_SCOPES: frozenset[str] = frozenset({"local", "domain"})


# ===========================================================================
# Entity types
# ===========================================================================

class EntityType(str, Enum):
    PROCESS = "process"
    FILE = "file"
    HASH = "hash"
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    USER = "user"
    HOST = "host"
    REGISTRY = "registry"
    MITRE_TECHNIQUE = "mitre_technique"
    ALERT = "alert"
    EVENT = "event"
    EVIDENCE = "evidence"


# ---------------------------------------------------------------------------
# Identity classification
# ---------------------------------------------------------------------------

# Occurrence identity: identity mengikuti ID record sumbernya.
OCCURRENCE_IDENTITY_TYPES: frozenset[EntityType] = frozenset({
    EntityType.EVENT,
    EntityType.ALERT,
    EntityType.EVIDENCE,
})


# Substantive identity: entity graph yang bisa di-merge.
SUBSTANTIVE_ENTITY_TYPES: frozenset[EntityType] = frozenset({
    EntityType.PROCESS,
    EntityType.FILE,
    EntityType.HASH,
    EntityType.IP,
    EntityType.DOMAIN,
    EntityType.URL,
    EntityType.USER,
    EntityType.HOST,
    EntityType.REGISTRY,
    EntityType.MITRE_TECHNIQUE,
})


# Always host-scoped.
ALWAYS_HOST_SCOPED: frozenset[EntityType] = frozenset({
    EntityType.PROCESS,
    EntityType.FILE,
    EntityType.REGISTRY,
})


# Global: identity tidak bergantung host.
GLOBAL_ENTITY_TYPES: frozenset[EntityType] = frozenset({
    EntityType.HASH,
    EntityType.IP,
    EntityType.DOMAIN,
    EntityType.URL,
    EntityType.MITRE_TECHNIQUE,
})


# Backward-compat alias.
HOST_SCOPED_ENTITY_TYPES = ALWAYS_HOST_SCOPED


# ===========================================================================
# Helpers
# ===========================================================================

def _normalize_ts(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _normalize_id_string(value: Any) -> str | None:
    """
    Normalisasi id provenance: harus string, di-strip, non-empty.
    Return None kalau tidak valid.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


def _normalize_optional_str(value: Any) -> str | None:
    """Strip; None kalau kosong."""
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    return stripped or None


# ===========================================================================
# Entity
# ===========================================================================

class Entity(BaseModel):
    """
    Canonical entity untuk AegisSOC Investigation Graph.
    """

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=False,
    )

    # ------------------------------------------------------------------
    # Identity
    # ------------------------------------------------------------------
    entity_id: str = Field(default_factory=lambda: str(uuid4()))
    schema_version: str = Field(default=SCHEMA_VERSION)
    tenant_id: str | None = None

    entity_type: EntityType

    # Observed representation (asli)
    value: str = Field(min_length=1, max_length=ENTITY_VALUE_MAX_LENGTH)

    # Canonical identity representation.
    # Diisi oleh layer normalizer/extractor.
    # Fallback = value.strip() (case-preserving).
    normalized_value: str = Field(default="")

    # Identity attributes khusus.
    # Dipakai hanya untuk entity yang membutuhkan atribut tambahan
    # sebagai bagian dari canonical identity.
    #
    # USER:
    #   identity_scope = "local"  → host-scoped
    #   identity_scope = "domain" → butuh identity_domain
    # HASH:
    #   hash_algorithm = "md5" | "sha1" | "sha256" | ...
    identity_scope: str | None = None
    identity_domain: str | None = None
    hash_algorithm: str | None = None

    # ------------------------------------------------------------------
    # Context
    # ------------------------------------------------------------------
    host: str | None = None

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    # ------------------------------------------------------------------
    # Provenance
    # ------------------------------------------------------------------
    source_event_ids: list[str] = Field(default_factory=list)
    source_evidence_ids: list[str] = Field(default_factory=list)

    # ------------------------------------------------------------------
    # Extensibility
    # ------------------------------------------------------------------
    properties: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ------------------------------------------------------------------
    # Deterministic identity
    # ------------------------------------------------------------------
    fingerprint: str | None = None

    # ==================================================================
    # Field validators
    # ==================================================================

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Entity value cannot be empty")
        return v

    @field_validator("normalized_value")
    @classmethod
    def _strip_normalized(cls, v: str) -> str:
        return v.strip()

    @field_validator("identity_scope")
    @classmethod
    def _normalize_identity_scope(cls, v: str | None) -> str | None:
        v = _normalize_optional_str(v)
        return v.lower() if v else None

    @field_validator("identity_domain")
    @classmethod
    def _normalize_identity_domain(cls, v: str | None) -> str | None:
        v = _normalize_optional_str(v)
        return v.lower() if v else None

    @field_validator("hash_algorithm")
    @classmethod
    def _normalize_hash_algorithm(cls, v: str | None) -> str | None:
        v = _normalize_optional_str(v)
        return v.lower() if v else None

    @field_validator("source_event_ids", "source_evidence_ids")
    @classmethod
    def _normalize_source_ids(cls, v: list[str]) -> list[str]:
        return sorted({
            item.strip()
            for item in v
            if item and item.strip()
        })

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, v: list[str]) -> list[str]:
        return sorted({
            item.strip().lower()
            for item in v
            if item and item.strip()
        })

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _ensure_utc(cls, v: datetime | None) -> datetime | None:
        return _normalize_ts(v)

    # ==================================================================
    # Model validator
    # ==================================================================

    @model_validator(mode="after")
    def _finalize(self) -> "Entity":
        # Fallback normalized_value
        if not self.normalized_value:
            object.__setattr__(
                self,
                "normalized_value",
                self.value.strip(),
            )

        # Temporal consistency
        if (
            self.first_seen is not None
            and self.last_seen is not None
            and self.first_seen > self.last_seen
        ):
            raise ValueError(
                "first_seen cannot be later than last_seen"
            )

        # Identity attribute validation
        if self.entity_type == EntityType.USER:
            if self.identity_scope not in VALID_USER_IDENTITY_SCOPES:
                raise ValueError(
                    "USER entity requires identity_scope='local' or 'domain'"
                )

            if (
                self.identity_scope == "domain"
                and not self.identity_domain
            ):
                raise ValueError(
                    "Domain USER requires identity_domain"
                )

            if (
                self.identity_scope == "local"
                and not self.host
            ):
                raise ValueError(
                    "Local USER requires host"
                )

            if self.hash_algorithm is not None:
                raise ValueError(
                    "USER entity cannot define hash_algorithm"
                )

        elif self.entity_type == EntityType.HASH:
            if not self.hash_algorithm:
                raise ValueError(
                    "HASH entity requires hash_algorithm"
                )

            if self.identity_scope is not None:
                raise ValueError(
                    "HASH entity cannot define identity_scope"
                )

            if self.identity_domain is not None:
                raise ValueError(
                    "HASH entity cannot define identity_domain"
                )

        else:
            if self.identity_scope is not None:
                raise ValueError(
                    f"{self.entity_type.value} entity cannot define "
                    "identity_scope"
                )

            if self.identity_domain is not None:
                raise ValueError(
                    f"{self.entity_type.value} entity cannot define "
                    "identity_domain"
                )

            if self.hash_algorithm is not None:
                raise ValueError(
                    f"{self.entity_type.value} entity cannot define "
                    "hash_algorithm"
                )

        return self
    # ==================================================================
    # Classification
    # ==================================================================

    @property
    def is_occurrence(self) -> bool:
        return self.entity_type in OCCURRENCE_IDENTITY_TYPES

    @property
    def is_substantive(self) -> bool:
        return self.entity_type in SUBSTANTIVE_ENTITY_TYPES

    @property
    def is_global(self) -> bool:
        return self.entity_type in GLOBAL_ENTITY_TYPES

    @property
    def is_host_scoped(self) -> bool:
        """
        Identity bergantung host.

        USER conditional:
        - identity_scope == "local"  → host-scoped
        - identity_scope == "domain" → tidak host-scoped
        """
        if self.entity_type in ALWAYS_HOST_SCOPED:
            return True
        if self.entity_type == EntityType.USER:
            return self._user_is_local()
        return False

    @property
    def has_provenance(self) -> bool:
        return bool(self.source_event_ids or self.source_evidence_ids)

    @property
    def event_count(self) -> int:
        return len(self.source_event_ids)

    @property
    def evidence_count(self) -> int:
        return len(self.source_evidence_ids)

    @property
    def observation_count(self) -> int:
        return self.event_count + self.evidence_count

    # ==================================================================
    # USER helpers
    # ==================================================================

    def _user_is_local(self) -> bool:
        """
        USER scope ditentukan eksplisit via identity_scope.

        - local  → host-scoped
        - domain → global dalam tenant/domain
        """
        return self.identity_scope != "domain"

    # ==================================================================
    # Fingerprint
    # ==================================================================

    def canonical_payload(self) -> dict[str, Any]:
        """
        Field yang mendefinisikan identity substantif.

        - OCCURRENCE (EVENT/ALERT/EVIDENCE):
              record_id = value

        - HOST:
              normalized_value

        - HASH:
              normalized_value + hash_algorithm

        - USER (local):
              normalized_value + host + identity_scope="local"

        - USER (domain):
              normalized_value + identity_domain + identity_scope="domain"

        - PROCESS/FILE/REGISTRY:
              normalized_value + host

        - IP/DOMAIN/URL/MITRE_TECHNIQUE:
              normalized_value

        Dikecualikan:
        - entity_id, first_seen, last_seen, source_*_ids,
          properties, tags, metadata, fingerprint
        """
        base: dict[str, Any] = {
            "schema_version": self.schema_version,
            "tenant_id": self.tenant_id,
            "entity_type": self.entity_type.value,
        }

        # -- Occurrence identity --------------------------------------
        if self.entity_type in OCCURRENCE_IDENTITY_TYPES:
            base["record_id"] = self.value.strip()
            return base

        # -- Substantive identity -------------------------------------
        base["normalized_value"] = self.normalized_value

        # -- Host-scoped ----------------------------------------------
        if self.entity_type in ALWAYS_HOST_SCOPED:
            base["host"] = (self.host or "").lower()

        # -- USER -----------------------------------------------------
        elif self.entity_type == EntityType.USER:
            base["identity_scope"] = self.identity_scope

            if self.identity_scope == "local":
                base["host"] = (self.host or "").lower()
            elif self.identity_scope == "domain":
                base["identity_domain"] = self.identity_domain or ""

        # -- HASH -----------------------------------------------------
        elif self.entity_type == EntityType.HASH:
            base["hash_algorithm"] = self.hash_algorithm or ""

        return base

    def calculate_fingerprint(self) -> str:
        """
        SHA-256 dari canonical_payload().

        Identity fingerprint, bukan integrity hash.
        """
        blob = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def with_fingerprint(self) -> "Entity":
        return self.model_copy(
            update={"fingerprint": self.calculate_fingerprint()}
        )

    def verify_fingerprint(self) -> bool:
        """
        Verifikasi identity fingerprint.

        Ini BUKAN integrity check.

        Field yang TIDAK memengaruhi fingerprint: properties, tags,
        source_event_ids, source_evidence_ids, first_seen, last_seen,
        metadata, entity_id.

        Field yang MEMENGARUHI fingerprint: schema_version, tenant_id,
        entity_type, value (occurrence), normalized_value, host
        (untuk host-scoped), identity_scope & identity_domain
        (untuk USER), hash_algorithm (untuk HASH).
        """
        if not self.fingerprint:
            return False
        return self.fingerprint == self.calculate_fingerprint()

    # ==================================================================
    # Identity comparison
    # ==================================================================

    def same_identity(self, other: "Entity") -> bool:
        if not isinstance(other, Entity):
            return False

        return (
            self.calculate_fingerprint()
            == other.calculate_fingerprint()
        )

    # ==================================================================
    # Temporal
    # ==================================================================

    def touch(self, timestamp: datetime) -> "Entity":
        ts = _normalize_ts(timestamp)
        if ts is None:
            return self

        first = self.first_seen
        last = self.last_seen

        if first is None or ts < first:
            first = ts
        if last is None or ts > last:
            last = ts

        return self.model_copy(
            update={"first_seen": first, "last_seen": last}
        )

    # ==================================================================
    # Merge
    # ==================================================================

    @staticmethod
    def _merge_properties(
        left: dict[str, Any],
        right: dict[str, Any],
    ) -> dict[str, Any]:
        result = dict(left)
        for key, value in right.items():
            if key not in result:
                result[key] = value
                continue

            existing = result[key]
            if isinstance(existing, list) and isinstance(value, list):
                seen: set[str] = set()
                merged: list[Any] = []
                for item in existing + value:
                    token = json.dumps(item, sort_keys=True, default=str)
                    if token in seen:
                        continue
                    seen.add(token)
                    merged.append(item)
                result[key] = merged
            else:
                result[key] = value
        return result

    @staticmethod
    def _merge_metadata(
        left: dict[str, Any],
        right: dict[str, Any],
        *,
        on_conflict: MetadataConflictPolicy,
    ) -> dict[str, Any]:
        merged = dict(left)
        for key, value in right.items():
            if key not in merged:
                merged[key] = value
                continue
            if merged[key] == value:
                continue
            if on_conflict == "left":
                continue
            if on_conflict == "right":
                merged[key] = value
                continue
            raise ValueError(
                f"metadata conflict for key {key!r}: "
                f"left={merged[key]!r}, right={value!r}"
            )
        return merged

    def merge(
        self,
        other: "Entity",
        *,
        on_metadata_conflict: MetadataConflictPolicy = (
            DEFAULT_METADATA_CONFLICT_POLICY
        ),
    ) -> "Entity":
        """
        Gabungkan dua entity dengan identitas yang sama.

        Fingerprint akan dihitung ulang dari identity canonical
        hasil akhir, bukan disalin dari self/other.
        """
        if not self.same_identity(other):
            raise ValueError(
                "cannot merge entities with different fingerprint"
            )

        merged_event_ids = sorted(
            set(self.source_event_ids) | set(other.source_event_ids)
        )
        merged_evidence_ids = sorted(
            set(self.source_evidence_ids) | set(other.source_evidence_ids)
        )
        merged_tags = sorted(set(self.tags) | set(other.tags))
        merged_properties = self._merge_properties(
            self.properties, other.properties
        )
        merged_metadata = self._merge_metadata(
            self.metadata,
            other.metadata,
            on_conflict=on_metadata_conflict,
        )

        def _min_ts(
            a: datetime | None, b: datetime | None
        ) -> datetime | None:
            if a is None:
                return b
            if b is None:
                return a
            return a if a <= b else b

        def _max_ts(
            a: datetime | None, b: datetime | None
        ) -> datetime | None:
            if a is None:
                return b
            if b is None:
                return a
            return a if a >= b else b

        merged = self.model_copy(update={
            "first_seen": _min_ts(self.first_seen, other.first_seen),
            "last_seen": _max_ts(self.last_seen, other.last_seen),
            "source_event_ids": merged_event_ids,
            "source_evidence_ids": merged_evidence_ids,
            "properties": merged_properties,
            "tags": merged_tags,
            "metadata": merged_metadata,
            "fingerprint": None,
        })

        return merged.with_fingerprint()

    # ==================================================================
    # Provenance helpers
    # ==================================================================

    def add_event(self, event_id: Any) -> "Entity":
        normalized = _normalize_id_string(event_id)
        if normalized is None:
            return self
        return self.model_copy(update={
            "source_event_ids": sorted(
                set(self.source_event_ids) | {normalized}
            )
        })

    def add_evidence(self, evidence_id: Any) -> "Entity":
        normalized = _normalize_id_string(evidence_id)
        if normalized is None:
            return self
        return self.model_copy(update={
            "source_evidence_ids": sorted(
                set(self.source_evidence_ids) | {normalized}
            )
        })

    def add_tag(self, tag: Any) -> "Entity":
        normalized = _normalize_id_string(tag)
        if normalized is None:
            return self
        return self.model_copy(update={
            "tags": sorted(set(self.tags) | {normalized.lower()})
        })

    # ==================================================================
    # Graph
    # ==================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.entity_id,
            "type": "Entity",
            "entity_type": self.entity_type.value,
            "value": self.value,
            "normalized_value": self.normalized_value,
            "identity_scope": self.identity_scope,
            "identity_domain": self.identity_domain,
            "hash_algorithm": self.hash_algorithm,
            "host": self.host,
            "fingerprint": self.fingerprint,
            "first_seen": (
                self.first_seen.isoformat()
                if self.first_seen else None
            ),
            "last_seen": (
                self.last_seen.isoformat()
                if self.last_seen else None
            ),
            "tags": list(self.tags),
            "properties": dict(self.properties),
        }

    def debug_relationships(self) -> list[dict[str, Any]]:
        """
        DEBUG ONLY.

        Bukan source of truth. Hubungan canonical dibangun oleh
        internal/graph/relationship_builder.py.
        """
        edges: list[dict[str, Any]] = []

        for event_id in self.source_event_ids:
            edges.append({
                "source": self.entity_id,
                "source_type": "Entity",
                "target": event_id,
                "target_type": "Event",
                "relationship": "OBSERVED_IN",
                "properties": {"_debug": True},
            })

        for evidence_id in self.source_evidence_ids:
            edges.append({
                "source": self.entity_id,
                "source_type": "Entity",
                "target": evidence_id,
                "target_type": "Evidence",
                "relationship": "CITED_BY",
                "properties": {"_debug": True},
            })

        return edges


# ===========================================================================
# Type alias
# ===========================================================================

EntityList = list[Entity]


__all__ = [
    "SCHEMA_VERSION",
    "ENTITY_VALUE_MAX_LENGTH",
    "MetadataConflictPolicy",
    "DEFAULT_METADATA_CONFLICT_POLICY",
    "VALID_USER_IDENTITY_SCOPES",
    "EntityType",
    "OCCURRENCE_IDENTITY_TYPES",
    "SUBSTANTIVE_ENTITY_TYPES",
    "ALWAYS_HOST_SCOPED",
    "HOST_SCOPED_ENTITY_TYPES",
    "GLOBAL_ENTITY_TYPES",
    "Entity",
    "EntityList",
]
