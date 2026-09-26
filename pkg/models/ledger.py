from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)


# ===========================================================================
# Constants
# ===========================================================================

SCHEMA_VERSION: str = "1.0"

HASH_ALGORITHM: str = "sha256"

HASH_HEX_LENGTH: int = 64

GENESIS_HASH: str = "GENESIS"

SEQUENCE_MIN: int = 0


# ===========================================================================
# Enums
# ===========================================================================

class LedgerOperation(str, Enum):
    """
    Jenis operasi yang dicatat di ledger.
    """
    APPEND = "append"
    VERIFY = "verify"
    ATTACH = "attach"
    DERIVE = "derive"
    ANALYST_VERIFY = "analyst_verify"


class LedgerVerificationStatus(str, Enum):
    """
    Status hasil verifikasi rantai ledger.
    """
    VALID = "valid"
    EMPTY = "empty"
    SEQUENCE_ANOMALY = "sequence_anomaly"
    GENESIS_ANOMALY = "genesis_anomaly"
    BROKEN_CHAIN = "broken_chain"
    HASH_MISMATCH = "hash_mismatch"
    INVALID = "invalid"


# ===========================================================================
# Ledger Entry
# ===========================================================================

class LedgerEntry(BaseModel):
    """
    Satu immutable-style entry dalam Evidence Ledger.

    Entry membawa:
        - sequence
        - evidence_id
        - evidence_hash
        - previous_hash
        - entry_hash
        - timestamp
        - operation
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        # validate_assignment sengaja dimatikan agar mutasi field
        # tetap memungkinkan untuk simulasi tampering di test,
        # dan agar verifikasi adalah satu-satunya gate untuk integritas.
        validate_assignment=False,
    )

    # --------------------------------------------------------------------
    # Identity
    # --------------------------------------------------------------------
    entry_id: str = Field(
        default_factory=lambda: f"LED-{uuid4().hex[:12]}"
    )
    schema_version: str = SCHEMA_VERSION

    # --------------------------------------------------------------------
    # Chain
    # --------------------------------------------------------------------
    sequence: int = Field(ge=SEQUENCE_MIN)

    evidence_id: str = Field(min_length=1)
    evidence_hash: str = Field(min_length=1)

    previous_hash: str = Field(min_length=1)
    entry_hash: str = Field(min_length=HASH_HEX_LENGTH, max_length=HASH_HEX_LENGTH)

    # --------------------------------------------------------------------
    # Metadata
    # --------------------------------------------------------------------
    operation: LedgerOperation = LedgerOperation.APPEND

    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict[str, Any] = Field(default_factory=dict)

    # ====================================================================
    # Validators
    # ====================================================================

    @field_validator("timestamp")
    @classmethod
    def _normalize_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("timestamp")
    def _serialize_timestamp(self, value: datetime) -> str:
        return value.isoformat()

    @field_validator("evidence_id", "evidence_hash")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("value cannot be empty")
        return value

    @field_validator("entry_hash")
    @classmethod
    def _validate_entry_hash(cls, value: str) -> str:
        value = value.strip().lower()
        if len(value) != HASH_HEX_LENGTH:
            raise ValueError(
                f"entry_hash must be {HASH_HEX_LENGTH} hex characters"
            )
        try:
            int(value, 16)
        except ValueError:
            raise ValueError("entry_hash must be valid hex")
        return value

    @field_validator("previous_hash")
    @classmethod
    def _validate_previous_hash(cls, value: str) -> str:
        value = value.strip()
        if value == GENESIS_HASH:
            return value

        value = value.lower()
        if len(value) != HASH_HEX_LENGTH:
            raise ValueError(
                "previous_hash must be GENESIS or "
                f"{HASH_HEX_LENGTH} hex characters"
            )
        try:
            int(value, 16)
        except ValueError:
            raise ValueError("previous_hash must be valid hex")
        return value

    # ====================================================================
    # Canonical Payload
    # ====================================================================

    def canonical_payload(self) -> dict[str, Any]:
        """
        Payload deterministik untuk menghitung entry_hash.

        Dikecualikan:
        - entry_id      (identity, bukan content)
        - entry_hash    (output)
        - metadata      (extensibility, tidak mengikat chain)

        Termasuk:
        - sequence, evidence_id, evidence_hash, previous_hash,
          timestamp, operation, schema_version
        """
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "operation": self.operation.value,
            "evidence_id": self.evidence_id,
            "evidence_hash": self.evidence_hash,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp.isoformat(),
        }

    # ====================================================================
    # Hashing
    # ====================================================================

    def calculate_entry_hash(self) -> str:
        payload = json.dumps(
            self.canonical_payload(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def verify_entry_hash(self) -> bool:
        return self.entry_hash == self.calculate_entry_hash()

    # ====================================================================
    # Factory
    # ====================================================================

    @classmethod
    def create(
        cls,
        *,
        sequence: int,
        evidence_id: str,
        evidence_hash: str,
        previous_hash: str = GENESIS_HASH,
        timestamp: datetime | None = None,
        operation: LedgerOperation = LedgerOperation.APPEND,
        metadata: dict[str, Any] | None = None,
    ) -> "LedgerEntry":
        """
        Buat LedgerEntry baru dengan entry_hash otomatis.
        """
        normalized_timestamp = timestamp or datetime.now(timezone.utc)

        if normalized_timestamp.tzinfo is None:
            normalized_timestamp = normalized_timestamp.replace(
                tzinfo=timezone.utc
            )
        else:
            normalized_timestamp = normalized_timestamp.astimezone(
                timezone.utc
            )

        payload = {
            "schema_version": SCHEMA_VERSION,
            "sequence": sequence,
            "operation": (
                operation.value
                if isinstance(operation, LedgerOperation)
                else str(operation)
            ),
            "evidence_id": evidence_id.strip(),
            "evidence_hash": evidence_hash.strip(),
            "previous_hash": previous_hash.strip(),
            "timestamp": normalized_timestamp.isoformat(),
        }

        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

        entry_hash = hashlib.sha256(serialized).hexdigest()

        return cls(
            sequence=sequence,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            previous_hash=previous_hash,
            timestamp=normalized_timestamp,
            operation=operation,
            entry_hash=entry_hash,
            metadata=metadata or {},
        )

    # ====================================================================
    # Properties
    # ====================================================================

    @property
    def is_genesis(self) -> bool:
        return self.sequence == 0 and self.previous_hash == GENESIS_HASH


# ===========================================================================
# Verification Result
# ===========================================================================

class LedgerVerificationResult(BaseModel):
    """
    Hasil verifikasi rantai ledger.
    """

    model_config = ConfigDict(extra="forbid")

    status: LedgerVerificationStatus = LedgerVerificationStatus.INVALID
    valid: bool = False

    total_entries: int = 0
    verified_entries: int = 0

    failed_sequence: int | None = None
    failed_entry_id: str | None = None
    failed_evidence_id: str | None = None
    reason: str | None = None

    verified_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("verified_at")
    @classmethod
    def _normalize_ts(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("verified_at")
    def _serialize_ts(self, value: datetime) -> str:
        return value.isoformat()


# ===========================================================================
# Evidence Ledger
# ===========================================================================

class EvidenceLedger(BaseModel):
    """
    Ordered hash chain untuk Evidence.

    Ledger bersifat append-only secara desain API.
    Entry baru selalu memakai:
        previous_hash = entry_hash entry terakhir
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=False,
    )

    # --------------------------------------------------------------------
    # Identity
    # --------------------------------------------------------------------
    ledger_id: str = Field(
        default_factory=lambda: f"LEDGER-{uuid4().hex[:12]}"
    )
    schema_version: str = SCHEMA_VERSION

    tenant_id: str | None = None
    case_id: str | None = None

    # --------------------------------------------------------------------
    # Entries
    # --------------------------------------------------------------------
    entries: list[LedgerEntry] = Field(default_factory=list)

    # --------------------------------------------------------------------
    # Timeline
    # --------------------------------------------------------------------
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # --------------------------------------------------------------------
    # Metadata
    # --------------------------------------------------------------------
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # ====================================================================
    # Validators
    # ====================================================================

    @field_validator("created_at", "updated_at")
    @classmethod
    def _normalize_ts(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @field_serializer("created_at", "updated_at")
    def _serialize_ts(self, value: datetime) -> str:
        return value.isoformat()

    @field_validator("tags")
    @classmethod
    def _normalize_tags(cls, values: list[str]) -> list[str]:
        return sorted({v.strip().lower() for v in values if v and v.strip()})

    @model_validator(mode="after")
    def _validate_sequence(self) -> "EvidenceLedger":
        """
        Sequence harus 0..N-1 berurutan.
        """
        for idx, entry in enumerate(self.entries):
            if entry.sequence != idx:
                raise ValueError(
                    f"entry at index {idx} has sequence {entry.sequence}, "
                    f"expected {idx}"
                )
        return self

    # ====================================================================
    # Properties
    # ====================================================================

    @property
    def is_empty(self) -> bool:
        return not self.entries

    @property
    def length(self) -> int:
        return len(self.entries)

    @property
    def size(self) -> int:
        return len(self.entries)

    @property
    def latest(self) -> LedgerEntry | None:
        if not self.entries:
            return None
        return self.entries[-1]

    @property
    def head(self) -> LedgerEntry | None:
        return self.latest

    @property
    def latest_hash(self) -> str:
        if not self.entries:
            return GENESIS_HASH
        return self.entries[-1].entry_hash

    @property
    def head_hash(self) -> str | None:
        head = self.head
        return head.entry_hash if head else None

    # ====================================================================
    # Append
    # ====================================================================

    def _touch(self) -> None:
        self.updated_at = datetime.now(timezone.utc)

    def append(
        self,
        *,
        evidence_id: str,
        evidence_hash: str,
        timestamp: datetime | None = None,
        operation: LedgerOperation = LedgerOperation.APPEND,
        metadata: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """
        Tambahkan evidence baru ke ledger.
        """
        sequence = len(self.entries)

        entry = LedgerEntry.create(
            sequence=sequence,
            evidence_id=evidence_id,
            evidence_hash=evidence_hash,
            previous_hash=self.latest_hash,
            timestamp=timestamp,
            operation=operation,
            metadata=metadata,
        )

        self.entries.append(entry)
        self._touch()
        return entry

    def append_evidence(
        self,
        evidence: Any,
        *,
        operation: LedgerOperation = LedgerOperation.APPEND,
        metadata: dict[str, Any] | None = None,
    ) -> LedgerEntry:
        """
        Convenience: append Evidence object.

        `evidence` diharapkan punya:
            evidence.evidence_id
            evidence.integrity.content_hash   (Evidence model kita)

        Fallback:
            evidence.content_hash             (kalau ada di field lain)

        Tidak mengimpor Evidence secara langsung untuk menghindari
        circular import.
        """
        evidence_id = getattr(evidence, "evidence_id", None)
        if not evidence_id:
            raise ValueError("evidence must have evidence_id")

        content_hash: str | None = None
        integrity = getattr(evidence, "integrity", None)
        if integrity is not None:
            content_hash = getattr(integrity, "content_hash", None)
        if not content_hash:
            content_hash = getattr(evidence, "content_hash", None)

        if not content_hash:
            raise ValueError(
                "evidence must have content_hash set "
                "(call evidence.with_content_hash() first)"
            )

        return self.append(
            evidence_id=str(evidence_id),
            evidence_hash=str(content_hash),
            operation=operation,
            metadata=metadata,
        )

    # ====================================================================
    # Verification
    # ====================================================================

    def verify(self) -> bool:
        """
        Verifikasi seluruh hash chain.
        Short-hand dari verify_detailed().valid.
        """
        return self.verify_detailed().valid

    def verify_detailed(self) -> LedgerVerificationResult:
        """
        Verifikasi seluruh rantai dan kembalikan hasil detail.

        Pemeriksaan per entry:
        1. sequence cocok dengan indeks
        2. previous_hash = GENESIS untuk genesis
        3. previous_hash = entry_hash entry sebelumnya untuk entry lain
        4. entry_hash cocok dengan recompute payload
        """
        now = datetime.now(timezone.utc)

        if self.is_empty:
            return LedgerVerificationResult(
                status=LedgerVerificationStatus.EMPTY,
                valid=True,
                total_entries=0,
                verified_entries=0,
                verified_at=now,
            )

        expected_prev: str = GENESIS_HASH

        for idx, entry in enumerate(self.entries):
            # 1. Sequence
            if entry.sequence != idx:
                return LedgerVerificationResult(
                    status=LedgerVerificationStatus.SEQUENCE_ANOMALY,
                    valid=False,
                    total_entries=len(self.entries),
                    verified_entries=idx,
                    failed_sequence=entry.sequence,
                    failed_entry_id=entry.entry_id,
                    failed_evidence_id=entry.evidence_id,
                    reason=(
                        f"sequence {entry.sequence} at index {idx}"
                    ),
                    verified_at=now,
                )

            # 2. Genesis
            if idx == 0:
                if entry.previous_hash != GENESIS_HASH:
                    return LedgerVerificationResult(
                        status=LedgerVerificationStatus.GENESIS_ANOMALY,
                        valid=False,
                        total_entries=len(self.entries),
                        verified_entries=0,
                        failed_sequence=entry.sequence,
                        failed_entry_id=entry.entry_id,
                        failed_evidence_id=entry.evidence_id,
                        reason="genesis entry previous_hash != GENESIS",
                        verified_at=now,
                    )
            else:
                # 3. Chain link
                if entry.previous_hash != expected_prev:
                    return LedgerVerificationResult(
                        status=LedgerVerificationStatus.BROKEN_CHAIN,
                        valid=False,
                        total_entries=len(self.entries),
                        verified_entries=idx,
                        failed_sequence=entry.sequence,
                        failed_entry_id=entry.entry_id,
                        failed_evidence_id=entry.evidence_id,
                        reason=(
                            f"previous_hash mismatch at sequence "
                            f"{entry.sequence}"
                        ),
                        verified_at=now,
                    )

            # 4. Entry hash
            if not entry.verify_entry_hash():
                return LedgerVerificationResult(
                    status=LedgerVerificationStatus.HASH_MISMATCH,
                    valid=False,
                    total_entries=len(self.entries),
                    verified_entries=idx,
                    failed_sequence=entry.sequence,
                    failed_entry_id=entry.entry_id,
                    failed_evidence_id=entry.evidence_id,
                    reason=(
                        f"entry_hash mismatch at sequence "
                        f"{entry.sequence}"
                    ),
                    verified_at=now,
                )

            expected_prev = entry.entry_hash

        return LedgerVerificationResult(
            status=LedgerVerificationStatus.VALID,
            valid=True,
            total_entries=len(self.entries),
            verified_entries=len(self.entries),
            verified_at=now,
        )

    def verify_against_evidence(
        self,
        evidence: Any,
    ) -> bool:
        """
        Cek apakah evidence yang direferensikan ledger masih cocok
        dengan content_hash yang tercatat.

        Berguna untuk mendeteksi evidence yang dimodifikasi
        setelah masuk ledger.
        """
        evidence_id = getattr(evidence, "evidence_id", None)
        if not evidence_id:
            return False

        # Cari entry terakhir untuk evidence_id ini
        matching_entries = self.get_evidence_entries(evidence_id)
        if not matching_entries:
            return False

        latest = matching_entries[-1]

        current_hash: str | None = None
        integrity = getattr(evidence, "integrity", None)
        if integrity is not None:
            current_hash = getattr(integrity, "content_hash", None)
        if not current_hash:
            current_hash = getattr(evidence, "content_hash", None)

        if not current_hash:
            return False

        return str(current_hash) == latest.evidence_hash

    # ====================================================================
    # Lookup
    # ====================================================================

    def contains_evidence(self, evidence_id: str) -> bool:
        return any(
            entry.evidence_id == evidence_id
            for entry in self.entries
        )

    def get_evidence_entries(
        self,
        evidence_id: str,
    ) -> list[LedgerEntry]:
        return [
            entry
            for entry in self.entries
            if entry.evidence_id == evidence_id
        ]

    def get_entry_by_sequence(
        self,
        sequence: int,
    ) -> LedgerEntry | None:
        if 0 <= sequence < len(self.entries):
            return self.entries[sequence]
        return None

    # ====================================================================
    # Graph
    # ====================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.ledger_id,
            "type": "EvidenceLedger",
            "tenant_id": self.tenant_id,
            "case_id": self.case_id,
            "size": self.size,
            "head_hash": self.head_hash,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "tags": list(self.tags),
        }

    def to_relationships(self) -> list[dict[str, Any]]:
        """
        Edge:
        - Ledger --RECORDS--> Evidence
        - Entry_n --PREVIOUS--> Entry_(n-1)
        """
        edges: list[dict[str, Any]] = []

        for entry in self.entries:
            edges.append({
                "source": self.ledger_id,
                "source_type": "EvidenceLedger",
                "target": entry.evidence_id,
                "target_type": "Evidence",
                "relationship": "RECORDS",
                "properties": {
                    "sequence": entry.sequence,
                    "entry_id": entry.entry_id,
                    "entry_hash": entry.entry_hash,
                    "operation": entry.operation.value,
                },
            })

            if entry.sequence > 0:
                prev = self.entries[entry.sequence - 1]
                edges.append({
                    "source": entry.entry_id,
                    "source_type": "LedgerEntry",
                    "target": prev.entry_id,
                    "target_type": "LedgerEntry",
                    "relationship": "PREVIOUS",
                    "properties": {
                        "previous_hash": entry.previous_hash,
                    },
                })

        return edges

    # ====================================================================
    # Serialization
    # ====================================================================

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


# ===========================================================================
# Type alias
# ===========================================================================

LedgerEntryList = list[LedgerEntry]
