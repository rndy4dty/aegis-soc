from datetime import datetime, timezone

from pkg.models.ledger import (
    GENESIS_HASH,
    EvidenceLedger,
    LedgerEntry,
    LedgerOperation,
    LedgerVerificationStatus,
)


def test_create_ledger_entry():
    entry = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
    )

    assert entry.entry_id.startswith("LED-")
    assert entry.sequence == 0
    assert entry.evidence_id == "EV-001"
    assert entry.evidence_hash == "abc123"
    assert entry.previous_hash == GENESIS_HASH
    assert entry.operation == LedgerOperation.APPEND
    assert len(entry.entry_hash) == 64
    assert entry.verify_entry_hash() is True
    assert entry.is_genesis is True


def test_entry_hash_is_deterministic():
    timestamp = datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )

    entry_a = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
        timestamp=timestamp,
    )

    entry_b = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
        timestamp=timestamp,
    )

    assert entry_a.entry_hash == entry_b.entry_hash


def test_entry_identity_does_not_affect_hash():
    timestamp = datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )

    entry_a = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
        timestamp=timestamp,
    )

    entry_b = LedgerEntry(
        entry_id="LED-DIFFERENT",
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
        previous_hash=GENESIS_HASH,
        timestamp=timestamp,
        entry_hash=entry_a.entry_hash,
    )

    assert entry_a.entry_hash == entry_b.entry_hash


def test_different_content_produces_different_hash():
    timestamp = datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )

    entry_a = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-001",
        evidence_hash="abc123",
        timestamp=timestamp,
    )

    entry_b = LedgerEntry.create(
        sequence=0,
        evidence_id="EV-002",
        evidence_hash="abc123",
        timestamp=timestamp,
    )

    assert entry_a.entry_hash != entry_b.entry_hash


def test_empty_ledger():
    ledger = EvidenceLedger()

    assert ledger.is_empty is True
    assert ledger.length == 0
    assert ledger.size == 0
    assert ledger.latest is None
    assert ledger.head is None
    assert ledger.latest_hash == GENESIS_HASH
    assert ledger.head_hash is None

    result = ledger.verify_detailed()

    assert result.status == LedgerVerificationStatus.EMPTY
    assert result.valid is True
    assert result.total_entries == 0
    assert result.verified_entries == 0


def test_append_first_entry():
    ledger = EvidenceLedger()

    entry = ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    assert ledger.length == 1
    assert entry.sequence == 0
    assert entry.previous_hash == GENESIS_HASH
    assert entry.is_genesis is True
    assert ledger.latest_hash == entry.entry_hash
    assert ledger.head_hash == entry.entry_hash
    assert ledger.verify() is True


def test_append_creates_hash_chain():
    ledger = EvidenceLedger()

    first = ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    second = ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    third = ledger.append(
        evidence_id="EV-003",
        evidence_hash="hash-003",
    )

    assert first.sequence == 0
    assert second.sequence == 1
    assert third.sequence == 2

    assert second.previous_hash == first.entry_hash
    assert third.previous_hash == second.entry_hash

    assert ledger.verify() is True


def test_append_with_operation():
    ledger = EvidenceLedger()

    entry = ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
        operation=LedgerOperation.DERIVE,
    )

    assert entry.operation == LedgerOperation.DERIVE
    assert entry.verify_entry_hash() is True


def test_tampering_evidence_hash_is_detected():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    assert ledger.verify() is True

    ledger.entries[0].evidence_hash = "TAMPERED"

    result = ledger.verify_detailed()

    assert result.status == LedgerVerificationStatus.HASH_MISMATCH
    assert result.valid is False
    assert result.failed_sequence == 0
    assert result.failed_evidence_id == "EV-001"


def test_tampering_previous_hash_is_detected():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    assert ledger.verify() is True

    ledger.entries[1].previous_hash = "INVALID"

    result = ledger.verify_detailed()

    assert result.status == LedgerVerificationStatus.BROKEN_CHAIN
    assert result.valid is False
    assert result.failed_sequence == 1
    assert result.failed_evidence_id == "EV-002"


def test_tampering_sequence_is_detected():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    assert ledger.verify() is True

    ledger.entries[1].sequence = 99

    result = ledger.verify_detailed()

    assert result.status == LedgerVerificationStatus.SEQUENCE_ANOMALY
    assert result.valid is False
    assert result.failed_sequence == 99


def test_genesis_anomaly_is_detected():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    assert ledger.verify() is True

    ledger.entries[0].previous_hash = "0" * 64

    result = ledger.verify_detailed()

    assert result.status == LedgerVerificationStatus.GENESIS_ANOMALY
    assert result.valid is False
    assert result.failed_sequence == 0


def test_contains_evidence():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    assert ledger.contains_evidence("EV-001") is True
    assert ledger.contains_evidence("EV-002") is True
    assert ledger.contains_evidence("EV-999") is False


def test_get_evidence_entries():
    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    entries = ledger.get_evidence_entries("EV-001")

    assert len(entries) == 1
    assert entries[0].evidence_id == "EV-001"


def test_get_entry_by_sequence():
    ledger = EvidenceLedger()

    first = ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    second = ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    assert ledger.get_entry_by_sequence(0) == first
    assert ledger.get_entry_by_sequence(1) == second
    assert ledger.get_entry_by_sequence(99) is None


def test_verify_against_evidence():
    class MockIntegrity:
        content_hash = "hash-001"

    class MockEvidence:
        evidence_id = "EV-001"
        integrity = MockIntegrity()

    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    evidence = MockEvidence()

    assert ledger.verify_against_evidence(evidence) is True


def test_verify_against_modified_evidence():
    class MockIntegrity:
        content_hash = "hash-ORIGINAL"

    class MockEvidence:
        evidence_id = "EV-001"
        integrity = MockIntegrity()

    ledger = EvidenceLedger()

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-ORIGINAL",
    )

    evidence = MockEvidence()

    evidence.integrity.content_hash = "hash-MODIFIED"

    assert ledger.verify_against_evidence(evidence) is False


def test_graph_node():
    ledger = EvidenceLedger(
        tenant_id="TENANT-001",
        case_id="CASE-001",
        tags=[" SOC ", "Evidence"],
    )

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    node = ledger.to_graph_node()

    assert node["id"] == ledger.ledger_id
    assert node["type"] == "EvidenceLedger"
    assert node["tenant_id"] == "TENANT-001"
    assert node["case_id"] == "CASE-001"
    assert node["size"] == 1
    assert node["head_hash"] == ledger.head_hash
    assert node["tags"] == ["evidence", "soc"]


def test_relationship_projection():
    ledger = EvidenceLedger()

    first = ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    second = ledger.append(
        evidence_id="EV-002",
        evidence_hash="hash-002",
    )

    relationships = ledger.to_relationships()

    assert len(relationships) == 3

    records = [
        relationship
        for relationship in relationships
        if relationship["relationship"] == "RECORDS"
    ]

    previous = [
        relationship
        for relationship in relationships
        if relationship["relationship"] == "PREVIOUS"
    ]

    assert len(records) == 2
    assert len(previous) == 1

    assert previous[0]["source"] == second.entry_id
    assert previous[0]["target"] == first.entry_id


def test_serialization():
    ledger = EvidenceLedger(
        tenant_id="TENANT-001",
        case_id="CASE-001",
    )

    ledger.append(
        evidence_id="EV-001",
        evidence_hash="hash-001",
    )

    data = ledger.to_dict()

    assert data["schema_version"] == "1.0"
    assert data["tenant_id"] == "TENANT-001"
    assert data["case_id"] == "CASE-001"
    assert len(data["entries"]) == 1
    assert data["entries"][0]["evidence_id"] == "EV-001"
    assert data["entries"][0]["operation"] == "append"
