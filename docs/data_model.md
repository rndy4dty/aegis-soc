# Data Model

## Event
Telemetry normalized dari berbagai sumber.

## Evidence
Unit pembuktian dengan SHA-256 content hash.

## Entity
Node graph dengan fingerprint (semantic identity).

## Relationship
Edge graph dengan fingerprint.

## Hypothesis
Klaim yang bisa didukung atau dibantah evidence.

Tipe: MAIN, COUNTER, SUB.

Status: PROPOSED, SUPPORTED, WEAKENED, CONFIRMED, REJECTED.

## InvestigationCase
Aggregate root.

## Fingerprint vs ID

| Aspek | ID | Fingerprint |
|---|---|---|
| Format | UUID | SHA-256 hex |
| Tujuan | Instance identity | Semantic identity |
| Deterministik | Tidak | Ya |
| Untuk merge | Tidak | Ya |
