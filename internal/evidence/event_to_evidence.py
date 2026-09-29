"""
Event → Evidence converter for AegisSOC.

Tugas:
    Event  →  0..N Evidence

Konversi deterministic dari canonical Event menjadi Evidence yang siap
dipakai untuk investigation (correlation, hypothesis, risk).

Prinsip:
- Deterministik. Event yang sama → evidence yang sama (termasuk ID/hash).
- Satu Event menghasilkan SATU Evidence utama (v1).
  Kalau nanti butuh multi-evidence per event, tambahkan opsi `explode=True`.
- `strength` diturunkan dari `event.severity` via severity band.
- `confidence` diturunkan dari `event.source_reliability` (NATO code).
- MITRE techniques disimpan di `data["mitre_techniques"]` agar
  HypothesisEngine bisa membacanya.
- Provenance menyimpan event_id, source, dan collector.
- `content_hash` diisi via `Evidence.with_content_hash()`.

Tidak melakukan:
- correlation
- hypothesis generation
- risk scoring
- enrichment eksternal
- LLM
"""

from __future__ import annotations

from typing import Any

from pkg.models.evidence import (
    Evidence,
    EvidenceProvenance,
    EvidenceStrength,
    EvidenceType,
)
from pkg.models.event import (
    Event,
    EventCategory,
    EventSource,
    SourceReliability,
)


# ===========================================================================
# Constants
# ===========================================================================

# Severity band → EvidenceStrength.
SEVERITY_CRITICAL_THRESHOLD: int = 85
SEVERITY_STRONG_THRESHOLD: int = 70
SEVERITY_MODERATE_THRESHOLD: int = 40


# SourceReliability (NATO) → confidence 0..1.
RELIABILITY_CONFIDENCE: dict[SourceReliability, float] = {
    SourceReliability.A: 1.00,
    SourceReliability.B: 0.85,
    SourceReliability.C: 0.70,
    SourceReliability.D: 0.50,
    SourceReliability.E: 0.30,
    SourceReliability.F: 0.20,
}


# EventCategory → EvidenceType.

# EventCategory → EvidenceType.
#
# Catatan: `EvidenceType` di model AegisSOC tidak punya OTHER.
# Untuk event tanpa context spesifik (CONFIGURATION, OTHER), kita
# pakai `EvidenceType.EVENT` sebagai default.
CATEGORY_TO_EVIDENCE_TYPE: dict[EventCategory, EvidenceType] = {
    EventCategory.PROCESS: EvidenceType.PROCESS,
    EventCategory.FILE: EvidenceType.FILE,
    EventCategory.REGISTRY: EvidenceType.REGISTRY,
    EventCategory.NETWORK: EvidenceType.NETWORK,
    EventCategory.HTTP: EvidenceType.NETWORK,
    EventCategory.DNS: EvidenceType.DNS,
    EventCategory.AUTHENTICATION: EvidenceType.AUTHENTICATION,
    EventCategory.ACCOUNT: EvidenceType.AUTHENTICATION,
    EventCategory.CONFIGURATION: EvidenceType.EVENT,
    EventCategory.OTHER: EvidenceType.EVENT,
}

# ===========================================================================
# Internal helpers
# ===========================================================================

def _severity_to_strength(severity: int) -> EvidenceStrength:
    if severity >= SEVERITY_CRITICAL_THRESHOLD:
        return EvidenceStrength.CRITICAL
    if severity >= SEVERITY_STRONG_THRESHOLD:
        return EvidenceStrength.STRONG
    if severity >= SEVERITY_MODERATE_THRESHOLD:
        return EvidenceStrength.MODERATE
    return EvidenceStrength.WEAK


def _reliability_to_confidence(
    reliability: SourceReliability | None,
) -> float:
    if reliability is None:
        return 0.5
    return RELIABILITY_CONFIDENCE.get(reliability, 0.5)


def _category_to_evidence_type(category: EventCategory) -> EvidenceType:
    return CATEGORY_TO_EVIDENCE_TYPE.get(category, EvidenceType.EVENT)

def _context_to_dict(context: Any) -> dict[str, Any] | None:
    """
    Konversi sub-context Pydantic (ProcessContext, NetworkContext, dll.)
    menjadi dict JSON-safe.
    """
    if context is None:
        return None
    if hasattr(context, "model_dump"):
        return context.model_dump(mode="json", exclude_none=True)
    if isinstance(context, dict):
        return {k: v for k, v in context.items() if v is not None}
    return None


def _build_title(event: Event) -> str:
    """
    Generate title human-readable dari event.
    """
    category = event.category
    event_type = event.event_type or "event"

    if category == EventCategory.PROCESS and event.process:
        name = event.process.name or "unknown"
        pid = event.process.pid
        if pid is not None:
            return f"{event_type}: {name} (PID {pid})"
        return f"{event_type}: {name}"

    if category in (EventCategory.NETWORK, EventCategory.HTTP) and event.network:
        src = event.network.source_ip or "?"
        dst = event.network.destination_ip or "?"
        port = event.network.destination_port
        if port:
            return f"{event_type}: {src} → {dst}:{port}"
        return f"{event_type}: {src} → {dst}"

    if category == EventCategory.DNS and event.dns:
        q = event.dns.query or "?"
        return f"{event_type}: DNS {q}"

    if category == EventCategory.FILE and event.file:
        path = event.file.path or event.file.name or "?"
        return f"{event_type}: {path}"

    if category == EventCategory.REGISTRY and event.registry:
        key = event.registry.key or "?"
        return f"{event_type}: {key}"

    if category == EventCategory.AUTHENTICATION:
        user = event.user or "?"
        host = event.host or "?"
        return f"{event_type}: {user} @ {host}"

    return f"{event_type}"


def _build_data(event: Event) -> dict[str, Any]:
    """
    Bangun dict data lengkap dari event.
    """
    data: dict[str, Any] = {
        "event_id": event.event_id,
        "event_type": event.event_type,
        "category": event.category.value,
        "severity": event.severity,
        "source": event.source.value,
        "platform": event.platform.value,
        "host": event.host,
        "user": event.user,
        "domain": event.domain,
    }

    # -- Contexts ----------------------------------------------------
    process = _context_to_dict(event.process)
    network = _context_to_dict(event.network)
    file_ctx = _context_to_dict(event.file)
    registry = _context_to_dict(event.registry)
    dns = _context_to_dict(event.dns)

    if process is not None:
        data["process"] = process
    if network is not None:
        data["network"] = network
    if file_ctx is not None:
        data["file"] = file_ctx
    if registry is not None:
        data["registry"] = registry
    if dns is not None:
        data["dns"] = dns

    # -- Detection ---------------------------------------------------
    if event.rule_id:
        data["rule_id"] = event.rule_id
    if event.rule_name:
        data["rule_name"] = event.rule_name
    if event.rule_level is not None:
        data["rule_level"] = event.rule_level

    if event.mitre_techniques:
        data["mitre_techniques"] = list(event.mitre_techniques)
    if event.mitre_tactics:
        data["mitre_tactics"] = list(event.mitre_tactics)

    # -- Tags --------------------------------------------------------
    if event.tags:
        data["event_tags"] = list(event.tags)

    return {k: v for k, v in data.items() if v is not None}


# ===========================================================================
# EventToEvidenceConverter
# ===========================================================================

class EventToEvidenceConverter:
    """
    Stateless converter: Event → list[Evidence].

    Default: satu Evidence per Event.
    Kalau `always_emit=True` dan Event kosong (tanpa context),
    tetap menghasilkan satu Evidence generik.
    """

    def __init__(self, *, always_emit: bool = True) -> None:
        self.always_emit = always_emit

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def convert(self, event: Event) -> list[Evidence]:
        """
        Kembalikan list evidence yang dihasilkan dari event.

        v1: selalu 0 atau 1 evidence.
        """
        if not self._has_meaningful_content(event):
            if self.always_emit:
                return [self._build_evidence(event)]
            return []

        return [self._build_evidence(event)]

    def convert_many(
        self, events: list[Event]
    ) -> list[Evidence]:
        """
        Konversi beberapa event sekaligus.
        """
        out: list[Evidence] = []
        for event in events:
            out.extend(self.convert(event))
        return out

    # -------------------------------------------------------------------
    # Build
    # -------------------------------------------------------------------

    @staticmethod
    def _has_meaningful_content(event: Event) -> bool:
        """
        Event dianggap bermakna kalau punya salah satu:
        - severity > 0
        - rule_id
        - mitre_techniques
        - process / network / file / registry / dns context
        """
        if event.severity > 0:
            return True
        if event.rule_id:
            return True
        if event.mitre_techniques:
            return True
        if any([
            event.process,
            event.network,
            event.file,
            event.registry,
            event.dns,
        ]):
            return True
        return False

    def _build_evidence(self, event: Event) -> Evidence:
        evidence_type = _category_to_evidence_type(event.category)
        strength = _severity_to_strength(event.severity)
        confidence = _reliability_to_confidence(
            event.source_reliability,
        )

        title = _build_title(event)
        description = (
            f"{event.event_type} detected on "
            f"{event.host or 'unknown host'} "
            f"(severity {event.severity})."
        )

        data = _build_data(event)

        provenance = EvidenceProvenance(
            source=event.source.value,
            source_reliability=event.source_reliability,
            collector="event_to_evidence",
            collector_version="1.0",
            parent_event_id=event.event_id,
            transformation="Event to Evidence",
            collected_at=event.timestamp,
        )

        evidence = Evidence(
            tenant_id=event.tenant_id,
            case_id=event.investigation_id,
            evidence_type=evidence_type,
            strength=strength,
            title=title,
            description=description,
            observed_at=event.timestamp,
            confidence=confidence,
            data=data,
            event_id=event.event_id,
            provenance=provenance,
            tags=list(event.tags) if event.tags else [],
        )

        return evidence.with_content_hash()


# ===========================================================================
# Factory
# ===========================================================================

def event_to_evidence(
    event: Event,
    *,
    always_emit: bool = True,
) -> list[Evidence]:
    """Convenience factory."""
    return EventToEvidenceConverter(
        always_emit=always_emit
    ).convert(event)


def events_to_evidence(
    events: list[Event],
    *,
    always_emit: bool = True,
) -> list[Evidence]:
    """Convenience factory untuk banyak event."""
    return EventToEvidenceConverter(
        always_emit=always_emit
    ).convert_many(events)


__all__ = [
    "SEVERITY_CRITICAL_THRESHOLD",
    "SEVERITY_STRONG_THRESHOLD",
    "SEVERITY_MODERATE_THRESHOLD",
    "RELIABILITY_CONFIDENCE",
    "CATEGORY_TO_EVIDENCE_TYPE",
    "EventToEvidenceConverter",
    "event_to_evidence",
    "events_to_evidence",
]
