from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Iterable
from uuid import uuid4

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    field_validator,
    model_validator,
)

from pkg.models.correlation import (
    DEFAULT_REASON_WEIGHTS,
    CorrelationReason,
    WeightMode,
    combine_weight_values,
    score_reasons,
)


SCHEMA_VERSION = "1.0"

DEFAULT_TIME_WINDOW_SECONDS = 300
DEFAULT_MIN_CONFIDENCE = 0.40
DEFAULT_MIN_REASONS = 1
DEFAULT_MAX_RESULTS = 500


# ===========================================================================
# Generic helpers
# ===========================================================================


def _attr(obj: Any, name: str, default: Any = None) -> Any:
    """
    Ambil attribute dari object atau key dari mapping.

    Mendukung:
    - Pydantic model
    - dataclass / object biasa
    - dict
    """

    if obj is None:
        return default

    if isinstance(obj, dict):
        return obj.get(name, default)

    return getattr(obj, name, default)


def _event_id(event: Any) -> str | None:
    value = _attr(event, "event_id")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _timestamp(event: Any) -> datetime | None:
    value = _attr(event, "timestamp")

    if not isinstance(value, datetime):
        return None

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def _host(event: Any) -> str | None:
    value = _attr(event, "host")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _user(event: Any) -> str | None:
    value = _attr(event, "user")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _process(event: Any) -> Any:
    return _attr(event, "process")


def _process_name(event: Any) -> str | None:
    process = _process(event)

    if process is None:
        return None

    value = _attr(process, "name")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _process_pid(event: Any) -> int | None:
    process = _process(event)

    if process is None:
        return None

    pid = _attr(process, "pid")

    return pid if isinstance(pid, int) else None


def _process_parent_pid(event: Any) -> int | None:
    process = _process(event)

    if process is None:
        return None

    ppid = _attr(process, "parent_pid")

    return ppid if isinstance(ppid, int) else None


def _network(event: Any) -> Any:
    return _attr(event, "network")


def _source_ip(event: Any) -> str | None:
    network = _network(event)

    if network is None:
        return None

    value = _attr(network, "source_ip")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _destination_ip(event: Any) -> str | None:
    network = _network(event)

    if network is None:
        return None

    value = _attr(network, "destination_ip")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _file(event: Any) -> Any:
    return _attr(event, "file")


def _file_hash(event: Any) -> str | None:
    """
    Ambil hash file.

    Prioritas:
    sha256 > sha1 > md5

    FileContext menggunakan:
        hashes: dict[str, str]

    Juga mendukung fallback:
        file.hash
    """

    file_ctx = _file(event)

    if file_ctx is None:
        return None

    hashes = _attr(file_ctx, "hashes")

    if isinstance(hashes, dict) and hashes:
        for algorithm in ("sha256", "sha1", "md5"):
            value = hashes.get(algorithm)

            if value:
                return str(value).strip().lower()

    value = _attr(file_ctx, "hash")

    if value is None:
        return None

    value = str(value).strip()

    return value.lower() if value else None


def _file_path(event: Any) -> str | None:
    file_ctx = _file(event)

    if file_ctx is None:
        return None

    value = _attr(file_ctx, "path")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _registry_key(event: Any) -> str | None:
    registry = _attr(event, "registry")

    if registry is None:
        return None

    value = _attr(registry, "key")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _dns_query(event: Any) -> str | None:
    dns = _attr(event, "dns")

    if dns is None:
        return None

    value = _attr(dns, "query")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _mitre_techniques(event: Any) -> set[str]:
    """
    MITRE techniques berada langsung pada Event:

        event.mitre_techniques
    """

    techniques = _attr(event, "mitre_techniques") or []

    if isinstance(techniques, str):
        techniques = [techniques]

    return {
        str(technique).strip()
        for technique in techniques
        if str(technique).strip()
    }


def _rule_id(event: Any) -> str | None:
    value = _attr(event, "rule_id")

    if value is None:
        return None

    value = str(value).strip()

    return value or None


def _eq_ci(left: str | None, right: str | None) -> bool:
    """
    Case-insensitive equality.

    None / empty values tidak dianggap sama.
    """

    if not left or not right:
        return False

    return left.strip().lower() == right.strip().lower()


# ===========================================================================
# Correlation Result
# ===========================================================================


class ReasonBreakdown(BaseModel):
    """
    Breakdown satu alasan korelasi.

    Menjelaskan bagaimana setiap reason berkontribusi terhadap score.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    reason: CorrelationReason
    label: str
    category: str | None = None
    weight: float = Field(
        ge=0.0,
        le=1.0,
    )

    def format_line(self) -> str:
        category = self.category or "unknown"
        return (
            f"- {self.reason.value}: {self.label} "
            f"[{category}] (weight={self.weight:.2f})"
        )

def format_line(self) -> str:
    category = self.category or "unknown"
    return (
        f"- {self.reason.value}: {self.label} "
        f"[{category}] (weight={self.weight:.2f})"
    )

class CorrelationResult(BaseModel):
    """
    Hasil korelasi pairwise antara dua event.

    Pair-based:
        source_event_id + related_event_id

    Digunakan untuk menjawab:

        "Kenapa EV-A terkorelasi dengan EV-B?"
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
    )

    # -----------------------------------------------------------------------
    # Identity
    # -----------------------------------------------------------------------

    correlation_id: str = Field(
        default_factory=lambda: f"PAIR-{uuid4().hex[:10]}"
    )

    schema_version: str = SCHEMA_VERSION

    tenant_id: str | None = None
    case_id: str | None = None

    # -----------------------------------------------------------------------
    # Pair
    # -----------------------------------------------------------------------

    source_event_id: str
    related_event_id: str

    # -----------------------------------------------------------------------
    # Reasoning
    # -----------------------------------------------------------------------

    reasons: list[CorrelationReason] = Field(
        default_factory=list
    )

    rationale: list[str] = Field(
        default_factory=list
    )

    # -----------------------------------------------------------------------
    # Scores
    # -----------------------------------------------------------------------

    score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )

    weight_mode: WeightMode = WeightMode.ADDITIVE

    total_raw: float = Field(
        default=0.0,
        ge=0.0,
    )

    breakdown: list[ReasonBreakdown] = Field(
        default_factory=list
    )

    # -----------------------------------------------------------------------
    # Time
    # -----------------------------------------------------------------------

    time_delta_seconds: float | None = Field(
        default=None,
        ge=0.0,
    )

    # -----------------------------------------------------------------------
    # Meta
    # -----------------------------------------------------------------------

    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict
    )

    # =======================================================================
    # Validators
    # =======================================================================

    @field_validator("source_event_id", "related_event_id")
    @classmethod
    def _validate_id(cls, value: str) -> str:
        value = value.strip()

        if not value:
            raise ValueError("event id cannot be empty")

        return value

    @field_validator("reasons")
    @classmethod
    def _normalize_reasons(
        cls,
        value: list[CorrelationReason],
    ) -> list[CorrelationReason]:
        """
        Deduplicate reason sambil mempertahankan urutan.
        """

        return list(dict.fromkeys(value))

    @field_validator("rationale")
    @classmethod
    def _normalize_rationale(
        cls,
        value: list[str],
    ) -> list[str]:
        cleaned: list[str] = []

        for item in value:
            text = str(item).strip()

            if text:
                cleaned.append(text)

        return cleaned

    @field_validator("created_at")
    @classmethod
    def _normalize_created_at(
        cls,
        value: datetime,
    ) -> datetime:
        if value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)

        return value.astimezone(timezone.utc)

    @field_serializer("created_at")
    def _serialize_created_at(
        self,
        value: datetime,
    ) -> str:
        return value.astimezone(timezone.utc).isoformat()

    @model_validator(mode="after")
    def _validate_pair(self) -> "CorrelationResult":
        if self.source_event_id == self.related_event_id:
            raise ValueError(
                "source_event_id and related_event_id "
                "must be different"
            )

        if (
            self.time_delta_seconds is not None
            and self.time_delta_seconds < 0
        ):
            raise ValueError(
                "time_delta_seconds cannot be negative"
            )

        return self

    # =======================================================================
    # Properties
    # =======================================================================

    @property
    def reason_count(self) -> int:
        return len(self.reasons)

    @property
    def is_strong(self) -> bool:
        return self.confidence >= 0.70

    @property
    def is_weak(self) -> bool:
        return self.confidence < 0.40

    # =======================================================================
    # Audit helpers
    # =======================================================================

    def audit_lines(self) -> list[str]:
        """
        Representasi correlation yang dapat dibaca analyst.
        """

        lines = [
		f"correlation_id: {self.correlation_id}",
		f"source_event_id: {self.source_event_id}",
		f"related_event_id: {self.related_event_id}",
		f"score: {self.score:.2f}",
		f"confidence: {self.confidence:.2f}",
		f"weight_mode: {self.weight_mode.value}",
		f"reason_count: {self.reason_count}",
		f"total_raw_weight: {self.total_raw:.2f}",        ]

        if self.time_delta_seconds is not None:
            lines.append(
                f"Time Delta: {self.time_delta_seconds:.2f}s"
            )

        lines.append("Reasons:")

        if self.breakdown:
            lines.extend(
                item.format_line()
                for item in self.breakdown
            )
        else:
            lines.append("- none")

        if self.rationale:
            lines.append("Rationale:")

            lines.extend(
                f"- {item}"
                for item in self.rationale
            )

        return lines

    def render_audit(self) -> str:
        """
        Render correlation sebagai audit-friendly text.
        """

        return "\n".join(self.audit_lines())

    # =======================================================================
    # Graph helpers
    # =======================================================================

    def to_graph_node(self) -> dict[str, Any]:
        return {
            "id": self.correlation_id,
            "type": "correlation",
            "schema_version": self.schema_version,
            "score": self.score,
            "confidence": self.confidence,
            "reason_count": self.reason_count,
        }

    def to_relationships(self) -> list[dict[str, Any]]:
        return [
            {
                "source": self.correlation_id,
                "target": self.source_event_id,
                "type": "correlates_source",
            },
            {
                "source": self.correlation_id,
                "target": self.related_event_id,
                "type": "correlates_related",
            },
        ]


# ===========================================================================
# Pair Correlation Engine
# ===========================================================================


class PairCorrelationEngine:
    """
    Deterministic pairwise correlation engine.

    Pipeline:

        Event A
           +
        Event B
           |
           v
        Reason Detection
           |
           v
        Score + Breakdown
           |
           v
        Confidence
           |
           v
        CorrelationResult
    """

    def __init__(
        self,
        *,
        time_window_seconds: float = DEFAULT_TIME_WINDOW_SECONDS,
        min_confidence: float = DEFAULT_MIN_CONFIDENCE,
        min_reasons: int = DEFAULT_MIN_REASONS,
        max_results: int = DEFAULT_MAX_RESULTS,
        reason_weights: dict[CorrelationReason, float] | None = None,
        weight_mode: WeightMode = WeightMode.ADDITIVE,
        confidence_mode: WeightMode = WeightMode.PROBABILISTIC_OR,
    ) -> None:
        if time_window_seconds < 0:
            raise ValueError(
                "time_window_seconds must be >= 0"
            )

        if not 0.0 <= min_confidence <= 1.0:
            raise ValueError(
                "min_confidence must be between 0 and 1"
            )

        if min_reasons < 1:
            raise ValueError(
                "min_reasons must be >= 1"
            )

        if max_results < 1:
            raise ValueError(
                "max_results must be >= 1"
            )

        self.time_window_seconds = float(
            time_window_seconds
        )

        self.min_confidence = float(
            min_confidence
        )

        self.min_reasons = int(
            min_reasons
        )

        self.max_results = int(
            max_results
        )

        self.reason_weights = (
            dict(DEFAULT_REASON_WEIGHTS)
            if reason_weights is None
            else dict(reason_weights)
        )

        self.weight_mode = weight_mode
        self.confidence_mode = confidence_mode

    # =======================================================================
    # Public API
    # =======================================================================

    def correlate(
        self,
        source_event: Any,
        candidate_events: Iterable[Any],
    ) -> list[CorrelationResult]:
        """
        Korelasikan satu source event dengan candidate events.
        """

        source_id = _event_id(source_event)

        if not source_id:
            return []

        results: list[CorrelationResult] = []

        for candidate in candidate_events:
            candidate_id = _event_id(candidate)

            if not candidate_id:
                continue

            if candidate_id == source_id:
                continue

            result = self._correlate_pair(
                source_event,
                candidate,
            )

            if result is not None:
                results.append(result)

        results.sort(
            key=lambda result: (
                -result.confidence,
                -result.score,
                result.related_event_id,
            )
        )

        return results[: self.max_results]

    def correlate_all(
        self,
        events: Iterable[Any],
    ) -> list[CorrelationResult]:
        """
        Korelasikan seluruh event secara pairwise.

        Hasil deterministic:
        - sort event by timestamp + event_id
        - evaluasi pasangan i < j
        - hasil sort by confidence, score, IDs
        """

        events_list = [
            event
            for event in events
            if _event_id(event)
        ]

        if len(events_list) < 2:
            return []

        events_sorted = sorted(
            events_list,
            key=lambda event: (
                _timestamp(event)
                or datetime.min.replace(
                    tzinfo=timezone.utc
                ),
                _event_id(event) or "",
            ),
        )

        results: list[CorrelationResult] = []

        count = len(events_sorted)

        for i in range(count):
            source_event = events_sorted[i]

            source_ts = _timestamp(source_event)

            if source_ts is None:
                continue

            for j in range(i + 1, count):
                related_event = events_sorted[j]

                related_ts = _timestamp(related_event)

                if related_ts is None:
                    continue

                delta = (
                    related_ts - source_ts
                ).total_seconds()

                if delta > self.time_window_seconds:
                    break

                result = self._correlate_pair(
                    source_event,
                    related_event,
                )

                if result is not None:
                    results.append(result)

        results.sort(
            key=lambda result: (
                -result.confidence,
                -result.score,
                result.source_event_id,
                result.related_event_id,
            )
        )

        return results[: self.max_results]

    # =======================================================================
    # Internal pair correlation
    # =======================================================================

    def _correlate_pair(
        self,
        source_event: Any,
        related_event: Any,
    ) -> CorrelationResult | None:
        source_id = _event_id(source_event)
        related_id = _event_id(related_event)

        if not source_id or not related_id:
            return None

        if source_id == related_id:
            return None

        source_ts = _timestamp(source_event)
        related_ts = _timestamp(related_event)

        if source_ts is None or related_ts is None:
            return None

        time_delta = abs(
            (
                related_ts - source_ts
            ).total_seconds()
        )

        if time_delta > self.time_window_seconds:
            return None

        reasons: list[CorrelationReason] = []
        rationale: list[str] = []

        # -------------------------------------------------------------------
        # Host
        # -------------------------------------------------------------------

        source_host = _host(source_event)
        related_host = _host(related_event)

        if _eq_ci(source_host, related_host):
            reasons.append(
                CorrelationReason.SAME_HOST
            )

            rationale.append(
                f"same host: {source_host}"
            )

        # -------------------------------------------------------------------
        # User
        # -------------------------------------------------------------------

        source_user = _user(source_event)
        related_user = _user(related_event)

        if _eq_ci(source_user, related_user):
            reasons.append(
                CorrelationReason.SAME_USER
            )

            rationale.append(
                f"same user: {source_user}"
            )

        # -------------------------------------------------------------------
        # Process name
        #
        # Hanya bermakna jika host sama.
        # -------------------------------------------------------------------

        same_host = _eq_ci(
            source_host,
            related_host,
        )

        if same_host:
            source_process_name = _process_name(
                source_event
            )

            related_process_name = _process_name(
                related_event
            )

            if _eq_ci(
                source_process_name,
                related_process_name,
            ):
                reasons.append(
                    CorrelationReason.SAME_PROCESS_NAME
                )

                rationale.append(
                    f"same process name: "
                    f"{source_process_name}"
                )

        # -------------------------------------------------------------------
        # Process ID
        # -------------------------------------------------------------------

        if same_host:
            source_pid = _process_pid(
                source_event
            )

            related_pid = _process_pid(
                related_event
            )

            if (
                source_pid is not None
                and related_pid is not None
                and source_pid == related_pid
            ):
                reasons.append(
                    CorrelationReason.SAME_PROCESS_ID
                )

                rationale.append(
                    f"same process PID: {source_pid}"
                )

        # -------------------------------------------------------------------
        # Parent-child
        # -------------------------------------------------------------------

        if same_host:
            source_pid = _process_pid(
                source_event
            )

            source_ppid = _process_parent_pid(
                source_event
            )

            related_pid = _process_pid(
                related_event
            )

            related_ppid = _process_parent_pid(
                related_event
            )

            is_parent_child = (
                source_ppid is not None
                and related_pid is not None
                and source_ppid == related_pid
            ) or (
                related_ppid is not None
                and source_pid is not None
                and related_ppid == source_pid
            )

            if is_parent_child:
                reasons.append(
                    CorrelationReason.PARENT_CHILD
                )

                rationale.append(
                    "parent-child process relation "
                    f"(pid={source_pid}/{related_pid}, "
                    f"ppid={source_ppid}/{related_ppid})"
                )

        # -------------------------------------------------------------------
        # File hash
        # -------------------------------------------------------------------

        source_hash = _file_hash(
            source_event
        )

        related_hash = _file_hash(
            related_event
        )

        if _eq_ci(
            source_hash,
            related_hash,
        ):
            reasons.append(
                CorrelationReason.SAME_FILE_HASH
            )

            rationale.append(
                f"same file hash: {source_hash}"
            )

        # -------------------------------------------------------------------
        # File path
        # -------------------------------------------------------------------

        source_path = _file_path(
            source_event
        )

        related_path = _file_path(
            related_event
        )

        if _eq_ci(
            source_path,
            related_path,
        ):
            reasons.append(
                CorrelationReason.SAME_FILE_PATH
            )

            rationale.append(
                f"same file path: {source_path}"
            )

        # -------------------------------------------------------------------
        # Source IP
        # -------------------------------------------------------------------

        source_ip = _source_ip(
            source_event
        )

        related_source_ip = _source_ip(
            related_event
        )

        if _eq_ci(
            source_ip,
            related_source_ip,
        ):
            reasons.append(
                CorrelationReason.SAME_SOURCE_IP
            )

            rationale.append(
                f"same source IP: {source_ip}"
            )

        # -------------------------------------------------------------------
        # Destination IP
        # -------------------------------------------------------------------

        source_destination_ip = _destination_ip(
            source_event
        )

        related_destination_ip = _destination_ip(
            related_event
        )

        if _eq_ci(
            source_destination_ip,
            related_destination_ip,
        ):
            reasons.append(
                CorrelationReason.SAME_DESTINATION_IP
            )

            rationale.append(
                f"same destination IP: "
                f"{source_destination_ip}"
            )

        # -------------------------------------------------------------------
        # DNS query
        # -------------------------------------------------------------------

        source_dns = _dns_query(
            source_event
        )

        related_dns = _dns_query(
            related_event
        )

        if _eq_ci(
            source_dns,
            related_dns,
        ):
            reasons.append(
                CorrelationReason.SAME_DNS_QUERY
            )

            rationale.append(
                f"same DNS query: {source_dns}"
            )

        # -------------------------------------------------------------------
        # Registry key
        # -------------------------------------------------------------------

        source_registry = _registry_key(
            source_event
        )

        related_registry = _registry_key(
            related_event
        )

        if _eq_ci(
            source_registry,
            related_registry,
        ):
            reasons.append(
                CorrelationReason.SAME_REGISTRY_KEY
            )

            rationale.append(
                f"same registry key: "
                f"{source_registry}"
            )

        # -------------------------------------------------------------------
        # MITRE technique
        # -------------------------------------------------------------------

        source_mitre = _mitre_techniques(
            source_event
        )

        related_mitre = _mitre_techniques(
            related_event
        )

        shared_mitre = (
            source_mitre & related_mitre
        )

        if shared_mitre:
            reasons.append(
                CorrelationReason.SAME_MITRE_TECHNIQUE
            )

            rationale.append(
                "shared MITRE techniques: "
                f"{sorted(shared_mitre)}"
            )

        # -------------------------------------------------------------------
        # Detection rule
        # -------------------------------------------------------------------

        source_rule = _rule_id(
            source_event
        )

        related_rule = _rule_id(
            related_event
        )

        if _eq_ci(
            source_rule,
            related_rule,
        ):
            reasons.append(
                CorrelationReason.SAME_RULE
            )

            rationale.append(
                f"same rule: {source_rule}"
            )

        # -------------------------------------------------------------------
        # Minimum reasons
        # -------------------------------------------------------------------

        if len(reasons) < self.min_reasons:
            return None

        # -------------------------------------------------------------------
        # Score + breakdown
        # -------------------------------------------------------------------

        scoring = score_reasons(
            reasons,
            weights=self.reason_weights,
            mode=self.weight_mode,
        )

        score = float(
            scoring["score"]
        )

        total_raw = float(
            scoring["total_raw"]
        )

        breakdown = [
            ReasonBreakdown(**item)
            for item in scoring["breakdown"]
        ]

        # -------------------------------------------------------------------
        # Confidence
        #
        # Confidence dihitung dari bobot reason menggunakan probabilistic OR
        # secara default.
        # -------------------------------------------------------------------

        confidence_weights = [
            float(item.weight)
            for item in breakdown
        ]

        confidence = combine_weight_values(
            confidence_weights,
            mode=self.confidence_mode,
        )

        # -------------------------------------------------------------------
        # Minimum confidence
        # -------------------------------------------------------------------

        if confidence < self.min_confidence:
            return None

        # -------------------------------------------------------------------
        # Result
        # -------------------------------------------------------------------

        return CorrelationResult(
            tenant_id=_attr(
                source_event,
                "tenant_id",
            ),
            case_id=_attr(
                source_event,
                "investigation_id",
            ),
            source_event_id=source_id,
            related_event_id=related_id,
            reasons=reasons,
            rationale=rationale,
            score=score,
            confidence=confidence,
            weight_mode=self.weight_mode,
            total_raw=total_raw,
            breakdown=breakdown,
            time_delta_seconds=time_delta,
            metadata={
                "reason_count": len(reasons),
                "time_window_seconds": (
                    self.time_window_seconds
                ),
                "confidence_mode": (
                    self.confidence_mode.value
                ),
            },
        )


# ===========================================================================
# Convenience functions
# ===========================================================================


def correlate(
    source_event: Any,
    candidate_events: Iterable[Any],
    **kwargs: Any,
) -> list[CorrelationResult]:
    """
    Convenience wrapper untuk PairCorrelationEngine.
    """

    return PairCorrelationEngine(
        **kwargs
    ).correlate(
        source_event,
        candidate_events,
    )


def correlate_all(
    events: Iterable[Any],
    **kwargs: Any,
) -> list[CorrelationResult]:
    """
    Convenience wrapper untuk correlate_all().
    """

    return PairCorrelationEngine(
        **kwargs
    ).correlate_all(events)


# ===========================================================================
# Type alias
# ===========================================================================

PairCorrelationResultList = list[CorrelationResult]


__all__ = [
    "SCHEMA_VERSION",
    "DEFAULT_TIME_WINDOW_SECONDS",
    "DEFAULT_MIN_CONFIDENCE",
    "DEFAULT_MIN_REASONS",
    "DEFAULT_MAX_RESULTS",
    "ReasonBreakdown",
    "CorrelationResult",
    "PairCorrelationEngine",
    "PairCorrelationResultList",
    "correlate",
    "correlate_all",
]
