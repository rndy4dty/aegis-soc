"""
Correlation primitives for AegisSOC.

Modul ini HANYA berisi model dan fungsi murni.

Engine TIDAK di sini. Engine ada di internal/correlation/correlation.py.
"""

from __future__ import annotations

from enum import Enum
from math import isfinite
from typing import Iterable, Mapping, Sequence


SCHEMA_VERSION: str = "1.0"

SCORE_MIN: float = 0.0
SCORE_MAX: float = 1.0

WEIGHT_MIN: float = 0.0
WEIGHT_MAX: float = 1.0


class CorrelationReasonCategory(str, Enum):
    IDENTITY = "identity"
    PROCESS = "process"
    FILE = "file"
    NETWORK = "network"
    REGISTRY = "registry"
    DETECTION = "detection"


class CorrelationReason(str, Enum):
    SAME_HOST = "same_host"
    SAME_USER = "same_user"

    SAME_PROCESS_NAME = "same_process_name"
    SAME_PROCESS_ID = "same_process_id"
    PARENT_CHILD = "parent_child"

    SAME_FILE_HASH = "same_file_hash"
    SAME_FILE_PATH = "same_file_path"

    SAME_SOURCE_IP = "same_source_ip"
    SAME_DESTINATION_IP = "same_destination_ip"
    SAME_DNS_QUERY = "same_dns_query"

    SAME_REGISTRY_KEY = "same_registry_key"

    SAME_MITRE_TECHNIQUE = "same_mitre_technique"
    SAME_RULE = "same_rule"


REASON_CATEGORY: dict[CorrelationReason, CorrelationReasonCategory] = {
    CorrelationReason.SAME_HOST: CorrelationReasonCategory.IDENTITY,
    CorrelationReason.SAME_USER: CorrelationReasonCategory.IDENTITY,
    CorrelationReason.SAME_PROCESS_NAME: CorrelationReasonCategory.PROCESS,
    CorrelationReason.SAME_PROCESS_ID: CorrelationReasonCategory.PROCESS,
    CorrelationReason.PARENT_CHILD: CorrelationReasonCategory.PROCESS,
    CorrelationReason.SAME_FILE_HASH: CorrelationReasonCategory.FILE,
    CorrelationReason.SAME_FILE_PATH: CorrelationReasonCategory.FILE,
    CorrelationReason.SAME_SOURCE_IP: CorrelationReasonCategory.NETWORK,
    CorrelationReason.SAME_DESTINATION_IP: CorrelationReasonCategory.NETWORK,
    CorrelationReason.SAME_DNS_QUERY: CorrelationReasonCategory.NETWORK,
    CorrelationReason.SAME_REGISTRY_KEY: CorrelationReasonCategory.REGISTRY,
    CorrelationReason.SAME_MITRE_TECHNIQUE: CorrelationReasonCategory.DETECTION,
    CorrelationReason.SAME_RULE: CorrelationReasonCategory.DETECTION,
}


REASON_LABELS: dict[CorrelationReason, str] = {
    CorrelationReason.SAME_HOST: "Same host",
    CorrelationReason.SAME_USER: "Same user",
    CorrelationReason.SAME_PROCESS_NAME: "Same process name",
    CorrelationReason.SAME_PROCESS_ID: "Same process ID",
    CorrelationReason.PARENT_CHILD: "Parent-child process relation",
    CorrelationReason.SAME_FILE_HASH: "Same file hash",
    CorrelationReason.SAME_FILE_PATH: "Same file path",
    CorrelationReason.SAME_SOURCE_IP: "Same source IP",
    CorrelationReason.SAME_DESTINATION_IP: "Same destination IP",
    CorrelationReason.SAME_DNS_QUERY: "Same DNS query",
    CorrelationReason.SAME_REGISTRY_KEY: "Same registry key",
    CorrelationReason.SAME_MITRE_TECHNIQUE: "Shared MITRE technique",
    CorrelationReason.SAME_RULE: "Same detection rule",
}


DEFAULT_REASON_WEIGHTS: dict[CorrelationReason, float] = {
    CorrelationReason.SAME_HOST: 0.15,
    CorrelationReason.SAME_USER: 0.15,
    CorrelationReason.SAME_PROCESS_NAME: 0.20,
    CorrelationReason.SAME_PROCESS_ID: 0.30,
    CorrelationReason.PARENT_CHILD: 0.35,
    CorrelationReason.SAME_FILE_HASH: 0.40,
    CorrelationReason.SAME_FILE_PATH: 0.20,
    CorrelationReason.SAME_SOURCE_IP: 0.25,
    CorrelationReason.SAME_DESTINATION_IP: 0.30,
    CorrelationReason.SAME_DNS_QUERY: 0.25,
    CorrelationReason.SAME_REGISTRY_KEY: 0.30,
    CorrelationReason.SAME_MITRE_TECHNIQUE: 0.15,
    CorrelationReason.SAME_RULE: 0.10,
}


class WeightMode(str, Enum):
    ADDITIVE = "additive"
    PROBABILISTIC_OR = "probabilistic_or"
    MAX = "max"


DEFAULT_WEIGHT_MODE: WeightMode = WeightMode.ADDITIVE


ReasonWeights = Mapping[CorrelationReason, float]
ReasonSequence = Sequence[CorrelationReason]


def validate_reason_weights(
    weights: Mapping,
    *,
    merge_defaults: bool = False,
) -> dict[CorrelationReason, float]:
    base: dict[CorrelationReason, float] = {}
    if merge_defaults:
        base.update(DEFAULT_REASON_WEIGHTS)

    for reason, weight in weights.items():
        coerced: CorrelationReason
        if isinstance(reason, CorrelationReason):
            coerced = reason
        else:
            try:
                coerced = CorrelationReason(reason)
            except (ValueError, TypeError) as exc:
                raise ValueError(
                    f"Unknown correlation reason: {reason!r}"
                ) from exc

        try:
            value = float(weight)
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"Weight for {coerced.value!r} must be numeric."
            ) from exc

        if not isfinite(value):
            raise ValueError(
                f"Weight for {coerced.value!r} must be finite."
            )

        if not WEIGHT_MIN <= value <= WEIGHT_MAX:
            raise ValueError(
                f"Weight for {coerced.value!r} must be between "
                f"{WEIGHT_MIN} and {WEIGHT_MAX}."
            )

        base[coerced] = value

    return base


def get_weight(
    reason: CorrelationReason,
    weights: ReasonWeights | None = None,
) -> float:
    if weights is not None and reason in weights:
        return float(weights[reason])
    return float(DEFAULT_REASON_WEIGHTS.get(reason, 0.0))


def describe_reason(reason: CorrelationReason) -> str:
    return REASON_LABELS.get(reason, reason.value)


def reasons_by_category(
    category: CorrelationReasonCategory,
) -> list[CorrelationReason]:
    return sorted(
        (r for r, c in REASON_CATEGORY.items() if c == category),
        key=lambda r: r.value,
    )


def category_of(
    reason: CorrelationReason,
) -> CorrelationReasonCategory | None:
    return REASON_CATEGORY.get(reason)


def _coerce_reason(value: object) -> CorrelationReason | None:
    if isinstance(value, CorrelationReason):
        return value
    try:
        return CorrelationReason(value)
    except (ValueError, TypeError):
        return None


def _dedup_reasons(
    reasons: Iterable[object],
) -> list[CorrelationReason]:
    seen: set[CorrelationReason] = set()
    out: list[CorrelationReason] = []
    for raw in reasons:
        coerced = _coerce_reason(raw)
        if coerced is None or coerced in seen:
            continue
        seen.add(coerced)
        out.append(coerced)
    return out


def combine_weight_values(
    values: Sequence[float],
    *,
    mode: WeightMode = DEFAULT_WEIGHT_MODE,
) -> float:
    if not values:
        return SCORE_MIN

    cleaned: list[float] = []
    for v in values:
        try:
            fv = float(v)
        except (TypeError, ValueError):
            continue
        if not isfinite(fv):
            continue
        fv = min(max(fv, WEIGHT_MIN), WEIGHT_MAX)
        cleaned.append(fv)

    if not cleaned:
        return SCORE_MIN

    if mode == WeightMode.MAX:
        score = max(cleaned)
    elif mode == WeightMode.PROBABILISTIC_OR:
        product = 1.0
        for w in cleaned:
            product *= (1.0 - w)
        score = 1.0 - product
    else:
        score = sum(cleaned)

    return min(max(score, SCORE_MIN), SCORE_MAX)


def combine_weights(
    reasons: Iterable[object],
    weights: ReasonWeights | None = None,
    *,
    mode: WeightMode = DEFAULT_WEIGHT_MODE,
) -> float:
    ordered = _dedup_reasons(reasons)
    if not ordered:
        return SCORE_MIN

    if weights is not None:
        active_weights = validate_reason_weights(
            weights, merge_defaults=True
        )
    else:
        active_weights = dict(DEFAULT_REASON_WEIGHTS)

    values = [active_weights.get(r, 0.0) for r in ordered]
    return combine_weight_values(values, mode=mode)


def score_reasons(
    reasons: Iterable[object],
    weights: ReasonWeights | None = None,
    *,
    mode: WeightMode = DEFAULT_WEIGHT_MODE,
) -> dict:
    ordered = _dedup_reasons(reasons)

    if weights is not None:
        active_weights = validate_reason_weights(
            weights, merge_defaults=True
        )
    else:
        active_weights = dict(DEFAULT_REASON_WEIGHTS)

    breakdown: list[dict] = []
    values: list[float] = []
    total_raw = 0.0

    for r in ordered:
        w = float(active_weights.get(r, 0.0))
        values.append(w)
        total_raw += w

        category = REASON_CATEGORY.get(r)
        breakdown.append({
            "reason": r.value,
            "label": REASON_LABELS.get(r, r.value),
            "category": category.value if category is not None else None,
            "weight": w,
        })

    breakdown.sort(key=lambda item: (-item["weight"], item["reason"]))

    score = combine_weight_values(values, mode=mode)

    return {
        "score": score,
        "mode": mode.value,
        "reason_count": len(ordered),
        "total_raw": total_raw,
        "breakdown": breakdown,
    }


__all__ = [
    "SCHEMA_VERSION",
    "SCORE_MIN",
    "SCORE_MAX",
    "WEIGHT_MIN",
    "WEIGHT_MAX",
    "CorrelationReason",
    "CorrelationReasonCategory",
    "REASON_CATEGORY",
    "REASON_LABELS",
    "DEFAULT_REASON_WEIGHTS",
    "WeightMode",
    "DEFAULT_WEIGHT_MODE",
    "ReasonWeights",
    "ReasonSequence",
    "validate_reason_weights",
    "get_weight",
    "describe_reason",
    "reasons_by_category",
    "category_of",
    "combine_weight_values",
    "combine_weights",
    "score_reasons",
]
