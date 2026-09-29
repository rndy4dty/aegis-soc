"""
Deterministic hypothesis engine for AegisSOC.

Tugas:
    (Evidence[], CorrelationResult[], InvestigationGraph?) -> list[Hypothesis]

Menghasilkan hypothesis MAIN, COUNTER, dan SUB secara deterministic
dari evidence + correlation + sinyal graph. TIDAK memakai LLM.

Prinsip:
- Deterministik. Input sama -> output sama (termasuk urutan).
- Setiap hypothesis membawa rationale eksplisit.
- MAIN hypothesis dipicu oleh MITRE technique dari evidence.
- COUNTER hypothesis dibuat untuk setiap MAIN.
- SUB hypothesis dipicu oleh sinyal graph / correlation.
- Missing evidence diisi berdasarkan template per MITRE technique.
- Tidak mengubah Evidence, Correlation, atau Graph.

Sumber MITRE technique di evidence:
- evidence.data["mitre_techniques"] (kalau extractor mengisi)
- evidence.tags yang match pattern T<digit><digit><digit><digit>
  dengan optional .<digit><digit><digit>
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from pkg.models.evidence import Evidence, EvidenceAssessment
from pkg.models.hypothesis import (
    Hypothesis,
    HypothesisSource,
    HypothesisStatus,
    HypothesisType,
)


# ===========================================================================
# Template registry
# ===========================================================================

@dataclass(frozen=True)
class MitreTemplate:
    """Template hypothesis untuk satu MITRE technique."""
    technique: str
    main_statement: str
    counter_statement: str
    missing_evidence: tuple[str, ...] = ()


MITRE_HYPOTHESIS_TEMPLATES: dict[str, MitreTemplate] = {
    "T1546.011": MitreTemplate(
        technique="T1546.011",
        main_statement=(
            "Possible persistence via Application Shimming"
        ),
        counter_statement=(
            "Legitimate Windows compatibility activity via "
            "PcaSvc or installer framework"
        ),
        missing_evidence=(
            "shim database modification",
            "initiating parent process lineage",
            "related registry modifications",
        ),
    ),
    "T1059.001": MitreTemplate(
        technique="T1059.001",
        main_statement=(
            "Possible execution via PowerShell"
        ),
        counter_statement=(
            "Legitimate administrative or automation script"
        ),
        missing_evidence=(
            "script content or command line",
            "user context and logon origin",
        ),
    ),
    "T1059.003": MitreTemplate(
        technique="T1059.003",
        main_statement=(
            "Possible execution via Windows Command Shell"
        ),
        counter_statement=(
            "Legitimate batch or administrative command execution"
        ),
        missing_evidence=(
            "command line arguments",
            "parent process lineage",
        ),
    ),
    "T1105": MitreTemplate(
        technique="T1105",
        main_statement=(
            "Possible ingress tool transfer"
        ),
        counter_statement=(
            "Legitimate file download or software update"
        ),
        missing_evidence=(
            "destination endpoint and protocol",
            "file hash and signature status",
        ),
    ),
    "T1055": MitreTemplate(
        technique="T1055",
        main_statement=(
            "Possible process injection"
        ),
        counter_statement=(
            "Legitimate use of process memory by debugging "
            "or accessibility tools"
        ),
        missing_evidence=(
            "memory region modification details",
            "target process integrity level",
        ),
    ),
    "T1071": MitreTemplate(
        technique="T1071",
        main_statement=(
            "Possible command and control via application "
            "layer protocol"
        ),
        counter_statement=(
            "Legitimate outbound traffic via standard protocol"
        ),
        missing_evidence=(
            "destination reputation",
            "beacon interval analysis",
        ),
    ),
}


GENERIC_TEMPLATE_PREFIX = "Possible activity related to"


# ===========================================================================
# Constants
# ===========================================================================

MIN_EVIDENCE_FOR_MAIN = 1
MIN_SUPPORT_FOR_STATUS = 2
MIN_GRAPH_HOPS_FOR_SUB = 3

# Pattern MITRE technique ID: Txxxx atau Txxxx.yyy
_MITRE_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


# ===========================================================================
# Internal helpers
# ===========================================================================

def _sort_evidence(evidence: Iterable[Evidence]) -> list[Evidence]:
    return sorted(
        evidence,
        key=lambda e: (e.evidence_type.value, e.evidence_id),
    )


def _techniques_from_evidence(
    evidence: list[Evidence],
) -> dict[str, list[str]]:
    """
    Kumpulkan MITRE technique -> list evidence_id.

    Sumber:
    - evidence.data["mitre_techniques"] (kalau extractor mengisi)
    - evidence.tags yang match pattern Txxxx atau Txxxx.yyy
    """
    result: dict[str, list[str]] = {}

    for ev in evidence:
        techniques: set[str] = set()

        # -- data --------------------------------------------------------
        data = getattr(ev, "data", None) or {}
        if isinstance(data, dict):
            raw = data.get("mitre_techniques")
            if isinstance(raw, (list, tuple, set)):
                for t in raw:
                    t_str = str(t).upper().strip()
                    if _MITRE_PATTERN.match(t_str):
                        techniques.add(t_str)
            elif isinstance(raw, str):
                t_str = raw.upper().strip()
                if _MITRE_PATTERN.match(t_str):
                    techniques.add(t_str)

        # -- tags -------------------------------------------------------
        for tag in ev.tags:
            tag_upper = str(tag).upper().strip()
            if _MITRE_PATTERN.match(tag_upper):
                techniques.add(tag_upper)

        for t in techniques:
            result.setdefault(t, []).append(ev.evidence_id)

    for t in result:
        result[t] = sorted(set(result[t]))

    return result


def _template_for(technique: str) -> MitreTemplate:
    return MITRE_HYPOTHESIS_TEMPLATES.get(
        technique,
        MitreTemplate(
            technique=technique,
            main_statement=(
                f"{GENERIC_TEMPLATE_PREFIX} {technique}"
            ),
            counter_statement=(
                f"Legitimate activity that could be misclassified "
                f"as {technique}"
            ),
            missing_evidence=(
                "additional corroborating evidence",
            ),
        ),
    )


def _status_from_support(support_count: int) -> HypothesisStatus:
    if support_count >= MIN_SUPPORT_FOR_STATUS:
        return HypothesisStatus.SUPPORTED
    return HypothesisStatus.PROPOSED


def _confidence_from_support(count: int) -> float:
    """
    Confidence scale berdasarkan jumlah supporting evidence.

        1  -> 0.30
        2  -> 0.55
        3  -> 0.70
        4  -> 0.80
        5+ -> 0.90
    """
    if count <= 0:
        return 0.0
    if count == 1:
        return 0.30
    if count == 2:
        return 0.55
    if count == 3:
        return 0.70
    if count == 4:
        return 0.80
    return 0.90


def _walk_forward(
    graph: Any,
    start_id: str,
    rel_type: Any,
    *,
    max_depth: int = 10,
) -> list[str]:
    """
    BFS forward dari start_id mengikuti rel_type.
    Return list entity_id yang dikunjungi (tidak termasuk start).
    """
    visited: set[str] = set()
    frontier = [start_id]

    for _ in range(max_depth):
        next_frontier: list[str] = []
        for eid in frontier:
            for r in graph.outgoing(eid):
                if r.relationship_type != rel_type:
                    continue
                if r.target_id in visited:
                    continue
                visited.add(r.target_id)
                next_frontier.append(r.target_id)
        if not next_frontier:
            break
        frontier = next_frontier

    return sorted(visited)


# ===========================================================================
# HypothesisEngine
# ===========================================================================

class HypothesisEngine:
    """
    Stateless deterministic hypothesis generator.
    """

    def __init__(
        self,
        *,
        min_evidence_for_main: int = MIN_EVIDENCE_FOR_MAIN,
    ) -> None:
        if min_evidence_for_main < 1:
            raise ValueError("min_evidence_for_main must be >= 1")
        self.min_evidence_for_main = min_evidence_for_main

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def generate(
        self,
        *,
        evidence: list[Evidence] | None = None,
        correlations: list[Any] | None = None,
        graph: Any = None,
        tenant_id: str | None = None,
        investigation_id: str | None = None,
    ) -> list[Hypothesis]:
        evidence = _sort_evidence(evidence or [])
        correlations = list(correlations or [])

        technique_map = _techniques_from_evidence(evidence)

        hypotheses: list[Hypothesis] = []

        # -- MAIN + COUNTER per technique -------------------------------
        for technique in sorted(technique_map.keys()):
            support_ids = technique_map[technique]
            if len(support_ids) < self.min_evidence_for_main:
                continue

            template = _template_for(technique)

            main = self._build_main(
                template=template,
                support_ids=support_ids,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
            )
            hypotheses.append(main)

            counter = self._build_counter(
                template=template,
                parent=main,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
            )
            hypotheses.append(counter)

        # -- SUB dari sinyal graph --------------------------------------
        if graph is not None:
            hypotheses.extend(
                self._build_graph_subs(
                    graph=graph,
                    tenant_id=tenant_id,
                    investigation_id=investigation_id,
                )
            )

        # -- SUB dari correlation ---------------------------------------
        if correlations:
            sub_corr = self._build_correlation_sub(
                correlations=correlations,
                tenant_id=tenant_id,
                investigation_id=investigation_id,
            )
            if sub_corr is not None:
                hypotheses.append(sub_corr)

        # -- Attach contradicting evidence ------------------------------
        hypotheses = self._attach_contradicting(hypotheses, evidence)

        # -- Fingerprint + sort -----------------------------------------
        hypotheses = [h.with_fingerprint() for h in hypotheses]
        return self._sort(hypotheses)

    # -------------------------------------------------------------------
    # MAIN
    # -------------------------------------------------------------------

    @staticmethod
    def _build_main(
        *,
        template: MitreTemplate,
        support_ids: list[str],
        tenant_id: str | None,
        investigation_id: str | None,
    ) -> Hypothesis:
        status = _status_from_support(len(support_ids))

        return Hypothesis(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            hypothesis_type=HypothesisType.MAIN,
            statement=template.main_statement,
            description=(
                f"Deterministically proposed from {len(support_ids)} "
                f"evidence item(s) referencing {template.technique}."
            ),
            mitre_techniques=[template.technique],
            status=status,
            confidence=_confidence_from_support(len(support_ids)),
            supporting_evidence_ids=support_ids,
            missing_evidence=list(template.missing_evidence),
            source=HypothesisSource.DETERMINISTIC,
            rationale=(
                f"MITRE technique {template.technique} detected across "
                f"evidence: {', '.join(support_ids)}."
            ),
            created_by="hypothesis_engine",
        )

    # -------------------------------------------------------------------
    # COUNTER
    # -------------------------------------------------------------------

    @staticmethod
    def _build_counter(
        *,
        template: MitreTemplate,
        parent: Hypothesis,
        tenant_id: str | None,
        investigation_id: str | None,
    ) -> Hypothesis:
        return Hypothesis(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            hypothesis_type=HypothesisType.COUNTER,
            statement=template.counter_statement,
            description=(
                "Counter-hypothesis: alternative explanation that "
                "could account for the same evidence."
            ),
            mitre_techniques=[template.technique],
            status=HypothesisStatus.PROPOSED,
            confidence=0.0,
            supporting_evidence_ids=[],
            contradicting_evidence_ids=[],
            missing_evidence=list(template.missing_evidence),
            source=HypothesisSource.DETERMINISTIC,
            rationale=(
                f"Counter to MAIN hypothesis: {parent.statement}."
            ),
            created_by="hypothesis_engine",
        )

    # -------------------------------------------------------------------
    # SUB from graph
    # -------------------------------------------------------------------

    def _build_graph_subs(
        self,
        *,
        graph: Any,
        tenant_id: str | None,
        investigation_id: str | None,
    ) -> list[Hypothesis]:
        out: list[Hypothesis] = []

        chain_signal = self._detect_process_chain(graph)
        if chain_signal is not None:
            out.append(Hypothesis(
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                hypothesis_type=HypothesisType.SUB,
                parent_hypothesis_id=None,
                statement=(
                    "Multi-process execution chain detected"
                ),
                description=(
                    f"Process chain with depth >= "
                    f"{MIN_GRAPH_HOPS_FOR_SUB} detected in graph."
                ),
                mitre_techniques=["T1059"],
                status=HypothesisStatus.PROPOSED,
                confidence=0.0,
                source=HypothesisSource.DETERMINISTIC,
                rationale=chain_signal,
                created_by="hypothesis_engine",
            ))

        file_signal = self._detect_shared_hash(graph)
        if file_signal is not None:
            out.append(Hypothesis(
                tenant_id=tenant_id,
                investigation_id=investigation_id,
                hypothesis_type=HypothesisType.SUB,
                parent_hypothesis_id=None,
                statement=(
                    "Same file hash observed across multiple hosts"
                ),
                description=(
                    "Shared file hash across hosts may indicate "
                    "lateral movement or shared artifact."
                ),
                mitre_techniques=["T1570"],
                status=HypothesisStatus.PROPOSED,
                confidence=0.0,
                source=HypothesisSource.DETERMINISTIC,
                rationale=file_signal,
                created_by="hypothesis_engine",
            ))

        return out

    @staticmethod
    def _detect_process_chain(graph: Any) -> str | None:
        try:
            from pkg.models.entity import EntityType
            from pkg.models.relationship import RelationshipType
        except ImportError:
            return None

        try:
            procs = graph.entities_by_type(EntityType.PROCESS)
        except AttributeError:
            return None

        if not procs:
            return None

        max_depth = 0
        deepest_root = None

        for proc in procs:
            descendants = _walk_forward(
                graph, proc.entity_id,
                RelationshipType.SPAWNED,
                max_depth=10,
            )
            depth = len(descendants)
            if depth > max_depth:
                max_depth = depth
                deepest_root = proc

        if max_depth >= (MIN_GRAPH_HOPS_FOR_SUB - 1) and deepest_root:
            return (
                f"Process chain from {deepest_root.value} "
                f"reaches depth {max_depth + 1}."
            )
        return None

    @staticmethod
    def _detect_shared_hash(graph: Any) -> str | None:
        try:
            from pkg.models.entity import EntityType
            from pkg.models.relationship import RelationshipType
        except ImportError:
            return None

        try:
            hashes = graph.entities_by_type(EntityType.HASH)
        except AttributeError:
            return None

        if not hashes:
            return None

        for h in hashes:
            incoming = graph.incoming(h.entity_id)
            file_links = [
                r for r in incoming
                if r.relationship_type == RelationshipType.HAS_HASH
            ]
            host_set: set[str] = set()
            for r in file_links:
                file_entity = graph.get_entity(r.source_id) \
                    if hasattr(graph, "get_entity") else None
                if file_entity is None:
                    continue
                if file_entity.host:
                    host_set.add(file_entity.host)

            if len(host_set) > 1:
                return (
                    f"Hash {h.value} observed across "
                    f"{len(host_set)} hosts: {sorted(host_set)}."
                )
        return None

    # -------------------------------------------------------------------
    # SUB from correlation
    # -------------------------------------------------------------------

    def _build_correlation_sub(
        self,
        *,
        correlations: list[Any],
        tenant_id: str | None,
        investigation_id: str | None,
    ) -> Hypothesis | None:
        if not correlations:
            return None

        best = max(
            correlations,
            key=lambda c: getattr(c, "confidence", 0.0),
        )
        conf = getattr(best, "confidence", 0.0)
        if conf < 0.5:
            return None

        cid = getattr(best, "correlation_id", "unknown")
        reasons = getattr(best, "reasons", []) or []
        reason_str = ", ".join(
            r.value if hasattr(r, "value") else str(r)
            for r in reasons
        ) or "n/a"

        return Hypothesis(
            tenant_id=tenant_id,
            investigation_id=investigation_id,
            hypothesis_type=HypothesisType.SUB,
            parent_hypothesis_id=None,
            statement=(
                "Correlated event cluster indicates a single activity"
            ),
            description=(
                f"Correlation {cid} with confidence {conf:.2f} "
                f"groups multiple events."
            ),
            status=HypothesisStatus.PROPOSED,
            confidence=0.0,
            source=HypothesisSource.DETERMINISTIC,
            rationale=(
                f"Correlation {cid} (reasons: {reason_str})."
            ),
            created_by="hypothesis_engine",
        )

    # -------------------------------------------------------------------
    # Contradicting evidence attachment
    # -------------------------------------------------------------------

    @staticmethod
    def _attach_contradicting(
        hypotheses: list[Hypothesis],
        evidence: list[Evidence],
    ) -> list[Hypothesis]:
        contra_map: dict[str, list[str]] = {}

        for ev in evidence:
            for link in ev.hypothesis_links:
                if link.assessment == EvidenceAssessment.CONTRADICTS:
                    contra_map.setdefault(
                        link.hypothesis_id, []
                    ).append(ev.evidence_id)

        if not contra_map:
            return hypotheses

        out: list[Hypothesis] = []
        for h in hypotheses:
            ids = contra_map.get(h.hypothesis_id)
            if ids:
                h = h.model_copy(update={
                    "contradicting_evidence_ids": sorted(set(ids)),
                })
            out.append(h)
        return out

    # -------------------------------------------------------------------
    # Sort
    # -------------------------------------------------------------------

    @staticmethod
    def _sort(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
        type_order = {
            HypothesisType.MAIN: 0,
            HypothesisType.COUNTER: 1,
            HypothesisType.SUB: 2,
            HypothesisType.UNKNOWN: 3,
        }
        return sorted(hypotheses, key=lambda h: (
            type_order.get(h.hypothesis_type, 99),
            h.fingerprint or "",
        ))


# ===========================================================================
# Factory
# ===========================================================================

def generate_hypotheses(
    *,
    evidence: list[Evidence] | None = None,
    correlations: list[Any] | None = None,
    graph: Any = None,
    tenant_id: str | None = None,
    investigation_id: str | None = None,
    min_evidence_for_main: int = MIN_EVIDENCE_FOR_MAIN,
) -> list[Hypothesis]:
    """Convenience factory."""
    return HypothesisEngine(
        min_evidence_for_main=min_evidence_for_main,
    ).generate(
        evidence=evidence,
        correlations=correlations,
        graph=graph,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
    )


__all__ = [
    "MIN_EVIDENCE_FOR_MAIN",
    "MIN_SUPPORT_FOR_STATUS",
    "MIN_GRAPH_HOPS_FOR_SUB",
    "GENERIC_TEMPLATE_PREFIX",
    "MitreTemplate",
    "MITRE_HYPOTHESIS_TEMPLATES",
    "HypothesisEngine",
    "generate_hypotheses",
]
