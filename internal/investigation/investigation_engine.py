"""
Investigation Engine for AegisSOC.

Orkestrasi end-to-end:

    events
      │
      ├──► EventToEvidence       ──►  Evidence[]
      │
      ├──► EntityExtractor       ──►  Entity[]
      │       │
      │       ▼
      │    EntityResolver        ──►  EntityStore (canonical)
      │
      ├──► RelationshipBuilder   ──►  Relationship[]   (per event)
      │       │
      │       ▼
      │    RelationshipResolver  ──►  RelationshipStore (canonical)
      │
      ├──► CorrelationEngine     ──►  CorrelationResult[]
      │
      ├──► HypothesisEngine      ──►  Hypothesis[]
      │
      └──► RiskEngine            ──►  RiskAssessment
                                       │
                                       ▼
                                 InvestigationCase
                                       │
                                       ▼
                                 InvestigationResult

Prinsip:
- Deterministik. Input sama → output sama.
- Setiap sub-engine sudah diuji terpisah; engine ini hanya orkestrasi.
- Tidak ada LLM, tidak ada I/O jaringan.
- InvestigationCase sebagai aggregate root.
- InvestigationResult sebagai hasil lengkap satu run.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from internal.evidence.event_to_evidence import EventToEvidenceConverter
from internal.graph.entity_extractor import EntityExtractor
from internal.graph.entity_resolver import (
    EntityResolver,
    EntityStore,
)
from internal.graph.graph_store import InvestigationGraph
from internal.graph.relationship_builder import RelationshipBuilder
from internal.graph.relationship_resolver import (
    RelationshipResolver,
    RelationshipStore,
)
from internal.investigation.hypothesis_engine import HypothesisEngine
from internal.investigation.risk_engine import (
    RiskAssessment,
    RiskConfig,
    RiskEngine,
)

from internal.correlation.correlation import (
    CorrelationResult,
    PairCorrelationEngine,

)
from pkg.models.entity import Entity
from pkg.models.evidence import Evidence
from pkg.models.event import Event
from pkg.models.hypothesis import Hypothesis
from pkg.models.investigation import (
    InvestigationCase,
    InvestigationCategory,
    InvestigationPriority,
    InvestigationStatus,
)
from pkg.models.relationship import Relationship


# ===========================================================================
# Result
# ===========================================================================

@dataclass
class InvestigationResult:
    """
    Hasil lengkap satu run investigation.
    """

    case: InvestigationCase
    graph: InvestigationGraph
    evidence: list[Evidence] = field(default_factory=list)
    correlations: list[CorrelationResult] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    risk: RiskAssessment | None = None

    # -----------------------------------------------------------------
    # Convenience
    # -----------------------------------------------------------------

    @property
    def evidence_count(self) -> int:
        return len(self.evidence)

    @property
    def correlation_count(self) -> int:
        return len(self.correlations)

    @property
    def hypothesis_count(self) -> int:
        return len(self.hypotheses)

    @property
    def risk_score(self) -> int:
        return self.risk.risk_score if self.risk else 0

    @property
    def confidence(self) -> float:
        return self.risk.confidence if self.risk else 0.0

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case.case_id,
            "title": self.case.title,
            "status": self.case.status.value,
            "priority": self.case.priority.value,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "evidence_count": self.evidence_count,
            "correlation_count": self.correlation_count,
            "hypothesis_count": self.hypothesis_count,
            "entity_count": self.graph.entity_count,
            "relationship_count": self.graph.relationship_count,
        }


# ===========================================================================
# InvestigationEngine
# ===========================================================================

class InvestigationEngine:
    """
    Orkestrasi end-to-end: events → InvestigationResult.

    Stateless. Bisa di-reuse.
    """

    def __init__(
        self,
        *,
        evidence_converter: EventToEvidenceConverter | None = None,
        entity_extractor: EntityExtractor | None = None,
        entity_resolver: EntityResolver | None = None,
        relationship_builder: RelationshipBuilder | None = None,
        relationship_resolver: RelationshipResolver | None = None,
        correlation_engine: PairCorrelationEngine | None = None,
        hypothesis_engine: HypothesisEngine | None = None,
        risk_engine: RiskEngine | None = None,
        risk_config: RiskConfig | None = None,
    ) -> None:
        self._evidence_converter = (
            evidence_converter or EventToEvidenceConverter()
        )
        self._entity_extractor = entity_extractor or EntityExtractor()
        self._entity_resolver = entity_resolver or EntityResolver()
        self._relationship_builder = (
            relationship_builder or RelationshipBuilder()
        )
        self._relationship_resolver = (
            relationship_resolver or RelationshipResolver()
        )
        self._correlation_engine = (
            correlation_engine or PairCorrelationEngine()
        )
        self._hypothesis_engine = (
            hypothesis_engine or HypothesisEngine()
        )
        self._risk_engine = (
            risk_engine or RiskEngine(config=risk_config)
        )
    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def run(
        self,
        events: list[Event],
        *,
        title: str,
        description: str | None = None,
        tenant_id: str | None = None,
        analyst: str | None = None,
        category: InvestigationCategory = InvestigationCategory.UNKNOWN,
        priority: InvestigationPriority | None = None,
    ) -> InvestigationResult:
        events = list(events)

        # -- 1. Convert events → evidence ------------------------------
        evidence = self._evidence_converter.convert_many(events)

        # -- 2. Build graph --------------------------------------------
        graph = self._build_graph(events)

        # -- 3. Correlate events ---------------------------------------
        # -- 3. Correlate events ---------------------------------------
        correlations = self._correlation_engine.correlate_all(events)
        # -- 4. Generate hypotheses ------------------------------------
        hypotheses = self._hypothesis_engine.generate(
            evidence=evidence,
            correlations=correlations,
            graph=graph,
            tenant_id=tenant_id,
        )

        # -- 5. Compute risk -------------------------------------------
        risk = self._risk_engine.compute(
            evidence=evidence,
            correlations=correlations,
            hypotheses=hypotheses,
        )

        # -- 6. Assemble case ------------------------------------------
        case = self._build_case(
            events=events,
            graph=graph,
            evidence=evidence,
            correlations=correlations,
            hypotheses=hypotheses,
            title=title,
            description=description,
            tenant_id=tenant_id,
            analyst=analyst,
            category=category,
            priority=priority,
        )

        # -- 7. Apply risk to case -------------------------------------
        self._risk_engine.apply_to_case(
            case,
            risk,
            reason="initial investigation",
            evidence_ids=[e.evidence_id for e in evidence],
            hypothesis_ids=[h.hypothesis_id for h in hypotheses],
        )

        return InvestigationResult(
            case=case,
            graph=graph,
            evidence=evidence,
            correlations=correlations,
            hypotheses=hypotheses,
            risk=risk,
        )

    # -------------------------------------------------------------------
    # Sub-steps
    # -------------------------------------------------------------------

    def _build_graph(self, events: list[Event]) -> InvestigationGraph:
        # 1. Extract entities per event
        all_entities: list[Entity] = []
        for event in events:
            all_entities.extend(self._entity_extractor.extract(event))

        # 2. Resolve entities → canonical
        entity_store = self._entity_resolver.resolve(all_entities)
        canonical_entities = entity_store.to_list()

        # 3. Build relationships from canonical entities
        all_relationships: list[Relationship] = []
        for event in events:
            all_relationships.extend(
                self._relationship_builder.build(
                    event, canonical_entities
                )
            )

        # 4. Resolve relationships
        relationship_store = self._relationship_resolver.resolve(
            all_relationships
        )

        return InvestigationGraph(
            entity_store,
            relationship_store,
            events_processed=len(events),
        )

    def _build_case(
        self,
        *,
        events: list[Event],
        graph: InvestigationGraph,
        evidence: list[Evidence],
        correlations: list[CorrelationResult],
        hypotheses: list[Hypothesis],
        title: str,
        description: str | None,
        tenant_id: str | None,
        analyst: str | None,
        category: InvestigationCategory,
        priority: InvestigationPriority | None,
    ) -> InvestigationCase:
        # Priority default: derive dari severity maksimum event
        if priority is None:
            priority = self._derive_priority(events)

        # Severity: ambil max dari events
        max_severity = max(
            (e.severity for e in events), default=0,
        )

        case = InvestigationCase(
            title=title,
            description=description,
            category=category,
            priority=priority,
            severity=max_severity,
            tenant_id=tenant_id,
        )

        # -- Attach references ----------------------------------------
        for event in events:
            case.add_event(event.event_id)
            if event.rule_id:
                case.add_alert(event.rule_id)

        for ev in evidence:
            case.add_evidence(ev.evidence_id)

        for h in hypotheses:
            case.add_hypothesis(h.hypothesis_id)

        for entity in graph.entities:
            case.add_entity(entity.entity_id)

        # -- Assign analyst -------------------------------------------
        if analyst:
            case.assign_analyst(analyst)

        # -- Transition: DETECTED → TRIAGED ----------------------------
        if case.can_transition_to(InvestigationStatus.TRIAGED):
            case.transition_to(InvestigationStatus.TRIAGED)

        return case

    # -------------------------------------------------------------------
    # Derivation helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _derive_priority(
        events: list[Event],
    ) -> InvestigationPriority:
        if not events:
            return InvestigationPriority.LOW

        max_severity = max(e.severity for e in events)

        if max_severity >= 85:
            return InvestigationPriority.CRITICAL
        if max_severity >= 70:
            return InvestigationPriority.HIGH
        if max_severity >= 40:
            return InvestigationPriority.MEDIUM
        return InvestigationPriority.LOW


# ===========================================================================
# Factory
# ===========================================================================

def investigate(
    events: list[Event],
    *,
    title: str,
    description: str | None = None,
    tenant_id: str | None = None,
    analyst: str | None = None,
    category: InvestigationCategory = InvestigationCategory.UNKNOWN,
    priority: InvestigationPriority | None = None,
    risk_config: RiskConfig | None = None,
) -> InvestigationResult:
    """Convenience factory."""
    engine = InvestigationEngine(
        risk_config=risk_config,
    )
    return engine.run(
        events,
        title=title,
        description=description,
        tenant_id=tenant_id,
        analyst=analyst,
        category=category,
        priority=priority,
    )


__all__ = [
    "InvestigationResult",
    "InvestigationEngine",
    "investigate",
]
