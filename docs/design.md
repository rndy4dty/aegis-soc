# Design Decisions

## Deterministic First
Core engine deterministic. AI hanya enhancement.
Alasan: reproducible, auditable, offline, murah.

## Evidence Grounding
Setiap finding wajib punya evidence pendukung.
Alasan: LLM rentan halusinasi.

## Counter-Hypothesis
Setiap MAIN hypothesis punya COUNTER.
Alasan: mencegah bias confirmation.

## Fingerprint vs ID
Merge by fingerprint (SHA-256), bukan UUID.

## Rule Engine as Default
RuleEngineProvider default. LLM opsional.

## Multi-Agent Orchestrator
4 agent: Hypothesis, Counter, Critic, Report.

## Fallback Chain
Cloud LLM -> Local LLM -> Multi-Agent -> Rule Engine.

## Immutability
Model Pydantic immutable by convention.
