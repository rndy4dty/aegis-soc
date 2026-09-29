# Architecture

## Pipeline

    Wazuh / Sysmon / File events
            |
            v
      Canonical Event
            |
            +--> Evidence
            +--> Entity + Relationship
            |
            v
      Correlation Engine
            |
            v
      Hypothesis Engine
            |
            v
      Risk Engine
            |
            v
      InvestigationCase
            |
            v
      Report / AI Narrative

## Layer

| Layer | Lokasi | Tugas |
|---|---|---|
| Ingestion | internal/collector/ | Wazuh, Sysmon, File |
| Domain Models | pkg/models/ | Event, Evidence, Entity, Hypothesis |
| Detection | internal/detection/ | Sigma-like + LOLBin |
| Graph | internal/graph/ | Extractor, Builder, Resolver |
| Evidence | internal/evidence/ | Event to Evidence |
| Correlation | internal/correlation/ | Timeline, ProcessTree |
| Investigation | internal/investigation/ | Risk, Hypothesis, Orchestrator |
| Threat Intel | internal/threat_intel/ | VT, OTX, MISP |
| AI | internal/ai/ | Rule engine, Multi-agent, LLM |

## Prinsip

1. Deterministic first.
2. Evidence-grounded.
3. Content-hashed.
4. Deterministic output.
