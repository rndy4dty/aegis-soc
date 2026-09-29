# AegisSOC

**Deterministic SOC Investigation Engine with Optional AI Enhancement**

AegisSOC transforms raw security events into structured, evidence-based
investigation cases containing evidence, correlations, hypotheses, risk
scoring, and analyst-oriented narratives.

The core philosophy is **deterministic-first**: the investigation engine
does not depend on AI or external LLM services. AI is an optional
enhancement layer that can assist with investigation narratives and
analysis. The system remains fully functional when AI providers are
unavailable.

![AegisSOC Dashboard](docs/images/aegis.png)

---

## What is AegisSOC?

AegisSOC is an investigation engine designed for SOC workflows. It
processes security events and produces structured investigation cases
that can be reviewed, reproduced, and audited.

Every finding in the investigation is grounded in explicit evidence.
The system does not generate findings without supporting evidence.

**Pipeline:**
Raw events (Wazuh, Sysmon, file)
|
v
Canonical Event
|
+--> Evidence (content-hashed)
+--> Entity + Relationship (graph)
|
v
Correlation Engine
|
v
Hypothesis Engine (MAIN + COUNTER + SUB)
|
v
Risk Engine (0-100 with breakdown)
|
v
Investigation Case
|
+--> Deterministic Report (always available)
|
+--> Optional AI Enhancement (if configured)

text

Note: AI sits **alongside** the investigation pipeline, not inside it.
The deterministic report is generated independently and remains the
source of truth.

---

## What AegisSOC is NOT

To clarify its scope:

- **Not an AI-first SOC** that relies on an LLM as its primary
  investigation engine.
- **Not a machine-learning detection system.** Detection is currently
  rule-based (Sigma-like rules, LOLBin registry).
- **Not an autonomous response system.** AegisSOC investigates and
  analyzes; it does not automatically execute response actions.
- **Not dependent on external AI services.** AI is optional; the
  deterministic pipeline works without API keys or internet access.

---

## Architecture: Deterministic vs AI Layers

### Deterministic Layer (always active)

The investigation engine itself is fully deterministic. Given the same
input, it produces the same output.

| Component | Function |
|---|---|
| Correlation Engine | Rule-based matching (same host, temporal proximity) |
| Detection Engine | Sigma-like rules + LOLBin registry |
| Hypothesis Engine | Template-based hypothesis generation |
| Risk Engine | Explicit mathematical scoring model |
| Reporter | Template-based rendering (markdown / JSON / text) |
| Deterministic Rule Engine | Template-based narrative generation |

All components above are **reproducible** and **auditable**.

### Optional AI Layer

AI providers are opt-in. They add a narrative layer on top of the
deterministic report.

| Component | Type | Activation |
|---|---|---|
| Ollama Provider | Local LLM | `--ai --provider ollama` |
| Cloud LLM Provider | LLM (OpenAI-compatible) | `--ai --provider cloud` |
| Multi-Agent Orchestrator | Orchestration pattern | `--ai --provider multi_agent` |

Note: the multi-agent orchestrator is an **orchestration pattern**, not
a model provider. It coordinates agents (hypothesis, counter, critic,
report) and can use LLM providers underneath.

### Graceful Degradation

AI failures are isolated from the deterministic investigation pipeline:

- Missing API key: the AI provider is skipped.
- Ollama not running: fallback to the next configured provider.
- All AI providers unavailable: the system falls back to the
  deterministic rule engine for narrative.

The investigation itself (evidence, correlation, hypotheses, risk score)
is never dependent on AI availability.

### When AI is Actually Used

AI is only invoked when **all** of the following are true:

1. The user explicitly requests it (`--ai --provider ...`).
2. A provider is available (Ollama running, or API key configured).
3. A request originates from the user (CLI, API call, or dashboard).

Otherwise, the system runs entirely deterministic.

---

## Features

| Category | Feature | AI? |
|---|---|---|
| Ingestion | Wazuh alert, Sysmon event, file/NDJSON | - |
| Detection | Sigma-like rules, LOLBin registry | - |
| Graph | Entity extraction, relationship builder | - |
| Correlation | Pair, cluster, timeline | - |
| Evidence | SHA-256 content hash, provenance | - |
| Hypothesis | MAIN, COUNTER, SUB | - |
| Risk | Multi-factor scoring with breakdown | - |
| Threat Intel | VirusTotal, AlienVault OTX, MISP adapters | - |
| Narrative | Deterministic rule engine | - |
| Narrative | Multi-agent orchestrator | Orchestration |
| Narrative | Ollama / Cloud LLM | LLM |
| Feedback | Analyst verdict tracking | - |
| Simulation | 4 built-in attack scenarios | - |
| Interface | CLI, Streamlit dashboard, REST API | - |
| Deployment | Docker, Kubernetes, Helm | - |
| Observability | Logging, Prometheus metrics, tracing | - |

Notes:

- **Threat Intel**: the three providers are implemented as adapters.
  Live usage requires configured API keys or endpoints.
- **AI?** column: blank = deterministic, `Orchestration` = agentic
  pattern without an LLM underneath, `LLM` = invokes a language model.

---

## Quick Start

### Install
git clone https://github.com/rndy4dty/aegis-soc.git
cd aegis-soc
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

text

### Run Investigation Without AI
python -m cli investigate
--events examples/application_shimming.json
--title "Application Shimming"
--format markdown

text

No LLM is invoked. The output is fully deterministic.

### Run Investigation With AI Enhancement
Multi-agent orchestration (deterministic agents, no LLM)
python -m cli investigate
--events examples/application_shimming.json
--title "Application Shimming"
--format markdown --ai --provider multi_agent

Ollama (local LLM)
ollama serve # separate terminal
python -m cli investigate
--events examples/application_shimming.json
--title "Application Shimming"
--format markdown --ai --provider ollama

Cloud LLM (requires API key)
export AEGIS_CLOUD_LLM_API_KEY="sk-..."
python -m cli investigate
--events examples/application_shimming.json
--title "Application Shimming"
--format markdown --ai --provider cloud

text

### Attack Simulation
python -m cli scenario list
python -m cli scenario run shimming --format text
python -m cli scenario run powershell_cradle --format markdown
python -m cli scenario run credential_dump --format text
python -m cli scenario run lateral_movement --format json

text

### Docker
cd deploy
docker compose build
docker compose run --rm aegis investigate
--events /data/application_shimming.json
--title "Application Shimming" --format text

text

### Dashboard
pip install -r requirements-dashboard.txt
streamlit run internal/dashboard/app.py

text

Open http://localhost:8501.

### REST API
pip install -r requirements-api.txt
uvicorn api.main:app --reload

text

Open http://localhost:8000/docs for the Swagger UI.

---

## Example Output

### Deterministic (no AI)
Risk Score : 45/100
Confidence : 0.54
Priority : CRITICAL
Status : triaged

Breakdown:
evidence +40.0
correlation +3.3
hypothesis +13.8
penalty -12.0

Hypotheses:
[MAIN] Possible persistence via Application Shimming
(supported, confidence 0.55)
[COUNTER] Legitimate Windows compatibility activity
[SUB] Correlated event cluster indicates single activity

Recommended Actions:

Inspect sdbinst.exe command line and parent process

Review Shim Database modifications

Collect missing evidence: initiating parent lineage

text

### With AI Narrative (via LLM)
AI Narrative
Investigasi 'Application Shimming' menganalisis 2 event dari host
terkait. Sistem mengekstrak 2 evidence dan menemukan 1 korelasi
antar-event dengan confidence 0.66...

[narrative generated by the LLM]

Investigation Report: Application Shimming
[deterministic report as above]

text

---

## Screenshots

### Dashboard - Initial View

Streamlit UI for visual investigation: input form and case metadata.

![AegisSOC Dashboard](docs/images/aegis.png)

### Dashboard - Investigation Result

After running an investigation: metrics cards (risk score, confidence,
priority, status), attack timeline, and risk breakdown chart.

![AegisSOC Dashboard Result](docs/images/dashboard-result.png)

---

## Test
pytest -q

text

Run this command to see the current test count in your checkout.

Coverage:

- Unit tests for all models, engines, and providers
- Integration tests for the end-to-end pipeline
- API tests for all endpoints
- Deterministic (no flaky tests)

---

## Project Structure
aegis-soc/
├── pkg/models/ # domain models (Pydantic)
├── internal/
│ ├── collector/ # Wazuh, Sysmon, file source
│ ├── detection/ # Sigma-like rules, LOLBin
│ ├── correlation/ # timeline, process tree
│ ├── graph/ # entity extractor, resolver, builder
│ ├── evidence/ # event -> evidence
│ ├── investigation/ # risk, hypothesis, orchestrator
│ ├── threat_intel/ # VT, OTX, MISP adapters
│ ├── ai/ # rule engine, multi-agent, LLM adapters
│ ├── feedback/ # analyst verdict tracking
│ ├── simulation/ # attack scenarios
│ ├── observability/ # logging, metrics, tracing
│ ├── reporter/ # markdown, JSON, text
│ └── dashboard/ # Streamlit UI
├── cli/ # command-line interface
├── api/ # FastAPI REST endpoints
├── deploy/ # Docker, K8s, Helm
├── docs/ # documentation + screenshots
└── tests/ # test suite

text

---

## Design Principles

1. **Deterministic first.** The core engine is reproducible and
   independent of AI availability.
2. **Evidence-grounded.** Every finding is backed by explicit evidence
   with a SHA-256 content hash.
3. **Auditable.** Every risk score has explicit contributing factors.
4. **AI optional.** The system is fully functional without an LLM.
5. **Graceful degradation.** AI failures are isolated from the
   deterministic investigation pipeline.
6. **Immutable by convention.** Investigation models are treated as
   immutable after creation.

---

## Documentation

- [Architecture](docs/architecture.md) - pipeline and layers
- [Data Model](docs/data_model.md) - schema reference
- [Demo](docs/demo.md) - walkthrough with sample output
- [Design Decisions](docs/design.md) - principles and trade-offs

---

## License

MIT
