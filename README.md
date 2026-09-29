# AegisSOC

**Evidence-Grounded AI Investigation & Correlation Engine**

AegisSOC mengubah raw security events menjadi investigation case
yang terstruktur: evidence, correlation, hypothesis, risk score,
dan narrative analis.

## Kenapa AegisSOC

- Setiap klaim didasarkan pada evidence - tidak ada finding tanpa bukti.
- Hipotesis punya counter - bukan hanya cari yang mendukung.
- Risk score bisa dijelaskan - setiap kenaikan punya faktor eksplisit.
- LLM opsional - rule engine selalu tersedia, offline, gratis.

## Fitur

| Kategori | Fitur |
|---|---|
| Ingestion | Wazuh alert, Sysmon event, file/NDJSON |
| Detection | Sigma-like rules, LOLBin registry |
| Graph | Entity extraction, relationship builder |
| Correlation | Pair correlation, cluster correlation, timeline |
| Evidence | Content hash, provenance, verification |
| Hypothesis | MAIN, COUNTER, SUB |
| Risk | Multi-factor scoring, breakdown |
| Threat Intel | VirusTotal, OTX, MISP (opsional) |
| AI | Rule engine, multi-agent, Ollama, cloud LLM |
| Interface | CLI, Streamlit dashboard, REST API |
| Feedback | Analyst verdict tracking |
| Deployment | Docker, docker-compose |

## Quick Start

Python:

    pip install -r requirements.txt
    python -m cli investigate --events examples/application_shimming.json --title 'Application Shimming' --format markdown --ai

Docker:

    cd deploy
    docker compose build
    docker compose run --rm aegis investigate --events /data/application_shimming.json --title 'Application Shimming' --format text

Dashboard:

    pip install -r requirements-dashboard.txt
    streamlit run internal/dashboard/app.py

API:

    pip install -r requirements-api.txt
    uvicorn api.main:app --reload

## Test

    pytest -q

## Struktur

    aegis-soc/
    ├── pkg/models/         # domain models
    ├── internal/           # engine modules
    ├── cli/                # command-line
    ├── api/                # FastAPI
    ├── deploy/             # Docker
    └── tests/              # test suite

## Lisensi

MIT
