# AegisSOC

**Deterministic Investigation Engine + AI Enhancement Opsional**

AegisSOC mengubah raw security events menjadi investigation case
yang terstruktur: evidence, correlation, hypothesis, risk score,
dan narrative analis.

Filosofi utama: **deterministic engine sebagai primary, AI sebagai
enhancement opsional**. Sistem tetap berfungsi 100% tanpa AI.

![AegisSOC Dashboard](docs/images/aegis.png)

---

## Apa AegisSOC Itu

Investigation engine untuk SOC analyst. Menerima security events
dan menghasilkan investigation case yang bisa diaudit.

Setiap klaim di dalam report **didasarkan pada evidence eksplisit**.
Tidak ada finding tanpa bukti pendukung.

---

## Apa AegisSOC BUKAN

Supaya tidak salah paham:

- **BUKAN AI SOC** yang mengandalkan LLM sebagai satu-satunya otak.
- **BUKAN machine learning** untuk deteksi. Detection-nya rule-based.
- **BUKAN autonomous responder.** Hanya investigasi, tidak aksi otomatis.
- **TIDAK membutuhkan API key** atau internet untuk berfungsi penuh.
  AI sepenuhnya opsional.

---

## Arsitektur: Deterministic vs AI

### Layer Deterministic (selalu aktif, tanpa AI)

| Komponen | Fungsi |
|---|---|
| Correlation Engine | Rule-based matching (same host, temporal) |
| Detection Engine | Sigma-like rules + LOLBin registry |
| Hypothesis Engine | Template-based (MITRE ke hypothesis) |
| Risk Engine | Formula matematis |
| Reporter | Template rendering (markdown/JSON/text) |
| Rule Engine Provider | Template-based narrative |

Semua **reproducible** dan **auditable**. Input sama = output sama.

### Layer AI (opsional, hanya aktif kalau diminta)

| Komponen | Jenis | Kapan Aktif |
|---|---|---|
| Ollama Provider | LLM local | `--ai --provider ollama` |
| Cloud LLM | LLM (OpenAI-compatible) | `--ai --provider cloud` |
| Multi-Agent | Agentic pattern | `--ai --provider multi_agent` |

Kalau AI tidak tersedia:

- API key tidak ada: provider di-skip otomatis
- Ollama tidak jalan: fallback ke provider berikutnya
- Semua LLM gagal: fallback ke rule engine

Sistem **tidak pernah crash** karena AI tidak tersedia.

---

## Fitur

| Kategori | Fitur | AI? |
|---|---|---|
| Ingestion | Wazuh alert, Sysmon event, file/NDJSON | - |
| Detection | Sigma-like rules, LOLBin registry | - |
| Graph | Entity extraction, relationship builder | - |
| Correlation | Pair, cluster, timeline | - |
| Evidence | SHA-256 content hash, provenance | - |
| Hypothesis | MAIN, COUNTER, SUB | - |
| Risk | Multi-factor scoring, breakdown | - |
| Threat Intel | VirusTotal, OTX, MISP | - |
| Narrative | Rule engine (deterministic) | - |
| Narrative | Multi-agent orchestrator | Agentic |
| Narrative | Ollama / Cloud LLM | LLM |
| Feedback | Analyst verdict tracking | - |
| Simulation | 4 attack scenarios | - |
| Interface | CLI, Streamlit, REST API | - |
| Deploy | Docker, K8s, Helm | - |
| Observability | Logging, metrics, tracing | - |

---

## Quick Start

### Install

```bash
git clone https://github.com/rndy4dty/aegis-soc.git
cd aegis-soc
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Tanpa AI

```bash
python -m cli investigate --events examples/application_shimming.json --title 'App Shim' --format markdown
```

### Dengan AI

```bash
python -m cli investigate --events examples/application_shimming.json --title 'App Shim' --format markdown --ai --provider multi_agent
```

### Dashboard

```bash
pip install -r requirements-dashboard.txt
streamlit run internal/dashboard/app.py
```

---

## Screenshots

### Dashboard Streamlit

Streamlit UI untuk visual investigation: metrics cards, attack
timeline, hypotheses, risk breakdown, AI narrative, dan export.

![AegisSOC Dashboard](docs/images/aegis.png)

### Dashboard — Investigation Result

Hasil setelah menjalankan investigation: metrics cards (risk score,
confidence, priority, status), attack timeline, dan risk breakdown.

![AegisSOC Dashboard Result](docs/images/dashboard-result.png)


---

## Test

```bash
pytest -q
```

**Status:** 905 tests passing.

---

## Prinsip Desain

1. **Deterministic first.** Core engine reproducible. AI hanya enhancement.
2. **Evidence-grounded.** Setiap finding punya evidence eksplisit.
3. **Auditable.** Semua angka bisa dijelaskan.
4. **AI opsional.** Sistem tetap 100% fungsional tanpa LLM.
5. **Fallback chain.** Cloud LLM, Local LLM, Multi-Agent, Rule Engine.
6. **Immutable by convention.** Model tidak dimutasi setelah dibuat.

---

## Lisensi

MIT
