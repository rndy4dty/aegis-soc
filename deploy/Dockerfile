# syntax=docker/dockerfile:1.6
# ============================================================================
# AegisSOC - Investigation Engine
# ============================================================================

FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt /build/requirements.txt
RUN pip install --upgrade pip && pip install -r requirements.txt

# ---------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app \
    PATH="/opt/venv/bin:$PATH"

RUN useradd --create-home --shell /bin/bash aegis

WORKDIR /app

COPY --from=builder /opt/venv /opt/venv

COPY --chown=aegis:aegis pkg/ /app/pkg/
COPY --chown=aegis:aegis internal/ /app/internal/
COPY --chown=aegis:aegis cli/ /app/cli/
COPY --chown=aegis:aegis examples/ /app/examples/

USER aegis

ENTRYPOINT ["python", "-m", "cli"]
CMD ["--help"]
