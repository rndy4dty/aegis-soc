

"""
AegisSOC FastAPI app.

Jalankan:
    uvicorn api.main:app --reload
    # atau
    python -m api.main

Env:
- AEGIS_API_KEY : opsional, kalau diset maka header X-API-Key wajib.
"""

from __future__ import annotations

import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from api.routers import auth as auth_router
from api import __version__
from api.deps import get_settings
from api.routers import (
    health,
    investigation,
    meta,
)


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.app_name,
        version=settings.version,
        description=(
            "Evidence-Grounded AI Investigation & Correlation Engine"
        ),
    )

    # CORS: dev-friendly, aktifkan semua origin. Produksi: ganti.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Observability ------------------------------------------------
    from api.observability import instrument_fastapi
    instrument_fastapi(app)

    app.include_router(health.router)
    app.include_router(auth_router.router)
    app.include_router(investigation.router)
    app.include_router(meta.router)
    return app

app = create_app()


def main() -> None:
    import uvicorn

    port = int(os.environ.get("AEGIS_API_PORT", "8000"))
    uvicorn.run(
        "api.main:app",
        host="0.0.0.0",
        port=port,
        reload=False,
    )


if __name__ == "__main__":
    main()


__all__ = ["app", "create_app", "main", "version"]
