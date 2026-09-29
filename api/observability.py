"""
FastAPI observability middleware.

- Structured request logging
- Metrics (Prometheus /metrics endpoint)
- Trace propagation (X-Trace-Id header)
"""

from __future__ import annotations

import time
from typing import Callable

from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse

from internal.observability import (
    get_logger,
    get_registry,
    new_trace,
)


logger = get_logger("aegis.api")


def instrument_fastapi(app: FastAPI) -> None:
    """
    Pasang middleware + /metrics endpoint.
    """
    registry = get_registry()

    requests_total = registry.counter(
        "aegis_http_requests_total",
        help="Total HTTP requests",
    )
    request_duration = registry.histogram(
        "aegis_http_request_duration_seconds",
        help="Request duration in seconds",
    )
    errors_total = registry.counter(
        "aegis_http_errors_total",
        help="Total HTTP error responses (status >= 400)",
    )

    def _path_counter(path: str):
        """Counter per-path, di-cache oleh registry."""
        return registry.counter(
            "aegis_http_requests_by_path_total",
            help="Requests per path",
            labels={"path": path},
        )

    @app.middleware("http")
    async def observability_middleware(
        request: Request,
        call_next: Callable,
    ) -> Response:
        # Extract or generate trace id
        trace_id = request.headers.get("X-Trace-Id")
        ctx = new_trace(trace_id=trace_id)

        start = time.perf_counter()

        try:
            response = await call_next(request)
        except Exception:
            errors_total.inc()
            requests_total.inc()
            _path_counter(request.url.path).inc()
            duration = time.perf_counter() - start
            request_duration.observe(duration)
            logger.exception(
                "request failed",
                extra={
                    "method": request.method,
                    "path": request.url.path,
                    "trace_id": ctx.trace_id,
                    "duration_s": duration,
                },
            )
            raise

        duration = time.perf_counter() - start

        requests_total.inc()
        _path_counter(request.url.path).inc()
        request_duration.observe(duration)

        if response.status_code >= 400:
            errors_total.inc()

        response.headers["X-Trace-Id"] = ctx.trace_id

        logger.info(
            "request",
            extra={
                "method": request.method,
                "path": request.url.path,
                "status": response.status_code,
                "duration_s": round(duration, 4),
                "trace_id": ctx.trace_id,
            },
        )

        return response

    @app.get("/metrics", include_in_schema=False)
    async def metrics_endpoint() -> Response:
        body = get_registry().render()
        return PlainTextResponse(
            content=body,
            media_type="text/plain; version=0.0.4",
        )


__all__ = ["instrument_fastapi"]
