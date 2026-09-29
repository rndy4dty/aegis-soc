"""
Structured logging (JSON).

Format:
    {"ts": "...", "level": "INFO", "logger": "aegis.api",
     "msg": "...", "trace_id": "...", "extra": {...}}
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any


class JSONFormatter(logging.Formatter):
    """
    Formatter yang menghasilkan JSON satu baris per log record.
    """

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }

        # Trace context (kalau ada)
        try:
            from internal.observability.tracing import (
                get_current_trace,
            )
            trace = get_current_trace()
            if trace is not None:
                payload["trace_id"] = trace.trace_id
                if trace.span_id:
                    payload["span_id"] = trace.span_id
        except ImportError:
            pass

        # Extra fields
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in record.__dict__.items():
            if key.startswith("_") or key in (
                "name", "msg", "args", "levelname", "levelno",
                "pathname", "filename", "module", "exc_info",
                "exc_text", "stack_info", "lineno", "funcName",
                "created", "msecs", "relativeCreated", "thread",
                "threadName", "processName", "process", "message",
                "asctime",
            ):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)

        return json.dumps(payload, default=str, ensure_ascii=False)


def setup_logging(
    *,
    level: str = "INFO",
    use_json: bool = True,
) -> None:
    """
    Setup root logger.

    - use_json=True  → JSON formatter (production)
    - use_json=False → plain text (development)
    """
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(level.upper())

    handler = logging.StreamHandler(sys.stdout)
    if use_json:
        handler.setFormatter(JSONFormatter())
    else:
        handler.setFormatter(logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
        ))

    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    """Ambil logger dengan nama."""
    return logging.getLogger(name)


__all__ = ["JSONFormatter", "setup_logging", "get_logger"]
