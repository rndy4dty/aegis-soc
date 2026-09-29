"""
Generic webhook notifier.

Config via env:
- AEGIS_WEBHOOK_URL (wajib)
- AEGIS_WEBHOOK_TOKEN (opsional, header Authorization)
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.notifications.base import (
    NotificationLevel,
    NotificationResult,
    format_investigation,
    render_text,
)


class WebhookNotifier:
    """POST JSON payload ke URL generik."""

    def __init__(
        self,
        *,
        url: str | None = None,
        token: str | None = None,
        timeout: int = 10,
    ) -> None:
        if url is not None:
            self._url = url
        else:
            self._url = os.environ.get("AEGIS_WEBHOOK_URL") or ""
        if token is not None:
            self._token = token
        else:
            self._token = (
                os.environ.get("AEGIS_WEBHOOK_TOKEN") or ""
            )
        self._timeout = timeout

    def name(self) -> str:
        return "webhook"

    def is_available(self) -> bool:
        return bool(self._url)

    def send(
        self,
        result: InvestigationResult,
        *,
        level: NotificationLevel,
        message: str | None = None,
    ) -> NotificationResult:
        if not self.is_available():
            return NotificationResult(
                channel=self.name(),
                success=False,
                level=level,
                error="webhook not configured",
            )

        payload = format_investigation(result, level=level)
        payload["text"] = render_text(payload, message=message)

        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"

        try:
            req = urllib.request.Request(
                self._url,
                data=json.dumps(payload).encode("utf-8"),
                headers=headers,
                method="POST",
            )
            with urllib.request.urlopen(
                req, timeout=self._timeout
            ) as resp:
                if resp.status >= 400:
                    return NotificationResult(
                        channel=self.name(),
                        success=False,
                        level=level,
                        error=f"HTTP {resp.status}",
                    )
        except (
            urllib.error.URLError,
            socket.timeout,
            OSError,
        ) as exc:
            return NotificationResult(
                channel=self.name(),
                success=False,
                level=level,
                error=str(exc),
            )

        return NotificationResult(
            channel=self.name(),
            success=True,
            level=level,
        )


__all__ = ["WebhookNotifier"]
