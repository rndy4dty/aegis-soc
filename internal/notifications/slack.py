"""
Slack notifier via webhook.

Config via env:
- AEGIS_SLACK_WEBHOOK_URL  (wajib)
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


class SlackNotifier:
    """Kirim notifikasi ke Slack via incoming webhook."""

    def __init__(
        self,
        *,
        webhook_url: str | None = None,
        timeout: int = 10,
    ) -> None:
        if webhook_url is not None:
            self._webhook_url = webhook_url
        else:
            self._webhook_url = (
                os.environ.get("AEGIS_SLACK_WEBHOOK_URL") or ""
            )
        self._timeout = timeout

    def name(self) -> str:
        return "slack"

    def is_available(self) -> bool:
        return bool(self._webhook_url)

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
                error="slack not configured (missing webhook URL)",
            )

        payload = format_investigation(result, level=level)
        text = render_text(payload, message=message)

        body = {
            "text": text,
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": text,
                    },
                },
            ],
        }

        try:
            req = urllib.request.Request(
                self._webhook_url,
                data=json.dumps(body).encode("utf-8"),
                headers={"Content-Type": "application/json"},
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


__all__ = ["SlackNotifier"]
