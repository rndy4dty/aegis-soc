"""
Email notifier via SMTP.

Config via env:
- AEGIS_SMTP_HOST      (wajib)
- AEGIS_SMTP_PORT      (default 587)
- AEGIS_SMTP_USER      (opsional)
- AEGIS_SMTP_PASSWORD  (opsional)
- AEGIS_SMTP_USE_TLS   (default true)
- AEGIS_EMAIL_FROM     (wajib)
- AEGIS_EMAIL_TO       (koma-separated, wajib)
"""

from __future__ import annotations

import os
import smtplib
from email.message import EmailMessage

from internal.investigation.investigation_engine import (
    InvestigationResult,
)
from internal.notifications.base import (
    NotificationLevel,
    NotificationResult,
    format_investigation,
    render_text,
)


class EmailNotifier:
    """Kirim notifikasi via SMTP."""

    def __init__(
        self,
        *,
        host: str | None = None,
        port: int | None = None,
        user: str | None = None,
        password: str | None = None,
        use_tls: bool | None = None,
        sender: str | None = None,
        recipients: list[str] | None = None,
    ) -> None:
        self._host = host or os.environ.get("AEGIS_SMTP_HOST") or ""
        self._port = int(
            port
            or os.environ.get("AEGIS_SMTP_PORT")
            or 587
        )
        self._user = (
            user or os.environ.get("AEGIS_SMTP_USER") or ""
        )
        self._password = (
            password
            or os.environ.get("AEGIS_SMTP_PASSWORD")
            or ""
        )
        if use_tls is not None:
            self._use_tls = use_tls
        else:
            self._use_tls = (
                os.environ.get("AEGIS_SMTP_USE_TLS", "true").lower()
                in ("1", "true", "yes", "on")
            )
        self._sender = (
            sender or os.environ.get("AEGIS_EMAIL_FROM") or ""
        )
        if recipients is not None:
            self._recipients = list(recipients)
        else:
            raw = os.environ.get("AEGIS_EMAIL_TO") or ""
            self._recipients = [
                r.strip() for r in raw.split(",") if r.strip()
            ]

    def name(self) -> str:
        return "email"

    def is_available(self) -> bool:
        return bool(
            self._host
            and self._sender
            and self._recipients
        )

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
                error="email not configured",
            )

        payload = format_investigation(result, level=level)
        body = render_text(payload, message=message)

        subject = (
            f"[{payload['level'].upper()}] "
            f"{payload['title']} "
            f"(risk {payload['risk_score']}/100)"
        )

        msg = EmailMessage()
        msg["From"] = self._sender
        msg["To"] = ", ".join(self._recipients)
        msg["Subject"] = subject
        msg.set_content(body)

        try:
            with smtplib.SMTP(
                self._host, self._port, timeout=10
            ) as smtp:
                if self._use_tls:
                    smtp.starttls()
                if self._user and self._password:
                    smtp.login(self._user, self._password)
                smtp.send_message(msg)
        except Exception as exc:  # noqa: BLE001
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


__all__ = ["EmailNotifier"]
