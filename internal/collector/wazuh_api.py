"""
Wazuh REST API client.

Config via env:
- AEGIS_WAZUH_API_URL       (default: https://localhost:55000)
- AEGIS_WAZUH_USER          (default: wazuh)
- AEGIS_WAZUH_PASSWORD      (wajib)
- AEGIS_WAZUH_VERIFY_SSL    (default: false)
- AEGIS_WAZUH_TIMEOUT       (default: 15 detik)

API:
- POST /security/user/authenticate  -> JWT token
- GET  /alerts                      -> list alerts
"""

from __future__ import annotations

import base64
import json
import os
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


DEFAULT_URL = "https://localhost:55000"
DEFAULT_USER = "wazuh"
DEFAULT_TIMEOUT = 15


@dataclass
class WazuhAlert:
    """Satu alert dari Wazuh API."""
    alert_id: str
    timestamp: datetime
    raw: dict[str, Any]


class WazuhAPIClient:
    """Client untuk Wazuh REST API."""

    def __init__(
        self,
        *,
        url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        verify_ssl: bool | None = None,
        timeout: int | None = None,
    ) -> None:
        self._url = (
            url
            or os.environ.get("AEGIS_WAZUH_API_URL")
            or DEFAULT_URL
        ).rstrip("/")
        self._user = (
            user
            or os.environ.get("AEGIS_WAZUH_USER")
            or DEFAULT_USER
        )
        self._password = (
            password
            or os.environ.get("AEGIS_WAZUH_PASSWORD")
            or ""
        )
        if verify_ssl is not None:
            self._verify_ssl = verify_ssl
        else:
            self._verify_ssl = (
                os.environ.get("AEGIS_WAZUH_VERIFY_SSL", "false").lower()
                in ("1", "true", "yes", "on")
            )
        self._timeout = int(
            timeout
            or os.environ.get("AEGIS_WAZUH_TIMEOUT")
            or DEFAULT_TIMEOUT
        )
        self._token: str | None = None

        if self._verify_ssl:
            self._ssl_context = ssl.create_default_context()
        else:
            self._ssl_context = ssl._create_unverified_context()  # noqa: SLF001

    @property
    def url(self) -> str:
        return self._url

    @property
    def is_configured(self) -> bool:
        return bool(self._password)

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def login(self) -> str:
        if not self.is_configured:
            raise RuntimeError(
                "wazuh API not configured (missing password)"
            )

        endpoint = f"{self._url}/security/user/authenticate"
        creds = base64.b64encode(
            f"{self._user}:{self._password}".encode("utf-8")
        ).decode("ascii")

        try:
            req = urllib.request.Request(
                endpoint,
                headers={
                    "Authorization": f"Basic {creds}",
                    "Content-Type": "application/json",
                },
                method="POST",
            )
            with urllib.request.urlopen(
                req,
                timeout=self._timeout,
                context=self._ssl_context,
            ) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"wazuh login failed: HTTP {exc.code} {exc.reason}"
            ) from exc
        except (urllib.error.URLError, socket.timeout) as exc:
            raise RuntimeError(
                f"wazuh login unreachable: {exc}"
            ) from exc

        token = body.get("data", {}).get("token")
        if not token:
            raise RuntimeError(
                f"wazuh login returned no token: {body}"
            )
        self._token = str(token)
        return self._token

    def _ensure_token(self) -> str:
        if self._token is None:
            self.login()
        assert self._token is not None
        return self._token

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def get_alerts(
        self,
        *,
        limit: int = 100,
        since: datetime | None = None,
        offset: int = 0,
        sort: str = "-timestamp",
    ) -> list[WazuhAlert]:
        token = self._ensure_token()

        params: dict[str, str] = {
            "limit": str(limit),
            "offset": str(offset),
            "sort": sort,
        }
        if since is not None:
            params["search"] = since.strftime("%Y-%m-%dT%H:%M:%S")

        query = urllib.parse.urlencode(params)
        endpoint = f"{self._url}/alerts?{query}"

        try:
            req = urllib.request.Request(
                endpoint,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                },
                method="GET",
            )
            with urllib.request.urlopen(
                req,
                timeout=self._timeout,
                context=self._ssl_context,
            ) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 401:
                self._token = None
                return self.get_alerts(
                    limit=limit, since=since, offset=offset, sort=sort
                )
            raise RuntimeError(
                f"wazuh get_alerts failed: HTTP {exc.code} {exc.reason}"
            ) from exc
        except (urllib.error.URLError, socket.timeout) as exc:
            raise RuntimeError(
                f"wazuh get_alerts unreachable: {exc}"
            ) from exc

        return self._parse_alerts(body)

    @staticmethod
    def _parse_alerts(body: dict[str, Any]) -> list[WazuhAlert]:
        items = body.get("data", {}).get("affected_items", [])
        if not isinstance(items, list):
            return []

        out: list[WazuhAlert] = []
        for item in items:
            if not isinstance(item, dict):
                continue
            alert_id = str(item.get("id") or "")
            ts = _parse_wazuh_ts(item.get("timestamp"))
            out.append(
                WazuhAlert(
                    alert_id=alert_id,
                    timestamp=ts,
                    raw=item,
                )
            )
        return out


def _parse_wazuh_ts(value: Any) -> datetime:
    if isinstance(value, str):
        for cand in (
            value,
            value.replace("+0000", "+00:00"),
            value.replace("Z", "+00:00"),
        ):
            try:
                dt = datetime.fromisoformat(cand)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue
    return datetime.now(timezone.utc)


__all__ = [
    "WazuhAPIClient",
    "WazuhAlert",
    "DEFAULT_URL",
    "DEFAULT_USER",
]
