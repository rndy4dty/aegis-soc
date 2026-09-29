"""
MISP provider (stub).

Konfigurasi via environment:
- MISP_URL
- MISP_API_KEY
- MISP_TIMEOUT (opsional, default 15)

Stub: is_available() False kalau config kurang.
Lookup di-delegate ke http_post (bisa di-inject untuk test).
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from typing import Any, Callable

from internal.threat_intel.base import (
    Indicator,
    IndicatorType,
    IntelResult,
)


DEFAULT_TIMEOUT = 15

HttpPost = Callable[
    [str, dict[str, str], dict[str, Any], int],
    dict[str, Any],
]


def _default_http_post(
    url: str,
    headers: dict[str, str],
    payload: dict[str, Any],
    timeout: int,
) -> dict[str, Any]:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            **headers,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(
            f"MISP HTTP {exc.code}: {exc.reason} — {body[:200]}"
        ) from exc
    except (urllib.error.URLError, socket.timeout) as exc:
        raise RuntimeError(f"MISP unreachable: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"MISP invalid JSON: {exc}") from exc


class MISPProvider:
    """MISP provider (via REST search endpoint)."""

    def __init__(
        self,
        *,
        url: str | None = None,
        api_key: str | None = None,
        timeout: int | None = None,
        http_post: HttpPost | None = None,
    ) -> None:
        if url is not None:
            self._url = url.rstrip("/")
        else:
            self._url = (
                os.environ.get("MISP_URL") or ""
            ).rstrip("/")

        if api_key is not None:
            self._api_key = api_key
        else:
            self._api_key = os.environ.get("MISP_API_KEY") or ""

        if timeout is not None:
            self._timeout = timeout
        else:
            self._timeout = int(
                os.environ.get("MISP_TIMEOUT") or DEFAULT_TIMEOUT
            )

        self._http_post = http_post or _default_http_post

    def name(self) -> str:
        return "misp"

    def is_available(self) -> bool:
        return bool(self._url) and bool(self._api_key)

    def lookup(self, indicator: Indicator) -> IntelResult:
        if not self.is_available():
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error="misp not configured (missing URL or API key)",
            )

        endpoint = f"{self._url}/attributes/restSearch"

        try:
            data = self._http_post(
                endpoint,
                {
                    "Authorization": self._api_key,
                    "Accept": "application/json",
                },
                {
                    "value": indicator.value,
                    "type": self._misp_type(indicator),
                    "limit": 10,
                },
                self._timeout,
            )
        except RuntimeError as exc:
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error=str(exc),
            )

        return self._parse(data, indicator)

    # ------------------------------------------------------------------

    @staticmethod
    def _misp_type(indicator: Indicator) -> str:
        mapping = {
            IndicatorType.HASH: "sha256",
            IndicatorType.IP: "ip-dst",
            IndicatorType.DOMAIN: "domain",
            IndicatorType.URL: "url",
        }
        return mapping.get(indicator.type, "text")

    @staticmethod
    def _parse(
        data: dict[str, Any],
        indicator: Indicator,
    ) -> IntelResult:
        attrs = (
            data.get("response", {})
            .get("Attribute", [])
        )
        if not isinstance(attrs, list):
            attrs = []

        found = len(attrs) > 0
        tags: list[str] = []
        for a in attrs:
            for t in (a.get("Tag") or []):
                if isinstance(t, dict) and t.get("name"):
                    tags.append(str(t["name"]))

        return IntelResult(
            indicator=indicator,
            provider="misp",
            found=found,
            malicious_count=len(attrs),
            total_count=len(attrs),
            tags=sorted(set(tags)),
            raw=data,
        )


__all__ = ["MISPProvider"]
