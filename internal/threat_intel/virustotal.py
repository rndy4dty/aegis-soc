"""
VirusTotal provider.

Konfigurasi via environment:
- VIRUSTOTAL_API_KEY (wajib untuk live lookup)
- VIRUSTOTAL_TIMEOUT (opsional, default 15)

Kalau API key tidak diset → is_available() == False.
Untuk testing, bisa inject `http_get` callable untuk mocking.
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


DEFAULT_BASE_URL = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT = 15

HttpGet = Callable[[str, dict[str, str], int], dict[str, Any]]


def _default_http_get(
    url: str,
    headers: dict[str, str],
    timeout: int,
) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"__not_found__": True}
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(
            f"VT HTTP {exc.code}: {exc.reason} — {body[:200]}"
        ) from exc
    except (urllib.error.URLError, socket.timeout) as exc:
        raise RuntimeError(f"VT unreachable: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"VT invalid JSON: {exc}") from exc


class VirusTotalProvider:
    """
    VirusTotal v3 API.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int | None = None,
        http_get: HttpGet | None = None,
    ) -> None:
        if api_key is not None:
            self._api_key = api_key
        else:
            self._api_key = (
                os.environ.get("VIRUSTOTAL_API_KEY") or ""
            )

        self._base_url = base_url.rstrip("/")

        if timeout is not None:
            self._timeout = timeout
        else:
            self._timeout = int(
                os.environ.get("VIRUSTOTAL_TIMEOUT")
                or DEFAULT_TIMEOUT
            )

        self._http_get = http_get or _default_http_get

    # ------------------------------------------------------------------

    def name(self) -> str:
        return "virustotal"

    def is_available(self) -> bool:
        return bool(self._api_key)

    def lookup(self, indicator: Indicator) -> IntelResult:
        if not self.is_available():
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error="virustotal not configured (missing API key)",
            )

        endpoint = self._endpoint(indicator)
        if endpoint is None:
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error=(
                    f"virustotal does not support "
                    f"indicator type {indicator.type.value}"
                ),
            )

        try:
            data = self._http_get(
                endpoint,
                {"x-apikey": self._api_key},
                self._timeout,
            )
        except RuntimeError as exc:
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error=str(exc),
            )

        if isinstance(data, dict) and data.get("__not_found__"):
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                found=False,
            )

        return self._parse(data, indicator)

    # ------------------------------------------------------------------

    def _endpoint(self, indicator: Indicator) -> str | None:
        if indicator.type == IndicatorType.HASH:
            return f"{self._base_url}/files/{indicator.value}"
        if indicator.type == IndicatorType.IP:
            return f"{self._base_url}/ip_addresses/{indicator.value}"
        if indicator.type == IndicatorType.DOMAIN:
            return f"{self._base_url}/domains/{indicator.value}"
        if indicator.type == IndicatorType.URL:
            # VT butuh base64 url-safe encoding untuk URL; skip dulu
            return None
        return None

    def _parse(
        self,
        data: dict[str, Any],
        indicator: Indicator,
    ) -> IntelResult:
        attrs = (
            data.get("data", {})
            .get("attributes", {})
        )
        if not isinstance(attrs, dict):
            attrs = {}

        last_stats = attrs.get("last_analysis_stats") or {}
        malicious = int(last_stats.get("malicious", 0))
        suspicious = int(last_stats.get("suspicious", 0))
        harmless = int(last_stats.get("harmless", 0))
        undetected = int(last_stats.get("undetected", 0))

        total = malicious + suspicious + harmless + undetected

        reputation = attrs.get("reputation")
        if reputation is not None:
            try:
                reputation = int(reputation)
            except (ValueError, TypeError):
                reputation = None

        # Tags / family names
        tags: list[str] = []
        for key in ("tags", "popular_threat_classification"):
            raw = attrs.get(key)
            if isinstance(raw, list):
                tags.extend(str(x) for x in raw)
            elif isinstance(raw, dict):
                suggested = raw.get("suggested_threat_label")
                if suggested:
                    tags.append(str(suggested))

        return IntelResult(
            indicator=indicator,
            provider=self.name(),
            found=True,
            malicious_count=malicious + suspicious,
            total_count=total,
            reputation=reputation,
            tags=sorted(set(tags)),
            raw=data,
        )


__all__ = ["VirusTotalProvider", "DEFAULT_BASE_URL"]
