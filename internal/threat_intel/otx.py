"""
AlienVault OTX provider.

Konfigurasi via environment:
- OTX_API_KEY (wajib)
- OTX_TIMEOUT (opsional, default 15)
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


DEFAULT_BASE_URL = "https://otx.alienvault.com/api/v1"
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
            f"OTX HTTP {exc.code}: {exc.reason} — {body[:200]}"
        ) from exc
    except (urllib.error.URLError, socket.timeout) as exc:
        raise RuntimeError(f"OTX unreachable: {exc}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"OTX invalid JSON: {exc}") from exc


class OTXProvider:
    """AlienVault OTX provider."""

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
            self._api_key = os.environ.get("OTX_API_KEY") or ""

        self._base_url = base_url.rstrip("/")

        if timeout is not None:
            self._timeout = timeout
        else:
            self._timeout = int(
                os.environ.get("OTX_TIMEOUT") or DEFAULT_TIMEOUT
            )

        self._http_get = http_get or _default_http_get

    def name(self) -> str:
        return "otx"

    def is_available(self) -> bool:
        return bool(self._api_key)

    def lookup(self, indicator: Indicator) -> IntelResult:
        if not self.is_available():
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error="otx not configured (missing API key)",
            )

        endpoint = self._endpoint(indicator)
        if endpoint is None:
            return IntelResult(
                indicator=indicator,
                provider=self.name(),
                error=(
                    f"otx does not support "
                    f"{indicator.type.value}"
                ),
            )

        try:
            data = self._http_get(
                endpoint,
                {"X-OTX-API-KEY": self._api_key},
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
        if indicator.type == IndicatorType.IP:
            return f"{self._base_url}/indicators/IPv4/{indicator.value}/general"
        if indicator.type == IndicatorType.DOMAIN:
            return f"{self._base_url}/indicators/domain/{indicator.value}/general"
        if indicator.type == IndicatorType.HASH:
            return f"{self._base_url}/indicators/file/{indicator.value}/general"
        return None

    def _parse(
        self,
        data: dict[str, Any],
        indicator: Indicator,
    ) -> IntelResult:
        pulse_info = data.get("pulse_info") or {}
        pulse_count = int(pulse_info.get("count", 0))
        pulses = pulse_info.get("pulses") or []

        tags: list[str] = []
        for pulse in pulses[:20]:
            if isinstance(pulse, dict):
                for t in pulse.get("tags") or []:
                    tags.append(str(t))

        return IntelResult(
            indicator=indicator,
            provider=self.name(),
            found=pulse_count > 0,
            malicious_count=pulse_count,
            total_count=pulse_count,
            tags=sorted(set(tags)),
            raw=data,
        )


__all__ = ["OTXProvider", "DEFAULT_BASE_URL"]
