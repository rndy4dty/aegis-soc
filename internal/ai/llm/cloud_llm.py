"""
Cloud LLM provider (OpenAI-compatible endpoint).

Kompatibel dengan:
- OpenAI   (https://api.openai.com/v1)
- OpenRouter, Together, Groq, vLLM, Ollama-OpenAI, dsb.

Konfigurasi via environment:
- AEGIS_CLOUD_LLM_BASE_URL   (default: https://api.openai.com/v1)
- AEGIS_CLOUD_LLM_API_KEY    (wajib)
- AEGIS_CLOUD_LLM_MODEL      (default: gpt-4o-mini)
- AEGIS_CLOUD_LLM_TIMEOUT    (default: 60 detik)

Kalau API key tidak diset → is_available() == False.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request

from internal.ai.llm.prompts import build_narrative_prompt
from internal.ai.provider import BaseProvider
from internal.investigation.investigation_engine import (
    InvestigationResult,
)


DEFAULT_BASE_URL = "https://api.openai.com/v1"
DEFAULT_MODEL = "gpt-4o-mini"
DEFAULT_TIMEOUT = 60


class CloudLLMProvider(BaseProvider):
    """OpenAI-compatible provider."""

    _name = "openai_compatible"


    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ) -> None:
        # Catatan: gunakan `is not None` supaya explicit empty string
        # dihormati (tidak jatuh ke env).
        if base_url is not None:
            self._base_url = base_url.rstrip("/")
        else:
            self._base_url = (
                os.environ.get("AEGIS_CLOUD_LLM_BASE_URL")
                or DEFAULT_BASE_URL
            ).rstrip("/")

        if api_key is not None:
            self._api_key = api_key
        else:
            self._api_key = (
                os.environ.get("AEGIS_CLOUD_LLM_API_KEY") or ""
            )

        if model is not None:
            self._model = model
        else:
            self._model = (
                os.environ.get("AEGIS_CLOUD_LLM_MODEL")
                or DEFAULT_MODEL
            )

        if timeout is not None:
            self._timeout = int(timeout)
        else:
            self._timeout = int(
                os.environ.get("AEGIS_CLOUD_LLM_TIMEOUT")
                or DEFAULT_TIMEOUT
            )
    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        """True kalau API key dan base URL tersedia."""
        return bool(self._api_key) and bool(self._base_url)

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        if not self.is_available():
            raise RuntimeError(
                "cloud LLM not configured "
                "(missing API key or base URL)"
            )

        prompt = build_narrative_prompt(result)

        payload = {
            "model": self._model,
            "messages": [
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.2,
            "max_tokens": 800,
        }

        url = f"{self._base_url}/chat/completions"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            },
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout
            ) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
            raise RuntimeError(
                f"cloud LLM HTTP error {exc.code}: "
                f"{exc.reason} — {body[:200]}"
            ) from exc
        except (urllib.error.URLError, socket.timeout) as exc:
            raise RuntimeError(
                f"cloud LLM unreachable: {exc}"
            ) from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"cloud LLM returned invalid JSON: {exc}"
            ) from exc

        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError(
                f"cloud LLM unexpected response shape: {exc}"
            ) from exc

        if not isinstance(content, str) or not content.strip():
            raise RuntimeError(
                "cloud LLM returned empty content"
            )
        return content.strip()


__all__ = ["CloudLLMProvider", "DEFAULT_BASE_URL", "DEFAULT_MODEL"]
