"""
Local LLM provider menggunakan Ollama.

Konfigurasi via environment:
- OLLAMA_HOST  (default: http://localhost:11434)
- OLLAMA_MODEL (default: llama3.2)
- OLLAMA_TIMEOUT (default: 60 detik)

Tidak butuh SDK eksternal; pakai stdlib urllib.
Kalau Ollama tidak jalan → is_available() == False.
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


DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
DEFAULT_TIMEOUT = 60


class LocalLLMProvider(BaseProvider):
    """Ollama provider."""

    _name = "ollama"

    def __init__(
        self,
        *,
        host: str | None = None,
        model: str | None = None,
        timeout: int | None = None,
    ) -> None:
        if host is not None:
            self._host = host.rstrip("/")
        else:
            self._host = (
                os.environ.get("OLLAMA_HOST") or DEFAULT_HOST
            ).rstrip("/")

        if model is not None:
            self._model = model
        else:
            self._model = (
                os.environ.get("OLLAMA_MODEL") or DEFAULT_MODEL
            )

        if timeout is not None:
            self._timeout = int(timeout)
        else:
            self._timeout = int(
                os.environ.get("OLLAMA_TIMEOUT") or DEFAULT_TIMEOUT
            )


    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def name(self) -> str:
        return self._name

    def is_available(self) -> bool:
        """
        Cek Ollama API: GET /api/tags.
        Return True hanya kalau endpoint merespons.
        """
        url = f"{self._host}/api/tags"
        try:
            with urllib.request.urlopen(
                url, timeout=3
            ) as resp:
                return resp.status == 200
        except (
            urllib.error.URLError,
            socket.timeout,
            ConnectionError,
            OSError,
        ):
            return False

    def generate_narrative(
        self, result: InvestigationResult
    ) -> str:
        prompt = build_narrative_prompt(result)

        payload = {
            "model": self._model,
            "prompt": prompt,
            "stream": False,
        }

        url = f"{self._host}/api/generate"
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(
                req, timeout=self._timeout
            ) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise RuntimeError(
                f"ollama HTTP error {exc.code}: {exc.reason}"
            ) from exc
        except (urllib.error.URLError, socket.timeout) as exc:
            raise RuntimeError(
                f"ollama unreachable: {exc}"
            ) from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"ollama returned invalid JSON: {exc}"
            ) from exc

        text = data.get("response")
        if not isinstance(text, str) or not text.strip():
            raise RuntimeError(
                "ollama returned empty response"
            )
        return text.strip()


__all__ = ["LocalLLMProvider", "DEFAULT_HOST", "DEFAULT_MODEL"]
