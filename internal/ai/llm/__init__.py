"""
LLM provider adapters for AegisSOC.

- LocalLLMProvider  : Ollama (http://localhost:11434)
- CloudLLMProvider  : OpenAI-compatible endpoint (OpenAI / vLLM / OpenRouter)

Keduanya opsional. Kalau tidak tersedia, AIRouter fallback ke rule engine.
"""

from internal.ai.llm.local_llm import LocalLLMProvider
from internal.ai.llm.cloud_llm import CloudLLMProvider

__all__ = ["LocalLLMProvider", "CloudLLMProvider"]
