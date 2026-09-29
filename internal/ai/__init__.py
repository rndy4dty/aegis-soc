"""
AI layer for AegisSOC.

Komponen:
- AIProvider         : Protocol untuk semua provider (rule, local LLM, cloud LLM)
- RuleEngineProvider : Deterministic narrative (default, selalu tersedia)
- AIRouter           : Pilih provider + fallback chain

Filosofi:
- Deterministic engine adalah primary.
- AI (LLM) adalah enhancement opsional.
- Kalau LLM tidak tersedia, rule engine tetap menghasilkan narrative.
"""

from internal.ai.provider import AIProvider, BaseProvider
from internal.ai.rule_engine import RuleEngineProvider
from internal.ai.router import AIRouter, narrate

__all__ = [
    "AIProvider",
    "BaseProvider",
    "RuleEngineProvider",
    "AIRouter",
    "narrate",
]
