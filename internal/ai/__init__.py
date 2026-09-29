"""
AI layer for AegisSOC.

Komponen:
- AIProvider          : Protocol untuk semua provider
- RuleEngineProvider  : Deterministic narrative (default)
- MultiAgentProvider  : 4-agent orchestrator
- AIRouter            : Pilih provider + fallback chain
"""

from internal.ai.provider import AIProvider, BaseProvider
from internal.ai.rule_engine import RuleEngineProvider
from internal.ai.router import AIRouter, narrate
from internal.ai.multi_agent import MultiAgentProvider

__all__ = [
    "AIProvider",
    "BaseProvider",
    "RuleEngineProvider",
    "MultiAgentProvider",
    "AIRouter",
    "narrate",
]
