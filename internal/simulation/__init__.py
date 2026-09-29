"""
Attack simulation untuk demo & testing.

Menghasilkan skenario serangan end-to-end sebagai list[Event]
yang siap di-feed ke InvestigationEngine.

Semua deterministic. Tidak butuh external dependency.
"""

from internal.simulation.attack_scenario import (
    ATTACK_SCENARIOS,
    AttackScenario,
    build_scenario,
    list_scenarios,
)

__all__ = [
    "AttackScenario",
    "ATTACK_SCENARIOS",
    "build_scenario",
    "list_scenarios",
]
