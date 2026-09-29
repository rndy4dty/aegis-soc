"""
AI Router for AegisSOC.

Memilih provider narrative secara berurutan berdasarkan prioritas.
Jika provider gagal atau tidak tersedia, otomatis fallback ke
provider berikutnya.

Default provider chain:
    1. Provider yang di-inject caller (LLM, dsb.)
    2. RuleEngineProvider (selalu tersedia)

Prinsip:
- Deterministik bila tidak ada LLM.
- Tidak crash jika provider gagal — fallback ke berikutnya.
- Log provider yang dipakai via metadata.
"""

from __future__ import annotations

from internal.ai.provider import AIProvider
from internal.ai.rule_engine import RuleEngineProvider
from internal.investigation.investigation_engine import (
    InvestigationResult,
)


# ===========================================================================
# AIRouter
# ===========================================================================

class AIRouter:
    """
    Router narrative dari beberapa provider.
    """

    def __init__(
        self,
        providers: list[AIProvider] | None = None,
        *,
        include_rule_engine: bool = True,
    ) -> None:
        chain: list[AIProvider] = []
        if providers:
            chain.extend(providers)

        if include_rule_engine:
            chain.append(RuleEngineProvider())

        if not chain:
            raise ValueError(
                "AIRouter requires at least one provider "
                "(or include_rule_engine=True)"
            )

        self._providers = chain

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def narrate(self, result: InvestigationResult) -> str:
        """
        Hasilkan narrative dari InvestigationResult.

        Urutan: coba tiap provider berurutan.
        Skip provider yang is_available() == False.
        Catch exception, lanjut ke provider berikutnya.

        Raise RuntimeError jika semua provider gagal.
        """
        errors: list[str] = []

        for provider in self._providers:
            name = provider.name()

            try:
                if not provider.is_available():
                    errors.append(f"{name}: not available")
                    continue
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{name}: is_available raised {exc!r}")
                continue

            try:
                narrative = provider.generate_narrative(result)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{name}: {exc!r}")
                continue

            if narrative and narrative.strip():
                return narrative

            errors.append(f"{name}: empty narrative")

        raise RuntimeError(
            "all AI providers failed: " + "; ".join(errors)
        )

    def narrate_with_provider(
        self,
        result: InvestigationResult,
        *,
        provider_name: str,
    ) -> str:
        """
        Paksa pakai provider tertentu.
        Raise ValueError kalau tidak ketemu.
        """
        for provider in self._providers:
            if provider.name() == provider_name:
                if not provider.is_available():
                    raise RuntimeError(
                        f"provider {provider_name!r} is not available"
                    )
                return provider.generate_narrative(result)

        raise ValueError(
            f"provider {provider_name!r} not found in router"
        )

    def available_providers(self) -> list[str]:
        """
        Return nama provider yang is_available() == True.
        """
        out: list[str] = []
        for p in self._providers:
            try:
                if p.is_available():
                    out.append(p.name())
            except Exception:  # noqa: BLE001
                continue
        return out

    def all_providers(self) -> list[str]:
        return [p.name() for p in self._providers]


# ===========================================================================
# Convenience
# ===========================================================================

def narrate(
    result: InvestigationResult,
    *,
    providers: list[AIProvider] | None = None,
) -> str:
    """Shortcut: AIRouter().narrate(result)."""
    return AIRouter(providers=providers).narrate(result)


__all__ = ["AIRouter", "narrate"]
