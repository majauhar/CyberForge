"""Injection strategy registry."""

from __future__ import annotations

from injector.base import InjectionStrategy
from injector.vanilla_agent_v1.run import VanillaInjectionStrategy

_REGISTRY: dict[str, type[InjectionStrategy]] = {
    "vanilla_agent_v1": VanillaInjectionStrategy,
}


def get_injection_strategy(strategy_id: str) -> InjectionStrategy:
    try:
        return _REGISTRY[strategy_id]()
    except KeyError as exc:
        valid = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"Unknown injection strategy '{strategy_id}'. Valid: {valid}") from exc

