"""Maps injection_strategy_id -> InjectionStrategy implementation."""

from injector.base import InjectionStrategy
from injector.cve_inject.run import CVEInjectStrategy
from injector.llm_inject.run import LLMInjectStrategy

INJECTOR_REGISTRY: dict[str, type[InjectionStrategy]] = {
    "llm_inject": LLMInjectStrategy,
    "cve_inject": CVEInjectStrategy,
}


def get_injection_strategy(strategy_id: str) -> InjectionStrategy:
    cls = INJECTOR_REGISTRY.get(strategy_id)
    if cls is None:
        available = list(INJECTOR_REGISTRY.keys())
        raise ValueError(f"Unknown injection strategy {strategy_id!r}. Available: {available}")
    return cls()
