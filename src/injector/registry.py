"""Maps injection_strategy_id -> InjectionStrategy implementation."""

from injector.base import InjectionStrategy
from injector.fuzzer_llm_inject.run import FuzzerLLMInjectStrategy
from injector.llm_inject.run import LLMInjectStrategy

INJECTOR_REGISTRY: dict[str, type[InjectionStrategy]] = {
    "llm_inject": LLMInjectStrategy,
    "fuzzer_llm_inject": FuzzerLLMInjectStrategy,
}

# Maps selection_strategy_id -> injection_strategy_id
_SELECTION_TO_INJECTION: dict[str, str] = {
    "llm_explore": "llm_inject",
    "static_analysis": "llm_inject",
    "fuzz_guided": "fuzzer_llm_inject",
    "codeql": "llm_inject",
}


def get_injection_strategy(strategy_id: str) -> InjectionStrategy:
    cls = INJECTOR_REGISTRY.get(strategy_id)
    if cls is None:
        available = list(INJECTOR_REGISTRY.keys())
        raise ValueError(f"Unknown injection strategy {strategy_id!r}. Available: {available}")
    return cls()


def get_injection_strategy_for_selection(selection_strategy_id: str) -> InjectionStrategy:
    """Route to injection strategy based on selection strategy."""
    injection_strategy_id = _SELECTION_TO_INJECTION.get(selection_strategy_id)
    if injection_strategy_id is None:
        available = list(_SELECTION_TO_INJECTION.keys())
        raise ValueError(f"Unknown selection strategy {selection_strategy_id!r}. Available: {available}")
    return get_injection_strategy(injection_strategy_id)
