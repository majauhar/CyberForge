"""Maps selection_strategy_id -> SelectionStrategy implementation."""

from selector.base import SelectionStrategy
from selector.codeql.run import CodeQLStrategy
from selector.cve_select.run import CVESelectStrategy
from selector.fuzz_guided.run import FuzzGuidedStrategy
from selector.llm_explore.run import LLMExploreStrategy
from selector.static_analysis.run import StaticAnalysisStrategy

SELECTOR_REGISTRY: dict[str, type[SelectionStrategy]] = {
    "cve_select": CVESelectStrategy,
    "llm_explore": LLMExploreStrategy,
    "static_analysis": StaticAnalysisStrategy,
    "fuzz_guided": FuzzGuidedStrategy,
    "codeql": CodeQLStrategy,
}


def get_selection_strategy(strategy_id: str) -> SelectionStrategy:
    cls = SELECTOR_REGISTRY.get(strategy_id)
    if cls is None:
        available = list(SELECTOR_REGISTRY.keys())
        raise ValueError(f"Unknown selection strategy {strategy_id!r}. Available: {available}")
    return cls()
