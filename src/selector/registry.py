"""Selection strategy registry."""

from __future__ import annotations

from selector.base import SelectionStrategy
from selector.vanilla_agent_v1.run import VanillaSelectionStrategy

_REGISTRY: dict[str, type[SelectionStrategy]] = {
    "vanilla_agent_v1": VanillaSelectionStrategy,
}


def get_selection_strategy(strategy_id: str) -> SelectionStrategy:
    try:
        return _REGISTRY[strategy_id]()
    except KeyError as exc:
        valid = ", ".join(sorted(_REGISTRY))
        raise ValueError(f"Unknown selection strategy '{strategy_id}'. Valid: {valid}") from exc

