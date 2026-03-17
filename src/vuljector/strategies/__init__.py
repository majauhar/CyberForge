"""Strategy registry for vuljector."""

from .agent_based_full_v1 import AgentBasedFullV1Strategy
from .base import FailureCause, InjectionContext, InjectionResult, InjectionStrategy

STRATEGIES: dict[str, type[InjectionStrategy]] = {
    "agent_based_full_v1": AgentBasedFullV1Strategy,
}


def get_strategy(method_id: str) -> InjectionStrategy:
    try:
        return STRATEGIES[method_id]()
    except KeyError as exc:
        valid = ", ".join(sorted(STRATEGIES))
        raise ValueError(f"Unknown method_id '{method_id}'. Valid values: {valid}") from exc


__all__ = [
    "FailureCause",
    "InjectionContext",
    "InjectionResult",
    "InjectionStrategy",
    "get_strategy",
]
