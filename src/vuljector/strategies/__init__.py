"""Strategy registry for vuljector."""

from .agent_based_full_v1 import agent_based_full_v1
from .base import FailureCause, InjectionContext, InjectionResult, Vuljector

VULJECTORS: dict[str, Vuljector] = {
    "agent_based_full_v1": agent_based_full_v1,
}


def get_vuljector(method_id: str) -> Vuljector:
    try:
        return VULJECTORS[method_id]
    except KeyError as exc:
        valid = ", ".join(sorted(VULJECTORS))
        raise ValueError(f"Unknown method_id '{method_id}'. Valid values: {valid}") from exc


__all__ = [
    "FailureCause",
    "InjectionContext",
    "InjectionResult",
    "Vuljector",
    "get_vuljector",
]
