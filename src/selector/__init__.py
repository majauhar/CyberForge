"""Selection strategies package."""

__all__ = ["get_selection_strategy"]


def get_selection_strategy(strategy_id: str):
    from .registry import get_selection_strategy as _get_selection_strategy

    return _get_selection_strategy(strategy_id)
