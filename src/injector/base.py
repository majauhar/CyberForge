"""Abstract base for injection method implementations."""

from __future__ import annotations

from abc import ABC, abstractmethod

from vuljector.strategies.base import InjectionContext, InjectionResult


class InjectionMethod(ABC):
    """Standard interface for an injection method.

    Each method lives under injector/<method_id>/run.py and is invoked via
    'python3 -m injector.<method_id>.run --context <json>'.
    """

    @abstractmethod
    def run(self, context: InjectionContext) -> InjectionResult:
        raise NotImplementedError
