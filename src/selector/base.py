"""Selection strategy interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionResult


@dataclass
class SelectionRequest:
    project: str
    run_id: str
    strategy_id: str
    model_id: str
    cwe_groups: list[str] | None
    cwe_ids: list[str] | None
    target_dir: str = ""
    max_candidates: int = 30
    filters: dict = field(default_factory=dict)


class SelectionStrategy(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        raise NotImplementedError

    def setup(self, runtime: ContainerRuntime) -> None:
        return None

    @abstractmethod
    def run(self, runtime: ContainerRuntime, request: SelectionRequest) -> SelectionResult:
        raise NotImplementedError

