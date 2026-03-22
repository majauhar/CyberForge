"""Injection strategy interfaces."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import InjectionResult, SelectionCandidate


@dataclass
class InjectionRequest:
    project: str
    run_id: str
    strategy_id: str
    model_id: str
    num_vulnerabilities: int
    debug: bool
    # Relative sub-path within run_mount for this attempt's artifacts
    # (e.g. "attempt_00"). Empty string means root of run_mount.
    attempt_dir: str = ""


class InjectionStrategy(ABC):
    @property
    @abstractmethod
    def id(self) -> str:
        raise NotImplementedError

    def setup(self, runtime: ContainerRuntime) -> None:
        return None

    @abstractmethod
    def run(
        self,
        runtime: ContainerRuntime,
        request: InjectionRequest,
        candidate: SelectionCandidate,
    ) -> InjectionResult:
        raise NotImplementedError
