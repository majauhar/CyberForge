"""Base contracts for vuljector injection strategies."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Literal

from setup import ContainerRuntime


class FailureCause(str, Enum):
    UNIT_TESTS_FAILED = "unit_tests_failed"
    EXPLOIT_FAILED_ON_VULNERABLE = "exploit_failed_on_vulnerable"
    EXPLOIT_SUCCEEDS_ON_BOTH = "exploit_succeeds_on_both"
    OTHER = "other"


@dataclass
class InjectionContext:
    project: str
    run_id: str
    method_id: str
    model_id: str
    target_dir: str
    secure_base_commit: str
    cwe_groups: list[str] | None
    cwe_ids: list[str] | None
    debug: bool
    project_root: str
    repo_dir_in_container: str
    unit_test_cmd: str | None = None


@dataclass
class InjectionResult:
    status: Literal["success", "failure"]
    cwe_group: str | None
    cwe_id: str | None
    failure_cause: FailureCause | None
    failure_message: str
    retries: int
    models_used: list[str]
    token_usage: dict | None
    cost: float | None
    complexity: str | None
    exploit_dir_in_container: str


class InjectionStrategy(ABC):
    """Abstract strategy interface for vuljector."""

    @property
    @abstractmethod
    def id(self) -> str:
        raise NotImplementedError

    def setup(self, runtime: ContainerRuntime, context: InjectionContext) -> None:
        """Optional strategy-specific setup. Default: no-op."""
        return None

    @abstractmethod
    def run(self, runtime: ContainerRuntime, context: InjectionContext) -> InjectionResult:
        raise NotImplementedError
