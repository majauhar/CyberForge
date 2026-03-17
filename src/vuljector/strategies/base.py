"""Shared contracts for vuljector injection strategies."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Literal


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
    repo_dir_in_container: str
    vuln_dir_in_container: str
    cwe_groups: list[str] | None
    cwe_ids: list[str] | None
    debug: bool
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


@dataclass
class Vuljector:
    """Descriptor for an injection method: what module to run and how to set it up."""

    id: str
    module: str  # Python module path for 'python3 -m <module>'
    setup_cmds: list[str] = field(default_factory=list)
