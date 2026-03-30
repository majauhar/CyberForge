"""Typed data contracts for agent task runner."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class TaskType(str, Enum):
    ZERO_DAY_POC = "zero_day_poc"
    ONE_DAY_POC = "one_day_poc"
    SECURE_PATCH = "secure_patch"

    @property
    def extracts_exploit(self) -> bool:
        return self in (TaskType.ZERO_DAY_POC, TaskType.ONE_DAY_POC)

    @property
    def extracts_patch(self) -> bool:
        return self is TaskType.SECURE_PATCH

    @property
    def agent_output_filename(self) -> str:
        return "attack.py" if self.extracts_exploit else "fix.patch"

    @property
    def agent_output_container_path(self) -> str:
        return f"/tmp/{self.agent_output_filename}"


@dataclass
class SyntheticTaskSpec:
    """Everything needed to run the agent on one synthetic vulnerability task."""

    project: str
    vulnerability_id: str
    task_type: TaskType
    model_id: str
    # From vulnerability_metadata.json
    secure_base_commit: str
    cwe_id: str
    cwe_group: str
    # From snapshot/manifest.json
    affected_files: list[str]
    # Patch diff (git format) that introduces the vulnerability
    patch_diff: str
    # Absolute host path to the reference PoC exploit
    reference_exploit_path: Path
    # Natural language description for prompted tasks (one_day_poc / secure_patch)
    vuln_description: str = ""

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["task_type"] = self.task_type.value
        d["reference_exploit_path"] = str(self.reference_exploit_path)
        return d


@dataclass
class AgentTaskResult:
    """Outcome of running the agent on one synthetic task."""

    schema_version: str
    project: str
    vulnerability_id: str
    task_type: str
    model_id: str
    run_id: str
    timestamp_utc: str
    # "success" | "failure" | "no_output" (agent produced no artifact)
    validation_status: str
    validation_checks: dict[str, str] = field(default_factory=dict)
    failure_cause: str | None = None
    failure_message: str = ""
    quality_metrics: dict[str, Any] = field(default_factory=dict)
    # Relative paths within run_dir
    paths: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
