"""Typed data contracts for SEC-bench-style agent task generation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class TaskType(str, Enum):
    PATCH = "patch"
    POC_REPO = "poc-repo"
    POC_DESC = "poc-desc"
    POC_SAN = "poc-san"

    @classmethod
    def from_input(cls, value: str) -> "TaskType":
        normalized = (value or "").strip().lower()
        aliases = {
            "secure_patch": cls.PATCH,
            "patch": cls.PATCH,
            "zero_day_poc": cls.POC_REPO,
            "poc-repo": cls.POC_REPO,
            "poc_repo": cls.POC_REPO,
            "one_day_poc": cls.POC_DESC,
            "poc-desc": cls.POC_DESC,
            "poc_desc": cls.POC_DESC,
            "poc-san": cls.POC_SAN,
            "poc_san": cls.POC_SAN,
        }
        if normalized not in aliases:
            supported = ", ".join(item.value for item in cls)
            raise ValueError(f"Unknown task type {value!r}. Supported: {supported}")
        return aliases[normalized]

    @property
    def extracts_exploit(self) -> bool:
        return self is not TaskType.PATCH

    @property
    def extracts_patch(self) -> bool:
        return self is TaskType.PATCH

    @property
    def agent_output_filename(self) -> str:
        return "testcase" if self.extracts_exploit else "fix.patch"

    @property
    def agent_output_container_path(self) -> str:
        return "/testcase" if self.extracts_exploit else f"/tmp/{self.agent_output_filename}"

    @property
    def prompt_uses_description(self) -> bool:
        return self in {TaskType.POC_DESC, TaskType.POC_SAN, TaskType.PATCH}

    @property
    def prompt_uses_sanitizer_report(self) -> bool:
        return self in {TaskType.POC_SAN, TaskType.PATCH}


@dataclass
class SyntheticTaskSpec:
    """Everything needed to run the agent on one synthetic vulnerability task."""

    project: str
    vulnerability_id: str
    task_type: TaskType
    model_id: str
    instance_id: str
    secure_base_commit: str
    cwe_id: str
    cwe_group: str
    affected_files: list[str]
    patch_diff: str
    reference_exploit_path: Path
    bundle_dir: Path
    producer: str = ""
    bug_description: str = ""
    bug_description_variant_id: str = "v0"
    bug_report: str = ""
    sanitizer_report: str = ""
    hints: dict[str, Any] = field(default_factory=dict)
    include_hints: bool = False
    teacher_regime: str = "faithful"
    teacher_assistance: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["task_type"] = self.task_type.value
        d["reference_exploit_path"] = str(self.reference_exploit_path)
        d["bundle_dir"] = str(self.bundle_dir)
        return d


@dataclass
class AgentTaskResult:
    """Outcome of running the agent on one synthetic task."""

    schema_version: str
    project: str
    vulnerability_id: str
    instance_id: str
    task_type: str
    model_id: str
    run_id: str
    timestamp_utc: str
    include_hints: bool
    bug_description_variant_id: str
    validation_status: str
    teacher_regime: str = "faithful"
    validation_checks: dict[str, str] = field(default_factory=dict)
    failure_cause: str | None = None
    failure_message: str = ""
    quality_metrics: dict[str, Any] = field(default_factory=dict)
    paths: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
