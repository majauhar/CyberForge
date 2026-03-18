"""Typed data contracts for setup/selection/injection workflow."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ProjectConfig:
    schema_version: str
    project: str
    target_dir: str
    secure_base_commit: str
    repos: dict[str, str]
    source: dict[str, str]
    unit_tests: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SelectionCandidate:
    candidate_id: str
    rank: int
    cwe_group: str
    cwe_id: str
    repo_path: str
    symbol: str
    location_hint: str
    rationale: str
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SelectionResult:
    schema_version: str
    project: str
    run_id: str
    timestamp_utc: str
    selection_strategy_id: str
    candidates: list[SelectionCandidate]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["candidates"] = [c.to_dict() for c in self.candidates]
        return payload


@dataclass
class InjectionResult:
    schema_version: str
    project: str
    run_id: str
    timestamp_utc: str
    status: Literal["success", "failure"]
    selected_candidate_id: str | None
    cwe_group: str | None
    cwe_id: str | None
    strategy: dict[str, Any]
    usage: dict[str, Any]
    paths: dict[str, str]
    failure: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    schema_version: str
    project: str
    run_id: str
    timestamp_utc: str
    status: Literal["success", "failure"]
    checks: dict[str, str]
    failure_cause: str | None
    failure_message: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotFile:
    repo_path: str
    snapshot_path: str
    change_type: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class SnapshotManifest:
    schema_version: str
    project: str
    vulnerability_id: str
    files: list[SnapshotFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["files"] = [f.to_dict() for f in self.files]
        return payload

