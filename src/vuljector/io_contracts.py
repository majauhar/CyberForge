"""Typed data contracts for setup/selection/injection workflow."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal


def utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class ProjectConfig:
    project: str
    target_dir: str
    secure_base_commit: str
    main_repo_url: str
    fuzzing_engine: str = "libfuzzer"
    dockerhub_image: str | None = None
    unit_tests: dict[str, Any] | None = None
    # Explicit language override for CodeQL analysis (e.g. "cpp", "python", "javascript").
    language: str | None = None
    # Optional second-path harnesses intended for post-crash triage tools such as Rex.
    triage_harnesses: list[dict[str, Any]] | None = None

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
    # Primary language of the target file — drives prompt selection and plugin dispatch.
    language: str = "python"
    # Optional location precision — set by static_analysis strategy.
    line_range: tuple[int, int] | None = None
    # Strategy-specific overflow bag. Static analysis puts complexity_score,
    # difficulty, call_path, checkpoint, operation, evidence, cwe_candidates here.
    # LLM explore puts its raw candidate dict fields here.
    extra: dict[str, Any] = field(default_factory=dict)

    # ── Typed accessors into extra ────────────────────────────────────────────
    @property
    def checkpoint(self) -> dict[str, Any]:
        """Checkpoint dict set by static_analysis: {type, text, line}."""
        return self.extra.get("checkpoint") or {}

    @property
    def operation(self) -> dict[str, Any]:
        """Operation dict set by static_analysis: {type, text, line}."""
        return self.extra.get("operation") or {}

    @property
    def cwe_candidates(self) -> list[str]:
        """Candidate CWE IDs ranked by likelihood (set by static_analysis)."""
        return self.extra.get("cwe_candidates") or []

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        # tuple is not JSON-serialisable by default; convert to list.
        if d.get("line_range") is not None:
            d["line_range"] = list(d["line_range"])
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SelectionCandidate":
        lr = d.get("line_range")
        return cls(
            candidate_id=d["candidate_id"],
            rank=d["rank"],
            cwe_group=d.get("cwe_group", ""),
            cwe_id=d.get("cwe_id", ""),
            repo_path=d.get("repo_path", ""),
            symbol=d.get("symbol", ""),
            location_hint=d.get("location_hint", ""),
            rationale=d.get("rationale", ""),
            confidence=float(d.get("confidence", 0.5)),
            language=d.get("language", "python"),
            line_range=tuple(lr) if lr else None,  # type: ignore[arg-type]
            extra=d.get("extra", {}),
        )


@dataclass
class SelectionResult:
    project: str
    run_id: str
    timestamp_utc: str
    selection_strategy_id: str
    candidates: list[SelectionCandidate]

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["candidates"] = [c.to_dict() for c in self.candidates]
        return payload

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "SelectionResult":
        return cls(
            project=d["project"],
            run_id=d["run_id"],
            timestamp_utc=d.get("timestamp_utc", ""),
            selection_strategy_id=d.get("selection_strategy_id", ""),
            candidates=[SelectionCandidate.from_dict(c) for c in d.get("candidates", [])],
        )


@dataclass
class InjectionResult:
    project: str
    run_id: str
    timestamp_utc: str
    status: Literal["success", "failure"]
    selected_candidate_id: str | None
    cwe_group: str | None
    cwe_id: str | None
    strategy: dict[str, Any]
    usage: dict[str, Any]
    # Real file paths relative to the run directory (exploit_dir, inject_vulnerability.diff, etc.)
    paths: dict[str, str]
    # Inline artifact content — patch diff, attack script, etc. NOT file paths.
    artifacts: dict[str, str] = field(default_factory=dict)
    failure: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    project: str
    run_id: str
    timestamp_utc: str
    status: Literal["success", "failure"]
    checks: dict[str, str]
    failure_cause: str | None
    failure_message: str
    unit_test_passed_count: int | None = None
    unit_test_message: str = ""
    unit_test_raw_output: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
