"""Configurable post-selection candidate triage."""

from __future__ import annotations

import copy
import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from utils.json_io import write_json
from utils.paths import new_run_id, runs_root
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso


DEFAULT_SELECTION_TRIAGE_PROFILES: dict[str, dict[str, Any]] = {
    "balanced": {
        "include_path_buckets": ["prod", "example"],
        "exclude_checkpoint_path_buckets": ["test"],
        "require_checkpoint": True,
        "require_checkpoint_text": False,
        "allow_cross_file_checkpoint": True,
        "allow_missing_checkpoint_scope": False,
        "allowed_checkpoint_scopes": ["dominates", "conditional", "caller"],
        "max_call_hops": 4,
        "max_module_crossings": 3,
        "blocked_operation_types": ["data_return"],
        "max_candidates_per_site": 2,
        "max_candidates_per_file": 20,
        "max_candidates_total": 200,
        "score_weights": {
            "confidence": 2.0,
            "checkpoint_present": 1.5,
            "checkpoint_same_file": 1.5,
            "path_bucket_prod": 1.0,
            "path_bucket_example": 0.25,
            "scope_dominates": 1.0,
            "scope_conditional": 0.5,
            "scope_caller": -0.75,
            "call_hops_penalty": -0.5,
            "module_crossings_penalty": -0.5,
            "cross_file_checkpoint_penalty": -0.75,
            "difficulty_expert": 0.5,
            "difficulty_hard": 0.25,
            "difficulty_easy": -0.75,
        },
    },
    "conservative": {
        "include_path_buckets": ["prod"],
        "exclude_checkpoint_path_buckets": ["test", "example"],
        "require_checkpoint": True,
        "require_checkpoint_text": True,
        "allow_cross_file_checkpoint": False,
        "allow_missing_checkpoint_scope": False,
        "allowed_checkpoint_scopes": ["dominates", "conditional"],
        "max_call_hops": 2,
        "max_module_crossings": 1,
        "blocked_operation_types": ["data_return", "state_mutation", "array_index"],
        "max_candidates_per_site": 1,
        "max_candidates_per_file": 10,
        "max_candidates_total": 100,
        "score_weights": {
            "confidence": 2.0,
            "checkpoint_present": 2.0,
            "checkpoint_same_file": 2.0,
            "path_bucket_prod": 1.0,
            "scope_dominates": 1.0,
            "scope_conditional": 0.5,
            "call_hops_penalty": -0.75,
            "module_crossings_penalty": -0.75,
            "difficulty_easy": -1.0,
        },
    },
    "exploratory": {
        "include_path_buckets": ["prod", "example", "test"],
        "exclude_checkpoint_path_buckets": [],
        "require_checkpoint": False,
        "require_checkpoint_text": False,
        "allow_cross_file_checkpoint": True,
        "allow_missing_checkpoint_scope": True,
        "allowed_checkpoint_scopes": ["dominates", "conditional", "caller", "none"],
        "max_call_hops": 8,
        "max_module_crossings": 8,
        "blocked_operation_types": [],
        "max_candidates_per_site": 3,
        "max_candidates_per_file": 30,
        "max_candidates_total": 400,
        "score_weights": {
            "confidence": 2.0,
            "checkpoint_present": 1.0,
            "checkpoint_same_file": 0.75,
            "path_bucket_prod": 1.0,
            "path_bucket_example": 0.25,
            "path_bucket_test": -0.5,
            "scope_dominates": 0.5,
            "scope_conditional": 0.25,
            "scope_caller": -0.25,
            "call_hops_penalty": -0.25,
            "module_crossings_penalty": -0.25,
            "difficulty_expert": 0.75,
            "difficulty_hard": 0.5,
        },
    },
}


@dataclass(slots=True)
class SelectionTriageConfig:
    profile: str
    include_path_buckets: set[str]
    exclude_checkpoint_path_buckets: set[str]
    require_checkpoint: bool
    require_checkpoint_text: bool
    allow_cross_file_checkpoint: bool
    allow_missing_checkpoint_scope: bool
    allowed_checkpoint_scopes: set[str]
    max_call_hops: int | None
    max_module_crossings: int | None
    blocked_operation_types: set[str]
    max_candidates_per_site: int
    max_candidates_per_file: int
    max_candidates_total: int | None
    score_weights: dict[str, float]

    @classmethod
    def from_sources(
        cls,
        *,
        profile: str,
        config_path: Path | None = None,
        inline_overrides: dict[str, Any] | None = None,
    ) -> "SelectionTriageConfig":
        if profile not in DEFAULT_SELECTION_TRIAGE_PROFILES:
            known = ", ".join(sorted(DEFAULT_SELECTION_TRIAGE_PROFILES))
            raise ValueError(f"Unknown selection triage profile '{profile}'. Known profiles: {known}")

        merged = copy.deepcopy(DEFAULT_SELECTION_TRIAGE_PROFILES[profile])
        if config_path is not None:
            merged = _deep_merge(merged, json.loads(config_path.read_text(encoding="utf-8")))
        if inline_overrides:
            merged = _deep_merge(merged, inline_overrides)

        return cls(
            profile=profile,
            include_path_buckets=set(merged["include_path_buckets"]),
            exclude_checkpoint_path_buckets=set(merged["exclude_checkpoint_path_buckets"]),
            require_checkpoint=bool(merged["require_checkpoint"]),
            require_checkpoint_text=bool(merged["require_checkpoint_text"]),
            allow_cross_file_checkpoint=bool(merged["allow_cross_file_checkpoint"]),
            allow_missing_checkpoint_scope=bool(merged["allow_missing_checkpoint_scope"]),
            allowed_checkpoint_scopes=set(merged["allowed_checkpoint_scopes"]),
            max_call_hops=merged.get("max_call_hops"),
            max_module_crossings=merged.get("max_module_crossings"),
            blocked_operation_types=set(merged["blocked_operation_types"]),
            max_candidates_per_site=int(merged["max_candidates_per_site"]),
            max_candidates_per_file=int(merged["max_candidates_per_file"]),
            max_candidates_total=merged.get("max_candidates_total"),
            score_weights={k: float(v) for k, v in merged["score_weights"].items()},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "include_path_buckets": sorted(self.include_path_buckets),
            "exclude_checkpoint_path_buckets": sorted(self.exclude_checkpoint_path_buckets),
            "require_checkpoint": self.require_checkpoint,
            "require_checkpoint_text": self.require_checkpoint_text,
            "allow_cross_file_checkpoint": self.allow_cross_file_checkpoint,
            "allow_missing_checkpoint_scope": self.allow_missing_checkpoint_scope,
            "allowed_checkpoint_scopes": sorted(self.allowed_checkpoint_scopes),
            "max_call_hops": self.max_call_hops,
            "max_module_crossings": self.max_module_crossings,
            "blocked_operation_types": sorted(self.blocked_operation_types),
            "max_candidates_per_site": self.max_candidates_per_site,
            "max_candidates_per_file": self.max_candidates_per_file,
            "max_candidates_total": self.max_candidates_total,
            "score_weights": self.score_weights,
        }


def run_selection_triage(
    *,
    selection_file: Path,
    profile: str = "balanced",
    config_path: Path | None = None,
    output_dir: Path | None = None,
    inline_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload = json.loads(selection_file.read_text(encoding="utf-8"))
    selection = SelectionResult.from_dict(payload)
    config = SelectionTriageConfig.from_sources(
        profile=profile,
        config_path=config_path,
        inline_overrides=inline_overrides,
    )
    out_dir = output_dir or _default_selection_triage_output_dir(selection.project)
    out_dir.mkdir(parents=True, exist_ok=True)

    file_counts: Counter[str] = Counter()
    site_counts: Counter[str] = Counter()
    decisions: list[dict[str, Any]] = []
    kept_candidates: list[SelectionCandidate] = []
    kept_total = 0

    for candidate in selection.candidates:
        decision = _evaluate_candidate(candidate, config, file_counts, site_counts)
        if (
            decision["kept"]
            and config.max_candidates_total is not None
            and kept_total >= config.max_candidates_total
        ):
            decision["kept"] = False
            decision["rejected_reasons"].append("global_quota_exhausted")
        decisions.append(decision)
        if not decision["kept"]:
            continue

        file_counts[candidate.repo_path] += 1
        site_counts[decision["site_key"]] += 1
        kept_total += 1

        annotated = SelectionCandidate.from_dict(candidate.to_dict())
        annotated.extra = {
            **annotated.extra,
            "selection_triage": {
                "score": decision["score"],
                "path_bucket": decision["path_bucket"],
                "site_key": decision["site_key"],
                "kept_reasons": decision["kept_reasons"],
            },
        }
        kept_candidates.append(annotated)

    kept_candidates.sort(
        key=lambda c: (
            -float((c.extra.get("selection_triage") or {}).get("score", 0.0)),
            c.rank,
        )
    )
    for new_rank, candidate in enumerate(kept_candidates, start=1):
        candidate.rank = new_rank

    filtered_selection = SelectionResult(
        project=selection.project,
        run_id=f"{selection.run_id}_selection_triage",
        timestamp_utc=utc_now_iso(),
        selection_strategy_id=f"{selection.selection_strategy_id}:selection_triage",
        candidates=kept_candidates,
    )
    write_json(out_dir / "filtered_candidates.json", filtered_selection.to_dict())

    report = {
        "schema_version": "selection_triage_v1",
        "selection_file": str(selection_file),
        "project": selection.project,
        "output_dir": str(out_dir),
        "source_run_id": selection.run_id,
        "source_selection_strategy_id": selection.selection_strategy_id,
        "generated_run_id": filtered_selection.run_id,
        "timestamp_utc": utc_now_iso(),
        "config": config.to_dict(),
        "summary": _build_selection_triage_summary(selection, kept_candidates, decisions),
        "decisions": decisions,
    }
    write_json(out_dir / "selection_triage_report.json", report)
    return report


def _default_selection_triage_output_dir(project: str) -> Path:
    return runs_root() / "quality_control" / "selection_triage" / project / new_run_id("selection_triage")


def _evaluate_candidate(
    candidate: SelectionCandidate,
    config: SelectionTriageConfig,
    file_counts: Counter[str],
    site_counts: Counter[str],
) -> dict[str, Any]:
    extra = candidate.extra or {}
    checkpoint = extra.get("checkpoint") or {}
    operation = extra.get("operation") or {}
    evidence = extra.get("evidence") or {}

    repo_path = candidate.repo_path
    checkpoint_file = checkpoint.get("file") or ""
    operation_type = operation.get("type") or ""
    checkpoint_scope = evidence.get("checkpoint_scope") or "none"
    call_hops = int(evidence.get("call_hops") or 0)
    module_crossings = int(evidence.get("module_crossings") or 0)
    path_bucket = _classify_path_bucket(repo_path)
    checkpoint_bucket = _classify_path_bucket(checkpoint_file) if checkpoint_file else "missing"
    checkpoint_present = bool(checkpoint_file)
    checkpoint_same_file = checkpoint_file == repo_path if checkpoint_file else False
    site_key = _site_key(candidate)

    rejected: list[str] = []
    kept_reasons: list[str] = []

    if path_bucket not in config.include_path_buckets:
        rejected.append(f"path_bucket:{path_bucket}")
    if checkpoint_bucket in config.exclude_checkpoint_path_buckets:
        rejected.append(f"checkpoint_path_bucket:{checkpoint_bucket}")
    if config.require_checkpoint and not checkpoint_present:
        rejected.append("missing_checkpoint")
    if config.require_checkpoint_text and not (checkpoint.get("text") or "").strip():
        rejected.append("missing_checkpoint_text")
    if (not config.allow_missing_checkpoint_scope) and checkpoint_scope == "none":
        rejected.append("missing_checkpoint_scope")
    if checkpoint_scope not in config.allowed_checkpoint_scopes:
        rejected.append(f"checkpoint_scope:{checkpoint_scope}")
    if (not config.allow_cross_file_checkpoint) and checkpoint_present and not checkpoint_same_file:
        rejected.append("cross_file_checkpoint")
    if config.max_call_hops is not None and call_hops > config.max_call_hops:
        rejected.append(f"call_hops>{config.max_call_hops}")
    if config.max_module_crossings is not None and module_crossings > config.max_module_crossings:
        rejected.append(f"module_crossings>{config.max_module_crossings}")
    if operation_type in config.blocked_operation_types:
        rejected.append(f"blocked_operation:{operation_type}")
    if site_counts[site_key] >= config.max_candidates_per_site:
        rejected.append("site_quota_exhausted")
    if file_counts[repo_path] >= config.max_candidates_per_file:
        rejected.append("file_quota_exhausted")

    score = _score_candidate(
        candidate=candidate,
        path_bucket=path_bucket,
        checkpoint_present=checkpoint_present,
        checkpoint_same_file=checkpoint_same_file,
        checkpoint_scope=checkpoint_scope,
        call_hops=call_hops,
        module_crossings=module_crossings,
        config=config,
    )
    if checkpoint_present:
        kept_reasons.append("checkpoint_present")
    if checkpoint_same_file:
        kept_reasons.append("checkpoint_same_file")
    if path_bucket == "prod":
        kept_reasons.append("production_path")
    if checkpoint_scope in {"dominates", "conditional"}:
        kept_reasons.append(f"scope:{checkpoint_scope}")

    return {
        "candidate_id": candidate.candidate_id,
        "repo_path": repo_path,
        "symbol": candidate.symbol,
        "cwe_id": candidate.cwe_id,
        "path_bucket": path_bucket,
        "site_key": site_key,
        "score": round(score, 4),
        "kept": not rejected,
        "rejected_reasons": rejected,
        "kept_reasons": kept_reasons,
        "features": {
            "checkpoint_present": checkpoint_present,
            "checkpoint_same_file": checkpoint_same_file,
            "checkpoint_scope": checkpoint_scope,
            "call_hops": call_hops,
            "module_crossings": module_crossings,
            "difficulty": extra.get("difficulty", ""),
            "operation_type": operation_type,
            "path_bucket": path_bucket,
            "checkpoint_path_bucket": checkpoint_bucket,
        },
    }


def _score_candidate(
    *,
    candidate: SelectionCandidate,
    path_bucket: str,
    checkpoint_present: bool,
    checkpoint_same_file: bool,
    checkpoint_scope: str,
    call_hops: int,
    module_crossings: int,
    config: SelectionTriageConfig,
) -> float:
    weights = config.score_weights
    score = float(candidate.confidence) * weights.get("confidence", 0.0)
    if checkpoint_present:
        score += weights.get("checkpoint_present", 0.0)
    if checkpoint_same_file:
        score += weights.get("checkpoint_same_file", 0.0)
    score += weights.get(f"path_bucket_{path_bucket}", 0.0)
    score += weights.get(f"scope_{checkpoint_scope}", 0.0)
    difficulty = (candidate.extra or {}).get("difficulty") or ""
    if difficulty:
        score += weights.get(f"difficulty_{difficulty}", 0.0)
    score += call_hops * weights.get("call_hops_penalty", 0.0)
    score += module_crossings * weights.get("module_crossings_penalty", 0.0)
    if checkpoint_present and not checkpoint_same_file:
        score += weights.get("cross_file_checkpoint_penalty", 0.0)
    return score


def _site_key(candidate: SelectionCandidate) -> str:
    extra = candidate.extra or {}
    checkpoint = extra.get("checkpoint") or {}
    operation = extra.get("operation") or {}
    parts = [
        candidate.repo_path,
        candidate.symbol,
        checkpoint.get("type") or "none",
        operation.get("type") or "none",
    ]
    return "::".join(parts)


def _classify_path_bucket(path: str) -> str:
    lowered = path.lower()
    if "/tests/" in lowered or lowered.startswith("tests/") or "test_" in lowered:
        return "test"
    if lowered.startswith("examples/") or "/examples/" in lowered:
        return "example"
    return "prod"


def _build_selection_triage_summary(
    selection: SelectionResult,
    kept: list[SelectionCandidate],
    decisions: list[dict[str, Any]],
) -> dict[str, Any]:
    reject_counts: Counter[str] = Counter()
    bucket_counts: Counter[str] = Counter()
    kept_bucket_counts: Counter[str] = Counter()
    for decision in decisions:
        bucket_counts[decision["path_bucket"]] += 1
        if decision["kept"]:
            kept_bucket_counts[decision["path_bucket"]] += 1
        for reason in decision["rejected_reasons"]:
            reject_counts[reason] += 1

    return {
        "input_candidates": len(selection.candidates),
        "kept_candidates": len(kept),
        "rejected_candidates": len(selection.candidates) - len(kept),
        "path_bucket_counts": dict(bucket_counts),
        "kept_path_bucket_counts": dict(kept_bucket_counts),
        "top_rejection_reasons": dict(reject_counts.most_common(20)),
    }


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
