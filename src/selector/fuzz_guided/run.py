"""Fuzz-guided selection via a harness-first fuzz-native planner."""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from selector.base import SelectionStrategy
from selector.fuzz_guided.planner import plan_fuzz_guided_candidates
from selector.fuzz_guided.surface import load_project_fuzz_surface
from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso


logger = logging.getLogger(__name__)


class FuzzGuidedStrategy(SelectionStrategy):
    @property
    def id(self) -> str:
        return "fuzz_guided"

    def setup(self, runtime: ContainerRuntime) -> None:
        _ensure_repo_checkout(runtime)

    def run(self, runtime: ContainerRuntime, request: Any) -> SelectionResult:
        repo_path = _resolve_repo_path(runtime, request)
        surface = load_project_fuzz_surface(request.project)
        candidates = plan_fuzz_guided_candidates(
            project=request.project,
            repo_root=repo_path,
            surface=surface,
            max_candidates=None,
        )
        candidates = _rank_candidates(candidates)

        filters = getattr(request, "filters", {}) or {}
        cwe_ids = set(filters.get("cwe_ids", []))
        cwe_groups = set(filters.get("cwe_groups", []))
        if cwe_ids or cwe_groups:
            candidates = [
                candidate for candidate in candidates
                if (not cwe_ids or candidate.cwe_id in cwe_ids)
                or (not cwe_groups or candidate.cwe_group in cwe_groups)
            ]

        max_candidates = getattr(request, "max_candidates", None)
        if max_candidates is not None:
            candidates = candidates[:max_candidates]
        for rank, candidate in enumerate(candidates, start=1):
            candidate.rank = rank

        return SelectionResult(
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )


def _ensure_repo_checkout(runtime: ContainerRuntime) -> None:
    url = (getattr(runtime, "main_repo_url", "") or "").strip()
    if not url:
        logger.warning(
            "[%s] No repo URL for target_dir=%r; fuzz-guided selection may fail if source is absent.",
            runtime.project,
            runtime.target_dir,
        )
        return

    clone_dest = runtime.workspace_dir / runtime.target_dir
    if clone_dest.is_dir():
        logger.info("[%s] Source already cloned at %s", runtime.project, clone_dest)
        return

    logger.info("[%s] Cloning %s into %s", runtime.project, url, clone_dest)
    subprocess.run(["git", "clone", url, str(clone_dest)], check=True)
    commit = getattr(runtime, "secure_base_commit", "") or ""
    if commit:
        logger.info("[%s] Checking out secure_base_commit %s", runtime.project, commit)
        subprocess.run(["git", "-C", str(clone_dest), "checkout", commit], check=True)


def _resolve_repo_path(runtime: ContainerRuntime, request: Any) -> Path:
    target_dir = getattr(request, "target_dir", None) or getattr(runtime, "target_dir", None) or ""
    workspace = getattr(runtime, "workspace_dir", None)
    if workspace and target_dir:
        candidate = Path(workspace) / target_dir
        if not candidate.is_dir():
            _ensure_repo_checkout(runtime)
        if candidate.is_dir():
            return candidate
    raise RuntimeError(
        f"Cannot resolve repo path for target_dir={target_dir!r}. "
        "Ensure main_repo_url in project.json so the source can be cloned."
    )


def _rank_candidates(candidates: list[SelectionCandidate]) -> list[SelectionCandidate]:
    bucket_priority = {
        "high_confidence_hot_path": 0,
        "medium_confidence_hot_path": 1,
        "helper_reachable_slice": 2,
        "weak_or_coarse_match": 3,
    }
    ordered = sorted(
        candidates,
        key=lambda candidate: (
            -float(candidate.confidence or 0.0),
            bucket_priority.get(((candidate.extra.get("fuzz_native") or {}).get("hot_path_bucket") or ""), 3),
            0 if ((candidate.extra.get("fuzz_native") or {}).get("reachability_kind") == "runtime_function") else 1,
            candidate.repo_path,
            candidate.symbol,
            candidate.candidate_id,
        ),
    )
    for rank, candidate in enumerate(ordered, start=1):
        candidate.rank = rank
    return ordered
