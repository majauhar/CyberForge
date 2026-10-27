"""
StaticAnalysisStrategy — checkpoint × operation cross-product pipeline.

Runs the full 7-stage static analysis pipeline on the project source tree
and maps VulnCandidate results into SelectionCandidate objects.
"""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Directory segments and filename markers that indicate NON-library code
# (fuzz harnesses, tests, examples, vendored deps). Injecting there yields
# unrealistic vulnerabilities in test scaffolding rather than real library
# functions, so these are excluded from selection candidates by default.
_EXCLUDE_DIR_SEGMENTS = {
    "fuzz", "fuzzing", "fuzzer", "fuzzers", "ossfuzz", "oss-fuzz",
    "test", "tests", "testing", "unittest", "unittests",
    "example", "examples", "sample", "samples", "demo", "demos",
    "bench", "benchmark", "benchmarks",
    "doc", "docs", "third_party", "thirdparty", "external", "extern",
    "vendor", "contrib", "deps",
}
_EXCLUDE_NAME_SUBSTRINGS = ("fuzz", "harness", "llvmfuzzer")


def _is_excluded_source(path: str) -> bool:
    """True if a candidate file is a fuzz harness / test / example (not library code)."""
    p = (path or "").replace("\\", "/").lower()
    if not p:
        return False
    parts = p.split("/")
    if any(seg in _EXCLUDE_DIR_SEGMENTS for seg in parts[:-1]):
        return True
    name = parts[-1]
    stem = name.rsplit(".", 1)[0]
    if any(sub in name for sub in _EXCLUDE_NAME_SUBSTRINGS):
        return True
    if stem.startswith("test") or stem.endswith("test") or "_test" in stem or "test_" in stem:
        return True
    return False


from selector.base import SelectionStrategy
from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso

# Pipeline lives as a sibling package inside this directory.
from selector.static_analysis.pipeline import run as run_pipeline


class StaticAnalysisStrategy(SelectionStrategy):
    """
    Selection via regex-based static analysis (no LLM required).

    The pipeline runs on the host against the repo path obtained from the
    container runtime's workspace mount. It does not need the container's
    build environment — it is pure Python AST + regex analysis.
    """

    @property
    def id(self) -> str:
        return "static_analysis"

    def setup(self, runtime: ContainerRuntime) -> None:
        """Clone the project source locally so static analysis can run on the host."""
        url = (getattr(runtime, "main_repo_url", "") or "").strip()
        if not url:
            logger.warning(
                "[%s] No repo URL for target_dir=%r (set main_repo_url in project.json) — "
                "static analysis may fail if source is not already on host.",
                runtime.project, runtime.target_dir,
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

    def run(
        self,
        runtime: ContainerRuntime,
        request: Any,
    ) -> SelectionResult:
        from vuljector.io_contracts import SelectionResult

        repo_path = _resolve_repo_path(runtime, request)
        filters = getattr(request, "filters", {}) or {}
        # top_n=None returns all candidates — static analysis is a one-time mine of all locations.
        pipeline_output = run_pipeline(
            repo_path=str(repo_path),
            top_n=None,
        )

        candidates = _map_candidates(pipeline_output.candidates)

        # Exclude fuzz-harness / test / example files so injections land in real
        # library source. Override with VULJECTOR_SELECTION_INCLUDE_HARNESS=1.
        if os.environ.get("VULJECTOR_SELECTION_INCLUDE_HARNESS", "").lower() not in ("1", "true", "yes"):
            filtered = [c for c in candidates if not _is_excluded_source(c.repo_path)]
            dropped = len(candidates) - len(filtered)
            if filtered:
                if dropped:
                    logger.info(
                        "[%s] static_analysis: excluded %d harness/test/example candidates; %d library candidates remain",
                        getattr(request, "project", "?"), dropped, len(filtered),
                    )
                candidates = filtered
            elif candidates:
                logger.warning(
                    "[%s] static_analysis: harness/test filter removed ALL %d candidates; keeping unfiltered "
                    "(set VULJECTOR_SELECTION_INCLUDE_HARNESS=1 to silence)",
                    getattr(request, "project", "?"), len(candidates),
                )

        # Apply CWE filters if requested.
        cwe_ids = set(filters.get("cwe_ids", []))
        cwe_groups = set(filters.get("cwe_groups", []))
        if cwe_ids or cwe_groups:
            candidates = [
                c for c in candidates
                if (not cwe_ids or c.cwe_id in cwe_ids)
                or (not cwe_groups or c.cwe_group in cwe_groups)
            ]

        max_cand = getattr(request, "max_candidates", None)
        if max_cand is not None:
            candidates = candidates[:max_cand]

        return SelectionResult(
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )


def _resolve_repo_path(runtime: ContainerRuntime, request: Any) -> Path:
    """
    Return the repo path on the host, cloning it lazily if needed.

    Source lives inside the Docker image at /src/<target_dir> and is not
    volume-mounted. We clone it locally into workspace_dir/<target_dir> using
    runtime.main_repo_url, then checkout secure_base_commit.
    """
    target_dir = getattr(request, "target_dir", None) or getattr(runtime, "target_dir", None) or ""
    workspace = getattr(runtime, "workspace_dir", None)

    if workspace and target_dir:
        candidate = Path(workspace) / target_dir
        if not candidate.is_dir():
            # Clone lazily — safe to call even if is_strategy_setup_done skipped setup().
            url = (getattr(runtime, "main_repo_url", "") or "").strip()
            if url:
                logger.info("[%s] Cloning %s → %s", runtime.project, url, candidate)
                subprocess.run(["git", "clone", url, str(candidate)], check=True)
                commit = getattr(runtime, "secure_base_commit", "") or ""
                if commit:
                    logger.info("[%s] Checking out %s", runtime.project, commit)
                    subprocess.run(["git", "-C", str(candidate), "checkout", commit], check=True)
        if candidate.is_dir():
            return candidate

    raise RuntimeError(
        f"Cannot resolve repo path for target_dir={target_dir!r}. "
        "Ensure main_repo_url in project.json so the source can be cloned."
    )


def _map_candidates(vuln_candidates: list) -> list[SelectionCandidate]:
    """
    Map VulnCandidate objects from the static analysis pipeline to
    SelectionCandidate objects for the io_contracts layer.

    Field mapping:
      injection_hint   → location_hint
      function         → symbol
      cwe_candidates[0] → cwe_id  (first = primary)
      cwe_groups[0]    → cwe_group
      complexity_score → confidence (inverted + normalised: lower complexity
                         = higher injectability confidence)
      everything else  → extra{}
    """
    results: list[SelectionCandidate] = []
    max_score = max((c.complexity_score for c in vuln_candidates), default=1.0) or 1.0

    for rank, vc in enumerate(vuln_candidates, start=1):
        cwe_candidates: list[str] = getattr(vc, "cwe_candidates", []) or []
        cwe_groups: list[str] = getattr(vc, "cwe_groups", []) or []
        score: float = getattr(vc, "complexity_score", 0.0) or 0.0

        extra: dict = {
            "complexity_score": score,
            "difficulty": getattr(vc, "difficulty", ""),
            "strategy": getattr(vc, "strategy", ""),
            "call_path": getattr(vc, "call_path", []),
            "cwe_candidates": cwe_candidates,
            "evidence": getattr(vc, "evidence", {}),
        }
        checkpoint = getattr(vc, "checkpoint", None)
        if checkpoint is not None:
            extra["checkpoint"] = (
                checkpoint.to_dict() if hasattr(checkpoint, "to_dict")
                else vars(checkpoint)
            )
        operation = getattr(vc, "operation", None)
        if operation is not None:
            extra["operation"] = (
                operation.to_dict() if hasattr(operation, "to_dict")
                else vars(operation)
            )

        line_range = getattr(vc, "line_range", None)
        if line_range and not isinstance(line_range, tuple):
            line_range = tuple(line_range)

        results.append(SelectionCandidate(
            candidate_id=f"sa_{rank:04d}",
            rank=rank,
            cwe_id=cwe_candidates[0] if cwe_candidates else "CWE-20",
            cwe_group=cwe_groups[0] if cwe_groups else "Input Validation",
            repo_path=getattr(vc, "file", ""),
            symbol=getattr(vc, "function", ""),
            location_hint=getattr(vc, "injection_hint", ""),
            rationale=f"static_analysis: {getattr(vc, 'strategy', '')} "
                      f"(score={score:.1f}, {extra['difficulty']})",
            # Invert: low complexity = high confidence of successful injection.
            confidence=round(1.0 - (score / max_score), 4),
            language=getattr(vc, "language", "python"),
            line_range=line_range,
            extra=extra,
        ))

    return results
