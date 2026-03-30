"""
CodeQLStrategy — taint-tracking-based vulnerability candidate selection.

Uses CodeQL's semantic analysis (inter-procedural taint tracking, resolved
call graphs, data-flow) to find checkpoint × operation pairs with verified
data flow. Produces SelectionCandidate objects compatible with the same
downstream injection pipeline as the static_analysis strategy.

Usage:
    uv run vuljector selection <project> codeql
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from selector.base import SelectionRequest, SelectionStrategy
from selector.codeql.db import create_or_reuse_db, codeql_language, get_db_root
from selector.codeql.executor import run_queries
from selector.codeql.installer import find_codeql_cli
from selector.codeql.mapping import map_results
from setup.container_runtime import ContainerRuntime
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso

logger = logging.getLogger(__name__)


class CodeQLStrategy(SelectionStrategy):
    """
    Selection strategy that builds a CodeQL database and runs taint-tracking
    queries to find injection candidates with verified data flow.

    Advantages over static_analysis:
    - Inter-procedural taint tracking: verifies the same variable flows
      from the checkpoint to the dangerous sink.
    - Resolved call graph: no short-name mismatches.
    - Type-aware sink detection: catches ORM / framework calls the regex
      plugins might miss.

    Trade-offs:
    - Requires CodeQL CLI on the host (~400MB).
    - DB creation: 1-4 min (Python/JS), 10-30 min (C/C++ with Docker build).
    - Results are a subset of static_analysis candidates — higher precision,
      lower recall.
    """

    @property
    def id(self) -> str:
        return "codeql"

    def setup(self, runtime: ContainerRuntime) -> None:
        """
        Verify CodeQL CLI is available and clone the source repo locally
        (same as static_analysis — source must be on the host for DB creation).
        """
        # Verify CLI early so the user gets a helpful error before cloning.
        cli = find_codeql_cli()
        logger.info("CodeQL CLI found at %s", cli)

        # Clone repo if not already present (mirrors static_analysis.setup)
        url = (getattr(runtime, "repos", {}) or {}).get(runtime.target_dir, "")
        if not url:
            logger.warning(
                "[%s] No repo URL in runtime.repos for target_dir=%r — "
                "CodeQL analysis may fail if source is not on host.",
                runtime.project, runtime.target_dir,
            )
            return

        clone_dest = runtime.workspace_dir / runtime.target_dir
        if clone_dest.is_dir():
            return

        logger.info("[%s] Cloning %s → %s", runtime.project, url, clone_dest)
        subprocess.run(["git", "clone", url, str(clone_dest)], check=True)

        commit = getattr(runtime, "secure_base_commit", "") or ""
        if commit:
            logger.info("[%s] Checking out %s", runtime.project, commit)
            subprocess.run(["git", "-C", str(clone_dest), "checkout", commit], check=True)

    def run(
        self,
        runtime: ContainerRuntime,
        request: Any,
    ) -> SelectionResult:
        cli = find_codeql_cli()
        repo_path = _resolve_repo_path(runtime, request)

        # Detect primary language (reuse static_analysis classifier)
        language = _detect_language(repo_path)
        if language is None:
            logger.warning(
                "[%s] No CodeQL-supported language detected — returning empty results.",
                runtime.project,
            )
            return SelectionResult(
                schema_version="v2",
                project=request.project,
                run_id=request.run_id,
                timestamp_utc=utc_now_iso(),
                selection_strategy_id=self.id,
                candidates=[],
            )
        codeql_lang = codeql_language(language)

        # Locate the DB root alongside the workspace
        runs_dir = repo_path.parent.parent.parent  # workspace/<project>/<target> → runs/
        db_root = get_db_root(runs_dir)

        # Optional build command from project config (for C/C++)
        build_command = _get_build_command(runtime)

        # Create or reuse database
        db_path = create_or_reuse_db(
            cli=cli,
            source_root=repo_path,
            language=language,
            db_root=db_root,
            project=runtime.project,
            build_command=build_command,
        )

        # Run queries
        raw_results = run_queries(
            cli=cli,
            db_path=db_path,
            language=codeql_lang,
            project=runtime.project,
        )

        # Map to SelectionCandidates
        candidates = map_results(raw_results, repo_path, runtime.project)

        # Apply CWE filters from request
        filters = getattr(request, "filters", {}) or {}
        cwe_ids = set(filters.get("cwe_ids", []))
        cwe_groups = set(filters.get("cwe_groups", []))
        if cwe_ids or cwe_groups:
            candidates = [
                c for c in candidates
                if (not cwe_ids or c.cwe_id in cwe_ids)
                or (not cwe_groups or c.cwe_group in cwe_groups)
            ]

        # Re-rank after filtering
        for rank, c in enumerate(candidates, start=1):
            c.rank = rank

        return SelectionResult(
            schema_version="v2",
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _resolve_repo_path(runtime: ContainerRuntime, request: Any) -> Path:
    """Return the host-side repo path, mirroring static_analysis._resolve_repo_path."""
    target_dir = getattr(request, "target_dir", None) or getattr(runtime, "target_dir", None) or ""
    workspace = getattr(runtime, "workspace_dir", None)

    if workspace and target_dir:
        candidate = Path(workspace) / target_dir
        if candidate.is_dir():
            return candidate

        # Lazy clone
        url = (getattr(runtime, "repos", {}) or {}).get(target_dir, "")
        if url:
            logger.info("[%s] Cloning %s → %s", runtime.project, url, candidate)
            subprocess.run(["git", "clone", url, str(candidate)], check=True)
            commit = getattr(runtime, "secure_base_commit", "") or ""
            if commit:
                subprocess.run(["git", "-C", str(candidate), "checkout", commit], check=True)
        if candidate.is_dir():
            return candidate

    raise RuntimeError(
        f"Cannot resolve repo path for target_dir={target_dir!r}. "
        "Ensure repos[target_dir] is set in project.json."
    )


def _detect_language(repo_path: Path) -> str | None:
    """
    Detect the primary language of a repo by file extension counts.
    Returns a CodeQL-supported Vuljector language label: 'python', 'javascript', or 'cpp'.
    Returns None if the language cannot be determined or is not supported by CodeQL.
    """
    from selector.static_analysis.classifier import classify_repo
    try:
        profile = classify_repo(repo_path)
        lang = profile.primary_language
        if lang in ("javascript", "js", "typescript", "ts"):
            return "javascript"
        if lang in ("c", "cpp", "c++"):
            return "cpp"
        if lang == "python":
            return "python"
        logger.warning(
            "[%s] Primary language %r is not supported by CodeQL — skipping.",
            repo_path.name, lang,
        )
        return None
    except Exception:
        logger.warning("Language detection failed for %s — skipping.", repo_path)
        return None


def _get_build_command(runtime: ContainerRuntime) -> list[str] | None:
    """
    Return a build command for compiled languages if specified in the project config.

    Looks for a 'codeql_build_command' key inside the unit_tests or a top-level
    'codeql' config block in project.json. Returns None if not set.
    """
    # ProjectConfig is stored on the runtime; check common locations.
    config = getattr(runtime, "_config", None) or getattr(runtime, "config", None)
    if config is None:
        return None

    # Check for explicit codeql config block: {"codeql": {"build_command": [...]}}
    codeql_cfg = getattr(config, "codeql", None) or {}
    if isinstance(codeql_cfg, dict):
        cmd = codeql_cfg.get("build_command")
        if cmd:
            return cmd if isinstance(cmd, list) else cmd.split()

    return None
