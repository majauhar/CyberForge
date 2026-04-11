"""CVE selection strategy — discover and rank CVEs from OSV.dev."""

from __future__ import annotations

import logging
from typing import Any

from injector.cve_inject.cve_fetcher import prepare_cve_candidates
from selector.base import SelectionStrategy
from setup.container_runtime import ContainerRuntime
from vuljector.core import load_project_config
from vuljector.io_contracts import SelectionCandidate, SelectionResult, utc_now_iso

logger = logging.getLogger(__name__)

_MAX_RETRIES_PER_CVE = 3


class CVESelectStrategy(SelectionStrategy):
    """
    Selection via CVE discovery from OSV.dev.

    Discovers real CVEs affecting the project, ranks by severity,
    fetches fixing commit diffs, and prepares candidates for CVE-guided injection.
    """

    @property
    def id(self) -> str:
        return "cve_select"

    def setup(self, runtime: ContainerRuntime) -> None:
        pass

    def run(self, runtime: ContainerRuntime, request: Any) -> SelectionResult:
        project = request.project
        max_candidates = getattr(request, "max_candidates", 10) or 10

        config = load_project_config(project)

        # Discover and prepare CVEs
        cve_list = prepare_cve_candidates(
            main_repo_url=config.main_repo_url,
            language=config.language,
            project=project,
            max_cves=max_candidates,
        )

        if not cve_list:
            logger.warning("[%s] No CVEs with resolvable fix diffs found", project)
            candidates = []
        else:
            candidates = [_cve_to_candidate(cve, rank) for rank, cve in enumerate(cve_list)]
            logger.info("[%s] Prepared %d CVE candidates", project, len(candidates))

        return SelectionResult(
            project=project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            selection_strategy_id=self.id,
            candidates=candidates,
        )


def _cve_to_candidate(cve, rank: int) -> SelectionCandidate:
    """Convert CVEData to SelectionCandidate."""
    cwe_id = cve.cwes[0] if cve.cwes else ""
    return SelectionCandidate(
        candidate_id=cve.cve_id or cve.vuln_id,
        rank=rank,
        cwe_group="",
        cwe_id=cwe_id,
        repo_path="",
        symbol="",
        location_hint=cve.description[:100],
        rationale=f"CVE fix diff from {cve.fix_commit_sha[:8]}",
        confidence=0.8,
        language="",
        extra={
            "cve_id": cve.cve_id,
            "cve_description": cve.description,
            "cvss": cve.cvss,
            "severity": cve.severity,
            "published": cve.published,
            "cwes": cve.cwes,
            "fix_commit_sha": cve.fix_commit_sha,
            "fix_diff": cve.fix_diff,
            "retry_limit": _MAX_RETRIES_PER_CVE,
            "queue_key": cve.cve_id or cve.vuln_id,
        },
    )
