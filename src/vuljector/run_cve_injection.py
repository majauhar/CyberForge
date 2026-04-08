"""CVE-inspired injection: fetch CVEs, synthesise candidates, run injection."""

from __future__ import annotations

import logging

from injector.cve_inject.cve_fetcher import CVEData, prepare_cve_candidates
from utils.json_io import write_json
from utils.paths import new_run_id, selection_run_dir
from vuljector.core import load_project_config
from vuljector.io_contracts import SelectionCandidate, utc_now_iso
from vuljector.run_injection import run_injection

logger = logging.getLogger(__name__)

_MAX_RETRIES_PER_CVE = 3


def _cve_to_candidate(cve: CVEData, rank: int) -> SelectionCandidate:
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
        language="",  # resolved at injection time from runtime.language
        extra={
            "strategy": "cve_inject",
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


def run_cve_injection(
    *,
    project: str,
    model_id: str,
    num_vulnerabilities: int = 1,
    max_cves: int = 10,
    debug: bool = False,
) -> dict:
    """
    Prepare an ordered usable CVE list for the project, then run injection with
    the cve_inject strategy.
    """
    config = load_project_config(project)
    cve_list = prepare_cve_candidates(
        main_repo_url=config.main_repo_url,
        language=config.language,
        project=project,
        max_cves=max_cves,
    )
    if not cve_list:
        raise ValueError(f"No CVEs with resolvable fix diffs found for '{project}'")

    target_vulnerabilities = min(num_vulnerabilities, len(cve_list))
    logger.info("[%s] %d ordered CVE candidates prepared; running injection ...", project, len(cve_list))
    candidates = [_cve_to_candidate(cve, rank) for rank, cve in enumerate(cve_list)]

    # Write a synthetic candidates.json so the standard run_injection() can consume it.
    sel_run_id = new_run_id("cve_select")
    sel_dir = selection_run_dir(project, sel_run_id)
    sel_dir.mkdir(parents=True, exist_ok=True)
    write_json(sel_dir / "candidates.json", {
        "project": project,
        "run_id": sel_run_id,
        "timestamp_utc": utc_now_iso(),
        "selection_strategy_id": "cve_fetch",
        "candidates": [c.to_dict() for c in candidates],
    })
    candidates_file = str(sel_dir / "candidates.json")

    return run_injection(
        project=project,
        strategy_id="cve_inject",
        model_id=model_id,
        candidates_file=candidates_file,
        num_vulnerabilities=target_vulnerabilities,
        debug=debug,
    )
