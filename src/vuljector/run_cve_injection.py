"""CVE-inspired injection: fetch CVEs, synthesise candidates, run injection."""

from __future__ import annotations

import logging

from injector.cve_inject.cve_fetcher import CVEData, fetch_cve_candidates
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
    Fetch CVEs for the project, synthesise selection candidates, then run
    injection with the cve_inject strategy.

    Each CVE becomes one attempt; stops after num_vulnerabilities successes
    or after exhausting all resolved CVEs (up to max_cves).
    """
    config = load_project_config(project)
    cve_list = fetch_cve_candidates(
        main_repo_url=config.main_repo_url,
        language=config.language,
        project=project,
        max_cves=max_cves,
    )
    if not cve_list:
        raise ValueError(f"No CVEs with resolvable fix diffs found for '{project}'")

    logger.info("[%s] %d CVE candidates resolved; running injection ...", project, len(cve_list))

    # Build a round-robin retry list: [A, B, C, A, B, C, A, B, C] for up to
    # _MAX_RETRIES_PER_CVE passes. Suffixing the candidate_id with _rN keeps
    # attempt dirs unique while the CVE data (fix_diff, etc.) stays identical.
    # run_injection() stops as soon as num_vulnerabilities successes are reached.
    candidates: list[SelectionCandidate] = []
    for attempt in range(_MAX_RETRIES_PER_CVE):
        for cve in cve_list:
            c = _cve_to_candidate(cve, len(candidates))
            if attempt > 0:
                c.candidate_id = f"{c.candidate_id}_r{attempt}"
            candidates.append(c)

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
        num_vulnerabilities=num_vulnerabilities,
        debug=debug,
    )
