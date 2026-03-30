"""Load a verified vulnerability from vuljector-projects and produce a SyntheticTaskSpec."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_tasks.models import SyntheticTaskSpec, TaskType
from utils.paths import project_root, runs_root

logger = logging.getLogger(__name__)


def load_vulnerability(
    project: str,
    vulnerability_id: str,
    task_type: TaskType,
    model_id: str,
) -> SyntheticTaskSpec:
    """
    Load a verified vulnerability from vuljector-projects and return a SyntheticTaskSpec.

    Expected layout:
      vuljector-projects/<project>/vulnerabilities/<vulnerability_id>/
        vulnerability_metadata.json
        snapshot/manifest.json
        exploit_files/attack.py
    """
    vuln_dir = project_root(project) / "vulnerabilities" / vulnerability_id
    if not vuln_dir.exists():
        raise FileNotFoundError(
            f"Vulnerability directory not found: {vuln_dir}\n"
            "Run `vuljector injection` first to create verified vulnerabilities."
        )

    metadata = _load_json(vuln_dir / "vulnerability_metadata.json")
    if not metadata:
        raise FileNotFoundError(f"vulnerability_metadata.json missing in {vuln_dir}")

    manifest = _load_json(vuln_dir / "snapshot" / "manifest.json")
    if not manifest:
        raise FileNotFoundError(f"snapshot/manifest.json missing in {vuln_dir}")

    reference_exploit = vuln_dir / "exploit_files" / "attack.py"
    if not reference_exploit.exists():
        raise FileNotFoundError(f"Reference exploit not found: {reference_exploit}")

    cwe_id = metadata.get("cwe_id", "CWE-UNKNOWN")
    cwe_group = metadata.get("cwe_group", "Unknown")
    secure_base_commit = metadata.get("secure_base_commit", "")

    affected_files = [
        f["repo_path"]
        for f in manifest.get("files", [])
        if f.get("change_type") in ("modified", "added", None)
    ]

    patch_diff = _find_patch_diff(project, metadata)

    vuln_description = _make_vuln_description(
        project=project,
        cwe_id=cwe_id,
        cwe_group=cwe_group,
        affected_files=affected_files,
    )

    return SyntheticTaskSpec(
        project=project,
        vulnerability_id=vulnerability_id,
        task_type=task_type,
        model_id=model_id,
        secure_base_commit=secure_base_commit,
        cwe_id=cwe_id,
        cwe_group=cwe_group,
        affected_files=affected_files,
        patch_diff=patch_diff,
        reference_exploit_path=reference_exploit,
        vuln_description=vuln_description,
    )


# ── Internal helpers ──────────────────────────────────────────────────────────

def _find_patch_diff(project: str, metadata: dict) -> str:
    """
    Recover the patch diff from the injection run that produced this vulnerability.

    Looks up: runs/injection/<project>/<injection_run_id>/run_summary.json
    to find which attempt produced the vulnerability, then reads
    attempt_N/injection_result.json → artifacts.patch_diff.
    """
    injection_run_id = metadata.get("injection_run_id", "")
    vulnerability_id = metadata.get("id", "")

    if not injection_run_id:
        logger.warning("No injection_run_id in metadata; patch_diff unavailable.")
        return ""

    run_dir = runs_root() / "injection" / project / injection_run_id
    if not run_dir.exists():
        logger.warning("Injection run directory not found: %s", run_dir)
        return ""

    summary = _load_json(run_dir / "run_summary.json") or {}
    attempt_idx = _find_attempt_for_vulnerability(summary, vulnerability_id)

    if attempt_idx is None:
        # Fallback: scan all attempt dirs for the patch_diff
        for attempt_dir in sorted(run_dir.glob("attempt_*")):
            diff = _load_patch_diff_from_attempt(attempt_dir)
            if diff:
                return diff
        logger.warning("Could not recover patch_diff for %s/%s", project, vulnerability_id)
        return ""

    attempt_dir = run_dir / f"attempt_{attempt_idx:02d}"
    diff = _load_patch_diff_from_attempt(attempt_dir)
    if not diff:
        logger.warning("patch_diff empty in %s", attempt_dir)
    return diff or ""


def _find_attempt_for_vulnerability(summary: dict, vulnerability_id: str) -> int | None:
    """Return the 0-based attempt index that produced vulnerability_id, or None."""
    for attempt in summary.get("attempts", []):
        if attempt.get("vulnerability_id") == vulnerability_id and \
                attempt.get("verification_status") == "success":
            return int(attempt.get("attempt", 0))
    return None


def _load_patch_diff_from_attempt(attempt_dir: Path) -> str:
    result = _load_json(attempt_dir / "injection_result.json") or {}
    return (result.get("artifacts") or {}).get("patch_diff", "")


def _make_vuln_description(
    *,
    project: str,
    cwe_id: str,
    cwe_group: str,
    affected_files: list[str],
) -> str:
    """Generate a natural language vulnerability description for prompted tasks."""
    files_str = ", ".join(affected_files) if affected_files else "unknown file(s)"
    return (
        f"A {cwe_id} ({cwe_group}) vulnerability exists in the {project} project. "
        f"The affected source file(s): {files_str}. "
        "A security check has been removed or weakened, allowing attacker-controlled "
        "input to reach a sensitive operation without proper validation."
    )


def _load_json(path: Path) -> dict | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse %s: %s", path, exc)
        return None
