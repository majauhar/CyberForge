"""Generate a CVE report for an existing vulnerability."""

from __future__ import annotations

import logging
from pathlib import Path

from setup.lifecycle import finish_phase, start_phase
from utils.json_io import read_json
from utils.paths import project_root
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.cve_report import generate_cve_report, write_cve_report

logger = logging.getLogger(__name__)

_REQUIRED_FILES = [
    "vulnerability_metadata.json",
    "patch.diff",
    "exploit_files",
]


def run_cve_report(
    *,
    project: str,
    vulnerability_id: str,
    model_id: str,
) -> dict:
    """Generate and write a CVE report for an existing vulnerability.

    The vulnerability must live under
    ``vuljector-projects/<project>/vulnerabilities/<vulnerability_id>/``
    and contain the required files produced by the injection phase.
    """
    vuln_dir = project_root(project) / "vulnerabilities" / vulnerability_id
    _validate_vulnerability_dir(vuln_dir, project, vulnerability_id)

    metadata = read_json(vuln_dir / "vulnerability_metadata.json")
    patch_diff = (vuln_dir / "patch.diff").read_text(encoding="utf-8")
    exploit_script = _read_exploit_script(vuln_dir)

    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)

    start_phase(runtime, phase="cve_report", run_dir=vuln_dir)
    try:
        cve_json = generate_cve_report(
            runtime=runtime,
            project=project,
            vulnerability_id=vulnerability_id,
            model_id=model_id,
            patch_diff=patch_diff,
            exploit_script=exploit_script,
            intended_cwe_group=metadata.get("cwe_group", ""),
            intended_cwe_id=metadata.get("cwe_id", ""),
        )
    finally:
        finish_phase(runtime)

    if not cve_json:
        raise RuntimeError(
            f"[{project}] CVE report generation failed for {vulnerability_id}"
        )

    write_cve_report(vuln_dir, cve_json)
    logger.info("[%s] CVE report written to %s", project, vuln_dir / "cve_report.json")
    return {"project": project, "vulnerability_id": vulnerability_id, "cve_report": str(vuln_dir / "cve_report.json")}


# ── Internal helpers ──────────────────────────────────────────────────────────

def _validate_vulnerability_dir(vuln_dir: Path, project: str, vulnerability_id: str) -> None:
    if not vuln_dir.exists():
        raise FileNotFoundError(
            f"Vulnerability directory not found: {vuln_dir}\n"
            f"Expected: vuljector-projects/{project}/vulnerabilities/{vulnerability_id}/"
        )
    missing = [f for f in _REQUIRED_FILES if not (vuln_dir / f).exists()]
    if missing:
        raise FileNotFoundError(
            f"Missing required files in {vuln_dir}: {', '.join(missing)}"
        )


def _read_exploit_script(vuln_dir: Path) -> str:
    exploit_dir = vuln_dir / "exploit_files"
    for candidate in ("attack.py", "exploit.py"):
        path = exploit_dir / candidate
        if path.exists():
            return path.read_text(encoding="utf-8")
    # Fall back to any .py file present
    py_files = sorted(exploit_dir.glob("*.py"))
    if py_files:
        return py_files[0].read_text(encoding="utf-8")
    return ""
