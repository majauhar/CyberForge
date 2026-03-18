"""Run injection phase independently."""

from __future__ import annotations

import shutil
from pathlib import Path

from injector.base import InjectionRequest
from injector.registry import get_injection_strategy
from setup.lifecycle import finish_phase, start_phase
from utils.github_utils import remove_git_dir, restore_git_dir
from utils.json_io import read_json, write_json
from utils.paths import (
    injection_run_dir,
    new_run_id,
    project_root,
)
from verifier import build_snapshot_from_container, run_verification
from vuljector.core import (
    build_runtime,
    ensure_setup_completed,
    load_project_config,
    next_vulnerability_id,
)
from vuljector.io_contracts import SelectionCandidate, VerificationResult, utc_now_iso


def run_injection(
    *,
    project: str,
    strategy_id: str,
    model_id: str,
    candidates_file: str,
    num_vulnerabilities: int = 1,
    debug: bool = False,
) -> dict:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)

    run_id = new_run_id("injection")
    run_dir = injection_run_dir(project, run_id)
    request_payload = {
        "schema_version": "v2",
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "selection_run_id": _selection_run_id_from_candidates(candidates_file),
        "candidates_file": candidates_file,
        "injection_strategy_id": strategy_id,
        "model_id": model_id,
        "num_vulnerabilities": num_vulnerabilities,
        "debug": debug,
    }
    write_json(run_dir / "injection_request.json", request_payload)

    candidates_payload = read_json(Path(candidates_file))
    candidates = [
        SelectionCandidate(
            candidate_id=str(c["candidate_id"]),
            rank=int(c["rank"]),
            cwe_group=str(c["cwe_group"]),
            cwe_id=str(c["cwe_id"]),
            repo_path=str(c["repo_path"]),
            symbol=str(c.get("symbol", "")),
            location_hint=str(c.get("location_hint", "")),
            rationale=str(c.get("rationale", "")),
            confidence=float(c.get("confidence", 0.5)),
        )
        for c in candidates_payload.get("candidates", [])
    ]
    if not candidates:
        raise ValueError("No candidates available in candidates_file.")
    candidate = sorted(candidates, key=lambda c: c.rank)[0]

    start_phase(runtime, phase="injection", run_dir=run_dir)
    try:
        remove_git_dir(runtime, runtime.repo_dir_in_container)
        strategy = get_injection_strategy(strategy_id)
        if not runtime.is_strategy_setup_done(phase="injection", strategy_id=strategy.id):
            strategy.setup(runtime)
            runtime.mark_strategy_setup_done(phase="injection", strategy_id=strategy.id)
        request = InjectionRequest(
            project=project,
            run_id=run_id,
            strategy_id=strategy_id,
            model_id=model_id,
            num_vulnerabilities=num_vulnerabilities,
            debug=debug,
        )
        injection_result = strategy.run(runtime, request, candidate)
        write_json(run_dir / "injection_result.json", injection_result.to_dict())

        git_backup_dir = runtime.workspace_dir / ".git_backup"
        if injection_result.status == "success":
            verification_result = run_verification(
                runtime=runtime,
                project=project,
                run_id=run_id,
                repo_dir=runtime.repo_dir_in_container,
                secure_base_commit=config.secure_base_commit,
                git_backup_dir=git_backup_dir,
                unit_tests=config.unit_tests,
                project_root=project_root(project),
                exploit_path="/workspace/run/artifacts/exploit_files/exploit.sh",
            )
        else:
            verification_result = VerificationResult(
                schema_version="v2",
                project=project,
                run_id=run_id,
                timestamp_utc=utc_now_iso(),
                status="failure",
                checks={
                    "unit_tests": "skipped",
                    "exploit_on_vulnerable": "skipped",
                    "exploit_on_secure": "skipped",
                },
                failure_cause=str((injection_result.failure or {}).get("cause") or "other"),
                failure_message=str((injection_result.failure or {}).get("message") or ""),
            )
        write_json(run_dir / "verification_result.json", verification_result.to_dict())

        should_persist = verification_result.status == "success" or debug
        if should_persist:
            vuln_dir, vulnerability_id = _dataset_vuln_dir(project, verification_result.status, debug)
            vuln_dir.mkdir(parents=True, exist_ok=True)

            # If code changed, create snapshot with temporary git restoration.
            restore_git_dir(runtime, runtime.repo_dir_in_container, git_backup_dir)
            manifest = build_snapshot_from_container(
                runtime,
                project=project,
                vulnerability_id=vulnerability_id,
                repo_dir=runtime.repo_dir_in_container,
                snapshot_dir=vuln_dir / "snapshot",
            )
            remove_git_dir(runtime, runtime.repo_dir_in_container)

            _copy_exploit_files(run_dir, vuln_dir)
            _write_vulnerability_metadata(
                project=project,
                vulnerability_id=vulnerability_id,
                vulnerability_dir=vuln_dir,
                selection_run_id=request_payload["selection_run_id"],
                injection_run_id=run_id,
                secure_base_commit=config.secure_base_commit,
                cwe_group=injection_result.cwe_group or candidate.cwe_group,
                cwe_id=injection_result.cwe_id or candidate.cwe_id,
                manifest=manifest.to_dict(),
            )
        else:
            vulnerability_id = ""

        payload = {
            "schema_version": "v2",
            "project": project,
            "run_id": run_id,
            "injection_status": injection_result.status,
            "verification_status": verification_result.status,
            "failure_cause": verification_result.failure_cause,
            "vulnerability_id": vulnerability_id,
            "run_dir": str(run_dir),
        }
        (run_dir / "logs").mkdir(parents=True, exist_ok=True)
        (run_dir / "logs" / "run.log").write_text("injection completed\n", encoding="utf-8")
        return payload
    finally:
        finish_phase(runtime)


def _selection_run_id_from_candidates(path: str) -> str:
    p = Path(path)
    if len(p.parts) >= 2:
        return p.parent.name
    return ""


def _dataset_vuln_dir(project: str, verification_status: str, debug: bool) -> tuple[Path, str]:
    base = project_root(project)
    if not debug:
        parent = base / "vulnerabilities"
    elif verification_status == "success":
        parent = base / "debug" / "success"
    else:
        parent = base / "debug" / "failed"
    vulnerability_id = next_vulnerability_id(parent)
    return parent / vulnerability_id, vulnerability_id


def _copy_exploit_files(run_dir: Path, vulnerability_dir: Path) -> None:
    src = run_dir / "artifacts" / "exploit_files"
    dst = vulnerability_dir / "exploit_files"
    if dst.exists():
        shutil.rmtree(dst)
    if src.exists():
        shutil.copytree(src, dst)
    else:
        dst.mkdir(parents=True, exist_ok=True)


def _write_vulnerability_metadata(
    *,
    project: str,
    vulnerability_id: str,
    vulnerability_dir: Path,
    selection_run_id: str,
    injection_run_id: str,
    secure_base_commit: str,
    cwe_group: str,
    cwe_id: str,
    manifest: dict,
) -> None:
    links = [
        {
            "repo_path": f["repo_path"],
            "snapshot_path": f["snapshot_path"],
        }
        for f in manifest.get("files", [])
    ]
    payload = {
        "schema_version": "v2",
        "id": vulnerability_id,
        "project": project,
        "cwe_group": cwe_group,
        "cwe_id": cwe_id,
        "selection_run_id": selection_run_id,
        "injection_run_id": injection_run_id,
        "snapshot_manifest": "snapshot/manifest.json",
        "snapshot_links": links,
        "exploit_dir": "exploit_files",
        "secure_base_commit": secure_base_commit,
        "complexity": None,
    }
    write_json(vulnerability_dir / "vulnerability_metadata.json", payload)

