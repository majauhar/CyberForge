"""Run injection phase independently."""

from __future__ import annotations

import logging
import shutil
from pathlib import Path

from injector.base import InjectionRequest
from injector.registry import get_injection_strategy
from setup.lifecycle import finish_phase, start_phase
from utils.github_utils import reset_to_secure_commit
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

logger = logging.getLogger(__name__)


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
        SelectionCandidate.from_dict(c)
        for c in candidates_payload.get("candidates", [])
    ]
    if not candidates:
        raise ValueError("No candidates available in candidates_file.")

    sorted_candidates = sorted(candidates, key=lambda c: c.rank)

    start_phase(runtime, phase="injection", run_dir=run_dir)
    # pip install the project source so exploits/unit tests can import it.
    # We skip the full build.sh (which compiles C fuzz targets and is slow);
    # a simple pip install is enough to make `import <project>` work.
    logger.info("[%s] pip installing project source in persistent container ...", project)
    install_result = runtime.exec(
        f"pip install -e {runtime.repo_dir_in_container} -q 2>&1 || true",
    )
    logger.info("[%s] pip install exit=%d output:\n%s", project, install_result.returncode,
                (install_result.stdout or install_result.stderr or "").strip()[-500:])
    try:
        strategy = get_injection_strategy(strategy_id)
        if not runtime.is_strategy_setup_done(phase="injection", strategy_id=strategy.id):
            strategy.setup(runtime)
            runtime.mark_strategy_setup_done(phase="injection", strategy_id=strategy.id)

        successes = 0
        vulnerability_ids: list[str] = []
        attempt_summaries: list[dict] = []

        for attempt_idx, candidate in enumerate(sorted_candidates):
            if successes >= num_vulnerabilities:
                break

            # Each injection attempt uses a fresh container (via run_agent_task),
            # so no repo reset is needed between attempts.

            attempt_dir = run_dir / f"attempt_{attempt_idx:02d}"
            attempt_dir.mkdir(parents=True, exist_ok=True)

            logger.info(
                "[%s] injection attempt %d/%d: candidate=%s",
                project, attempt_idx + 1, len(sorted_candidates), candidate.candidate_id,
            )

            request = InjectionRequest(
                project=project,
                run_id=run_id,
                strategy_id=strategy_id,
                model_id=model_id,
                num_vulnerabilities=num_vulnerabilities,
                debug=debug,
                attempt_dir=f"attempt_{attempt_idx:02d}",
            )
            injection_result = strategy.run(runtime, request, candidate)
            write_json(attempt_dir / "injection_result.json", injection_result.to_dict())

            if injection_result.status == "success":
                # Reset to secure base before applying this attempt's patch —
                # the previous attempt's verifier leaves the repo in the vulnerable
                # state (re-applies patch for snapshot), so we must start clean.
                reset_to_secure_commit(
                    runtime,
                    repo_dir=runtime.repo_dir_in_container,
                    secure_base_commit=config.secure_base_commit,
                )
                # Apply the patch produced by the agent (in its ephemeral fresh container)
                # to the persistent container so the verifier can run git diff + exploit.
                patch_diff = (injection_result.artifacts or {}).get("patch_diff", "")
                if patch_diff:
                    _apply_patch_to_persistent_container(
                        runtime,
                        repo_dir=runtime.repo_dir_in_container,
                        patch_diff=patch_diff,
                    )

                # Copy the exploit script into the persistent container at /tmp/<filename>
                # so exploit.sh can find it (the LLM wrote it to /tmp/ in its fresh container).
                exploit_filename = (injection_result.artifacts or {}).get("exploit_filename", "attack.py")
                exploit_host_path = attempt_dir / "artifacts" / "exploit_files" / exploit_filename
                if exploit_host_path.exists():
                    runtime.copy_to(exploit_host_path, f"/tmp/{exploit_filename}")
                    logger.info("[%s] Copied %s to /tmp/%s in persistent container", project, exploit_host_path.name, exploit_filename)
                else:
                    logger.warning("[%s] Exploit file not found on host: %s", project, exploit_host_path)

                verification_result = run_verification(
                    runtime=runtime,
                    project=project,
                    run_id=run_id,
                    repo_dir=runtime.repo_dir_in_container,
                    secure_base_commit=config.secure_base_commit,
                    git_backup_dir=None,
                    unit_tests=config.unit_tests,
                    project_root=project_root(project),
                    exploit_path=f"/workspace/run/attempt_{attempt_idx:02d}/artifacts/exploit_files/exploit.sh",
                )
            else:
                verification_result = VerificationResult(
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
            write_json(attempt_dir / "verification_result.json", verification_result.to_dict())

            should_persist = verification_result.status == "success" or debug
            if should_persist:
                vuln_dir, vulnerability_id = _dataset_vuln_dir(
                    project, verification_result.status, debug
                )
                vuln_dir.mkdir(parents=True, exist_ok=True)

                manifest = build_snapshot_from_container(
                    runtime,
                    project=project,
                    vulnerability_id=vulnerability_id,
                    repo_dir=runtime.repo_dir_in_container,
                    snapshot_dir=vuln_dir / "snapshot",
                )

                _copy_exploit_files(attempt_dir, vuln_dir)
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

                if verification_result.status == "success":
                    successes += 1
                    vulnerability_ids.append(vulnerability_id)
            else:
                vulnerability_id = ""

            attempt_summaries.append({
                "attempt": attempt_idx,
                "candidate_id": candidate.candidate_id,
                "injection_status": injection_result.status,
                "verification_status": verification_result.status,
                "failure_cause": verification_result.failure_cause,
                "vulnerability_id": vulnerability_id,
            })

        # Final summary written once after all attempts.
        payload = {
            "project": project,
            "run_id": run_id,
            "num_vulnerabilities_requested": num_vulnerabilities,
            "num_vulnerabilities_produced": successes,
            "vulnerability_ids": vulnerability_ids,
            "attempts": attempt_summaries,
            # Convenience: surface last attempt status for backward-compatible callers.
            "injection_status": attempt_summaries[-1]["injection_status"] if attempt_summaries else "failure",
            "verification_status": attempt_summaries[-1]["verification_status"] if attempt_summaries else "failure",
            "failure_cause": attempt_summaries[-1]["failure_cause"] if attempt_summaries else "no_candidates",
            "vulnerability_id": vulnerability_ids[-1] if vulnerability_ids else "",
            "run_dir": str(run_dir),
        }
        (run_dir / "logs").mkdir(parents=True, exist_ok=True)
        (run_dir / "logs" / "run.log").write_text("injection completed\n", encoding="utf-8")
        write_json(run_dir / "run_summary.json", payload)
        return payload
    finally:
        finish_phase(runtime)


def _apply_patch_to_persistent_container(
    runtime,
    *,
    repo_dir: str,
    patch_diff: str,
) -> None:
    """Apply the patch from the agent's ephemeral container to the persistent container."""
    import subprocess

    # Write patch into the container.
    # Ensure trailing newline — `patch` requires the patch file to end with \n.
    patch_bytes = (patch_diff if patch_diff.endswith("\n") else patch_diff + "\n").encode()
    result = subprocess.run(
        ["docker", "exec", "-i", runtime.container_name,
         "tee", "/tmp/vuljector_apply.patch"],
        input=patch_bytes,
        capture_output=True,
    )
    if result.returncode != 0:
        logger.warning(
            "[%s] Failed to write patch to container: %s",
            runtime.project, result.stderr.decode()[:200],
        )
        return
    # Use `patch -p1` instead of `git apply`:
    #   - `-p1` strips the `a/` prefix from git diff paths (--- a/src/... → src/...)
    #   - `--fuzz=3` allows up to 3 lines of context mismatch (more forgiving than git apply)
    #   - handles git-format diffs correctly (ignores `diff --git` header, parses ---/+++ lines)
    runtime.exec(
        "patch -p1 --fuzz=3 < /tmp/vuljector_apply.patch",
        workdir=repo_dir,
    ).raise_for_status("patch apply to persistent container failed")


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
