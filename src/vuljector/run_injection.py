"""Run injection phase independently."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
import logging
import re
import shutil
import subprocess
import time
from pathlib import Path

from injector.base import InjectionRequest
from injector.registry import get_injection_strategy_for_selection
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


def _model_run_suffix(model_id: str) -> str:
    value = model_id.strip().replace("/", "__")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value).strip("._-")
    return value or "model"


def run_injection(
    *,
    project: str,
    model_id: str,
    candidates_file: str,
    num_vulnerabilities: int = 1,
    debug: bool = False,
    on_run_initialized: Callable[[dict], None] | None = None,
) -> dict:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)

    run_id = new_run_id("injection", suffix=_model_run_suffix(model_id))
    run_dir = injection_run_dir(project, run_id)

    candidates_payload = read_json(Path(candidates_file))
    candidates = [
        SelectionCandidate.from_dict(c)
        for c in candidates_payload.get("candidates", [])
    ]
    if not candidates:
        raise ValueError("No candidates available in candidates_file.")

    sorted_candidates = sorted(candidates, key=lambda c: c.rank)

    # Determine injection strategy from selection phase
    selection_strategy_id = candidates_payload.get("selection_strategy_id", "")

    request_payload = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "selection_run_id": _selection_run_id_from_candidates(candidates_file),
        "candidates_file": candidates_file,
        "selection_strategy_id": selection_strategy_id,
        "model_id": model_id,
        "num_vulnerabilities": num_vulnerabilities,
        "debug": debug,
    }
    write_json(run_dir / "injection_request.json", request_payload)
    if on_run_initialized is not None:
        on_run_initialized(request_payload)

    start_phase(runtime, phase="injection", run_dir=run_dir)

    # Install unit_tests/ (test.sh + parse_results.py + support files) into the container.
    _unit_tests_host = project_root(project) / "unit_tests"
    if (_unit_tests_host / "test.sh").exists():
        runtime.copy_to(_unit_tests_host, "/workspace/run/unit_tests")
        runtime.exec(
            "chmod -R a+rX /workspace/run/unit_tests"
            " && chmod +x /workspace/run/unit_tests/test.sh /workspace/run/unit_tests/parse_results.py"
        )

    # Install project source if needed (Python only)
    if _needs_editable_install(runtime):
        logger.info("[%s] pip installing project source in persistent container ...", project)
        started_at = time.monotonic()
        result = runtime.exec(f"pip install -e {runtime.repo_dir_in_container} -q 2>&1 || true")
        duration_s = time.monotonic() - started_at
        output = (result.stdout or result.stderr or "").strip()[-500:]
        logger.info("[%s] pip install finished in %.2fs (rc=%d) output:\n%s", project, duration_s, result.returncode, output)
    else:
        logger.info("[%s] skipping pip install for non-Python project", project)
    try:
        strategy = get_injection_strategy_for_selection(selection_strategy_id)
        if not runtime.is_strategy_setup_done(phase="injection", strategy_id=strategy.id):
            strategy.setup(runtime)
            runtime.mark_strategy_setup_done(phase="injection", strategy_id=strategy.id)

        successes = 0
        vulnerability_ids: list[str] = []
        attempt_summaries: list[dict] = []
        queue = deque(sorted_candidates)
        attempt_counts: dict[str, int] = {}
        attempt_idx = 0

        while queue and successes < num_vulnerabilities:
            candidate = queue.popleft()
            extra = candidate.extra or {}
            queue_key = str(extra.get("queue_key") or candidate.candidate_id)
            retry_limit = max(1, int(extra.get("retry_limit") or 1))
            attempt_no = attempt_counts.setdefault(queue_key, 0) + 1
            attempt_counts[queue_key] = attempt_no

            attempt_dir = run_dir / f"attempt_{attempt_idx:02d}"
            attempt_dir.mkdir(parents=True, exist_ok=True)

            logger.info(
                "[%s] injection attempt %d: candidate=%s retry=%d/%d",
                project, attempt_idx + 1, candidate.candidate_id, attempt_no, retry_limit,
            )

            request = InjectionRequest(
                project=project,
                run_id=run_id,
                strategy_id=strategy.id,
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
                # Apply patch and copy exploit to persistent container
                artifacts = injection_result.artifacts or {}
                patch_diff = artifacts.get("patch_diff", "")
                if patch_diff:
                    _apply_patch_to_persistent_container(
                        runtime,
                        repo_dir=runtime.repo_dir_in_container,
                        patch_diff=patch_diff,
                    )

                exploit_filename = artifacts.get("exploit_filename", "attack.py")
                exploit_host_path = attempt_dir / "artifacts" / "exploit_files" / exploit_filename
                if exploit_host_path.exists():
                    runtime.copy_to(exploit_host_path, f"/tmp/{exploit_filename}")
                    logger.info("[%s] Copied %s to /tmp/%s", project, exploit_host_path.name, exploit_filename)
                else:
                    logger.warning("[%s] Exploit file not found: %s", project, exploit_host_path)

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
                    patch_diff = (injection_result.artifacts or {}).get("patch_diff", "")
                    if patch_diff:
                        (vuln_dir / "patch.diff").write_text(patch_diff, encoding="utf-8")
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
            if verification_result.status != "success" and attempt_no < retry_limit:
                queue.append(candidate)
            attempt_idx += 1

        # Final summary (surface last attempt status for backward compatibility)
        last_attempt = attempt_summaries[-1] if attempt_summaries else {}
        payload = {
            "project": project,
            "run_id": run_id,
            "num_vulnerabilities_requested": num_vulnerabilities,
            "num_vulnerabilities_produced": successes,
            "vulnerability_ids": vulnerability_ids,
            "attempts": attempt_summaries,
            "injection_status": last_attempt.get("injection_status", "failure"),
            "verification_status": last_attempt.get("verification_status", "failure"),
            "failure_cause": last_attempt.get("failure_cause", "no_candidates"),
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


def _needs_editable_install(runtime) -> bool:
    language = (getattr(runtime, "language", None) or "").strip().lower()
    return language in {"python", "python3"}


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
