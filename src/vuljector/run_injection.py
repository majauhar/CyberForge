"""Run injection phase independently."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable
import logging
import os
import re
import shutil
from pathlib import Path

from injector.base import InjectionRequest
from injector.registry import get_injection_strategy_for_selection
from utils.cwe import resolve_cwe_group
from utils.json_io import read_json, write_json
from utils.paths import injection_run_dir, new_run_id, project_root
from verifier import run_verification
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config, next_vulnerability_id
from vuljector.io_contracts import SelectionCandidate, VerificationResult, utc_now_iso

logger = logging.getLogger(__name__)


def _vuln_only_mode() -> bool:
    return (os.environ.get("VULJECTOR_INJECTION_MODE") or "").strip().lower() == "vuln_only"


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
    auto_fuzz_poc: bool = False,
    auto_fuzz_poc_exploit_timeout: int = 600,
    auto_fuzz_poc_max_total_time: int = 90,
    on_run_initialized: Callable[[dict], None] | None = None,
) -> dict:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)
    runtime.require_ready_image()

    run_id = new_run_id("injection", suffix=_model_run_suffix(model_id))
    run_dir = injection_run_dir(project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    runtime.run_mount_dir = run_dir

    candidates_payload = read_json(Path(candidates_file))
    candidates = [SelectionCandidate.from_dict(c) for c in candidates_payload.get("candidates", [])]
    if not candidates:
        raise ValueError("No candidates available in candidates_file.")

    sorted_candidates = sorted(candidates, key=lambda c: c.rank)
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
            project,
            attempt_idx + 1,
            candidate.candidate_id,
            attempt_no,
            retry_limit,
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
        try:
            injection_result = strategy.run(runtime, request, candidate)
        except Exception as exc:
            logger.exception("[%s] injection crashed on attempt %d", project, attempt_idx)
            injection_result = _verification_as_injection_failure(
                project=project,
                run_id=run_id,
                candidate=candidate,
                strategy_id=strategy.id,
                model_id=model_id,
                failure_cause="injection_exception",
                failure_message=_exception_message(exc),
            )
        write_json(attempt_dir / "injection_result.json", injection_result.to_dict())

        verification_result: VerificationResult

        if injection_result.status == "success" and not _vuln_only_mode():
            try:
                verification_result = _verify_attempt(
                    runtime=runtime,
                    config=config,
                    project=project,
                    run_id=run_id,
                    attempt_idx=attempt_idx,
                    attempt_dir=attempt_dir,
                    injection_result=injection_result,
                )
            except Exception as exc:
                logger.exception("[%s] verification handoff crashed on attempt %d", project, attempt_idx)
                verification_result = VerificationResult(
                    project=project,
                    run_id=run_id,
                    timestamp_utc=utc_now_iso(),
                    status="failure",
                    checks={
                        "unit_tests": "unknown",
                        "exploit_on_vulnerable": "unknown",
                        "exploit_on_secure": "unknown",
                    },
                    failure_cause="verification_exception",
                    failure_message=_exception_message(exc),
                )
        elif injection_result.status == "success":
            verification_result = VerificationResult(
                project=project,
                run_id=run_id,
                timestamp_utc=utc_now_iso(),
                status="success",
                checks={
                    "unit_tests": "skipped",
                    "exploit_on_vulnerable": "skipped",
                    "exploit_on_secure": "skipped",
                },
                failure_cause=None,
                failure_message="vuln_only_mode",
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

        should_persist = (verification_result.status == "success" and not _vuln_only_mode()) or debug
        if should_persist:
            vuln_dir, vulnerability_id = _dataset_vuln_dir(project, verification_result.status, debug)
            vuln_dir.mkdir(parents=True, exist_ok=True)
            _copy_exploit_files(attempt_dir, vuln_dir)
            patch_diff = (injection_result.artifacts or {}).get("patch_diff", "")
            if patch_diff:
                (vuln_dir / "inject_vulnerability.diff").write_text(patch_diff, encoding="utf-8")
            _write_vulnerability_metadata(
                project=project,
                vulnerability_id=vulnerability_id,
                vulnerability_dir=vuln_dir,
                selection_run_id=request_payload["selection_run_id"],
                injection_run_id=run_id,
                secure_base_commit=config.secure_base_commit,
                cwe_group=resolve_cwe_group(
                    injection_result.cwe_id or candidate.cwe_id,
                    fallback=injection_result.cwe_group or candidate.cwe_group,
                ),
                cwe_id=injection_result.cwe_id or candidate.cwe_id,
            )
            if verification_result.status == "success":
                successes += 1
                vulnerability_ids.append(vulnerability_id)
        elif _vuln_only_mode() and injection_result.status == "success":
            vulnerability_id = ""
        else:
            vulnerability_id = ""

        attempt_summaries.append(
            {
                "attempt": attempt_idx,
                "candidate_id": candidate.candidate_id,
                "injection_status": injection_result.status,
                "verification_status": verification_result.status,
                "failure_cause": verification_result.failure_cause,
                "vulnerability_id": vulnerability_id,
            }
        )
        if verification_result.status != "success" and attempt_no < retry_limit:
            queue.append(candidate)
        attempt_idx += 1

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
    if auto_fuzz_poc and not _vuln_only_mode():
        payload["posthoc_fuzz_poc"] = _run_posthoc_fuzz_poc(
            run_dir=run_dir,
            exploit_timeout=auto_fuzz_poc_exploit_timeout,
            max_total_time=auto_fuzz_poc_max_total_time,
        )
    (run_dir / "logs").mkdir(parents=True, exist_ok=True)
    (run_dir / "logs" / "run.log").write_text("injection completed\n", encoding="utf-8")
    write_json(run_dir / "run_summary.json", payload)
    return payload


def _verify_attempt(*, runtime, config, project: str, run_id: str, attempt_idx: int, attempt_dir: Path, injection_result) -> VerificationResult:
    artifacts = injection_result.artifacts or {}
    patch_diff = artifacts.get("patch_diff", "")
    exploit_dir = attempt_dir / "artifacts" / "exploit_files"
    exploit_wrapper_path = exploit_dir / "exploit.sh"
    if not patch_diff:
        raise RuntimeError("Verification requested without patch_diff.")
    if not exploit_wrapper_path.exists():
        raise RuntimeError(f"Missing exploit files in {exploit_dir}")

    session = runtime.new_session(run_mount_dir=attempt_dir)
    try:
        session.exec("rm -rf /tmp/exploit && mkdir -p /tmp/exploit")
        session.copy_to(exploit_dir, "/tmp/exploit")
        session.exec("find /tmp/exploit -maxdepth 1 -type f -name '*.sh' -exec chmod +x {} + 2>/dev/null || true")
        session.copy_to(exploit_wrapper_path, "/tmp/exploit.sh")
        session.exec("chmod +x /tmp/exploit.sh")
        verification_result = run_verification(
            runtime=session,
            project=project,
            run_id=run_id,
            repo_dir=runtime.repo_dir_in_container,
            patch_diff=patch_diff,
            unit_tests=config.unit_tests,
            project_root=project_root(project),
            exploit_path="/tmp/exploit.sh",
            rebuild_command=_rebuild_command(runtime),
        )
        return verification_result
    finally:
        session.stop()


def _rebuild_command(runtime) -> str | None:
    language = getattr(runtime, "language", None) or "c++"
    engine = getattr(runtime, "fuzzing_engine", None) or "libfuzzer"
    return f"FUZZING_LANGUAGE={language} FUZZING_ENGINE={engine} compile"


def _run_posthoc_fuzz_poc(*, run_dir: Path, exploit_timeout: int, max_total_time: int) -> dict:
    from vuljector.run_fuzz_poc import batch_generate_fuzz_poc_filtered

    try:
        summary = batch_generate_fuzz_poc_filtered(
            source_run_dir=run_dir,
            tag=run_dir.name,
            max_total_time=max_total_time,
            exploit_timeout=exploit_timeout,
        )
        return {
            "status": "success",
            "generated_run_dir": summary.get("generated_run_dir"),
            "verification": summary.get("verification"),
        }
    except Exception as exc:
        logger.exception("post-hoc fuzz-poc batch failed for %s", run_dir)
        return {
            "status": "failure",
            "failure_cause": "posthoc_fuzz_poc_exception",
            "failure_message": _exception_message(exc),
        }


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
) -> None:
    payload = {
        "id": vulnerability_id,
        "project": project,
        "cwe_group": cwe_group,
        "cwe_id": cwe_id,
        "selection_run_id": selection_run_id,
        "injection_run_id": injection_run_id,
        "secure_base_commit": secure_base_commit,
    }
    write_json(vulnerability_dir / "vulnerability_metadata.json", payload)


def _verification_as_injection_failure(
    *,
    project: str,
    run_id: str,
    candidate: SelectionCandidate,
    strategy_id: str,
    model_id: str,
    failure_cause: str,
    failure_message: str,
):
    from vuljector.io_contracts import InjectionResult

    return InjectionResult(
        project=project,
        run_id=run_id,
        timestamp_utc=utc_now_iso(),
        status="failure",
        selected_candidate_id=candidate.candidate_id,
        cwe_group=candidate.cwe_group,
        cwe_id=candidate.cwe_id,
        strategy={
            "id": strategy_id,
            "model_id": model_id,
            "retries": 0,
            "selection_candidate": candidate.to_dict(),
        },
        usage={
            "total_steps": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "estimated_cost_usd": 0.0,
            "models_used": [model_id],
        },
        paths={},
        artifacts={},
        failure={"cause": failure_cause, "message": failure_message},
    )


def _exception_message(exc: Exception) -> str:
    return str(exc) or exc.__class__.__name__
