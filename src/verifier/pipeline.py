"""Verification pipeline for ready-image-backed ephemeral sessions."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from setup.container_runtime import HARNESS_DIR
from vuljector.io_contracts import VerificationResult, utc_now_iso

from .exploit import run_exploit
from .unit_tests import run_unit_tests

logger = logging.getLogger(__name__)


PROJECT_CLEANUP_COMMANDS: dict[str, list[str]] = {
    "harfbuzz": [
        "rm -rf /src/all-fonts",
    ],
    "jq": [
        "rm -rf /src/seeds",
    ],
}

GENERIC_REBUILD_CLEANUP = r"""bash -lc '
set -e
shopt -s nullglob
rm -rf /out/*
for path in \
  /src/build \
  /src/build-* \
  /src/*-build \
  /src/*-install \
  /src/CMakeFiles \
  /src/CMakeCache.txt \
  /src/Testing \
  /src/Makefile \
  /src/cmake_install.cmake
do
  rm -rf "$path"
done
'"""


def _repo_local_rebuild_cleanup(repo_dir: str) -> str:
    return rf"""bash -lc '
set -e
shopt -s nullglob
repo_dir={repo_dir!r}
for path in \
  "$repo_dir/build" \
  "$repo_dir/build-"* \
  "$repo_dir/"*-build \
  "$repo_dir/"*-install \
  "$repo_dir/CMakeFiles" \
  "$repo_dir/CMakeCache.txt" \
  "$repo_dir/Testing" \
  "$repo_dir/cmake_install.cmake" \
  "$repo_dir/seeds"
do
  rm -rf "$path"
done
'"""


def _contains_any(text: str, patterns: list[str]) -> bool:
    hay = text.lower()
    return any(pattern.lower() in hay for pattern in patterns)


def _copy_harness_into_session(runtime, *, project_root: Path) -> None:
    unit_tests_dir = project_root / "unit_tests"
    runtime.exec(f"mkdir -p {HARNESS_DIR}").raise_for_status("failed to create harness directory")
    runtime.copy_to(unit_tests_dir, HARNESS_DIR)
    runtime.exec(
        f"chmod -R a+rX {HARNESS_DIR} && chmod +x {HARNESS_DIR}/test.sh {HARNESS_DIR}/parse_results.py"
    ).raise_for_status("failed to chmod harness")


def _prepare_clean_repo(runtime, *, repo_dir: str, secure_base_commit: str | None) -> None:
    if secure_base_commit:
        runtime.exec(f"git fetch origin {secure_base_commit}", workdir=repo_dir).raise_for_status(
            "git fetch secure_base_commit failed"
        )
        runtime.exec(f"git reset --hard {secure_base_commit}", workdir=repo_dir).raise_for_status(
            "git reset to secure_base_commit failed"
        )
    runtime.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean before rebuild failed")


def _run_rebuild_command(
    runtime,
    *,
    project: str,
    rebuild_command: str | None,
    failure_checks: dict[str, str],
    progress_phase: str,
    progress_callback: Callable[[dict[str, Any]], None] | None,
    run_id: str,
) -> VerificationResult | None:
    if not rebuild_command:
        return None
    if progress_callback is not None:
        progress_callback(
            {
                "project": project,
                "run_id": run_id,
                "timestamp_utc": utc_now_iso(),
                "status": "running",
                "checks": failure_checks,
                "failure_cause": None,
                "failure_message": "",
                "unit_test_passed_count": None,
                "unit_test_message": "",
                "unit_test_raw_output": "",
                "progress_phase": progress_phase,
                "complete": False,
            }
        )
    rebuild_result = runtime.exec(rebuild_command, timeout=1800)
    if rebuild_result.returncode == 0:
        return None
    detail = (rebuild_result.stderr or rebuild_result.stdout or "").strip()[-500:]
    logger.warning("[%s] rebuild failed: %s", project, detail)
    return VerificationResult(
        project=project,
        run_id=run_id,
        timestamp_utc=utc_now_iso(),
        status="failure",
        checks=failure_checks,
        failure_cause="rebuild_failed_after_patch",
        failure_message=detail or "rebuild after patch failed",
        unit_test_passed_count=None,
        unit_test_message="",
        unit_test_raw_output="",
        metadata={},
    )


def _classify_oracle_signal(
    *,
    output: str,
    triggered: bool,
    expected_crash_type: str | None,
    expected_crash_state: list[str] | None,
) -> tuple[bool, str | None]:
    """
    Return (is_valid_signal, invalid_reason).
    """
    infra_or_internal_patterns = [
        "MISSING_BINARY",
        "command not found",
        "No such file or directory",
        "AddressSanitizer: CHECK failed",
        "LeakSanitizer has encountered a fatal error",
        "runtime error: sanitizer",
    ]
    if _contains_any(output, infra_or_internal_patterns):
        return False, "infra_or_sanitizer_internal_error"

    if not triggered:
        return True, None

    if expected_crash_type and expected_crash_type.lower() not in output.lower():
        return False, "crash_type_mismatch"

    expected_frames = [frame.strip() for frame in (expected_crash_state or []) if frame and frame.strip()]
    if expected_frames:
        # Require at least one expected crash-state frame to appear.
        if not any(frame.lower() in output.lower() for frame in expected_frames[:5]):
            return False, "crash_state_mismatch"

    return True, None


def run_verification(
    *,
    runtime,
    project: str,
    run_id: str,
    repo_dir: str,
    patch_diff: str,
    unit_tests: dict | None,
    skip_unit_tests: bool = False,
    project_root: Path,
    exploit_path: str,
    expected_crash_type: str | None = None,
    expected_crash_state: list[str] | None = None,
    rebuild_command: str | None = None,
    exploit_timeout: int = 180,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> VerificationResult:
    logger.info("[%s] === VERIFICATION START ===", project)

    def _make_result(
        status,
        checks,
        failure_cause,
        failure_message,
        passed_count,
        test_message,
        test_raw_output,
        metadata: dict[str, Any] | None = None,
    ):
        return VerificationResult(
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status=status,
            checks=checks,
            failure_cause=failure_cause,
            failure_message=failure_message,
            unit_test_passed_count=passed_count,
            unit_test_message=test_message,
            unit_test_raw_output=test_raw_output,
            metadata=metadata or {},
        )

    def _emit_progress(
        phase: str,
        checks: dict[str, str],
        *,
        failure_cause: str | None = None,
        failure_message: str = "",
        passed_count: int | None = None,
        test_message: str = "",
        test_raw_output: str = "",
    ) -> None:
        if progress_callback is None:
            return
        progress_callback(
            {
                "project": project,
                "run_id": run_id,
                "timestamp_utc": utc_now_iso(),
                "status": "running",
                "checks": checks,
                "failure_cause": failure_cause,
                "failure_message": failure_message,
                "unit_test_passed_count": passed_count,
                "unit_test_message": test_message,
                "unit_test_raw_output": test_raw_output,
                "progress_phase": phase,
                "complete": False,
            }
        )

    logger.info("[%s] --- exploit on SECURE version ---", project)
    _emit_progress(
        "secure_started",
        {"unit_tests": "pending", "exploit_on_vulnerable": "pending", "exploit_on_secure": "running"},
    )
    secure_ok, secure_msg, secure_timed_out = run_exploit(
        runtime,
        repo_dir=repo_dir,
        exploit_path=exploit_path,
        label="secure",
        timeout_seconds=exploit_timeout,
    )
    if secure_timed_out:
        return _make_result(
            "failure",
            {"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "timed_out"},
            "exploit_timed_out_on_secure",
            secure_msg,
            None,
            "",
            "",
        )
    secure_valid, secure_invalid_reason = _classify_oracle_signal(
        output=secure_msg,
        triggered=secure_ok,
        expected_crash_type=expected_crash_type,
        expected_crash_state=expected_crash_state,
    )
    if not secure_valid:
        return _make_result(
            "failure",
            {"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "invalid"},
            "oracle_invalid_on_secure",
            secure_invalid_reason or secure_msg,
            None,
            "",
            "",
        )
    if secure_ok:
        return _make_result(
            "failure",
            {"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "failed"},
            "exploit_succeeds_on_secure",
            secure_msg or "Exploit succeeded on secure code.",
            None,
            "",
            "",
        )
    _emit_progress(
        "secure_passed",
        {"unit_tests": "pending", "exploit_on_vulnerable": "pending", "exploit_on_secure": "passed"},
    )

    _apply_patch(runtime, repo_dir=repo_dir, patch_diff=patch_diff)
    _emit_progress(
        "patch_applied",
        {"unit_tests": "pending", "exploit_on_vulnerable": "pending", "exploit_on_secure": "passed"},
    )

    if rebuild_command:
        logger.info("[%s] --- rebuild after patch ---", project)
        # Ready images can contain untracked build leftovers from the original
        # compile step (for example generated seed-corpus staging dirs). Clear
        # those before recompiling the patched tree. Also clear common shared
        # /out and top-level build/install leftovers so rebuild scripts that
        # expect a pristine environment don't fail on existing artifacts.
        runtime.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean before rebuild failed")
        runtime.exec(GENERIC_REBUILD_CLEANUP).raise_for_status("generic rebuild cleanup failed")
        runtime.exec(_repo_local_rebuild_cleanup(repo_dir)).raise_for_status("repo-local rebuild cleanup failed")
        for cmd in PROJECT_CLEANUP_COMMANDS.get(project, []):
            runtime.exec(cmd).raise_for_status(f"project cleanup failed: {cmd}")
        rebuild_result = runtime.exec(rebuild_command, timeout=1800)
        if rebuild_result.returncode != 0:
            detail = (rebuild_result.stderr or rebuild_result.stdout or "").strip()[-500:]
            logger.warning("[%s] rebuild after patch failed: %s", project, detail)
            return _make_result(
                "failure",
                {"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "passed"},
                "rebuild_failed_after_patch",
                detail or "rebuild after patch failed",
                None,
                "",
                "",
            )
        _emit_progress(
            "rebuild_finished",
            {"unit_tests": "pending", "exploit_on_vulnerable": "pending", "exploit_on_secure": "passed"},
        )

    if skip_unit_tests:
        test_status, passed_count, test_message, test_raw_output = "skipped", None, "Unit tests skipped by request.", ""
    else:
        logger.info("[%s] --- unit tests (on vulnerable version) ---", project)
        test_status, passed_count, test_message, test_raw_output = run_unit_tests(
            runtime,
            repo_dir=repo_dir,
            unit_tests=unit_tests,
            project_root=project_root,
        )
    _emit_progress(
        "pre_vulnerable",
        {"unit_tests": test_status, "exploit_on_vulnerable": "running", "exploit_on_secure": "passed"},
        passed_count=passed_count,
        test_message=test_message,
        test_raw_output=test_raw_output,
    )

    logger.info("[%s] --- exploit on VULNERABLE version ---", project)
    vuln_ok, vuln_msg, vuln_timed_out = run_exploit(
        runtime,
        repo_dir=repo_dir,
        exploit_path=exploit_path,
        label="vulnerable",
        timeout_seconds=exploit_timeout,
    )
    vuln_valid, vuln_invalid_reason = _classify_oracle_signal(
        output=vuln_msg,
        triggered=vuln_ok,
        expected_crash_type=expected_crash_type,
        expected_crash_state=expected_crash_state,
    )
    if not vuln_valid:
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "invalid", "exploit_on_secure": "passed"},
            "oracle_invalid_on_vulnerable",
            vuln_invalid_reason or vuln_msg,
            passed_count,
            test_message,
            test_raw_output,
        )
    if vuln_timed_out:
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "timed_out", "exploit_on_secure": "passed"},
            "exploit_timed_out_on_vulnerable",
            vuln_msg,
            passed_count,
            test_message,
            test_raw_output,
        )
    if not vuln_ok:
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "failed", "exploit_on_secure": "passed"},
            "exploit_failed_on_vulnerable",
            vuln_msg,
            passed_count,
            test_message,
            test_raw_output,
        )

    return _make_result(
        "success",
        {"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "passed"},
        None,
        "",
        passed_count,
        test_message,
        test_raw_output,
    )


def run_verification_from_setup_image(
    *,
    runtime,
    project: str,
    run_id: str,
    repo_dir: str,
    patch_diff: str,
    unit_tests: dict | None,
    skip_unit_tests: bool = False,
    project_root: Path,
    exploit_path: str,
    expected_crash_type: str | None = None,
    expected_crash_state: list[str] | None = None,
    rebuild_command: str | None = None,
    exploit_timeout: int = 180,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
) -> VerificationResult:
    """
    Alternate verification path that rebuilds in fresh setup-image-backed
    sessions instead of mutating the ready image in place.
    """

    def _emit_progress(
        phase: str,
        checks: dict[str, str],
        *,
        failure_cause: str | None = None,
        failure_message: str = "",
        passed_count: int | None = None,
        test_message: str = "",
        test_raw_output: str = "",
    ) -> None:
        if progress_callback is None:
            return
        progress_callback(
            {
                "project": project,
                "run_id": run_id,
                "timestamp_utc": utc_now_iso(),
                "status": "running",
                "checks": checks,
                "failure_cause": failure_cause,
                "failure_message": failure_message,
                "unit_test_passed_count": passed_count,
                "unit_test_message": test_message,
                "unit_test_raw_output": test_raw_output,
                "progress_phase": phase,
                "complete": False,
            }
        )

    def _failure(
        *,
        checks: dict[str, str],
        cause: str,
        message: str,
        passed_count: int | None = None,
        test_message: str = "",
        test_raw_output: str = "",
    ) -> VerificationResult:
        return VerificationResult(
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status="failure",
            checks=checks,
            failure_cause=cause,
            failure_message=message,
            unit_test_passed_count=passed_count,
            unit_test_message=test_message,
            unit_test_raw_output=test_raw_output,
            metadata={"rebuild_mode": "setup_image_clean"},
        )

    exploit_bytes = Path(exploit_path).read_bytes()

    secure = runtime.new_setup_session()
    try:
        _copy_harness_into_session(secure, project_root=project_root)
        _prepare_clean_repo(secure, repo_dir=repo_dir, secure_base_commit=getattr(runtime, "secure_base_commit", ""))
        secure.write_file("/tmp/exploit.sh", exploit_bytes)
        secure.exec("chmod +x /tmp/exploit.sh").raise_for_status("failed to chmod secure exploit")

        secure_rebuild = _run_rebuild_command(
            secure,
            project=project,
            rebuild_command=rebuild_command,
            failure_checks={"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "running"},
            progress_phase="secure_rebuild_started",
            progress_callback=progress_callback,
            run_id=run_id,
        )
        if secure_rebuild is not None:
            secure_rebuild.failure_cause = "secure_rebuild_failed"
            return secure_rebuild

        _emit_progress(
            "secure_started",
            {"unit_tests": "pending", "exploit_on_vulnerable": "pending", "exploit_on_secure": "running"},
        )
        secure_ok, secure_msg, secure_timed_out = run_exploit(
            secure,
            repo_dir=repo_dir,
            exploit_path="/tmp/exploit.sh",
            label="secure",
            timeout_seconds=exploit_timeout,
        )
        if secure_timed_out:
            return _failure(
                checks={"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "timed_out"},
                cause="exploit_timed_out_on_secure",
                message=secure_msg,
            )
        secure_valid, secure_invalid_reason = _classify_oracle_signal(
            output=secure_msg,
            triggered=secure_ok,
            expected_crash_type=expected_crash_type,
            expected_crash_state=expected_crash_state,
        )
        if not secure_valid:
            return _failure(
                checks={"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "invalid"},
                cause="oracle_invalid_on_secure",
                message=secure_invalid_reason or secure_msg,
            )
        if secure_ok:
            return _failure(
                checks={"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "failed"},
                cause="exploit_succeeds_on_secure",
                message=secure_msg or "Exploit succeeded on secure code.",
            )
    finally:
        secure.stop()

    vulnerable = runtime.new_setup_session()
    try:
        _copy_harness_into_session(vulnerable, project_root=project_root)
        _prepare_clean_repo(vulnerable, repo_dir=repo_dir, secure_base_commit=getattr(runtime, "secure_base_commit", ""))
        _apply_patch(vulnerable, repo_dir=repo_dir, patch_diff=patch_diff)
        vulnerable.write_file("/tmp/exploit.sh", exploit_bytes)
        vulnerable.exec("chmod +x /tmp/exploit.sh").raise_for_status("failed to chmod vulnerable exploit")

        vulnerable_rebuild = _run_rebuild_command(
            vulnerable,
            project=project,
            rebuild_command=rebuild_command,
            failure_checks={"unit_tests": "skipped", "exploit_on_vulnerable": "skipped", "exploit_on_secure": "passed"},
            progress_phase="vulnerable_rebuild_started",
            progress_callback=progress_callback,
            run_id=run_id,
        )
        if vulnerable_rebuild is not None:
            return vulnerable_rebuild

        if skip_unit_tests:
            test_status, passed_count, test_message, test_raw_output = "skipped", None, "Unit tests skipped by request.", ""
        else:
            test_status, passed_count, test_message, test_raw_output = run_unit_tests(
                vulnerable,
                repo_dir=repo_dir,
                unit_tests=unit_tests,
                project_root=project_root,
            )

        _emit_progress(
            "pre_vulnerable",
            {"unit_tests": test_status, "exploit_on_vulnerable": "running", "exploit_on_secure": "passed"},
            passed_count=passed_count,
            test_message=test_message,
            test_raw_output=test_raw_output,
        )
        vuln_ok, vuln_msg, vuln_timed_out = run_exploit(
            vulnerable,
            repo_dir=repo_dir,
            exploit_path="/tmp/exploit.sh",
            label="vulnerable",
            timeout_seconds=exploit_timeout,
        )
        vuln_valid, vuln_invalid_reason = _classify_oracle_signal(
            output=vuln_msg,
            triggered=vuln_ok,
            expected_crash_type=expected_crash_type,
            expected_crash_state=expected_crash_state,
        )
        if not vuln_valid:
            return _failure(
                checks={"unit_tests": test_status, "exploit_on_vulnerable": "invalid", "exploit_on_secure": "passed"},
                cause="oracle_invalid_on_vulnerable",
                message=vuln_invalid_reason or vuln_msg,
                passed_count=passed_count,
                test_message=test_message,
                test_raw_output=test_raw_output,
            )
        if vuln_timed_out:
            return _failure(
                checks={"unit_tests": test_status, "exploit_on_vulnerable": "timed_out", "exploit_on_secure": "passed"},
                cause="exploit_timed_out_on_vulnerable",
                message=vuln_msg,
                passed_count=passed_count,
                test_message=test_message,
                test_raw_output=test_raw_output,
            )
        if not vuln_ok:
            return _failure(
                checks={"unit_tests": test_status, "exploit_on_vulnerable": "failed", "exploit_on_secure": "passed"},
                cause="exploit_failed_on_vulnerable",
                message=vuln_msg,
                passed_count=passed_count,
                test_message=test_message,
                test_raw_output=test_raw_output,
            )
        return VerificationResult(
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status="success",
            checks={"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "passed"},
            failure_cause=None,
            failure_message="",
            unit_test_passed_count=passed_count,
            unit_test_message=test_message,
            unit_test_raw_output=test_raw_output,
            metadata={"rebuild_mode": "setup_image_clean"},
        )
    finally:
        vulnerable.stop()


def _apply_patch(runtime, *, repo_dir: str, patch_diff: str) -> None:
    patch_text = patch_diff if patch_diff.endswith("\n") else patch_diff + "\n"
    blocks = _split_patch_blocks(patch_text)
    if not blocks:
        runtime.write_file("/tmp/vuljector_apply.patch", patch_text)
        runtime.exec(
            "patch -p1 --fuzz=3 < /tmp/vuljector_apply.patch",
            workdir=repo_dir,
        ).raise_for_status("patch apply failed")
        return

    failures: list[str] = []
    for index, block in enumerate(blocks):
        remote_path = f"/tmp/vuljector_apply_{index:03d}.patch"
        runtime.write_file(remote_path, block)

        reverse_check = runtime.exec(
            f"git apply --reverse --check {remote_path}",
            workdir=repo_dir,
        )
        if reverse_check.returncode == 0:
            logger.info("skipping already-applied patch block %s", remote_path)
            continue

        apply_result = runtime.exec(
            f"patch -p1 --fuzz=3 < {remote_path}",
            workdir=repo_dir,
        )
        if apply_result.returncode != 0:
            detail = ((apply_result.stderr or "") + "\n" + (apply_result.stdout or "")).strip()
            failures.append(f"{remote_path}: {detail}")

    if failures:
        raise RuntimeError("patch apply failed: " + "\n\n".join(failures))


def _split_patch_blocks(patch_text: str) -> list[str]:
    lines = patch_text.splitlines(keepends=True)
    blocks: list[list[str]] = []
    current: list[str] = []

    for line in lines:
        if line.startswith("diff --git "):
            if current:
                blocks.append(current)
            current = [line]
            continue
        if current:
            current.append(line)

    if current:
        blocks.append(current)

    return ["".join(block) for block in blocks]
