"""Verification pipeline for ready-image-backed ephemeral sessions."""

from __future__ import annotations

import logging
from pathlib import Path

from vuljector.io_contracts import VerificationResult, utc_now_iso

from .exploit import run_exploit
from .unit_tests import run_unit_tests

logger = logging.getLogger(__name__)


def _contains_any(text: str, patterns: list[str]) -> bool:
    hay = text.lower()
    return any(pattern.lower() in hay for pattern in patterns)


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
) -> VerificationResult:
    logger.info("[%s] === VERIFICATION START ===", project)

    def _make_result(status, checks, failure_cause, failure_message, passed_count, test_message, test_raw_output):
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
        )

    logger.info("[%s] --- exploit on SECURE version ---", project)
    secure_ok, secure_msg, secure_timed_out = run_exploit(
        runtime,
        repo_dir=repo_dir,
        exploit_path=exploit_path,
        label="secure",
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

    _apply_patch(runtime, repo_dir=repo_dir, patch_diff=patch_diff)

    if rebuild_command:
        logger.info("[%s] --- rebuild after patch ---", project)
        rebuild_result = runtime.exec(rebuild_command, timeout=1800)
        if rebuild_result.returncode != 0:
            detail = (rebuild_result.stderr or rebuild_result.stdout or "").strip()[-500:]
            logger.warning("[%s] rebuild after patch failed; continuing verification: %s", project, detail)

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

    logger.info("[%s] --- exploit on VULNERABLE version ---", project)
    vuln_ok, vuln_msg, vuln_timed_out = run_exploit(
        runtime,
        repo_dir=repo_dir,
        exploit_path=exploit_path,
        label="vulnerable",
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


def _apply_patch(runtime, *, repo_dir: str, patch_diff: str) -> None:
    patch_text = patch_diff if patch_diff.endswith("\n") else patch_diff + "\n"
    runtime.write_file("/tmp/vuljector_apply.patch", patch_text)
    runtime.exec(
        "patch -p1 --fuzz=3 < /tmp/vuljector_apply.patch",
        workdir=repo_dir,
    ).raise_for_status("patch apply failed")
