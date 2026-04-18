"""Verification pipeline for V2 workflow."""

from __future__ import annotations

import logging
from pathlib import Path

from setup.container_runtime import ContainerRuntime
from utils.github_utils import reset_to_secure_commit
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
    runtime: ContainerRuntime,
    project: str,
    run_id: str,
    repo_dir: str,
    secure_base_commit: str,
    git_backup_dir: Path,  # kept for call-site compatibility, unused
    unit_tests: dict | None,
    skip_unit_tests: bool = False,
    project_root: Path,
    exploit_path: str,
    expected_crash_type: str | None = None,
    expected_crash_state: list[str] | None = None,
    pre_vulnerable_commands: list[str] | None = None,
    pre_secure_commands: list[str] | None = None,
) -> VerificationResult:
    logger.info("[%s] === VERIFICATION START ===", project)

    # .git is always present in the container (baked into the OSS-Fuzz image).
    runtime.exec("git diff --binary > /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
        "snapshot patch generation failed"
    )
    has_snapshot_patch = runtime.exec("test -s /tmp/vuljector.patch", workdir=repo_dir).returncode == 0

    # ── Unit tests (informational only — never aborts pipeline) ──────────────
    if skip_unit_tests:
        test_status, passed_count, test_message, test_raw_output = (
            "skipped",
            None,
            "Unit tests skipped by request.",
            "",
        )
    else:
        logger.info("[%s] --- unit tests (on vulnerable version) ---", project)
        test_status, passed_count, test_message, test_raw_output = run_unit_tests(
            runtime,
            repo_dir=repo_dir,
            unit_tests=unit_tests,
            project_root=project_root,
        )
        logger.info(
            "[%s] unit_tests: status=%s passed=%s message=%s\n--- test output ---\n%s\n--- end ---",
            project, test_status, passed_count, test_message, (test_raw_output or "")[:3000],
        )

    def _make_result(status, checks, failure_cause, failure_message) -> VerificationResult:
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

    def _run_pre_exploit_commands(commands: list[str] | None, *, phase: str) -> VerificationResult | None:
        if not commands:
            return None
        for idx, command in enumerate(commands, start=1):
            logger.info("[%s] --- %s command %d/%d: %s ---", project, phase, idx, len(commands), command)
            result = runtime.exec(command, workdir=repo_dir, timeout=1800)
            output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            if result.returncode == 0:
                continue
            return _make_result(
                "failure",
                {
                    "unit_tests": test_status,
                    "exploit_on_vulnerable": "skipped" if phase == "vulnerable setup" else "passed",
                    "exploit_on_secure": "skipped",
                },
                f"{phase.replace(' ', '_')}_failed",
                output or f"Command failed: {command}",
            )
        return None

    def _restore_vulnerable_snapshot() -> None:
        if not has_snapshot_patch:
            return
        runtime.exec("git apply --whitespace=fix /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
            "restore vulnerable patch failed"
        )

    # ── Check 1: exploit must trigger on vulnerable code ─────────────────────
    setup_failure = _run_pre_exploit_commands(pre_vulnerable_commands, phase="vulnerable setup")
    if setup_failure is not None:
        logger.info("[%s] === VERIFICATION FAIL: vulnerable pre-exploit setup failed ===", project)
        return setup_failure

    logger.info("[%s] --- exploit on VULNERABLE version ---", project)
    vuln_ok, vuln_msg, vuln_timed_out = run_exploit(
        runtime, repo_dir=repo_dir, exploit_path=exploit_path, label="vulnerable"
    )
    if vuln_timed_out:
        logger.info("[%s] === VERIFICATION FAIL: exploit timed out on vulnerable ===", project)
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "timed_out", "exploit_on_secure": "skipped"},
            "exploit_timed_out_on_vulnerable",
            vuln_msg,
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
            {"unit_tests": test_status, "exploit_on_vulnerable": "invalid", "exploit_on_secure": "skipped"},
            "oracle_invalid_on_vulnerable",
            vuln_invalid_reason or vuln_msg,
        )
    logger.info("[%s] exploit_on_vulnerable: triggered=%s", project, vuln_ok)
    if not vuln_ok:
        logger.info("[%s] === VERIFICATION FAIL: exploit did not trigger on vulnerable ===", project)
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "failed", "exploit_on_secure": "skipped"},
            "exploit_failed_on_vulnerable",
            vuln_msg,
        )

    # ── Reset to secure commit ────────────────────────────────────────────────
    logger.info("[%s] --- resetting to secure commit: %s ---", project, secure_base_commit)
    reset_to_secure_commit(
        runtime,
        repo_dir=repo_dir,
        secure_base_commit=secure_base_commit,
    )

    setup_failure = _run_pre_exploit_commands(pre_secure_commands, phase="secure setup")
    if setup_failure is not None:
        _restore_vulnerable_snapshot()
        logger.info("[%s] === VERIFICATION FAIL: secure pre-exploit setup failed ===", project)
        return setup_failure

    # ── Check 2: exploit must NOT trigger on secure code ─────────────────────
    logger.info("[%s] --- exploit on SECURE version ---", project)
    secure_ok, secure_msg, secure_timed_out = run_exploit(
        runtime, repo_dir=repo_dir, exploit_path=exploit_path, label="secure"
    )
    if secure_timed_out:
        _restore_vulnerable_snapshot()
        logger.info("[%s] === VERIFICATION FAIL: exploit timed out on secure ===", project)
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "timed_out"},
            "exploit_timed_out_on_secure",
            secure_msg,
        )
    secure_valid, secure_invalid_reason = _classify_oracle_signal(
        output=secure_msg,
        triggered=secure_ok,
        expected_crash_type=expected_crash_type,
        expected_crash_state=expected_crash_state,
    )
    if not secure_valid:
        _restore_vulnerable_snapshot()
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "invalid"},
            "oracle_invalid_on_secure",
            secure_invalid_reason or secure_msg,
        )
    logger.info("[%s] exploit_on_secure: triggered=%s", project, secure_ok)

    # Re-apply the vulnerability for snapshot generation.
    _restore_vulnerable_snapshot()

    if secure_ok:
        logger.info("[%s] === VERIFICATION FAIL: exploit triggers on secure version too ===", project)
        return _make_result(
            "failure",
            {"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "failed"},
            "exploit_succeeds_on_both",
            secure_msg or "Exploit succeeded on secure code.",
        )

    logger.info("[%s] === VERIFICATION SUCCESS ===", project)
    return _make_result(
        "success",
        {"unit_tests": test_status, "exploit_on_vulnerable": "passed", "exploit_on_secure": "passed"},
        None,
        "",
    )
