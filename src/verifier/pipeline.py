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


def run_verification(
    *,
    runtime: ContainerRuntime,
    project: str,
    run_id: str,
    repo_dir: str,
    secure_base_commit: str,
    git_backup_dir: Path,  # kept for call-site compatibility, unused
    unit_tests: dict | None,
    project_root: Path,
    exploit_path: str,
) -> VerificationResult:
    logger.info("[%s] === VERIFICATION START ===", project)

    # .git is always present in the container (baked into the OSS-Fuzz image).
    runtime.exec("git diff --binary > /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
        "snapshot patch generation failed"
    )

    # ── Unit tests (informational only — never aborts pipeline) ──────────────
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

    # ── Check 1: exploit must trigger on vulnerable code ─────────────────────
    logger.info("[%s] --- exploit on VULNERABLE version ---", project)
    vuln_ok, vuln_msg = run_exploit(
        runtime, repo_dir=repo_dir, exploit_path=exploit_path, label="vulnerable"
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

    # ── Check 2: exploit must NOT trigger on secure code ─────────────────────
    logger.info("[%s] --- exploit on SECURE version ---", project)
    secure_ok, secure_msg = run_exploit(
        runtime, repo_dir=repo_dir, exploit_path=exploit_path, label="secure"
    )
    logger.info("[%s] exploit_on_secure: triggered=%s", project, secure_ok)

    # Re-apply the vulnerability for snapshot generation.
    runtime.exec("git apply --whitespace=fix /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
        "restore vulnerable patch failed"
    )

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
