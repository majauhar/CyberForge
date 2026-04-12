"""Verification pipeline for ready-image-backed ephemeral sessions."""

from __future__ import annotations

import logging
from pathlib import Path

from vuljector.io_contracts import VerificationResult, utc_now_iso

from .exploit import run_exploit
from .unit_tests import run_unit_tests

logger = logging.getLogger(__name__)


def run_verification(
    *,
    runtime,
    project: str,
    run_id: str,
    repo_dir: str,
    patch_diff: str,
    unit_tests: dict | None,
    project_root: Path,
    exploit_path: str,
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
        runtime.exec(rebuild_command, timeout=1800).raise_for_status("rebuild after patch failed")

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
