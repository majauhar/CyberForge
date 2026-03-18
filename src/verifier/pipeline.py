"""Verification pipeline for V2 workflow."""

from __future__ import annotations

from pathlib import Path

from setup.container_runtime import ContainerRuntime
from utils.github_utils import remove_git_dir, reset_to_secure_commit, restore_git_dir
from vuljector.io_contracts import VerificationResult, utc_now_iso

from .exploit import run_exploit
from .unit_tests import run_unit_tests


def run_verification(
    *,
    runtime: ContainerRuntime,
    project: str,
    run_id: str,
    repo_dir: str,
    secure_base_commit: str,
    git_backup_dir: Path,
    unit_tests: dict | None,
    project_root: Path,
    exploit_path: str,
) -> VerificationResult:
    restore_git_dir(runtime, repo_dir, git_backup_dir)
    runtime.exec("git diff --binary > /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
        "snapshot patch generation failed"
    )

    test_status, passed_count, test_message = run_unit_tests(
        runtime,
        repo_dir=repo_dir,
        unit_tests=unit_tests,
        project_root=project_root,
    )
    if test_status == "failed":
        remove_git_dir(runtime, repo_dir)
        return VerificationResult(
            schema_version="v2",
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status="failure",
            checks={
                "unit_tests": "failed",
                "exploit_on_vulnerable": "skipped",
                "exploit_on_secure": "skipped",
            },
            failure_cause="unit_tests_failed",
            failure_message=test_message,
        )

    vuln_ok, vuln_msg = run_exploit(runtime, repo_dir=repo_dir, exploit_path=exploit_path)
    if not vuln_ok:
        remove_git_dir(runtime, repo_dir)
        return VerificationResult(
            schema_version="v2",
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status="failure",
            checks={
                "unit_tests": test_status,
                "exploit_on_vulnerable": "failed",
                "exploit_on_secure": "skipped",
            },
            failure_cause="exploit_failed_on_vulnerable",
            failure_message=vuln_msg,
        )

    reset_to_secure_commit(
        runtime,
        repo_dir=repo_dir,
        secure_base_commit=secure_base_commit,
        git_backup_dir=git_backup_dir,
    )
    restore_git_dir(runtime, repo_dir, git_backup_dir)
    secure_ok, secure_msg = run_exploit(runtime, repo_dir=repo_dir, exploit_path=exploit_path)
    runtime.exec("git apply --whitespace=fix /tmp/vuljector.patch", workdir=repo_dir).raise_for_status(
        "restore vulnerable patch failed"
    )
    remove_git_dir(runtime, repo_dir)

    if secure_ok:
        return VerificationResult(
            schema_version="v2",
            project=project,
            run_id=run_id,
            timestamp_utc=utc_now_iso(),
            status="failure",
            checks={
                "unit_tests": test_status,
                "exploit_on_vulnerable": "passed",
                "exploit_on_secure": "failed",
            },
            failure_cause="exploit_succeeds_on_both",
            failure_message=secure_msg or "Exploit succeeded on secure code.",
        )

    return VerificationResult(
        schema_version="v2",
        project=project,
        run_id=run_id,
        timestamp_utc=utc_now_iso(),
        status="success",
        checks={
            "unit_tests": test_status,
            "exploit_on_vulnerable": "passed",
            "exploit_on_secure": "passed",
        },
        failure_cause=None,
        failure_message="",
    )
