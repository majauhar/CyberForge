"""Final verification pipeline for injected vulnerabilities."""

from __future__ import annotations

from setup import ContainerRuntime
from vuljector.strategies.base import FailureCause, InjectionContext, InjectionResult


def run_verification(
    *,
    runtime: ContainerRuntime,
    context: InjectionContext,
    result: InjectionResult,
) -> InjectionResult:
    if result.status != "success":
        return result

    if context.unit_test_cmd:
        tests = runtime.exec(context.unit_test_cmd, workdir=context.repo_dir_in_container)
        if tests.returncode != 0:
            result.status = "failure"
            result.failure_cause = FailureCause.UNIT_TESTS_FAILED
            result.failure_message = (tests.stderr or tests.stdout).strip()
            return result

    exploit_sh = f"{context.vuln_dir_in_container}/exploit_files/exploit.sh"
    vuln_run = runtime.exec(f"bash {exploit_sh}", workdir=context.repo_dir_in_container)
    if vuln_run.returncode != 0:
        result.status = "failure"
        result.failure_cause = FailureCause.EXPLOIT_FAILED_ON_VULNERABLE
        result.failure_message = (vuln_run.stderr or vuln_run.stdout).strip()
        return result

    runtime.exec("git diff --binary > /tmp/vuljector.patch", workdir=context.repo_dir_in_container)
    if context.secure_base_commit:
        reset = runtime.exec(
            f"git reset --hard {context.secure_base_commit}",
            workdir=context.repo_dir_in_container,
        )
        if reset.returncode != 0:
            result.status = "failure"
            result.failure_cause = FailureCause.OTHER
            result.failure_message = (reset.stderr or reset.stdout).strip()
            return result
    secure_run = runtime.exec(f"bash {exploit_sh}", workdir=context.repo_dir_in_container)
    runtime.exec("git apply --whitespace=fix /tmp/vuljector.patch", workdir=context.repo_dir_in_container)

    if secure_run.returncode == 0:
        result.status = "failure"
        result.failure_cause = FailureCause.EXPLOIT_SUCCEEDS_ON_BOTH
        result.failure_message = "exploit.sh succeeded on secure code."
        return result

    return result
