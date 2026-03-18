"""Unit test verification helper."""

from __future__ import annotations

import re
from pathlib import Path

from setup.container_runtime import ContainerRuntime


def run_unit_tests(
    runtime: ContainerRuntime,
    *,
    repo_dir: str,
    unit_tests: dict | None,
    project_root: Path,
) -> tuple[str, int | None, str]:
    if not unit_tests or not unit_tests.get("enabled"):
        return "skipped", None, ""

    script_rel = str(unit_tests.get("script") or "unit_tests/test.sh")
    script_host = project_root / script_rel
    if not script_host.exists():
        return "failed", None, f"Missing unit test script: {script_host}"

    runtime.exec("mkdir -p /workspace/run/unit_tests").raise_for_status("mkdir unit_tests mount failed")
    runtime.copy_to(script_host, "/workspace/run/unit_tests/test.sh")
    runtime.exec("chmod +x /workspace/run/unit_tests/test.sh").raise_for_status("chmod test.sh failed")
    test_result = runtime.exec("bash /workspace/run/unit_tests/test.sh", workdir=repo_dir)
    stdout = (test_result.stdout or "") + "\n" + (test_result.stderr or "")
    passed_count = _extract_passing_count(stdout)

    expected = unit_tests.get("expected_passing_count")
    if expected is None:
        return "skipped", passed_count, "No expected_passing_count configured."
    if passed_count is None:
        return "failed", None, "Could not parse PASSING_TESTS=<N> from test output."
    if int(passed_count) != int(expected):
        return "failed", passed_count, f"Expected {expected} passing tests, got {passed_count}."
    return "passed", passed_count, ""


def _extract_passing_count(output: str) -> int | None:
    match = re.search(r"PASSING_TESTS\s*=\s*(\d+)", output)
    if match:
        return int(match.group(1))
    return None

