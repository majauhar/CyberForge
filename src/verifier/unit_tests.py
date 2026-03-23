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
) -> tuple[str, int | None, str, str]:
    """
    Returns (status, passed_count, message, raw_output).
    status is one of: "skipped", "passed", "failed", "parse_error".
    Never raises — caller decides whether to abort.
    """
    if not unit_tests or not unit_tests.get("enabled"):
        return "skipped", None, "", ""

    script_rel = str(unit_tests.get("script") or "unit_tests/test.sh")
    script_host = project_root / script_rel
    if not script_host.exists():
        return "failed", None, f"Missing unit test script: {script_host}", ""

    runtime.exec("mkdir -p /workspace/run/unit_tests").raise_for_status("mkdir unit_tests mount failed")
    runtime.copy_to(script_host, "/workspace/run/unit_tests/test.sh")
    runtime.exec("chmod +x /workspace/run/unit_tests/test.sh").raise_for_status("chmod test.sh failed")
    test_result = runtime.exec("bash /workspace/run/unit_tests/test.sh", workdir=repo_dir)
    raw_output = (test_result.stdout or "") + "\n" + (test_result.stderr or "")
    passed_count = _extract_passing_count(raw_output)

    if passed_count is None:
        return "parse_error", None, "Could not parse passing count from test output.", raw_output

    expected = unit_tests.get("expected_passing_count")
    if expected is None:
        return "passed", passed_count, "No baseline to compare against.", raw_output

    delta = int(passed_count) - int(expected)
    if delta == 0:
        return "passed", passed_count, f"{passed_count} passed (matches baseline).", raw_output
    else:
        return "failed", passed_count, f"{passed_count} passed, expected {expected} (delta={delta:+d}).", raw_output


def _extract_passing_count(output: str) -> int | None:
    # Custom format: PASSING_TESTS=N
    match = re.search(r"PASSING_TESTS\s*=\s*(\d+)", output)
    if match:
        return int(match.group(1))
    # Pytest native format: "N passed" (possibly with ", N skipped/failed/etc.")
    match = re.search(r"(\d+)\s+passed", output)
    if match:
        return int(match.group(1))
    return None
