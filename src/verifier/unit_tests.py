"""Unit test verification helper."""

from __future__ import annotations

import json
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
    parser_host = script_host.parent / "parse_results.py"
    if not parser_host.exists():
        raise RuntimeError(f"[{project_root}] Missing required {parser_host} (expected alongside unit_tests/test.sh).")

    test_result = runtime.exec("bash /workspace/run/unit_tests/test.sh", workdir=repo_dir)
    raw_output = (test_result.stdout or "") + "\n" + (test_result.stderr or "")
    passed_count = extract_passing_count(raw_output)

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


def extract_passing_count(output: str) -> int | None:
    """Parse the JSON summary line appended by parse_results.py: {"passed": N, "failed": M}.

    Scans from the end so stray stderr lines (e.g. pip warnings) after the JSON
    do not prevent detection.
    """
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line:
            continue
        try:
            return int(json.loads(line)["passed"])
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            continue
    return None
