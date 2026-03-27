"""Agent-based test harness discovery and baseline runner."""

from __future__ import annotations

import base64
import logging
import subprocess
from pathlib import Path

from utils.agent import AgentRequest, run_agent_task
from utils.agent.prompts import SYSTEM_TEMPLATE, TEST_DISCOVERY_TASK
from utils.paths import project_root
from verifier.unit_tests import extract_passing_count

from .layout import PARSER_PATH, write_test_harness

logger = logging.getLogger(__name__)


def run_baseline_unit_tests(*, runtime, project: str) -> tuple[int | None, bool]:
    """Run unit_tests/test.sh in a fresh container; return (passing_count, enabled)."""
    script_host = project_root(project) / "unit_tests" / "test.sh"
    if not script_host.exists():
        return None, False

    encoded_harness = base64.b64encode(script_host.read_text(encoding="utf-8").encode()).decode()

    parser_host = script_host.parent / "parse_results.py"
    if not parser_host.exists():
        raise RuntimeError(
            f"[{project}] Missing required {parser_host} (expected alongside unit_tests/test.sh)."
        )
    encoded_parser = base64.b64encode(parser_host.read_bytes()).decode()

    cmd = (
        f"bash /src/build.sh 2>&1 | tail -5 || true && "
        f"mkdir -p /workspace/run/unit_tests && "
        f"echo '{encoded_parser}' | base64 -d > /workspace/run/unit_tests/parse_results.py && "
        f"echo '{encoded_harness}' | base64 -d > /tmp/test_harness.sh && "
        f"chmod +x /tmp/test_harness.sh && "
        f"cd {runtime.repo_dir_in_container} && bash /tmp/test_harness.sh"
    )
    try:
        result = subprocess.run(
            ["docker", "run", "--rm", runtime.image_tag, "bash", "-c", cmd],
            capture_output=True, text=True, timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.warning("[%s] Baseline unit test run timed out.", project)
        return None, True

    out = (result.stdout or "") + "\n" + (result.stderr or "")
    count = extract_passing_count(out)
    if count is not None:
        return count, True
    logger.warning("[%s] Baseline output missing parse_results JSON summary.", project)
    return 0, True


def try_agent_harness(
    *, runtime, project: str, run_dir: Path, model_id: str, src_dir: str, unit_tests_dir: Path
) -> None:
    """
    Discover test harness via agent, write it, and validate with a baseline run.
    Raises RuntimeError if the agent produces no script or one missing the parser pipeline.
    Warns (does not raise) if baseline yields 0 passing tests.
    """
    logger.info("[%s] Running test discovery agent fallback.", project)
    trajectory_path = str(run_dir / "logs" / "test_discovery_trajectory.json")

    # Install parse_results.py so the agent can run and verify the full pipeline.
    parser_host = project_root(project) / "unit_tests" / "parse_results.py"
    encoded_parser = base64.b64encode(parser_host.read_bytes()).decode()
    install_parser = (
        f"mkdir -p /workspace/run/unit_tests && "
        f"echo '{encoded_parser}' | base64 -d > /workspace/run/unit_tests/parse_results.py && "
        f"chmod +x /workspace/run/unit_tests/parse_results.py"
    )

    agent_req = AgentRequest(
        model_id=model_id,
        prompt=TEST_DISCOVERY_TASK.format(project=project, src_dir=src_dir),
        workdir=runtime.repo_dir_in_container,
        system_template=SYSTEM_TEMPLATE,
        step_limit=30,
        cost_limit=1.0,
        setup_commands=["bash /src/build.sh 2>&1 | tail -30 || true", install_parser],
        extract_paths=["/tmp/test_harness.sh", "/tmp/baseline_output.txt"],
        post_commands=[
            "bash /tmp/test_harness.sh > /tmp/harness_out.txt 2>&1"
            "; echo HARNESS_EXIT:$?; tail -20 /tmp/harness_out.txt",
        ],
        trajectory_path=trajectory_path,
    )

    resp = run_agent_task(runtime, agent_req)
    harness_script = resp.extracted_files.get("/tmp/test_harness.sh", "").strip()

    if not harness_script:
        raise RuntimeError(
            f"[{project}] Test discovery agent did not produce /tmp/test_harness.sh. "
            f"Agent exit_status={resp.exit_status!r}. Check trajectory at {trajectory_path}"
        )
    if PARSER_PATH not in harness_script:
        raise RuntimeError(
            f"[{project}] Agent-produced test harness is missing parse_results.py pipeline "
            f"({PARSER_PATH} --framework <key>)."
        )

    write_test_harness(unit_tests_dir, harness_script)

    count, enabled = run_baseline_unit_tests(runtime=runtime, project=project)
    if enabled and (count or 0) > 0:
        logger.info("[%s] Agent fallback harness accepted (%d passing tests).", project, count)
    else:
        logger.warning(
            "[%s] Agent harness written but baseline yielded count=%s — review before use.",
            project, count,
        )
