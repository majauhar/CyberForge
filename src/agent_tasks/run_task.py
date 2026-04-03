"""Run swe-agent-mini on a SyntheticTaskSpec."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

from agent_tasks.models import SyntheticTaskSpec, TaskType
from agent_tasks.templates import format_task_prompt
from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, AgentResponse, run_agent_task
from utils.agent.prompts import INSTANCE_TEMPLATE, SYSTEM_TEMPLATE, build_harness_note
from utils.paths import project_root

logger = logging.getLogger(__name__)

# Agent budget for task runs — more generous than injection since the task is harder.
_STEP_LIMIT = 30
_COST_LIMIT = 3.0


def run_agent_on_task(
    runtime: ContainerRuntime,
    spec: SyntheticTaskSpec,
    run_dir: Path,
) -> tuple[AgentResponse, Path]:
    """
    Run swe-agent-mini on a synthetic vulnerability task.

    The agent runs in a fresh container (from the project's ready image).
    setup_commands put the container into the vulnerable state before the agent starts.

    Returns:
        (AgentResponse, trajectory_path)
    """
    setup_commands = _build_setup_commands(runtime, spec)
    post_commands = _build_post_commands(runtime, spec)
    prompt = _build_prompt(spec)
    extract_paths = [spec.task_type.agent_output_container_path]
    trajectory_path = run_dir / "trajectory.json"

    request = AgentRequest(
        model_id=spec.model_id,
        prompt=prompt,
        workdir=runtime.repo_dir_in_container,
        system_template=SYSTEM_TEMPLATE,
        instance_template=INSTANCE_TEMPLATE,
        step_limit=_STEP_LIMIT,
        cost_limit=_COST_LIMIT,
        setup_commands=setup_commands,
        post_commands=post_commands,
        extract_paths=extract_paths,
        trajectory_path=str(trajectory_path),
    )

    logger.info(
        "[%s] Running agent task type=%s vuln=%s model=%s",
        spec.project, spec.task_type.value, spec.vulnerability_id, spec.model_id,
    )
    response = run_agent_task(runtime, request)

    # Save extracted artifact to run_dir/artifacts/
    _save_artifact(response, spec, run_dir)

    return response, trajectory_path


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_setup_commands(runtime: ContainerRuntime, spec: SyntheticTaskSpec) -> list[str]:
    """Build the list of setup_commands to run before the agent starts."""
    cmds: list[str] = [
        "bash /src/build.sh 2>&1 | tail -20 || true",
    ]

    # Copy snapshot files to put the container in the vulnerable state.
    vuln_dir = project_root(spec.project) / "vulnerabilities" / spec.vulnerability_id
    snapshot_dir = vuln_dir / "snapshot" / "files"
    if snapshot_dir.exists():
        for snapshot_file in snapshot_dir.rglob("*"):
            if not snapshot_file.is_file():
                continue
            rel = snapshot_file.relative_to(snapshot_dir)
            dest = f"{runtime.repo_dir_in_container}/{rel}"
            content_b64 = base64.b64encode(
                snapshot_file.read_bytes()
            ).decode()
            cmds.append(
                f"mkdir -p $(dirname '{dest}')"
                f" && echo '{content_b64}' | base64 -d > '{dest}'"
                f" && echo 'Installed vulnerable {rel} OK'"
            )
    else:
        logger.warning(
            "[%s] No snapshot/files found for %s — agent will run on clean source.",
            spec.project, spec.vulnerability_id,
        )

    # Reinitialize git with vulnerable state as baseline — strips history so the
    # agent cannot cheat via git log/diff, while keeping git available for
    # secure_patch's post_command (git diff HEAD).
    repo = runtime.repo_dir_in_container
    cmds.append(
        f"rm -rf {repo}/.git"
        f" && git init {repo}"
        f" && git -C {repo} add -A"
        f" && git -C {repo} -c user.email=vuljector@local -c user.name=vuljector"
        f" commit -m baseline --allow-empty-message 2>&1 | tail -3"
        f" && echo 'Git baseline committed OK'"
    )

    # For secure_patch: also install the reference exploit and test harness.
    if spec.task_type == TaskType.SECURE_PATCH:
        # Reference exploit — agent uses this to verify their fix works.
        if spec.reference_exploit_path.exists():
            exploit_b64 = base64.b64encode(
                spec.reference_exploit_path.read_bytes()
            ).decode()
            cmds.append(
                f"echo '{exploit_b64}' | base64 -d > /tmp/ref_attack.py"
                " && chmod +x /tmp/ref_attack.py"
                " && echo 'Reference exploit installed OK'"
            )

        # Test harness.
        harness_path = project_root(spec.project) / "unit_tests" / "test.sh"
        if harness_path.exists():
            harness_b64 = base64.b64encode(
                harness_path.read_text(encoding="utf-8").encode()
            ).decode()
            cmds.append(
                f"echo '{harness_b64}' | base64 -d > /tmp/test_harness.sh"
                " && chmod +x /tmp/test_harness.sh"
                " && echo 'Test harness installed OK'"
            )

    return cmds


def _build_post_commands(runtime: ContainerRuntime, spec: SyntheticTaskSpec) -> list[str]:
    """Build post_commands that run after the agent but before file extraction."""
    if spec.task_type == TaskType.SECURE_PATCH:
        # Agent edits the file directly; generate a clean git diff for validation.
        return [
            f"cd {runtime.repo_dir_in_container}"
            f" && git diff HEAD > /tmp/fix.patch || true"
        ]
    return []


def _build_prompt(spec: SyntheticTaskSpec) -> str:
    """Format the task prompt for the given spec."""
    harness_path = project_root(spec.project) / "unit_tests" / "test.sh"
    harness_note = build_harness_note(
        harness_available=(
            spec.task_type == TaskType.SECURE_PATCH and harness_path.exists()
        )
    )

    return format_task_prompt(
        spec.task_type,
        project=spec.project,
        cwe_id=spec.cwe_id,
        cwe_group=spec.cwe_group,
        affected_files=spec.affected_files,
        patch_diff=spec.patch_diff,
        vuln_description=spec.vuln_description,
        harness_note=harness_note,
    )


def _save_artifact(
    response: AgentResponse,
    spec: SyntheticTaskSpec,
    run_dir: Path,
) -> None:
    """Save the agent's extracted output file to run_dir/artifacts/."""
    container_path = spec.task_type.agent_output_container_path
    content = response.extracted_files.get(container_path, "")

    if not content:
        logger.warning(
            "[%s] Agent did not produce %s (exit_status=%s)",
            spec.project, container_path, response.exit_status,
        )
        return

    artifacts_dir = run_dir / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    out_path = artifacts_dir / spec.task_type.agent_output_filename
    out_path.write_text(content, encoding="utf-8")
    logger.info("[%s] Saved agent artifact to %s", spec.project, out_path)

    # Mirror injection output format: create exploit.sh bash wrapper alongside attack.py.
    if spec.task_type.extracts_exploit:
        exploit_sh = (
            "#!/bin/bash\n"
            f"cd /src/{spec.project}\n"
            f"python3 {container_path}\n"
        )
        (artifacts_dir / "exploit.sh").write_text(exploit_sh, encoding="utf-8")
        (artifacts_dir / "exploit.sh").chmod(0o755)


def get_artifact_path(run_dir: Path, spec: SyntheticTaskSpec) -> Path | None:
    """Return the path of the agent's saved artifact, or None if it doesn't exist."""
    path = run_dir / "artifacts" / spec.task_type.agent_output_filename
    return path if path.exists() else None
