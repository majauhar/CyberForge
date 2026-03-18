"""Single-prompt agent runner executed inside the project container."""

from __future__ import annotations

import shlex

from setup.container_runtime import ContainerRuntime, ExecResult

from .models import SweAgentRequest, SweAgentResponse


def run_single_prompt_agent(
    runtime: ContainerRuntime,
    request: SweAgentRequest,
    *,
    log_path_in_run_mount: str = "/workspace/run/logs/swe_agent.log",
) -> SweAgentResponse:
    quoted_prompt = shlex.quote(request.prompt)
    quoted_model = shlex.quote(request.model_id)
    quoted_log = shlex.quote(log_path_in_run_mount)

    # Prefer dedicated sweagent command if available, otherwise fallback to
    # opencode CLI. Both execute inside container and write logs to run mount.
    cmd = (
        "mkdir -p /workspace/run/logs && "
        "if command -v sweagent >/dev/null 2>&1; then "
        f"sweagent run --model {quoted_model} --prompt {quoted_prompt} "
        f"2>&1 | tee {quoted_log}; "
        "else "
        f"opencode run {quoted_prompt} -m {quoted_model} "
        "--format text 2>&1 | tee "
        f"{quoted_log}; "
        "fi"
    )
    result: ExecResult = runtime.exec(cmd, workdir=request.workdir)
    return SweAgentResponse(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )

