"""mini-swe-agent runner: fresh container per task, matching working code approach."""

from __future__ import annotations

import logging
import os
from pathlib import Path

from setup.container_runtime import ContainerRuntime
from .models import AgentRequest, AgentResponse


def run_agent_task(
    runtime: ContainerRuntime,
    request: AgentRequest,
) -> AgentResponse:
    """
    Run mini-swe-agent in a fresh container from the project image.

    Matches the working OSSFuzzEnvironment.run_task() approach exactly:
      - DockerEnvironment(image=...) creates a fresh container per call
      - setup_commands run before the agent (e.g. build.sh)
      - post_commands run first (can normalise files, e.g. git diff HEAD)
      - Files are extracted via docker exec cat after post_commands
      - Container is destroyed when docker_env.close() is called
    """
    env = _collect_agent_env(request)
    os.environ.setdefault("MSWEA_COST_TRACKING", "ignore_errors")
    # Suppress minisweagent's startup banner which prints to stdout and corrupts
    # JSON output when the CLI result is captured via pipe/tee.
    os.environ.setdefault("MSWEA_SILENT_STARTUP", "1")

    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel
    except Exception as exc:
        return AgentResponse(
            returncode=1,
            stdout="",
            stderr=(
                "mini-swe-agent is not importable. "
                f"Install it in VulInjector/src environment. Details: {exc}"
            ),
        )

    docker_env = None
    try:
        active_image = runtime.active_image_tag
        docker_env = DockerEnvironment(
            image=active_image,
            cwd=request.workdir,
            env=env,
            timeout=120,
        )
        logging.info("[%s] Container started from %s%s", runtime.project, active_image,
                     " (ready image)" if active_image != runtime.image_tag else "")

        # ── Pre-agent setup commands (e.g. build.sh) ─────────────────────────
        for cmd in request.setup_commands:
            logging.info("[%s] Setup: %s", runtime.project, cmd[:80])
            docker_env.execute({"command": cmd}, timeout=300)

        # ── Model + agent ─────────────────────────────────────────────────────
        model_name = _normalize_litellm_model_name(request.model_id)
        lm = LitellmModel(
            model_name=model_name,
            model_kwargs={"drop_params": True},
            cost_tracking="ignore_errors",
            format_error_template=(
                "Tool call error:\n<error>\n{{error}}\n</error>\n\n"
                "Every response MUST use the bash tool at least once.\n"
                "Call it with: {\"command\": \"your_command_here\"}\n"
                "To finish, run exactly: echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\n"
                "(do not combine it with any other command)"
            ),
            observation_template=(
                "{%- if output.output | length < 10000 -%}"
                "{\n  \"returncode\": {{ output.returncode }},\n"
                "  \"output\": {{ output.output | tojson }}"
                "{%- if output.exception_info %}, \"exception_info\": {{ output.exception_info | tojson }}{% endif %}\n}"
                "{%- else -%}"
                "{\n  \"returncode\": {{ output.returncode }},\n"
                "  \"output_head\": {{ output.output[:5000] | tojson }},\n"
                "  \"output_tail\": {{ output.output[-5000:] | tojson }},\n"
                "  \"elided_chars\": {{ output.output | length - 10000 }},\n"
                "  \"warning\": \"Output too long.\""
                "{%- if output.exception_info %}, \"exception_info\": {{ output.exception_info | tojson }}{% endif %}\n}"
                "{%- endif -%}"
            ),
        )
        agent_kwargs: dict = dict(
            system_template=request.system_template,
            instance_template=request.instance_template,
            step_limit=request.step_limit,
            cost_limit=request.cost_limit,
        )
        if request.trajectory_path:
            traj = Path(request.trajectory_path)
            traj.parent.mkdir(parents=True, exist_ok=True)
            agent_kwargs["output_path"] = traj

        agent = DefaultAgent(lm, docker_env, **agent_kwargs)
        logging.info(
            "[%s] Agent running (model=%s, steps≤%d, cost≤$%.2f)",
            runtime.project, model_name, request.step_limit, request.cost_limit,
        )
        result = agent.run(task=request.prompt)

        exit_status = str(result.get("exit_status", ""))
        submission = str(result.get("submission", "") or "")
        messages = list(getattr(agent, "messages", []))
        n_steps = sum(1 for m in messages if m.get("role") == "assistant")

        # ── Post-agent commands (run BEFORE extraction so they can normalise files) ─
        # e.g. injection uses this to overwrite the agent's diff -u patch with
        # a proper `git diff HEAD` before we cat /tmp/vuln.patch out.
        post_results: list[dict] = []
        for cmd in request.post_commands:
            logging.info("[%s] Post: %s", runtime.project, cmd[:80])
            out = docker_env.execute({"command": cmd}, timeout=300)
            post_results.append({
                "command": cmd,
                "returncode": out.get("returncode"),
                "output": out.get("output", ""),
            })

        # ── Extract files from container (always — even if agent didn't submit) ─
        extracted: dict[str, str] = {}
        for path in request.extract_paths:
            out = docker_env.execute({"command": f"cat {path}"}, timeout=30)
            if out.get("returncode") == 0:
                extracted[path] = out.get("output", "")
                logging.info(
                    "[%s] Extracted %s (%d bytes)",
                    runtime.project, path, len(extracted[path]),
                )
            else:
                logging.warning(
                    "[%s] Could not extract %s: %s",
                    runtime.project, path, out.get("output", "")[:100],
                )

        if not submission:
            return AgentResponse(
                returncode=1,
                stdout="",
                stderr=f"Agent did not submit output (exit_status={exit_status})",
                messages=messages,
                extracted_files=extracted,
                post_results=post_results,
                exit_status=exit_status,
                total_steps=n_steps,
            )

        return AgentResponse(
            returncode=0,
            stdout=submission,
            stderr="",
            messages=messages,
            extracted_files=extracted,
            post_results=post_results,
            exit_status=exit_status,
            total_steps=n_steps,
        )

    except Exception as exc:
        logging.error("[%s] Agent error: %s", runtime.project, exc, exc_info=True)
        return AgentResponse(returncode=1, stdout="", stderr=str(exc))
    finally:
        if docker_env is not None:
            try:
                docker_env.close()
            except Exception:
                pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _normalize_litellm_model_name(model_id: str) -> str:
    if model_id.startswith("rchat/"):
        return "openai/" + model_id.removeprefix("rchat/")
    if "/" not in model_id:
        return "openai/" + model_id
    return model_id


def _collect_agent_env(request: AgentRequest) -> dict[str, str]:
    """Merge .env file + host env, bridge RCHAT/Azure shorthand keys."""
    from utils.paths import src_root
    file_env = _read_dotenv(src_root() / ".env")
    merged: dict[str, str] = {}
    merged.update(file_env)
    merged.update(dict(os.environ))

    if merged.get("AZURE_ENDPOINT"):
        merged.setdefault("AZURE_OPENAI_ENDPOINT", merged["AZURE_ENDPOINT"])
    if merged.get("AZURE_API_KEY"):
        merged.setdefault("AZURE_OPENAI_API_KEY", merged["AZURE_API_KEY"])
    if merged.get("AZURE_API_VERSION"):
        merged.setdefault("AZURE_OPENAI_API_VERSION", merged["AZURE_API_VERSION"])
    if merged.get("RCHAT_OSS_API_BASE"):
        merged.setdefault("OPENAI_BASE_URL", merged["RCHAT_OSS_API_BASE"])
        merged.setdefault("OPENAI_API_BASE", merged["RCHAT_OSS_API_BASE"])
    if merged.get("RCHAT_OSS_API_KEY"):
        merged.setdefault("OPENAI_API_KEY", merged["RCHAT_OSS_API_KEY"])
        merged.setdefault("OPENAI_KEY", merged["RCHAT_OSS_API_KEY"])

    allowed_keys = {
        "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_KEY",
        "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY",
        "AZURE_API_KEY", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_API_VERSION", "AZURE_API_VERSION", "AZURE_ENDPOINT",
        "LITELLM_API_BASE", "LITELLM_API_KEY", "LITELLM_CUSTOM_PROVIDER", "LITELLM_SSL_VERIFY",
        "RCHAT_OSS_API_BASE", "RCHAT_OSS_API_KEY",
        "PAGER", "MANPAGER", "PIP_PROGRESS_BAR", "TQDM_DISABLE", "PYTHONDONTWRITEBYTECODE",
    }
    env = {k: v for k, v in merged.items() if k in allowed_keys}
    env.setdefault("MSWEA_COST_TRACKING", "ignore_errors")
    env.setdefault("PAGER", "cat")
    env.setdefault("MANPAGER", "cat")
    env.setdefault("PIP_PROGRESS_BAR", "off")
    env.setdefault("TQDM_DISABLE", "1")
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    if "RCHAT_OSS_API_BASE" in env:
        env.setdefault("PYTHONHTTPSVERIFY", "0")
    return env


def _read_dotenv(path: os.PathLike[str] | str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        raw = open(path, "r", encoding="utf-8").read().splitlines()
    except OSError:
        return out
    for line in raw:
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key:
            out[key] = value
    return out
