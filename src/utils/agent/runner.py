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
    # Apply collected env to host process so litellm can see Azure/API keys.
    os.environ.update(env)
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
                f"Install it in Vuljector/src environment. Details: {exc}"
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
                "Your next response must include at least one bash tool call.\n"
                "Call the bash tool with JSON arguments of the form:\n"
                "{\"command\": \"your_command_here\"}\n"
                "Do not answer with a fenced bash block unless it is paired with a bash tool call.\n"
                "To finish, use a bash tool call with exactly:\n"
                "{\"command\": \"echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\"}\n"
                "Do not combine that final echo with any other command."
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

    # Bridge all Azure endpoint variants to AZURE_API_BASE (what litellm reads).
    azure_endpoint = (
        merged.get("AZURE_API_BASE")
        or merged.get("AZURE_OPENAI_ENDPOINT")
        or merged.get("AZURE_ENDPOINT")
    )
    if azure_endpoint:
        merged.setdefault("AZURE_API_BASE", azure_endpoint)
        merged.setdefault("AZURE_OPENAI_ENDPOINT", azure_endpoint)
    azure_key = merged.get("AZURE_OPENAI_API_KEY") or merged.get("AZURE_API_KEY")
    if azure_key:
        merged.setdefault("AZURE_API_KEY", azure_key)
        merged.setdefault("AZURE_OPENAI_API_KEY", azure_key)
    azure_version = merged.get("AZURE_OPENAI_API_VERSION") or merged.get("AZURE_API_VERSION")
    if azure_version:
        merged.setdefault("AZURE_API_VERSION", azure_version)
        merged.setdefault("AZURE_OPENAI_API_VERSION", azure_version)
    # For rchat, override empty OPENAI_* values (not just missing ones).
    if merged.get("RCHAT_OSS_API_BASE"):
        if not merged.get("OPENAI_BASE_URL", "").strip():
            merged["OPENAI_BASE_URL"] = merged["RCHAT_OSS_API_BASE"]
        if not merged.get("OPENAI_API_BASE", "").strip():
            merged["OPENAI_API_BASE"] = merged["RCHAT_OSS_API_BASE"]
    if merged.get("RCHAT_OSS_API_KEY"):
        if not merged.get("OPENAI_API_KEY", "").strip():
            merged["OPENAI_API_KEY"] = merged["RCHAT_OSS_API_KEY"]
        if not merged.get("OPENAI_KEY", "").strip():
            merged["OPENAI_KEY"] = merged["RCHAT_OSS_API_KEY"]

    allowed_keys = {
        "OPENAI_API_KEY", "OPENAI_BASE_URL", "OPENAI_API_BASE", "OPENAI_KEY",
        "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GEMINI_API_KEY", "OPENROUTER_API_KEY",
        "AZURE_API_KEY", "AZURE_API_BASE", "AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT",
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
        # Strip inline comments (e.g. "VALUE  # comment") and quotes.
        if " #" in value:
            value = value[:value.index(" #")]
        value = value.strip().strip("'").strip('"')
        if key:
            out[key] = value
    return out
