"""Single-prompt mini-swe-agent runner (host process, container execution)."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from setup.container_runtime import ContainerRuntime
from utils.paths import src_root

from .models import SweAgentRequest, SweAgentResponse


def run_single_prompt_agent(
    runtime: ContainerRuntime,
    request: SweAgentRequest,
    *,
    log_path_in_run_mount: str = "/workspace/run/logs/swe_agent.log",
) -> SweAgentResponse:
    env = _collect_agent_env(request)
    # mini-swe-agent reads this in the host process; avoid hard-failing when
    # litellm has no price metadata for the model.
    os.environ.setdefault("MSWEA_COST_TRACKING", env.get("MSWEA_COST_TRACKING", "ignore_errors"))
    log_file_on_host = _host_run_mount_path(runtime, log_path_in_run_mount)
    log_file_on_host.parent.mkdir(parents=True, exist_ok=True)
    log_file_on_host.write_text("mini-swe-agent run started\n", encoding="utf-8")

    try:
        from minisweagent.agents.default import DefaultAgent
        from minisweagent.environments.docker import DockerEnvironment
        from minisweagent.models.litellm_model import LitellmModel
    except Exception as exc:  # pragma: no cover - import failure reported to caller
        return SweAgentResponse(
            returncode=1,
            stdout="",
            stderr=(
                "mini-swe-agent is not importable in host environment. "
                f"Install it in VulInjector/src environment. Details: {exc}"
            ),
        )

    proxy_script = _write_docker_proxy_script(runtime.container_name)
    try:
        docker_env = DockerEnvironment(
            image=runtime.image_tag,
            cwd=request.workdir,
            env=env,
            executable=str(proxy_script),
            run_args=[],
            timeout=120,
        )
        model_name = _normalize_litellm_model_name(request.model_id)
        model_kwargs: dict[str, str] = {}
        # OpenAI-compatible (including RChat proxy)
        if model_name.startswith("openai/"):
            if env.get("OPENAI_API_KEY"):
                model_kwargs["api_key"] = env["OPENAI_API_KEY"]
            if env.get("OPENAI_BASE_URL"):
                model_kwargs["api_base"] = env["OPENAI_BASE_URL"]
            elif env.get("OPENAI_API_BASE"):
                model_kwargs["api_base"] = env["OPENAI_API_BASE"]
        # Azure OpenAI
        if model_name.startswith("azure/"):
            model_kwargs["custom_llm_provider"] = "azure"
            # Prefer Azure-specific endpoint/version if present.
            if env.get("AZURE_OPENAI_ENDPOINT"):
                model_kwargs["api_base"] = env["AZURE_OPENAI_ENDPOINT"]
            if env.get("AZURE_OPENAI_API_VERSION"):
                model_kwargs["api_version"] = env["AZURE_OPENAI_API_VERSION"]
            elif env.get("AZURE_API_VERSION"):
                model_kwargs["api_version"] = env["AZURE_API_VERSION"]
            if env.get("AZURE_OPENAI_API_KEY"):
                model_kwargs["api_key"] = env["AZURE_OPENAI_API_KEY"]
            elif env.get("AZURE_API_KEY"):
                model_kwargs["api_key"] = env["AZURE_API_KEY"]
        agent = DefaultAgent(
            LitellmModel(model_name=model_name, model_kwargs=model_kwargs),
            docker_env,
            system_template="You are a software engineer. Be concise.",
            instance_template=(
                "Task: {{task}}\n"
                "Return the final answer directly in your last message.\n"
                "If STRICT JSON is requested, answer with STRICT JSON only."
            ),
            step_limit=24,
        )
        result = agent.run(task=request.prompt)
        # DefaultAgent.run returns a dict with exit_status/submission.
        exit_status = str(result.get("exit_status", ""))
        submission = str(result.get("submission", "") or "")
        log_file_on_host.write_text(
            "mini-swe-agent run finished\n\n" + repr(result) + "\n",
            encoding="utf-8",
        )
        if not submission:
            return SweAgentResponse(
                returncode=1,
                stdout="",
                stderr=f"mini-swe-agent did not submit output (exit_status={exit_status})",
            )
        return SweAgentResponse(returncode=0, stdout=submission, stderr="")
    except Exception as exc:
        # Persist exception details in swe_agent.log for postmortem.
        log_file_on_host.write_text("mini-swe-agent run failed\n\n" + f"{exc}\n", encoding="utf-8")
        return SweAgentResponse(returncode=1, stdout="", stderr=str(exc))
    finally:
        try:
            docker_env.cleanup()
        except Exception:
            pass
        # Keep cleanup best-effort; only remove proxy after docker_env cleanup.
        try:
            proxy_script.unlink(missing_ok=True)
        except OSError:
            pass


def _host_run_mount_path(runtime: ContainerRuntime, container_path: str) -> Path:
    if not container_path.startswith("/workspace/run/"):
        raise ValueError(f"unsupported run mount path: {container_path}")
    rel = container_path.removeprefix("/workspace/run/")
    mount_dir = getattr(runtime, "run_mount_dir", None)
    if mount_dir is None:
        raise RuntimeError("runtime.run_mount_dir is not set")
    return Path(mount_dir) / rel


def _write_docker_proxy_script(container_name: str) -> Path:
    script = f"""#!/usr/bin/env bash
set -euo pipefail
REAL_DOCKER="${{REAL_DOCKER:-docker}}"
TARGET_CONTAINER="{container_name}"

subcmd="${{1:-}}"
shift || true

if [[ "$subcmd" == "run" ]]; then
  echo "$TARGET_CONTAINER"
  exit 0
fi

if [[ "$subcmd" == "exec" ]]; then
  args=()
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -w|-e)
        args+=("$1" "$2")
        shift 2
        ;;
      *)
        break
        ;;
    esac
  done
  # Skip the container id/name argument provided by mini-swe-agent.
  if [[ "$#" -gt 0 ]]; then
    shift 1
  fi
  exec "$REAL_DOCKER" exec "${{args[@]}}" "$TARGET_CONTAINER" "$@"
fi

if [[ "$subcmd" == "stop" || "$subcmd" == "rm" ]]; then
  # The runtime lifecycle owns container shutdown.
  exit 0
fi

exec "$REAL_DOCKER" "$subcmd" "$@"
"""
    fd, path = tempfile.mkstemp(prefix="vuljector-mswea-proxy-", suffix=".sh")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(script)
            f.flush()
            os.fsync(f.fileno())
    finally:
        try:
            os.close(fd)
        except OSError:
            pass
    tmp = Path(path)
    tmp.chmod(0o700)
    return tmp


def _collect_agent_env(request: SweAgentRequest) -> dict[str, str]:
    file_env = _read_dotenv(src_root() / ".env")
    host_env = dict(os.environ)

    merged: dict[str, str] = {}
    merged.update(file_env)
    merged.update(host_env)

    # Bridge common Azure shorthand names to litellm/openai expected names.
    # (User-friendly: allow AZURE_ENDPOINT/AZURE_API_KEY/AZURE_API_VERSION.)
    if merged.get("AZURE_ENDPOINT"):
        merged.setdefault("AZURE_OPENAI_ENDPOINT", merged["AZURE_ENDPOINT"])
    if merged.get("AZURE_API_KEY"):
        merged.setdefault("AZURE_OPENAI_API_KEY", merged["AZURE_API_KEY"])
    if merged.get("AZURE_API_VERSION"):
        merged.setdefault("AZURE_OPENAI_API_VERSION", merged["AZURE_API_VERSION"])

    # Bridge custom RCHAT keys into standard OpenAI-style keys used by litellm.
    if merged.get("RCHAT_OSS_API_BASE"):
        merged.setdefault("OPENAI_BASE_URL", merged["RCHAT_OSS_API_BASE"])
        merged.setdefault("OPENAI_API_BASE", merged["RCHAT_OSS_API_BASE"])
    if merged.get("RCHAT_OSS_API_KEY"):
        merged.setdefault("OPENAI_API_KEY", merged["RCHAT_OSS_API_KEY"])
        # For openai-compatible providers that read this naming convention.
        merged.setdefault("OPENAI_KEY", merged["RCHAT_OSS_API_KEY"])

    # Keep the set explicit so we do not leak unrelated host environment state.
    allowed_keys = {
        "OPENAI_API_KEY",
        "OPENAI_BASE_URL",
        "OPENAI_API_BASE",
        "OPENAI_KEY",
        "ANTHROPIC_API_KEY",
        "GOOGLE_API_KEY",
        "GEMINI_API_KEY",
        "OPENROUTER_API_KEY",
        "AZURE_API_KEY",
        "AZURE_OPENAI_API_KEY",
        "AZURE_OPENAI_ENDPOINT",
        "AZURE_OPENAI_API_VERSION",
        "AZURE_API_VERSION",
        "AZURE_ENDPOINT",
        "LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_CUSTOM_PROVIDER",
        "LITELLM_SSL_VERIFY",
        "RCHAT_OSS_API_BASE",
        "RCHAT_OSS_API_KEY",
    }

    env = {key: value for key, value in merged.items() if key in allowed_keys}
    # Avoid failures when model isn't present in litellm's cost registry.
    env.setdefault("MSWEA_COST_TRACKING", "ignore_errors")
    # RCHAT deployments frequently need disabled cert verification.
    if "RCHAT_OSS_API_BASE" in env:
        env.setdefault("PYTHONHTTPSVERIFY", "0")
    return env


def _normalize_litellm_model_name(model_id: str) -> str:
    # litellm expects provider prefixes like "openai/...", "anthropic/...", etc.
    # We allow "rchat/<model>" as a convenience alias when using the RChat OpenAI-like proxy.
    if model_id.startswith("rchat/"):
        return "openai/" + model_id.removeprefix("rchat/")
    if "/" not in model_id:
        # Default to OpenAI-style provider if user omitted prefix.
        return "openai/" + model_id
    return model_id


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

