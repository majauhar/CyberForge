"""Single-prompt mini-swe-agent runner executed inside project container."""

from __future__ import annotations

import os
import shlex

from setup.container_runtime import ContainerRuntime, ExecResult
from utils.paths import src_root

from .models import SweAgentRequest, SweAgentResponse


def run_single_prompt_agent(
    runtime: ContainerRuntime,
    request: SweAgentRequest,
    *,
    log_path_in_run_mount: str = "/workspace/run/logs/swe_agent.log",
) -> SweAgentResponse:
    quoted_log = shlex.quote(log_path_in_run_mount)
    python_script = _mini_swe_python_script()
    env = _collect_agent_env(request)

    cmd = (
        "mkdir -p /workspace/run/logs && "
        f"set -o pipefail && python3 -c {python_script} 2>&1 | tee {quoted_log}"
    )
    result: ExecResult = runtime.exec(cmd, workdir=request.workdir, env=env)
    return SweAgentResponse(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
    )


def _mini_swe_python_script() -> str:
    # Run mini-swe-agent with LocalEnvironment from inside the container.
    script = (
        "import os;"
        "from minisweagent.agents.default import DefaultAgent;"
        "from minisweagent.models.litellm_model import LitellmModel;"
        "from minisweagent.environments.local import LocalEnvironment;"
        "model_name=os.environ['VULJECTOR_MODEL_ID'];"
        "task=os.environ['VULJECTOR_PROMPT'];"
        "agent=DefaultAgent(LitellmModel(model_name=model_name), LocalEnvironment());"
        "result=agent.run(task);"
        "print(result)"
    )
    return shlex.quote(script)


def _collect_agent_env(request: SweAgentRequest) -> dict[str, str]:
    file_env = _read_dotenv(src_root() / ".env")
    host_env = dict(os.environ)

    merged: dict[str, str] = {}
    merged.update(file_env)
    merged.update(host_env)

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
        "LITELLM_API_BASE",
        "LITELLM_API_KEY",
        "LITELLM_CUSTOM_PROVIDER",
        "LITELLM_SSL_VERIFY",
        "RCHAT_OSS_API_BASE",
        "RCHAT_OSS_API_KEY",
    }

    env = {key: value for key, value in merged.items() if key in allowed_keys}
    env["VULJECTOR_MODEL_ID"] = request.model_id
    env["VULJECTOR_PROMPT"] = request.prompt
    # RCHAT deployments frequently need disabled cert verification.
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

