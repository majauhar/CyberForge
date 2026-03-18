"""Container-side setup for mini-swe-agent execution."""

from __future__ import annotations

from setup.container_runtime import ContainerRuntime


def ensure_swe_agent_ready(runtime: ContainerRuntime) -> None:
    # Keep setup minimal and deterministic inside the project container.
    runtime.exec(
        "python3 -m pip install --quiet --disable-pip-version-check "
        "mini-swe-agent",
    ).raise_for_status("failed to install mini-swe-agent")

