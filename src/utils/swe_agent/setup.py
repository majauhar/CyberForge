"""Container-side setup for vanilla SWE-agent execution."""

from __future__ import annotations

from setup.container_runtime import ContainerRuntime


def ensure_swe_agent_ready(runtime: ContainerRuntime) -> None:
    # Minimal baseline for our vanilla runner: prefer a dedicated swe-agent CLI if
    # available, otherwise we can still use opencode as the agent backend.
    runtime.exec(
        "python3 -m pip install --quiet --disable-pip-version-check "
        "opencode-ai",
    ).raise_for_status("failed to install agent backend dependencies")

