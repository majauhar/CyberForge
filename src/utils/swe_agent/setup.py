"""Setup hook for mini-swe-agent execution."""

from __future__ import annotations

from setup.container_runtime import ContainerRuntime


def ensure_swe_agent_ready(runtime: ContainerRuntime) -> None:
    # The mini-swe-agent process runs on host and uses DockerEnvironment to
    # execute commands inside the target container. No container-side install.
    _ = runtime

