"""Strategy adapter for the agent-based full injection method."""

from __future__ import annotations

from injector.agent_based_full_v1.run import run_agent_based_full_v1
from setup import ContainerRuntime

from .base import InjectionContext, InjectionResult, InjectionStrategy


class AgentBasedFullV1Strategy(InjectionStrategy):
    @property
    def id(self) -> str:
        return "agent_based_full_v1"

    def setup(self, runtime: ContainerRuntime, context: InjectionContext) -> None:
        # Keep setup minimal and idempotent; orchestrator caches this per setup hash.
        install_cmd = (
            "python3 -m pip install --disable-pip-version-check --no-input "
            "langgraph claude-agent-sdk opencode-ai"
        )
        runtime.exec(install_cmd)

    def run(self, runtime: ContainerRuntime, context: InjectionContext) -> InjectionResult:
        return run_agent_based_full_v1(runtime=runtime, context=context)
