"""Descriptor for the agent-based full injection method."""

from .base import Vuljector

agent_based_full_v1 = Vuljector(
    id="agent_based_full_v1",
    module="injector.agent_based_full_v1.run",
    setup_cmds=[
        "python3 -m pip install --quiet --disable-pip-version-check "
        "langgraph claude-agent-sdk opencode-ai",
    ],
)
