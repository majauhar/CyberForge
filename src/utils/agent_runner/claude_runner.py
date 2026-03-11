from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

from claude_agent_sdk import query
from claude_agent_sdk.types import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
)

from .agent_runner import AgentRunner, SessionStart

logger = logging.getLogger(__name__)

DEFAULT_CLAUDE_MODEL = "claude-opus-4-5"


class ClaudeAgentRunner(AgentRunner):
    """AgentRunner backed by claude-agent-sdk (sync wrapper around async query())."""

    def create_session(
        self,
        *,
        first_message: str,
        model: str = DEFAULT_CLAUDE_MODEL,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> SessionStart:
        return _run_sync(
            prompt=first_message,
            model=model,
            directory=directory,
            capture_output=capture_output,
            resume=None,
            get_session_id=True,
        )

    def continue_session(
        self,
        *,
        session_id: str,
        message: str,
        model: str = DEFAULT_CLAUDE_MODEL,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> Optional[str]:
        return _run_sync(
            prompt=message,
            model=model,
            directory=directory,
            capture_output=capture_output,
            resume=session_id,
            get_session_id=False,
        )


def _run_sync(
    *,
    prompt: str,
    model: str,
    directory: Optional[str],
    capture_output: bool,
    resume: Optional[str],
    get_session_id: bool,
) -> SessionStart | Optional[str]:
    async def _run() -> tuple[Optional[str], Optional[str]]:
        options = ClaudeAgentOptions(
            model=model,
            cwd=str(Path(directory).resolve()) if directory else None,
            resume=resume,
        )
        session_id: Optional[str] = None
        output_parts: list[str] = []
        async for message in query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        logger.info(block.text.rstrip())
                        if capture_output:
                            output_parts.append(block.text)
            elif isinstance(message, ResultMessage):
                session_id = message.session_id
        output = "".join(output_parts) if capture_output else None
        return session_id, output

    session_id, output = asyncio.run(_run())
    if get_session_id:
        if not session_id:
            raise RuntimeError("No session_id in Claude agent response")
        return SessionStart(session_id=session_id, output=output)
    return output
