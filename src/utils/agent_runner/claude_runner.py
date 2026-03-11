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
    StreamEvent,
    TextBlock,
    ThinkingBlock,
)

from .agent_runner import AgentRunner, SessionStart

logger = logging.getLogger(__name__)

DEFAULT_CLAUDE_MODEL = "claude-haiku-4-5"


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
        logger.info(
            "--- claude prompt start (model=%s, resume=%s) ---",
            model,
            resume,
        )
        logger.info(prompt)
        logger.info("--- claude prompt end ---")

        options = ClaudeAgentOptions(
            model=model,
            cwd=str(Path(directory).resolve()) if directory else None,
            resume=resume,
            include_partial_messages=True,
        )

        session_id: Optional[str] = None
        output_parts: list[str] = []
        streaming_buffer: str = ""
        active_tool_name: Optional[str] = None
        active_tool_input: str = ""

        def _flush_buffer(final: bool = False) -> None:
            nonlocal streaming_buffer
            # Log complete lines from the buffer; keep any trailing partial line.
            while "\n" in streaming_buffer:
                line, streaming_buffer = streaming_buffer.split("\n", 1)
                if line.strip():
                    logger.info(line)
            if final and streaming_buffer.strip():
                logger.info(streaming_buffer)
                streaming_buffer = ""

        async for message in query(prompt=prompt, options=options):
            # Stream partial text chunks in real time
            if isinstance(message, StreamEvent):
                event = message.event
                event_type = event.get("type")

                if event_type == "content_block_start":
                    content_block = event.get("content_block", {})
                    if content_block.get("type") == "tool_use":
                        active_tool_name = content_block.get("name") or "unknown_tool"
                        active_tool_input = ""
                        logger.info("[tool:start] %s", active_tool_name)

                elif event_type == "content_block_delta":
                    delta = event.get("delta", {})
                    if delta.get("type") == "text_delta":
                        text = delta.get("text", "")
                        if text:
                            streaming_buffer += text
                            _flush_buffer()
                            if capture_output:
                                output_parts.append(text)
                    elif delta.get("type") == "input_json_delta":
                        json_chunk = delta.get("partial_json", "")
                        if json_chunk:
                            active_tool_input += json_chunk

                elif event_type == "content_block_stop":
                    if active_tool_name:
                        if active_tool_input.strip():
                            logger.info("[tool:input] %s %s", active_tool_name, active_tool_input)
                        logger.info("[tool:stop] %s", active_tool_name)
                        active_tool_name = None
                        active_tool_input = ""

            elif isinstance(message, AssistantMessage):
                # We already streamed visible text above; only log reasoning / goals here
                # so we don't duplicate the final answer paragraphs.
                for block in message.content:
                    if isinstance(block, ThinkingBlock):
                        text = block.thinking
                    else:
                        continue

                    if not text:
                        continue

                    for line in text.splitlines():
                        if line.strip():
                            logger.info("[thinking] %s", line)
                    if capture_output:
                        output_parts.append(f"[thinking] {text}")

            elif isinstance(message, ResultMessage):
                session_id = message.session_id

        # Flush any remaining partial text so the last sentence isn't lost.
        _flush_buffer(final=True)

        output = "".join(output_parts) if capture_output else None
        return session_id, output

    session_id, output = asyncio.run(_run())
    if get_session_id:
        if not session_id:
            raise RuntimeError("No session_id in Claude agent response")
        return SessionStart(session_id=session_id, output=output)
    return output
