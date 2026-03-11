from __future__ import annotations

import json
import logging
import subprocess
from typing import Optional

from .agent_runner import AgentRunner, SessionStart

logger = logging.getLogger(__name__)

DEFAULT_MODEL = "rchat/gpt-oss-120b"
DEFAULT_OPENCODE_MODEL = DEFAULT_MODEL


def _session_list(directory: Optional[str] = None, max_count: Optional[int] = None) -> list[dict]:
    args = ["opencode", "session", "list", "--format", "json"]
    if max_count is not None:
        args.extend(["-n", str(max_count)])
    result = subprocess.run(args, capture_output=True, text=True, cwd=directory or None)
    if result.returncode != 0 or not result.stdout.strip():
        return []
    return json.loads(result.stdout)


def _get_latest_session_id(directory: Optional[str] = None) -> Optional[str]:
    sessions = _session_list(directory, max_count=1)
    return sessions[0]["id"] if sessions else None


def _get_session_id_by_name(
    name: str,
    most_recent_if_duplicates: bool = True,
    directory: Optional[str] = None,
) -> Optional[str]:
    """Session id for sessions with title == name (exact match)."""
    matches = [s for s in _session_list(directory) if s.get("title") == name]
    if not matches:
        return None
    if most_recent_if_duplicates:
        return matches[0]["id"]
    if len(matches) > 1:
        logger.warning("Multiple sessions with title %r (%d); returning None.", name, len(matches))
        return None
    return matches[0]["id"]


class OpencodeRunner(AgentRunner):
    """AgentRunner backed by the `opencode` CLI (subprocess)."""

    def create_session(
        self,
        *,
        first_message: str,
        model: str = DEFAULT_MODEL,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> SessionStart:
        output = self._run(first_message, model=model, directory=directory, capture_output=capture_output)
        session_id = _get_latest_session_id(directory)
        if not session_id:
            raise RuntimeError("Could not find session id after opencode run")
        return SessionStart(session_id=session_id, output=output)

    def continue_session(
        self,
        *,
        session_id: str,
        message: str,
        model: str = DEFAULT_MODEL,
        directory: Optional[str] = None,
        capture_output: bool = False,
    ) -> Optional[str]:
        return self._run(
            message,
            model=model,
            directory=directory,
            capture_output=capture_output,
            session_id=session_id,
        )

    def _run(
        self,
        prompt: str,
        *,
        model: str,
        directory: Optional[str],
        capture_output: bool,
        session_id: Optional[str] = None,
    ) -> Optional[str]:
        logger.info("--- opencode prompt start (model=%s, session=%s) ---", model, session_id)
        logger.info(prompt)
        logger.info("--- opencode prompt end ---")

        # Use JSON streaming mode so we can distinguish text, tools, and metadata.
        args = ["opencode", "run", prompt, "-m", model, "--format", "json"]
        if session_id:
            args.extend(["--session", session_id])
        if directory:
            args.extend(["--dir", directory])

        proc = subprocess.Popen(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=directory,
        )
        output_parts: list[str] = []
        streaming_buffer: str = ""

        def _flush_buffer(final: bool = False) -> None:
            nonlocal streaming_buffer
            # Log complete lines; keep any trailing partial line.
            while "\n" in streaming_buffer:
                line, streaming_buffer = streaming_buffer.split("\n", 1)
                if line.strip():
                    logger.info(line)
            if final and streaming_buffer.strip():
                logger.info(streaming_buffer)
                streaming_buffer = ""

        if proc.stdout:
            for raw_line in proc.stdout:
                line = raw_line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    # Fallback for any non-JSON output.
                    logger.info(line)
                    if capture_output:
                        output_parts.append(line + "\n")
                    continue

                event_type = event.get("type")

                if event_type == "text":
                    part = event.get("part", {})
                    text = part.get("text", "")
                    if text:
                        streaming_buffer += text
                        _flush_buffer()
                        if capture_output:
                            output_parts.append(text)

                elif event_type == "tool_use":
                    part = event.get("part", {})
                    tool = part.get("tool", "unknown_tool")
                    state = part.get("state", {}) or {}
                    tool_input = state.get("input")
                    tool_output = state.get("output")

                    # Keep tool logs compact.
                    def _short(obj: object, max_len: int = 200) -> str:
                        s = json.dumps(obj, default=str) if obj is not None else ""
                        return (s[: max_len - 3] + "...") if len(s) > max_len else s

                    logger.info("[tool] %s input=%s", tool, _short(tool_input))
                    if tool_output:
                        logger.info("[tool:output] %s %s", tool, _short(tool_output))

                    if capture_output:
                        if tool_input is not None:
                            output_parts.append(f"[tool] {tool} input={_short(tool_input)}\n")
                        if tool_output:
                            output_parts.append(f"[tool:output] {tool} {_short(tool_output)}\n")

                elif event_type == "error":
                    error = event.get("error", {})
                    name = error.get("name", "error")
                    message = (error.get("data") or {}).get("message") or ""
                    logger.error("[opencode:error] %s %s", name, message)
                    if capture_output:
                        output_parts.append(f"[opencode:error] {name} {message}\n")

                # We currently ignore `step_start` and `step_finish` to keep logs minimal.

        proc.wait()
        _flush_buffer(final=True)
        return "".join(output_parts) if capture_output else None

