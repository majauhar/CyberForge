"""Shared prompt templates and helpers."""

from __future__ import annotations


SYSTEM_TEMPLATE = """\
You are a software engineering assistant with full bash terminal access inside a \
Docker container.

## Action format
Every response must include at least one bash tool call.
Reasoning text is allowed, but bash tool calls are what execute actions.

## Rules
- Directory/env changes are NOT persistent. Prefix commands: `cd /path && ...`
- When finished, submit with this exact command in a bash tool call:
  `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`
Do NOT combine the final echo with anything else.

System: {{system}} {{release}} {{machine}}
"""


SECURITY_SYSTEM_TEMPLATE = """\
You are a security researcher with full bash terminal access inside a Docker container. \
Your goal is to identify exploitable vulnerability patterns in source code.

## Action format
Every response must include at least one bash tool call.
Reasoning text is allowed, but bash tool calls are what execute actions.

## Rules
- Directory/env changes are NOT persistent. Prefix commands: `cd /path && ...`
- Focus on security-critical code paths: authentication, authorization, input validation, \
  deserialization, file I/O, subprocess execution, SQL/template rendering.
- Think adversarially: which guards, if removed, would allow an attacker to reach a \
  dangerous operation with attacker-controlled input?
- When finished, submit with this exact command in a bash tool call:
  `echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT`
Do NOT combine the final echo with anything else.

System: {{system}} {{release}} {{machine}}
"""


INSTANCE_TEMPLATE = "{{ task }}"


def build_harness_note(harness_available: bool) -> str:
    """Return a one-line note about harness availability for injection prompts."""
    if harness_available:
        return (
            "A test harness is pre-installed at `/workspace/run/unit_tests/test.sh`. "
            "Run it to verify the patch does not break existing tests."
        )
    return (
        "No test harness is available for this project — "
        "skip the harness step and proceed to the next step."
    )


def extract_all_text_from_messages(messages: list[dict]) -> str:
    """
    Concatenate text from assistant and tool messages only.
    Skips user/system messages to avoid false-positive marker matches.
    """
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "")
        if role in ("user", "system"):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content.strip():
                parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "") or block.get("output", "")
                    if text and text.strip():
                        parts.append(text)
    return "\n\n".join(parts)
