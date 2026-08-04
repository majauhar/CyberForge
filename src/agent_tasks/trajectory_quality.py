"""Per-trajectory quality metrics for SFT filtering."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def compute_quality_metrics(trajectory_path: Path) -> dict[str, Any]:
    """
    Extract quality signals from a mini-swe-agent v2 trajectory JSON.

    Returns a dict suitable for inclusion in AgentTaskResult.quality_metrics.
    All fields are present even when the trajectory is missing/corrupt.

    SFT filter tiers:
      Tier 1 (keep): completed=True AND format_error_count==0
      Tier 2 (borderline): completed=True AND format_error_count<=2
      Drop: everything else
    """
    empty = _empty_metrics()
    if not trajectory_path or not trajectory_path.exists():
        logger.warning("Trajectory file not found: %s", trajectory_path)
        return empty

    try:
        raw = json.loads(trajectory_path.read_text(encoding="utf-8"))
    except Exception as exc:
        logger.warning("Failed to parse trajectory %s: %s", trajectory_path, exc)
        return empty

    info = raw.get("info") or {}
    config = info.get("config") or {}
    model_stats = info.get("model_stats") or {}
    messages: list[dict] = raw.get("messages") or []

    # mini-swe-agent v2 stores exit_status on info (not info.config); older
    # versions used info.config. Read info first, fall back to config.
    exit_status: str = str(info.get("exit_status") or config.get("exit_status") or "")
    api_calls: int = int(model_stats.get("api_calls") or 0)
    instance_cost: float = float(model_stats.get("instance_cost") or 0.0)

    # Count assistant turns as steps
    total_steps: int = sum(1 for m in messages if m.get("role") == "assistant")

    # Format errors: messages whose content contains the format_error_template marker
    format_error_count: int = _count_format_errors(messages)

    # Count bash tool calls (proxy for how much the agent actually did)
    bash_command_count: int = _count_bash_commands(messages)

    # A clean agent-initiated submit is "Submitted" in mini-swe-agent v2.x
    # (older/other harnesses used "Completed"). Hitting step/context limits
    # (LimitsExceeded / ContextWindowExceededError) is NOT a clean completion.
    completed: bool = exit_status in ("Submitted", "Completed")

    return {
        "exit_status": exit_status,
        "api_calls": api_calls,
        "total_steps": total_steps,
        "instance_cost": instance_cost,
        "format_error_count": format_error_count,
        "bash_command_count": bash_command_count,
        "completed": completed,
    }


def sft_tier(quality_metrics: dict[str, Any], validation_status: str) -> str:
    """
    Return the SFT quality tier for a trajectory.

    Tiers:
      "tier1"  — keep: completed + validated + no format errors
      "tier2"  — borderline: completed + validated + <=2 format errors
      "drop"   — discard
    """
    if validation_status != "success":
        return "drop"
    if not quality_metrics.get("completed"):
        return "drop"
    fmt_errs = int(quality_metrics.get("format_error_count") or 0)
    if fmt_errs == 0:
        return "tier1"
    if fmt_errs <= 2:
        return "tier2"
    return "drop"


# ── Internal helpers ──────────────────────────────────────────────────────────

def _empty_metrics() -> dict[str, Any]:
    return {
        "exit_status": "",
        "api_calls": 0,
        "total_steps": 0,
        "instance_cost": 0.0,
        "format_error_count": 0,
        "bash_command_count": 0,
        "completed": False,
    }


def _count_format_errors(messages: list[dict]) -> int:
    """
    Count messages that represent format errors from the model framework.
    mini-swe-agent injects a user message containing "Tool call error:" when
    the model's response doesn't follow the required format.
    """
    count = 0
    for msg in messages:
        if msg.get("role") != "user":
            continue
        content = msg.get("content", "")
        if isinstance(content, str) and "Tool call error:" in content:
            count += 1
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "") or ""
                    if "Tool call error:" in text:
                        count += 1
                        break
    return count


def _count_bash_commands(messages: list[dict]) -> int:
    """Count the number of bash tool_calls issued by the assistant."""
    count = 0
    for msg in messages:
        if msg.get("role") != "assistant":
            continue
        tool_calls = msg.get("tool_calls") or []
        for tc in tool_calls:
            fn = (tc.get("function") or {}).get("name", "")
            if fn == "bash":
                count += 1
    return count
