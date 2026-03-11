"""Utilities to build a compact, token-budgeted snapshot of a codebase.

This module shells out to `tree` (or falls back to `ls`) to summarize the
repository structure while respecting an exclusion pattern and a maximum
token budget, for use in prompts or debugging."""

import shutil
import subprocess
from pathlib import Path
from typing import Iterable


DEFAULT_EXCLUDE_PATTERN = "_*|venv|node_modules|.git|__pycache__|.idea|.vscode"


def _token_count(text: str) -> int:
    return len(text.split())


def _truncate_to_token_budget(text: str, max_tokens: int) -> str:
    """Keep full lines while trimming output to a token budget."""
    lines = text.splitlines()
    kept: list[str] = []
    used = 0
    for line in lines:
        line_tokens = len(line.split())
        if used + line_tokens > max_tokens:
            break
        kept.append(line)
        used += line_tokens

    if len(kept) < len(lines):
        kept.append("... [truncated]")

    return "\n".join(kept) + ("\n" if text.endswith("\n") else "")


def _run_command(cmd: list[str], cwd: str) -> str:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        capture_output=True,
        text=True,
    )
    if result.stdout.strip():
        return result.stdout
    if result.stderr.strip():
        return result.stderr
    return ""


def build_codebase_snapshot(
    directory: str,
    max_tokens: int = 1000,
    depths: Iterable[int] = (4, 3, 2),
    exclude_pattern: str = DEFAULT_EXCLUDE_PATTERN,
) -> str:
    """Build a compact text snapshot of the repository structure."""
    root = str(Path(directory).resolve())
    tree_available = shutil.which("tree") is not None

    if tree_available:
        last_tree_output = ""
        last_depth = None
        for depth in depths:
            command = ["tree", "-L", str(depth), "-I", exclude_pattern]
            output = _run_command(command, cwd=root)
            last_tree_output = output
            last_depth = depth
            if _token_count(output) <= max_tokens:
                return f"$ tree -L {depth} -I '{exclude_pattern}'\n{output}"

        if last_tree_output and last_depth is not None:
            trimmed = _truncate_to_token_budget(last_tree_output, max_tokens=max_tokens)
            return f"$ tree -L {last_depth} -I '{exclude_pattern}'\n{trimmed}"

    fallback_cmd = ["ls", "-la"]
    fallback_output = _run_command(fallback_cmd, cwd=root)
    return "$ ls -la\n" + fallback_output
