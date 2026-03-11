#!/usr/bin/env python3
"""CLI entrypoint for the vulnerability injection workflow."""

import argparse
import logging
import sys
from pathlib import Path

# Ensure the src root (parent of injector and utils) is on the path (works when run as script or -m)
_src_root = Path(__file__).resolve().parent.parent
if str(_src_root) not in sys.path:
    sys.path.insert(0, str(_src_root))

from injector.agents_basic_injection_v1.workflow import run
from utils import ClaudeAgentRunner, OpencodeRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
)


def main() -> None:
    parser = argparse.ArgumentParser(description="LangGraph vulnerability injection workflow")
    parser.add_argument("directory", type=str, help="Target codebase directory")
    parser.add_argument("--model", type=str, default=None, help="Model (default depends on agent)")
    parser.add_argument(
        "--cwe-group",
        type=str,
        default=None,
        help="Optional CWE group name; if not set, agent selects one (with retry up to 3 times)",
    )
    parser.add_argument(
        "--agent",
        type=str,
        choices=("opencode", "claude"),
        default="opencode",
        help="Agent backend (default: opencode)",
    )
    args = parser.parse_args()
    runner = ClaudeAgentRunner() if args.agent == "claude" else OpencodeRunner()
    try:
        result = run(args.directory, model=args.model, cwe_group=args.cwe_group, runner=runner)
    except ValueError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    if result.get("error"):
        print(result["error"], file=sys.stderr)
        sys.exit(1)
    print("Done. Session:", result.get("session_id"), "CWE group:", result.get("cwe_group"))


if __name__ == "__main__":
    main()
