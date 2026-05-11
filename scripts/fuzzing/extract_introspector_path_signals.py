#!/usr/bin/env python3
"""Extract calltree- and path-derived Introspector signals from a cached metadata file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from selector.fuzz_guided.guidance import load_json  # noqa: E402
from selector.fuzz_guided.path_signals import summarize_project_path_signals  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_file", help="Path to runs/ossfuzz_metadata/<project>.json")
    parser.add_argument("--top-n", type=int, default=12, help="Functions to keep per harness.")
    parser.add_argument("--output", help="Optional JSON output path.")
    args = parser.parse_args()

    cache_file = Path(args.cache_file).resolve()
    summary = summarize_project_path_signals(load_json(cache_file), top_n=args.top_n)
    summary["cache_file"] = str(cache_file)

    if args.output:
        output = Path(args.output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps({"output": str(output)}, indent=2))
        return

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
