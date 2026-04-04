#!/usr/bin/env python3
"""Run configurable selection triage over an existing candidates.json artifact."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from quality_control.selection_triage import (  # noqa: E402
    DEFAULT_SELECTION_TRIAGE_PROFILES,
    run_selection_triage,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("selection_file", help="Path to selection candidates.json")
    parser.add_argument(
        "--profile",
        default="balanced",
        choices=sorted(DEFAULT_SELECTION_TRIAGE_PROFILES),
        help="Built-in selection triage profile to start from.",
    )
    parser.add_argument(
        "--config",
        help="Optional JSON config override file merged onto the selected profile.",
    )
    parser.add_argument(
        "--overrides",
        help="Optional inline JSON object merged after --config.",
    )
    parser.add_argument(
        "--output-dir",
        help="Directory to write filtered_candidates.json and stage1_report.json.",
    )
    args = parser.parse_args()

    overrides = json.loads(args.overrides) if args.overrides else None
    report = run_selection_triage(
        selection_file=Path(args.selection_file).resolve(),
        profile=args.profile,
        config_path=Path(args.config).resolve() if args.config else None,
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        inline_overrides=overrides,
    )
    output_dir = Path(report["output_dir"]).resolve()
    print(json.dumps({
        "selection_triage_report": str((output_dir / "selection_triage_report.json").resolve()),
        "filtered_candidates": str((output_dir / "filtered_candidates.json").resolve()),
        "summary": report["summary"],
    }, indent=2))


if __name__ == "__main__":
    main()
