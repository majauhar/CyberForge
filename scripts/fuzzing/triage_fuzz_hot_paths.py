#!/usr/bin/env python3
"""Classify existing injection outputs into hot-path confidence buckets."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from quality_control.fuzz_hot_path_triage import run_fuzz_hot_path_triage  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source_dir", help="Injection run, fuzz-poc run, or other directory containing injection_result.json files.")
    parser.add_argument("--output-dir", help="Optional output directory for fuzz_hot_path_triage_report.json.")
    args = parser.parse_args()

    report = run_fuzz_hot_path_triage(
        source_dir=Path(args.source_dir).resolve(),
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
    )
    output_dir = Path(report["output_dir"]).resolve()
    print(
        json.dumps(
            {
                "fuzz_hot_path_triage_report": str((output_dir / "fuzz_hot_path_triage_report.json").resolve()),
                "summary": report["summary"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
