#!/usr/bin/env python3
"""Run or analyze repeated task-hardness trials over existing agent-task artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from quality_control.task_hardness import (  # noqa: E402
    analyze_task_hardness_runs,
    run_task_hardness_trials,
)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser("run", help="Run repeated agent-task trials via the Vuljector CLI")
    p_run.add_argument("project")
    p_run.add_argument("vulnerability_id")
    p_run.add_argument("task_type")
    p_run.add_argument("model_id")
    p_run.add_argument("--trials", type=int, default=3)
    p_run.add_argument("--output-dir", default=None)

    p_an = sub.add_parser("analyze", help="Analyze existing agent-task run directories")
    p_an.add_argument("run_dirs", nargs="+", help="One or more runs/agent_tasks/.../agent_task_* directories")
    p_an.add_argument("--output-dir", default=None)

    args = parser.parse_args()

    if args.command == "run":
        payload = run_task_hardness_trials(
            project=args.project,
            vulnerability_id=args.vulnerability_id,
            task_type=args.task_type,
            model_id=args.model_id,
            trials=args.trials,
            repo_root=REPO_ROOT,
            output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
        )
        analysis = payload["analysis"]
        out_dir = Path(payload["trial_summary"]["session_dir"]).resolve()
        print(json.dumps({
            "task_hardness_trials": str((out_dir / "task_hardness_trials.json").resolve()),
            "task_hardness_analysis": str((out_dir / "task_hardness_analysis.json").resolve()),
            "summary": analysis["summary"],
        }, indent=2))
        return

    payload = analyze_task_hardness_runs(
        run_dirs=[Path(p).resolve() for p in args.run_dirs],
        output_dir=Path(args.output_dir).resolve() if args.output_dir else None,
    )
    out_dir = Path(args.output_dir).resolve() if args.output_dir else None
    print(json.dumps({
        "task_hardness_analysis": str((out_dir / "task_hardness_analysis.json").resolve()) if out_dir else None,
        "summary": payload["summary"],
    }, indent=2))


if __name__ == "__main__":
    main()
