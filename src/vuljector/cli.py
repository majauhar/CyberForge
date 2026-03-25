"""CLI entrypoint for V2 phase-based workflow."""

from __future__ import annotations

import argparse
import json
import sys

from utils.paths import selection_run_dir
from vuljector.core import build_runtime, load_project_config
from vuljector.run_init import run_init
from vuljector.run_injection import run_injection
from vuljector.run_selection import run_selection
from vuljector.run_setup import run_setup


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    out = [x.strip() for x in value.split(",") if x.strip()]
    return out or None


def main() -> None:
    parser = argparse.ArgumentParser(description="Vuljector V2 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Create project.json from oss-fuzz metadata")
    p_init.add_argument("project", help="OSS-Fuzz project name (must exist under oss-fuzz/projects/)")
    p_init.add_argument("--oss-fuzz-path", required=True, help="Path to oss-fuzz checkout")
    p_init.add_argument("--target-dir", default=None,
                        help="Source subdirectory under /src/ in container (default: project name)")

    p_setup = sub.add_parser("setup", help="Run setup phase")
    p_setup.add_argument("project")
    p_setup.add_argument("--model-id", default="claude-sonnet-4-6", help="Model for test discovery agent")

    p_sel = sub.add_parser("selection", help="Run selection phase")
    p_sel.add_argument("project")
    p_sel.add_argument("strategy_id")
    p_sel.add_argument("model_id")
    p_sel.add_argument("--cwe-groups", default=None)
    p_sel.add_argument("--cwe-ids", default=None)
    p_sel.add_argument("--max-candidates", type=int, default=None,
                       help="Maximum candidates to return (default: strategy default)")

    p_inj = sub.add_parser("injection", help="Run injection phase")
    p_inj.add_argument("project")
    p_inj.add_argument("strategy_id")
    p_inj.add_argument("model_id")
    p_inj.add_argument("candidates_file")
    p_inj.add_argument("--num-vulnerabilities", type=int, default=1)
    p_inj.add_argument("--debug", action="store_true")

    p_run = sub.add_parser("run", help="Convenience wrapper")
    p_run.add_argument("project")
    p_run.add_argument("selection_strategy_id")
    p_run.add_argument("injection_strategy_id")
    p_run.add_argument("model_id")
    p_run.add_argument("--cwe-groups", default=None)
    p_run.add_argument("--cwe-ids", default=None)
    p_run.add_argument("--max-candidates", type=int, default=None,
                       help="Maximum candidates to return (default: strategy default)")
    p_run.add_argument("--num-vulnerabilities", type=int, default=1)
    p_run.add_argument("--debug", action="store_true")

    p_rep = sub.add_parser("report", help="Show metrics for an injection run")
    p_rep.add_argument("--run-dir", required=True, help="Path to injection run directory")
    p_rep.add_argument("--strategy", default=None,
                       help="Filter by selection strategy (e.g. static_analysis, llm_explore). Default: all.")

    args = parser.parse_args()

    if args.command == "report":
        from pathlib import Path
        from vuljector.report import show_injection_run
        show_injection_run(Path(args.run_dir).resolve(), strategy_filter=args.strategy)
        return

    try:
        if args.command == "init":
            payload = run_init(
                args.project,
                oss_fuzz_path=args.oss_fuzz_path,
                target_dir=args.target_dir,
            )
        elif args.command == "setup":
            payload = run_setup(args.project, model_id=args.model_id)
        elif args.command == "selection":
            payload = run_selection(
                project=args.project,
                strategy_id=args.strategy_id,
                model_id=args.model_id,
                cwe_groups=_split_csv(args.cwe_groups),
                cwe_ids=_split_csv(args.cwe_ids),
                max_candidates=args.max_candidates,
            )
        elif args.command == "injection":
            payload = run_injection(
                project=args.project,
                strategy_id=args.strategy_id,
                model_id=args.model_id,
                candidates_file=args.candidates_file,
                num_vulnerabilities=args.num_vulnerabilities,
                debug=args.debug,
            )
        else:
            payload = _run_convenience(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(payload, indent=2))


def _run_convenience(args: argparse.Namespace) -> dict:
    config = load_project_config(args.project)
    runtime = build_runtime(config)
    if not runtime.setup_completed():
        run_setup(args.project)
    selection_payload = run_selection(
        project=args.project,
        strategy_id=args.selection_strategy_id,
        model_id=args.model_id,
        cwe_groups=_split_csv(args.cwe_groups),
        cwe_ids=_split_csv(args.cwe_ids),
        max_candidates=args.max_candidates,
    )
    selection_run_id = selection_payload["run_id"]
    candidates_path = selection_run_dir(args.project, selection_run_id) / "candidates.json"
    return run_injection(
        project=args.project,
        strategy_id=args.injection_strategy_id,
        model_id=args.model_id,
        candidates_file=str(candidates_path),
        num_vulnerabilities=args.num_vulnerabilities,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()

