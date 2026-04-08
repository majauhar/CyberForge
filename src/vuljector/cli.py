"""CLI entrypoint for V2 phase-based workflow."""

from __future__ import annotations

import argparse
import json
import sys

from utils.paths import selection_run_dir
from vuljector.core import build_runtime, load_project_config
from vuljector.run_init import run_init
from vuljector.run_cve_injection import run_cve_injection
from vuljector.run_cve_report import run_cve_report
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

    p_init = sub.add_parser("init", help="Initialize project: metadata, image, commit, test harness")
    p_init.add_argument("project", help="OSS-Fuzz project name (must exist under oss-fuzz/projects/)")
    p_init.add_argument("--oss-fuzz-path", required=True, help="Path to oss-fuzz checkout")
    p_init.add_argument("--target-dir", default=None,
                        help="Source subdirectory under /src/ in container (default: project name)")
    p_init.add_argument("--model-id", default="claude-sonnet-4-6",
                        help="Model for test discovery agent fallback")
    p_init.add_argument("--publish-dockerhub-namespace", default=None,
        help="Optional Docker Hub namespace/org to publish <namespace>/<project>:setup during init")

    p_setup = sub.add_parser("setup", help="Build/cache image and ready container for local use")
    p_setup.add_argument("project")

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

    p_cve_inj = sub.add_parser("cve-injection", help="Inject vulnerabilities inspired by real CVEs (no selection phase required)")
    p_cve_inj.add_argument("project")
    p_cve_inj.add_argument("model_id")
    p_cve_inj.add_argument("--num-vulnerabilities", type=int, default=1,
                            help="Number of successful injections to produce (default: 1)")
    p_cve_inj.add_argument("--max-cves", type=int, default=10,
                            help="Maximum CVEs to fetch and attempt (default: 10)")
    p_cve_inj.add_argument("--debug", action="store_true")

    p_cve = sub.add_parser("cve-report", help="Generate CVE report for an existing vulnerability")
    p_cve.add_argument("project")
    p_cve.add_argument("vulnerability_id", help="e.g. vulnerability_5")
    p_cve.add_argument("model_id")
    
    p_at = sub.add_parser("agent-task", help="Run swe-agent-mini on a synthetic vulnerability task")
    p_at.add_argument("project", help="Project name (must exist in vuljector-projects/)")
    p_at.add_argument("vulnerability_id", help="e.g. vulnerability_0")
    p_at.add_argument(
        "task_type",
        choices=["zero_day_poc", "one_day_poc", "secure_patch"],
        help="Task type: zero_day_poc | one_day_poc | secure_patch",
    )
    p_at.add_argument("model_id", help="LiteLLM model ID (e.g. claude-sonnet-4-6)")

    p_rep = sub.add_parser("report", help="Show metrics for an injection run")
    p_rep.add_argument("--run-dir", required=True, help="Path to injection run directory")
    p_rep.add_argument("--strategy", default=None,
                       help="Filter by selection strategy (e.g. static_analysis, llm_explore). Default: all.")

    args = parser.parse_args()

    if args.command == "cve-injection":
        try:
            payload = run_cve_injection(
                project=args.project,
                model_id=args.model_id,
                num_vulnerabilities=args.num_vulnerabilities,
                max_cves=args.max_cves,
                debug=args.debug,
            )
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(payload, indent=2))
        return

    if args.command == "cve-report":
        try:
            payload = run_cve_report(
                project=args.project,
                vulnerability_id=args.vulnerability_id,
                model_id=args.model_id,
            )
        except Exception as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            sys.exit(1)
        print(json.dumps(payload, indent=2))
        return

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
                model_id=args.model_id,
                publish_dockerhub_namespace=args.publish_dockerhub_namespace,
            )
        elif args.command == "setup":
            payload = run_setup(args.project)
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
        elif args.command == "agent-task":
            from vuljector.run_agent_tasks import run_agent_task_pipeline
            payload = run_agent_task_pipeline(
                project=args.project,
                vulnerability_id=args.vulnerability_id,
                task_type=args.task_type,
                model_id=args.model_id,
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
