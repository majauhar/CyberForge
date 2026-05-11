"""CLI entrypoint for V2 phase-based workflow."""

from __future__ import annotations

import argparse
import json
import sys

from dotenv import load_dotenv

from utils.paths import env_file, selection_run_dir
from vuljector.core import build_runtime, load_project_config
from vuljector.run_init import run_init
from vuljector.run_cve_report import run_cve_report
from vuljector.run_afl_smoke import run_afl_smoke
from vuljector.run_fuzz_poc import (
    batch_generate_fuzz_poc,
    batch_verify_fuzz_poc,
    generate_fuzz_poc,
    verify_fuzz_poc_attempt,
)
from vuljector.run_fuzz_guided_poc import (
    batch_generate_guided_fuzz_poc,
    generate_guided_fuzz_poc,
)
from vuljector.run_injection import run_injection
from vuljector.run_rex_triage import batch_rex_triage
from vuljector.run_selection import run_selection
from vuljector.run_setup import run_setup


def _split_csv(value: str | None) -> list[str] | None:
    if not value:
        return None
    out = [x.strip() for x in value.split(",") if x.strip()]
    return out or None


def main() -> None:
    load_dotenv(env_file())

    parser = argparse.ArgumentParser(description="Vuljector V2 CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Initialize project: metadata, image, commit, test harness")
    p_init.add_argument("project", help="OSS-Fuzz project name (must exist under oss-fuzz/projects/)")
    p_init.add_argument("--oss-fuzz-path", required=True, help="Path to oss-fuzz checkout")
    p_init.add_argument("--target-dir", default=None,
                        help="Source subdirectory under /src/ in container (default: project name)")
    p_init.add_argument("--model-id", default="claude-sonnet-4-6",
                        help="Model for test discovery agent fallback")
    p_init.add_argument("--fuzzing-engine", default="libfuzzer",
                        help="Native fuzzing engine to bake into the ready image (default: libfuzzer)")
    p_init.add_argument("--publish-dockerhub-namespace", default=None,
        help="Optional Docker Hub namespace/org to publish <namespace>/<project>:setup during init")

    p_setup = sub.add_parser("setup", help="Build/cache image and ready container for local use")
    p_setup.add_argument("project")
    p_setup.add_argument("--fuzzing-engine", default=None,
                         help="Optional override to persist in project.json before building the ready image")

    p_sel = sub.add_parser("selection", help="Run selection phase")
    p_sel.add_argument("project")
    p_sel.add_argument("strategy_id")
    p_sel.add_argument("model_id", nargs="?", default=None,
                       help="LiteLLM model ID (required for static_analysis, codeql, llm_explore; not needed for cve_select)")
    p_sel.add_argument("--cwe-groups", default=None)
    p_sel.add_argument("--cwe-ids", default=None)
    p_sel.add_argument("--max-candidates", type=int, default=None,
                       help="Maximum candidates to return (default: strategy default)")

    p_inj = sub.add_parser("injection", help="Run injection phase (strategy auto-routes based on candidates)")
    p_inj.add_argument("project")
    p_inj.add_argument("candidates_file")
    p_inj.add_argument("model_id", nargs="?", default=None,
                       help="LiteLLM model ID (required for llm_inject/cve_inject)")
    p_inj.add_argument("--num-vulnerabilities", type=int, default=1)
    p_inj.add_argument("--debug", action="store_true")
    p_inj.add_argument("--auto-fuzz-poc", action="store_true",
                       help="After injection completes, automatically run post-hoc fuzz-poc batch generate+verify")
    p_inj.add_argument("--auto-fuzz-poc-exploit-timeout", type=int, default=600)
    p_inj.add_argument("--auto-fuzz-poc-max-total-time", type=int, default=90)

    p_cve_sel = sub.add_parser("cve-selection", help="Discover and rank CVEs for a project")
    p_cve_sel.add_argument("project")
    p_cve_sel.add_argument("--max-cves", type=int, default=10,
                            help="Maximum CVEs to fetch (default: 10)")

    p_run = sub.add_parser("run", help="Convenience wrapper: selection + injection (injection strategy auto-routes)")
    p_run.add_argument("project")
    p_run.add_argument("selection_strategy_id")
    p_run.add_argument("model_id", nargs="?", default=None,
                       help="LiteLLM model ID (required unless selection_strategy_id is cve_select)")
    p_run.add_argument("--cwe-groups", default=None)
    p_run.add_argument("--cwe-ids", default=None)
    p_run.add_argument("--max-candidates", type=int, default=None,
                       help="Maximum candidates to return (default: strategy default)")
    p_run.add_argument("--num-vulnerabilities", type=int, default=1)
    p_run.add_argument("--debug", action="store_true")

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

    p_fp = sub.add_parser("fuzz-poc", help="Generate and verify fuzz-backed PoC artifacts")
    fp_sub = p_fp.add_subparsers(dest="fuzz_poc_command", required=True)

    p_fpg = fp_sub.add_parser("generate", help="Generate one fuzz PoC attempt from a source attempt dir")
    p_fpg.add_argument("--source-attempt-dir", required=True)
    p_fpg.add_argument("--tag", default=None)
    p_fpg.add_argument("--force-fuzzer", default=None)
    p_fpg.add_argument("--max-total-time", type=int, default=90)
    p_fpg.add_argument("--top-fuzzers", type=int, default=1)
    p_fpg.add_argument("--no-curated-corpus", action="store_true")

    p_fpv = fp_sub.add_parser("verify", help="Verify one generated fuzz PoC attempt dir")
    p_fpv.add_argument("--attempt-dir", required=True)
    p_fpv.add_argument("--exploit-timeout", type=int, default=600)
    p_fpv.add_argument("--no-register-curated-results", action="store_true")

    p_fpr = fp_sub.add_parser("run", help="Generate then verify one fuzz PoC attempt")
    p_fpr.add_argument("--source-attempt-dir", required=True)
    p_fpr.add_argument("--tag", default=None)
    p_fpr.add_argument("--force-fuzzer", default=None)
    p_fpr.add_argument("--max-total-time", type=int, default=90)
    p_fpr.add_argument("--exploit-timeout", type=int, default=600)
    p_fpr.add_argument("--top-fuzzers", type=int, default=1)
    p_fpr.add_argument("--no-curated-corpus", action="store_true")
    p_fpr.add_argument("--no-register-curated-results", action="store_true")

    p_fpb = fp_sub.add_parser("batch", help="Generate fuzz PoCs for every attempt in a source injection run")
    p_fpb.add_argument("--source-run-dir", required=True)
    p_fpb.add_argument("--tag", default=None)
    p_fpb.add_argument("--force-fuzzer", default=None)
    p_fpb.add_argument("--max-total-time", type=int, default=90)
    p_fpb.add_argument("--limit", type=int, default=None)
    p_fpb.add_argument("--exploit-timeout", type=int, default=600)
    p_fpb.add_argument("--top-fuzzers", type=int, default=1)
    p_fpb.add_argument("--no-curated-corpus", action="store_true")
    p_fpb.add_argument("--no-register-curated-results", action="store_true")
    p_fpb.add_argument("--no-verify", action="store_true",
                       help="Generate only; skip inline verification during batch creation")

    p_fpbv = fp_sub.add_parser("batch-verify", help="Verify every generated fuzz PoC attempt in a fuzz-poc run")
    p_fpbv.add_argument("--run-dir", required=True)
    p_fpbv.add_argument("--exploit-timeout", type=int, default=600)

    p_fpgd = sub.add_parser("fuzz-guided-poc", help="Generate metadata-first fuzz PoCs from fuzz_guided injection runs")
    fpgd_sub = p_fpgd.add_subparsers(dest="fuzz_guided_poc_command", required=True)

    p_fgg = fpgd_sub.add_parser("generate", help="Generate one guided fuzz PoC attempt from a source attempt dir")
    p_fgg.add_argument("--source-attempt-dir", required=True)
    p_fgg.add_argument("--tag", default=None)
    p_fgg.add_argument("--force-fuzzer", default=None)
    p_fgg.add_argument("--max-total-time", type=int, default=90)
    p_fgg.add_argument("--top-fuzzers", type=int, default=1)
    p_fgg.add_argument("--no-curated-corpus", action="store_true")

    p_fgb = fpgd_sub.add_parser("batch", help="Generate guided fuzz PoCs for every attempt in a source injection run")
    p_fgb.add_argument("--source-run-dir", required=True)
    p_fgb.add_argument("--tag", default=None)
    p_fgb.add_argument("--force-fuzzer", default=None)
    p_fgb.add_argument("--max-total-time", type=int, default=90)
    p_fgb.add_argument("--limit", type=int, default=None)
    p_fgb.add_argument("--exploit-timeout", type=int, default=600)
    p_fgb.add_argument("--top-fuzzers", type=int, default=1)
    p_fgb.add_argument("--no-curated-corpus", action="store_true")
    p_fgb.add_argument("--no-register-curated-results", action="store_true")
    p_fgb.add_argument("--no-verify", action="store_true")

    p_rex = sub.add_parser("rex-triage", help="Prepare and triage successful crash cases for the Rex pilot")
    rex_sub = p_rex.add_subparsers(dest="rex_triage_command", required=True)

    p_rexb = rex_sub.add_parser("batch", help="Bundle and triage every successful attempt in a source run")
    p_rexb.add_argument("--source-run-dir", required=True)
    p_rexb.add_argument("--rex-python", default=None,
                        help="Optional Python executable that already has rex/archr installed")
    p_rexb.add_argument("--replay-timeout", type=int, default=120)
    p_rexb.add_argument("--rex-timeout", type=int, default=300)

    p_afl = sub.add_parser("afl-smoke", help="Build or reuse an AFL-ready image and run a short AFL++ smoke test")
    p_afl.add_argument("project")
    p_afl.add_argument("--fuzzer", default=None, help="Specific fuzz target binary under /out to execute")
    p_afl.add_argument("--seconds", type=int, default=15, help="How long AFL++ should fuzz before stopping")

    args = parser.parse_args()

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
    if args.command == "fuzz-poc":
        from pathlib import Path

        if args.fuzz_poc_command == "generate":
            payload = generate_fuzz_poc(
                source_attempt_dir=Path(args.source_attempt_dir).resolve(),
                tag=args.tag,
                force_fuzzer=args.force_fuzzer,
                max_total_time=args.max_total_time,
                top_fuzzers=args.top_fuzzers,
                use_curated_corpus=not args.no_curated_corpus,
            )
        elif args.fuzz_poc_command == "verify":
            payload = verify_fuzz_poc_attempt(
                attempt_dir=Path(args.attempt_dir).resolve(),
                exploit_timeout=args.exploit_timeout,
                register_curated_results=not args.no_register_curated_results,
            )
        elif args.fuzz_poc_command == "run":
            generated = generate_fuzz_poc(
                source_attempt_dir=Path(args.source_attempt_dir).resolve(),
                tag=args.tag,
                force_fuzzer=args.force_fuzzer,
                max_total_time=args.max_total_time,
                top_fuzzers=args.top_fuzzers,
                use_curated_corpus=not args.no_curated_corpus,
            )
            payload = {
                "generated": generated,
                "verification": [
                    verify_fuzz_poc_attempt(
                        attempt_dir=Path(attempt["attempt_dir"]).resolve(),
                        exploit_timeout=args.exploit_timeout,
                        register_curated_results=not args.no_register_curated_results,
                    )
                    for attempt in generated.get("attempts", [])
                ],
            }
        elif args.fuzz_poc_command == "batch":
            payload = batch_generate_fuzz_poc(
                source_run_dir=Path(args.source_run_dir).resolve(),
                tag=args.tag,
                force_fuzzer=args.force_fuzzer,
                max_total_time=args.max_total_time,
                limit=args.limit,
                exploit_timeout=None if args.no_verify else args.exploit_timeout,
                top_fuzzers=args.top_fuzzers,
                use_curated_corpus=not args.no_curated_corpus,
                register_curated_results=not args.no_register_curated_results,
            )
        else:
            payload = batch_verify_fuzz_poc(
                run_dir=Path(args.run_dir).resolve(),
                exploit_timeout=args.exploit_timeout,
            )
        print(json.dumps(payload, indent=2))
        return
    if args.command == "fuzz-guided-poc":
        from pathlib import Path

        if args.fuzz_guided_poc_command == "generate":
            payload = generate_guided_fuzz_poc(
                source_attempt_dir=Path(args.source_attempt_dir).resolve(),
                tag=args.tag,
                force_fuzzer=args.force_fuzzer,
                max_total_time=args.max_total_time,
                top_fuzzers=args.top_fuzzers,
                use_curated_corpus=not args.no_curated_corpus,
            )
        else:
            payload = batch_generate_guided_fuzz_poc(
                source_run_dir=Path(args.source_run_dir).resolve(),
                tag=args.tag,
                force_fuzzer=args.force_fuzzer,
                max_total_time=args.max_total_time,
                limit=args.limit,
                exploit_timeout=None if args.no_verify else args.exploit_timeout,
                top_fuzzers=args.top_fuzzers,
                use_curated_corpus=not args.no_curated_corpus,
                register_curated_results=not args.no_register_curated_results,
            )
        print(json.dumps(payload, indent=2))
        return
    if args.command == "rex-triage":
        from pathlib import Path

        payload = batch_rex_triage(
            source_run_dir=Path(args.source_run_dir).resolve(),
            rex_python=args.rex_python,
            replay_timeout=args.replay_timeout,
            rex_timeout=args.rex_timeout,
        )
        print(json.dumps(payload, indent=2))
        return

    try:
        if args.command == "init":
            payload = run_init(
                args.project,
                oss_fuzz_path=args.oss_fuzz_path,
                target_dir=args.target_dir,
                model_id=args.model_id,
                fuzzing_engine=args.fuzzing_engine,
                publish_dockerhub_namespace=args.publish_dockerhub_namespace,
            )
        elif args.command == "setup":
            payload = run_setup(args.project, fuzzing_engine=args.fuzzing_engine)
        elif args.command == "selection":
            # cve_select is programmatic; model_id not needed
            if args.strategy_id != "cve_select" and not args.model_id:
                parser.error("model_id is required for fuzz_guided, static_analysis, codeql, and llm_explore strategies")
            payload = run_selection(
                project=args.project,
                strategy_id=args.strategy_id,
                model_id=args.model_id,
                cwe_groups=_split_csv(args.cwe_groups),
                cwe_ids=_split_csv(args.cwe_ids),
                max_candidates=args.max_candidates,
            )
        elif args.command == "injection":
            if not args.model_id:
                parser.error("model_id is required for injection")
            payload = run_injection(
                project=args.project,
                model_id=args.model_id,
                candidates_file=args.candidates_file,
                num_vulnerabilities=args.num_vulnerabilities,
                debug=args.debug,
                auto_fuzz_poc=args.auto_fuzz_poc,
                auto_fuzz_poc_exploit_timeout=args.auto_fuzz_poc_exploit_timeout,
                auto_fuzz_poc_max_total_time=args.auto_fuzz_poc_max_total_time,
            )
        elif args.command == "agent-task":
            from vuljector.run_agent_tasks import run_agent_task_pipeline
            payload = run_agent_task_pipeline(
                project=args.project,
                vulnerability_id=args.vulnerability_id,
                task_type=args.task_type,
                model_id=args.model_id,
            )
        elif args.command == "afl-smoke":
            payload = run_afl_smoke(
                project=args.project,
                fuzzer=args.fuzzer,
                seconds=args.seconds,
            )
        else:
            payload = _run_convenience(args)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    print(json.dumps(payload, indent=2))


def _run_convenience(args: argparse.Namespace) -> dict:
    # cve_select is programmatic; model_id not needed
    if args.selection_strategy_id != "cve_select" and not args.model_id:
        raise ValueError("model_id is required for fuzz_guided, static_analysis, codeql, and llm_explore strategies")

    config = load_project_config(args.project)
    runtime = build_runtime(config)
    if not runtime.setup_completed():
        run_setup(args.project)
    selection_payload = run_selection(
        project=args.project,
        model_id=args.model_id,
        cwe_groups=_split_csv(args.cwe_groups),
        cwe_ids=_split_csv(args.cwe_ids),
        max_candidates=args.max_candidates,
    )
    selection_run_id = selection_payload["run_id"]
    candidates_path = selection_run_dir(args.project, selection_run_id) / "candidates.json"
    return run_injection(
        project=args.project,
        model_id=args.model_id,
        candidates_file=str(candidates_path),
        num_vulnerabilities=args.num_vulnerabilities,
        debug=args.debug,
    )


if __name__ == "__main__":
    main()
