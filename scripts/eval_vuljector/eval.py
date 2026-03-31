#!/usr/bin/env python3
"""Evaluate Vuljector selection strategies and models across test projects.

Usage:
    uv run python scripts/test_vuljector/eval.py <selection_strategy> <model> [options]

Examples:
    uv run python scripts/test_vuljector/eval.py static_analysis claude-sonnet-4-6
    uv run python scripts/test_vuljector/eval.py llm_explore claude-opus-4-6 --parallel 3
    uv run python scripts/test_vuljector/eval.py llm_explore claude-opus-4-6 --selection-model claude-haiku-4-5-20251001 --parallel 3
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import json
import logging
import sys
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
EVALS_DIR = Path(__file__).resolve().parent / "evals"

sys.path.insert(0, str(REPO_ROOT / "src"))
from utils.paths import injection_run_dir, projects_root, selection_run_dir, workspaces_root  # noqa: E402
from vuljector.report import _collect_injection_metrics  # noqa: E402
from vuljector.run_injection import run_injection  # noqa: E402
from vuljector.run_selection import run_selection  # noqa: E402
from vuljector.run_setup import run_setup  # noqa: E402


# ── Logging helper ─────────────────────────────────────────────────────────────

@contextlib.contextmanager
def _log_to_file(log_file: Path):
    """Temporarily route root-logger output to a file, filtered to the calling thread."""
    log_file.parent.mkdir(parents=True, exist_ok=True)
    tid = threading.get_ident()
    handler = logging.FileHandler(log_file)
    handler.addFilter(lambda r: r.thread == tid)
    logging.root.addHandler(handler)
    try:
        yield
    finally:
        logging.root.removeHandler(handler)
        handler.close()


# ── Project state checks ───────────────────────────────────────────────────────

def _is_initialized(project: str) -> bool:
    return (projects_root() / project / "project.json").exists()


def _is_setup(project: str) -> bool:
    runtime = workspaces_root() / project / "runtime.json"
    if not runtime.exists():
        return False
    try:
        return bool(json.loads(runtime.read_text()).get("setup_completed"))
    except Exception:
        return False


# ── Metrics ────────────────────────────────────────────────────────────────────

def _extract_metrics(injection_dir: Path, selection_dir: Path | None) -> dict:
    m = _collect_injection_metrics(injection_dir)

    candidates_count = 0
    if selection_dir:
        cf = selection_dir / "candidates.json"
        if cf.exists():
            candidates_count = len(json.loads(cf.read_text()).get("candidates", []))

    total = m["total"]
    ver_ok = m["ver_success"]

    summary_file = injection_dir / "run_summary.json"
    summary = json.loads(summary_file.read_text()) if summary_file.exists() else {}

    first_success = next(
        (a.get("attempt", 0) + 1 for a in m["attempts"] if a.get("ver_status") == "success"),
        None,
    )

    return {
        "candidates_count":            candidates_count,
        "total_attempts":              total,
        "injection_successes":         m["inj_success"],
        "verification_successes":      ver_ok,
        "success_rate":                ver_ok / total if total else 0.0,
        "first_success_attempt":       first_success,
        "num_vulnerabilities_produced": summary.get("num_vulnerabilities_produced", 0),
        "vulnerability_ids":           summary.get("vulnerability_ids", []),
        # cost & usage (summed across attempts)
        "total_cost_usd":              sum(m["costs"]),
        "total_input_tokens":          sum(m["input_tokens"]),
        "total_output_tokens":         sum(m["output_tokens"]),
        "total_steps":                 sum(m["steps"]),
        "total_api_calls":             sum(m["api_calls"]),
        "total_format_errors":         sum(m["format_errors"]),
        "total_retries":               sum(m["retries"]),
        # failure breakdown
        "exploit_on_both":             m["exploit_on_both"],
        "exv_passed":                  m["exv_passed"],
        "exs_passed":                  m["exs_passed"],
        "ut_failed_count":             m["ut_failed_count"],
        # per-attempt detail
        "attempts":                    m["attempts"],
    }


def _write_project_runs(eval_dir: Path, config: dict, project_runs: dict) -> None:
    payload = {
        "config": config,
        "projects": project_runs,
    }
    (eval_dir / "project_runs.json").write_text(json.dumps(payload, indent=2))


# ── Per-project runner ─────────────────────────────────────────────────────────

def _run_project(project: str, selection_strategy: str, selection_model: str, injection_model: str,
                 num_vulns: int, max_candidates: int | None, eval_dir: Path,
                 update_project_state: Callable[..., None]) -> dict:
    logs = eval_dir / "logs" / project
    update_project_state(project, log_dir=str(logs), status="pending")

    if not _is_initialized(project):
        update_project_state(project, status="skipped", reason="not initialized")
        return {"project": project, "status": "skipped", "reason": "not initialized"}

    # Setup (skip if already done)
    if not _is_setup(project):
        update_project_state(project, status="running", phase="setup")
        _log(project, "setup")
        try:
            with _log_to_file(logs / "setup.log"):
                run_setup(project)
        except Exception:
            update_project_state(project, status="failed", phase="setup")
            return {"project": project, "status": "failed", "phase": "setup"}

    # Selection
    update_project_state(project, status="running", phase="selection")
    _log(project, f"selection ({selection_strategy})")
    try:
        with _log_to_file(logs / "selection.log"):
            sel_payload = run_selection(project=project, strategy_id=selection_strategy, model_id=selection_model,
                                        max_candidates=max_candidates,
                                        on_run_initialized=lambda payload: update_project_state(
                                            project,
                                            status="running",
                                            phase="selection",
                                            selection_run_id=payload["run_id"],
                                            selection_run_dir=str(selection_run_dir(project, payload["run_id"])),
                                        ))
    except Exception:
        update_project_state(project, status="failed", phase="selection")
        return {"project": project, "status": "failed", "phase": "selection"}

    sel_dir = selection_run_dir(project, sel_payload["run_id"])
    cands_file = sel_dir / "candidates.json"
    if not cands_file.exists():
        update_project_state(project, status="failed", phase="selection",
                             reason="candidates.json missing")
        return {"project": project, "status": "failed", "phase": "selection",
                "reason": "candidates.json missing"}
    update_project_state(project, status="running", phase="selection_completed",
                         selection_run_id=sel_payload["run_id"], selection_run_dir=str(sel_dir),
                         candidates_file=str(cands_file))

    # Injection
    update_project_state(project, status="running", phase="injection")
    _log(project, "injection")
    try:
        with _log_to_file(logs / "injection.log"):
            inj_payload = run_injection(
                project=project, strategy_id="llm_inject", model_id=injection_model,
                candidates_file=str(cands_file), num_vulnerabilities=num_vulns,
                on_run_initialized=lambda payload: update_project_state(
                    project,
                    status="running",
                    phase="injection",
                    injection_run_id=payload["run_id"],
                    injection_run_dir=str(injection_run_dir(project, payload["run_id"])),
                ),
            )
    except Exception:
        update_project_state(project, status="failed", phase="injection")
        return {"project": project, "status": "failed", "phase": "injection"}

    inj_dir = injection_run_dir(project, inj_payload["run_id"])
    metrics = _extract_metrics(inj_dir, sel_dir)
    update_project_state(project, status="completed", phase="done",
                         selection_run_id=sel_payload["run_id"], selection_run_dir=str(sel_dir),
                         injection_run_id=inj_payload["run_id"], injection_run_dir=str(inj_dir),
                         candidates_file=str(cands_file),
                         num_vulnerabilities_produced=metrics["num_vulnerabilities_produced"],
                         vulnerability_ids=metrics["vulnerability_ids"])
    return {
        "project":           project,
        "status":            "completed",
        "selection_run_dir": str(sel_dir),
        "injection_run_dir": str(inj_dir),
        **metrics,
    }


def _log(project: str, phase: str) -> None:
    print(f"  [{project}] {phase}...", flush=True)


# ── Aggregation & display ──────────────────────────────────────────────────────

def _aggregate(results: list[dict]) -> dict:
    done = [r for r in results if r["status"] == "completed"]
    rates = [r["success_rate"] for r in done]
    return {
        "total":                  len(results),
        "completed":              len(done),
        "skipped":                sum(1 for r in results if r["status"] == "skipped"),
        "failed":                 sum(1 for r in results if r["status"] == "failed"),
        "total_vulns_produced":   sum(r.get("num_vulnerabilities_produced", 0) for r in done),
        "avg_success_rate":       sum(rates) / len(rates) if rates else 0.0,
        "total_cost_usd":         sum(r.get("total_cost_usd", 0.0) for r in done),
        "total_input_tokens":     sum(r.get("total_input_tokens", 0) for r in done),
        "total_output_tokens":    sum(r.get("total_output_tokens", 0) for r in done),
        "total_steps":            sum(r.get("total_steps", 0) for r in done),
        "total_format_errors":    sum(r.get("total_format_errors", 0) for r in done),
    }


def _print_result(res: dict) -> None:
    p = res["project"]
    if res["status"] == "completed":
        vok = res.get("verification_successes", 0)
        tot = res.get("total_attempts", 0)
        n   = res.get("num_vulnerabilities_produced", 0)
        print(f"  {p:<20} ok    {vok}/{tot} verified  {n} vulns produced")
    elif res["status"] == "skipped":
        print(f"  {p:<20} skip  {res.get('reason', '')}")
    else:
        detail = res.get("reason") or ""
        print(f"  {p:<20} FAIL  phase={res.get('phase', '?')}  {detail}")


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("selection_strategy", choices=["static_analysis", "llm_explore"],
                        help="Selection strategy to evaluate")
    parser.add_argument("model", help="Model ID for injection (and selection if --selection-model is not set)")
    parser.add_argument("--selection-model", default=None, metavar="MODEL",
                        help="Model ID for selection (llm_explore only) [defaults to model]")
    parser.add_argument("--projects-csv", default=str(Path(__file__).parent / "test_projects.csv"),
                        help="Path to test projects CSV [default: test_projects.csv]")
    parser.add_argument("--max-candidates", type=int, default=10, metavar="N",
                        help="Max candidates from selection per project [10]")
    parser.add_argument("--num-vulns", type=int, default=5, metavar="N",
                        help="Vulnerabilities to produce per project [5]")
    parser.add_argument("--parallel", type=int, default=1, metavar="N",
                        help="Parallel workers [1]")
    args = parser.parse_args()
    selection_model = args.selection_model or args.model

    logging.basicConfig(level=logging.INFO)

    # Load project list
    with open(args.projects_csv) as f:
        projects = [row["projects"] for row in csv.DictReader(f)]

    if not projects:
        sys.exit("No projects found in CSV.")

    # Create eval directory
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    eval_name = f"{ts}_{args.selection_strategy}_{args.model.replace('/', '_')}"
    eval_dir = EVALS_DIR / eval_name
    eval_dir.mkdir(parents=True, exist_ok=True)

    config = {
        "timestamp":          ts,
        "selection_strategy": args.selection_strategy,
        "injection_model":    args.model,
        "selection_model":    selection_model,
        "max_candidates":     args.max_candidates,
        "num_vulns":          args.num_vulns,
        "parallel":           args.parallel,
        "projects":           projects,
    }
    (eval_dir / "config.json").write_text(json.dumps(config, indent=2))
    project_runs = {
        project: {
            "status": "pending",
            "phase": "queued",
        }
        for project in projects
    }
    project_runs_lock = threading.Lock()

    def update_project_state(project: str, **fields) -> None:
        with project_runs_lock:
            project_runs.setdefault(project, {})
            project_runs[project].update(fields)
            _write_project_runs(eval_dir, config, project_runs)

    _write_project_runs(eval_dir, config, project_runs)

    print(f"Experiment : {eval_name}")
    print(f"Projects   : {len(projects)}")
    print(f"Output     : {eval_dir}")
    print()

    results: list[dict] = []

    def _work(p: str) -> dict:
        return _run_project(p, args.selection_strategy, selection_model, args.model,
                            args.num_vulns, args.max_candidates, eval_dir, update_project_state)

    if args.parallel > 1:
        with ThreadPoolExecutor(max_workers=args.parallel) as pool:
            futures = {pool.submit(_work, p): p for p in projects}
            for fut in as_completed(futures):
                res = fut.result()
                results.append(res)
                _print_result(res)
    else:
        for p in projects:
            res = _work(p)
            results.append(res)
            _print_result(res)

    agg = _aggregate(results)
    summary = {"aggregate": agg, "results": results}
    (eval_dir / "results.json").write_text(json.dumps(summary, indent=2))

    print()
    print("── Aggregate ─────────────────────────────────────────────")
    print(f"  Completed          : {agg['completed']}/{agg['total']}")
    print(f"  Skipped / Failed   : {agg['skipped']} / {agg['failed']}")
    print(f"  Total vulns        : {agg['total_vulns_produced']}")
    print(f"  Avg success rate   : {agg['avg_success_rate']:.1%}")
    print(f"  Total cost         : ${agg['total_cost_usd']:.4f}")
    print(f"  Total tokens       : {agg['total_input_tokens']}in / {agg['total_output_tokens']}out")
    print(f"  Total steps        : {agg['total_steps']}")
    print(f"  Format errors      : {agg['total_format_errors']}")
    print(f"  Results            : {eval_dir / 'results.json'}")


if __name__ == "__main__":
    main()
