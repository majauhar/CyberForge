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
import signal
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
        "verification_successes_with_unit_tests": m["ver_success_with_unit_tests"],
        "success_rate":                ver_ok / total if total else 0.0,
        "success_rate_with_unit_tests": (
            m["ver_success_with_unit_tests"] / total if total else 0.0
        ),
        "avg_steps":                   sum(m["steps"]) / total if total else 0.0,
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
        "llm_guardrail_refusals":      m["llm_guardrail_refusals"],
        "unit_test_failures":          m["ut_failed_count"],
        "unit_test_parse_errors":      m["ut_parse_error_count"],
        "unit_test_fail_but_verified": m["ut_failed_and_ver_success"],
        "unit_test_fail_and_exploit_succeeds_on_both": m["ut_failed_and_exploit_on_both"],
        "unit_test_fail_and_exploit_failed_on_vulnerable": m["ut_failed_and_exploit_failed_on_vulnerable"],
        "exploit_succeeds_on_both":    m["exploit_on_both"],
        "exploit_failed_on_vulnerable": m["exploit_failed_on_vulnerable"],
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


def _coerce_partial_result(project: str, project_state: dict) -> dict:
    status = project_state.get("status", "failed")
    if status == "completed":
        return {
            "project": project,
            "status": "completed",
            "selection_run_dir": project_state.get("selection_run_dir", ""),
            "injection_run_dir": project_state.get("injection_run_dir", ""),
            "candidates_count": 0,
            "total_attempts": 0,
            "injection_successes": 0,
            "verification_successes": 0,
            "verification_successes_with_unit_tests": 0,
            "success_rate": 0.0,
            "success_rate_with_unit_tests": 0.0,
            "avg_steps": 0.0,
            "first_success_attempt": None,
            "num_vulnerabilities_produced": project_state.get("num_vulnerabilities_produced", 0),
            "vulnerability_ids": project_state.get("vulnerability_ids", []),
            "total_cost_usd": 0.0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_steps": 0,
            "total_api_calls": 0,
            "total_format_errors": 0,
            "total_retries": 0,
            "llm_guardrail_refusals": 0,
            "unit_test_failures": 0,
            "unit_test_parse_errors": 0,
            "unit_test_fail_but_verified": 0,
            "unit_test_fail_and_exploit_succeeds_on_both": 0,
            "unit_test_fail_and_exploit_failed_on_vulnerable": 0,
            "exploit_succeeds_on_both": 0,
            "exploit_failed_on_vulnerable": 0,
            "exploit_on_both": 0,
            "exv_passed": 0,
            "exs_passed": 0,
            "ut_failed_count": 0,
            "attempts": [],
        }
    if status == "skipped":
        return {
            "project": project,
            "status": "skipped",
            "reason": project_state.get("reason", ""),
        }
    return {
        "project": project,
        "status": "failed",
        "phase": project_state.get("phase", "interrupted"),
        "reason": project_state.get("reason", "eval interrupted before project completed"),
    }


def _write_results(eval_dir: Path, results: list[dict]) -> None:
    agg = _aggregate(results)
    summary = {"aggregate": agg, "results": results}
    (eval_dir / "results.json").write_text(json.dumps(summary, indent=2))


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
                debug=True,
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
    total_attempts = sum(r.get("total_attempts", 0) for r in done)
    total_vulns_produced = sum(r.get("num_vulnerabilities_produced", 0) for r in done)
    total_vulns_produced_with_unit_tests = sum(
        r.get("verification_successes_with_unit_tests", 0) for r in done
    )
    total_cost_usd = sum(r.get("total_cost_usd", 0.0) for r in done)
    llm_guardrail_refusals = sum(r.get("llm_guardrail_refusals", 0) for r in done)
    unit_test_failures = sum(r.get("unit_test_failures", 0) for r in done)
    unit_test_parse_errors = sum(r.get("unit_test_parse_errors", 0) for r in done)
    unit_test_fail_but_verified = sum(r.get("unit_test_fail_but_verified", 0) for r in done)
    unit_test_fail_and_exploit_succeeds_on_both = sum(
        r.get("unit_test_fail_and_exploit_succeeds_on_both", 0) for r in done
    )
    unit_test_fail_and_exploit_failed_on_vulnerable = sum(
        r.get("unit_test_fail_and_exploit_failed_on_vulnerable", 0) for r in done
    )
    exploit_succeeds_on_both = sum(r.get("exploit_succeeds_on_both", 0) for r in done)
    exploit_failed_on_vulnerable = sum(r.get("exploit_failed_on_vulnerable", 0) for r in done)
    return {
        "total":                  len(results),
        "completed":              len(done),
        "skipped":                sum(1 for r in results if r["status"] == "skipped"),
        "failed":                 sum(1 for r in results if r["status"] == "failed"),
        "total_vulns_produced":   total_vulns_produced,
        "total_vulns_produced_with_unit_tests": total_vulns_produced_with_unit_tests,
        "total_attempts":         total_attempts,
        "overall_success_rate":   (
            total_vulns_produced / total_attempts if total_attempts else 0.0
        ),
        "overall_success_rate_with_unit_tests": (
            total_vulns_produced_with_unit_tests / total_attempts if total_attempts else 0.0
        ),
        "avg_steps":              (
            sum(r.get("total_steps", 0) for r in done) / total_attempts
            if total_attempts else 0.0
        ),
        "total_cost_usd":         total_cost_usd,
        "cost_per_vuln_produced": (
            total_cost_usd / total_vulns_produced if total_vulns_produced else 0.0
        ),
        "total_input_tokens":     sum(r.get("total_input_tokens", 0) for r in done),
        "total_output_tokens":    sum(r.get("total_output_tokens", 0) for r in done),
        "total_steps":            sum(r.get("total_steps", 0) for r in done),
        "total_format_errors":    sum(r.get("total_format_errors", 0) for r in done),
        "llm_guardrail_refusals": llm_guardrail_refusals,
        "llm_guardrail_refusal_rate": (
            llm_guardrail_refusals / total_attempts if total_attempts else 0.0
        ),
        "unit_test_failures":     unit_test_failures,
        "unit_test_failure_rate": (
            unit_test_failures / total_attempts if total_attempts else 0.0
        ),
        "unit_test_parse_errors": unit_test_parse_errors,
        "unit_test_parse_error_rate": (
            unit_test_parse_errors / total_attempts if total_attempts else 0.0
        ),
        "unit_test_fail_but_verified": unit_test_fail_but_verified,
        "unit_test_fail_but_verified_rate": (
            unit_test_fail_but_verified / total_attempts if total_attempts else 0.0
        ),
        "unit_test_fail_and_exploit_succeeds_on_both": unit_test_fail_and_exploit_succeeds_on_both,
        "unit_test_fail_and_exploit_succeeds_on_both_rate": (
            unit_test_fail_and_exploit_succeeds_on_both / total_attempts if total_attempts else 0.0
        ),
        "unit_test_fail_and_exploit_failed_on_vulnerable": unit_test_fail_and_exploit_failed_on_vulnerable,
        "unit_test_fail_and_exploit_failed_on_vulnerable_rate": (
            unit_test_fail_and_exploit_failed_on_vulnerable / total_attempts if total_attempts else 0.0
        ),
        "exploit_succeeds_on_both": exploit_succeeds_on_both,
        "exploit_succeeds_on_both_rate": (
            exploit_succeeds_on_both / total_attempts if total_attempts else 0.0
        ),
        "exploit_failed_on_vulnerable": exploit_failed_on_vulnerable,
        "exploit_failed_on_vulnerable_rate": (
            exploit_failed_on_vulnerable / total_attempts if total_attempts else 0.0
        ),
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

    def _handle_termination(signum, _frame) -> None:
        raise KeyboardInterrupt(f"received signal {signum}")

    previous_sigint = signal.getsignal(signal.SIGINT)
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGINT, _handle_termination)
    signal.signal(signal.SIGTERM, _handle_termination)

    print(f"Experiment : {eval_name}")
    print(f"Projects   : {len(projects)}")
    print(f"Output     : {eval_dir}")
    print()

    results: list[dict] = []

    def _work(p: str) -> dict:
        return _run_project(p, args.selection_strategy, selection_model, args.model,
                            args.num_vulns, args.max_candidates, eval_dir, update_project_state)

    try:
        if args.parallel > 1:
            with ThreadPoolExecutor(max_workers=args.parallel) as pool:
                futures = {pool.submit(_work, p): p for p in projects}
                for fut in as_completed(futures):
                    project = futures[fut]
                    try:
                        res = fut.result()
                    except Exception as exc:
                        update_project_state(project, status="failed", phase="internal_error", reason=str(exc))
                        res = {"project": project, "status": "failed", "phase": "internal_error", "reason": str(exc)}
                    results.append(res)
                    _print_result(res)
                    _write_results(eval_dir, results)
        else:
            for p in projects:
                try:
                    res = _work(p)
                except Exception as exc:
                    update_project_state(p, status="failed", phase="internal_error", reason=str(exc))
                    res = {"project": p, "status": "failed", "phase": "internal_error", "reason": str(exc)}
                results.append(res)
                _print_result(res)
                _write_results(eval_dir, results)
    finally:
        signal.signal(signal.SIGINT, previous_sigint)
        signal.signal(signal.SIGTERM, previous_sigterm)
        completed_projects = {r["project"] for r in results}
        final_results = list(results)
        with project_runs_lock:
            for project in projects:
                if project in completed_projects:
                    continue
                state = project_runs.get(project, {})
                if state.get("status") not in {"completed", "skipped", "failed"}:
                    state["status"] = "failed"
                    state["phase"] = state.get("phase", "interrupted")
                    state["reason"] = state.get("reason", "eval interrupted before project completed")
                project_runs[project] = state
                final_results.append(_coerce_partial_result(project, state))
            _write_project_runs(eval_dir, config, project_runs)
        _write_results(eval_dir, final_results)

    agg = _aggregate(final_results)
    print()
    print("── Aggregate ─────────────────────────────────────────────")
    print(f"  Completed          : {agg['completed']}/{agg['total']}")
    print(f"  Skipped / Failed   : {agg['skipped']} / {agg['failed']}")
    print(f"  Total vulns        : {agg['total_vulns_produced']}")
    print(f"  Overall success    : {agg['overall_success_rate']:.1%}")
    print(f"  Success w/ UT pass : {agg['overall_success_rate_with_unit_tests']:.1%}")
    print(f"  Total cost         : ${agg['total_cost_usd']:.4f}")
    print(f"  Cost / vuln        : ${agg['cost_per_vuln_produced']:.4f}")
    print(f"  Total tokens       : {agg['total_input_tokens']}in / {agg['total_output_tokens']}out")
    print(f"  Total steps        : {agg['total_steps']}")
    print(f"  Avg steps          : {agg['avg_steps']:.2f}")
    print(f"  Format errors      : {agg['total_format_errors']}")
    print(f"  Guardrail refusals : {agg['llm_guardrail_refusals']} ({agg['llm_guardrail_refusal_rate']:.1%})")
    print(f"  Unit test failures : {agg['unit_test_failures']} ({agg['unit_test_failure_rate']:.1%})")
    print(f"  UT parse errors    : {agg['unit_test_parse_errors']} ({agg['unit_test_parse_error_rate']:.1%})")
    print(f"  UT fail but verify : {agg['unit_test_fail_but_verified']} ({agg['unit_test_fail_but_verified_rate']:.1%})")
    print(f"  UT fail + on both  : {agg['unit_test_fail_and_exploit_succeeds_on_both']} ({agg['unit_test_fail_and_exploit_succeeds_on_both_rate']:.1%})")
    print(f"  UT fail + miss vuln: {agg['unit_test_fail_and_exploit_failed_on_vulnerable']} ({agg['unit_test_fail_and_exploit_failed_on_vulnerable_rate']:.1%})")
    print(f"  Exploit on both    : {agg['exploit_succeeds_on_both']} ({agg['exploit_succeeds_on_both_rate']:.1%})")
    print(f"  Exploit missed vuln: {agg['exploit_failed_on_vulnerable']} ({agg['exploit_failed_on_vulnerable_rate']:.1%})")
    print(f"  Results            : {eval_dir / 'results.json'}")


if __name__ == "__main__":
    main()
