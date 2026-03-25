"""Injection run metrics reporter — exposed as `vuljector report`."""

from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from pathlib import Path
from typing import Any


# ── Path helpers ───────────────────────────────────────────────────────────────

def _vuljector_root() -> Path:
    # src/vuljector/report.py → src/vuljector → src → project root
    return Path(__file__).resolve().parent.parent.parent


def _runs_root() -> Path:
    return _vuljector_root() / "runs"


def _selection_runs(project: str) -> list[Path]:
    base = _runs_root() / "selection" / project
    if not base.exists():
        return []
    return sorted(base.iterdir(), key=lambda p: p.name)


def _injection_runs(project: str) -> list[Path]:
    base = _runs_root() / "injection" / project
    if not base.exists():
        return []
    return sorted(base.iterdir(), key=lambda p: p.name)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:
        print(f"  [WARN] could not parse {path}: {exc}", file=sys.stderr)
        return None


# ── Formatting helpers ─────────────────────────────────────────────────────────

PASS  = "\033[32m✓\033[0m"
FAIL  = "\033[31m✗\033[0m"
SKIP  = "\033[33m–\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
RESET = "\033[0m"


def _bar(count: int, total: int, width: int = 20) -> str:
    if total == 0:
        return " " * width
    filled = round(count / total * width)
    return "█" * filled + "░" * (width - filled)


def _pct(num: int, denom: int) -> str:
    if denom == 0:
        return "  n/a"
    return f"{num / denom * 100:5.1f}%"


def _header(title: str) -> None:
    print(f"\n{BOLD}{'━' * 70}{RESET}")
    print(f"{BOLD}  {title}{RESET}")
    print(f"{BOLD}{'━' * 70}{RESET}")


def _section(title: str) -> None:
    print(f"\n  {BOLD}{title}{RESET}")
    print(f"  {'─' * 60}")


def _stat_row(label: str, mean: float, median: float, mode_val: Any,
              fmt: str = ".1f", prefix: str = "", suffix: str = "") -> None:
    def _fmt(v: Any) -> str:
        if v is None:
            return "  n/a "
        if isinstance(v, float):
            return f"{prefix}{v:{fmt}}{suffix}"
        return f"{prefix}{v}{suffix}"
    print(f"    {label:<24}  mean={_fmt(mean):<12}  median={_fmt(median):<12}  mode={_fmt(mode_val)}")


def _safe_mode(values: list) -> Any:
    if not values:
        return None
    try:
        return statistics.mode(values)
    except statistics.StatisticsError:
        return Counter(values).most_common(1)[0][0]


# ── Trajectory helpers ─────────────────────────────────────────────────────────

def _load_trajectory(run_dir: Path, attempt_name: str) -> dict[str, Any] | None:
    return _load_json(run_dir / "logs" / f"{attempt_name}_trajectory.json")


def _trajectory_stats(traj: dict[str, Any]) -> dict[str, Any]:
    if not traj:
        return {}
    info = traj.get("info", {})
    model_stats = info.get("model_stats", {})
    return {
        "api_calls":     model_stats.get("api_calls", 0),
        "instance_cost": model_stats.get("instance_cost", 0.0),
        "exit_status":   info.get("exit_status", "?"),
    }


# ── Metric collection ──────────────────────────────────────────────────────────

def _collect_injection_metrics(run_dir: Path) -> dict[str, Any]:
    """Walk all attempt_* dirs and collect per-attempt data + rolled-up counters."""
    attempt_dirs = sorted(run_dir.glob("attempt_*"))

    attempts: list[dict[str, Any]] = []

    input_tokens:  list[int]   = []
    output_tokens: list[int]   = []
    steps:         list[int]   = []
    api_calls_all: list[int]   = []
    costs:         list[float] = []
    format_errors: list[int]   = []
    retries:       list[int]   = []
    ut_counts:     list[int]   = []

    total           = 0
    inj_success     = 0
    inj_failure     = 0
    ver_success     = 0
    exploit_on_both = 0
    exv_passed      = 0
    exs_passed      = 0
    ut_failed_count = 0

    for attempt_dir in attempt_dirs:
        inj  = _load_json(attempt_dir / "injection_result.json")
        ver  = _load_json(attempt_dir / "verification_result.json")
        traj = _load_trajectory(run_dir, attempt_dir.name)

        if inj is None:
            continue

        total += 1
        usage        = inj.get("usage") or {}
        strategy     = inj.get("strategy") or {}
        inj_status   = inj.get("status", "failure")
        ver_status   = (ver or {}).get("status", "failure") if ver else "skipped"
        failure_cause = (ver or {}).get("failure_cause") or (inj.get("failure") or {}).get("cause")
        checks       = (ver or {}).get("checks") or {} if ver else {}

        if inj_status == "success":
            inj_success += 1
        else:
            inj_failure += 1

        if ver and ver_status == "success":
            ver_success += 1

        if failure_cause == "exploit_succeeds_on_both":
            exploit_on_both += 1

        if checks.get("exploit_on_vulnerable") == "passed":
            exv_passed += 1
        if checks.get("exploit_on_secure") == "passed":
            exs_passed += 1

        in_tok  = usage.get("total_input_tokens", 0)
        out_tok = usage.get("total_output_tokens", 0)
        n_steps = usage.get("total_steps", 0)
        cost    = usage.get("estimated_cost_usd", 0.0)

        input_tokens.append(in_tok)
        output_tokens.append(out_tok)
        steps.append(n_steps)
        costs.append(cost)
        retries.append(strategy.get("retries", 0))

        t_api_calls   = 0
        t_format_errs = 0
        if traj:
            tstats        = _trajectory_stats(traj)
            t_api_calls   = tstats.get("api_calls", 0)
            t_format_errs = max(0, t_api_calls - n_steps)
            api_calls_all.append(t_api_calls)
            format_errors.append(t_format_errs)

        ut_count   = (ver or {}).get("unit_test_passed_count") if ver else None
        ut_message = (ver or {}).get("unit_test_message", "") if ver else ""
        if ut_count is not None:
            ut_counts.append(ut_count)

        attempts.append({
            "name":          attempt_dir.name,
            "candidate_id":  inj.get("selected_candidate_id") or inj.get("candidate_id", "?"),
            "cwe_group":     inj.get("cwe_group", ""),
            "cwe_id":        inj.get("cwe_id", ""),
            "inj_status":    inj_status,
            "ver_status":    ver_status,
            "failure_cause": failure_cause,
            "checks":        checks,
            "in_tok":        in_tok,
            "out_tok":       out_tok,
            "steps":         n_steps,
            "api_calls":     t_api_calls,
            "format_errors": t_format_errs,
            "cost":          cost,
            "retries":       strategy.get("retries", 0),
            "ut_count":      ut_count,
            "ut_message":    ut_message,
        })

    ut_baseline = max(ut_counts) if ut_counts else None
    for a in attempts:
        if a["ut_count"] is not None and ut_baseline is not None:
            a["ut_delta"] = a["ut_count"] - ut_baseline
            if a["ut_delta"] < 0:
                ut_failed_count += 1
        else:
            a["ut_delta"] = None

    return {
        "input_tokens":  input_tokens,
        "output_tokens": output_tokens,
        "steps":         steps,
        "api_calls":     api_calls_all,
        "costs":         costs,
        "format_errors": format_errors,
        "retries":       retries,
        "ut_counts":     ut_counts,
        "ut_baseline":   ut_baseline,
        "total":           total,
        "inj_success":     inj_success,
        "inj_failure":     inj_failure,
        "ver_success":     ver_success,
        "exploit_on_both": exploit_on_both,
        "exv_passed":      exv_passed,
        "exs_passed":      exs_passed,
        "ut_failed_count": ut_failed_count,
        "attempts":        attempts,
    }


# ── Router ─────────────────────────────────────────────────────────────────────

def _is_single_run(path: Path) -> bool:
    """True if path is a single injection_XXXXZ run dir, false if it's a project-level dir."""
    return (path / "injection_request.json").exists()


def show_injection_run(run_dir: Path) -> None:
    """Entry point: auto-detect single run vs. project-level dir and dispatch."""
    if _is_single_run(run_dir):
        _show_single_injection_run(run_dir)
    else:
        child_runs = sorted(
            [d for d in run_dir.iterdir() if d.is_dir() and (d / "injection_request.json").exists()],
            key=lambda p: p.name,
        )
        if not child_runs:
            print(f"No injection runs found under {run_dir}")
            return
        _show_aggregated_injection_runs(run_dir, child_runs)


# ── Report: single injection run ───────────────────────────────────────────────

def _show_single_injection_run(run_dir: Path) -> None:
    run_id  = run_dir.name
    request = _load_json(run_dir / "injection_request.json") or {}
    summary = _load_json(run_dir / "run_summary.json")

    strategy  = request.get("injection_strategy_id", "?")
    model     = request.get("model_id", "?")
    timestamp = request.get("timestamp_utc", "?")
    num_vuln  = request.get("num_vulnerabilities", "?")
    cand_file = request.get("candidates_file", "?")

    _header(f"Injection run: {run_id}")
    print(f"  Strategy           : {strategy}")
    print(f"  Model              : {model}")
    print(f"  Timestamp          : {timestamp}")
    print(f"  Num vulnerabilities: {num_vuln}")
    print(f"  Candidates file    : {cand_file}")

    if summary:
        produced  = summary.get("num_vulnerabilities_produced", "?")
        requested = summary.get("num_vulnerabilities_requested", "?")
        vuln_ids  = summary.get("vulnerability_ids", [])
        print(f"\n  {BOLD}Run outcome{RESET}  →  {produced} / {requested} vulnerabilities produced", end="")
        if vuln_ids:
            print(f"  (saved as: {', '.join(vuln_ids)})", end="")
        print()

    m     = _collect_injection_metrics(run_dir)
    total = m["total"]

    if total == 0:
        print("\n  (no attempt directories found)")
        return

    # ── 1. Attack Success Metrics ──────────────────────────────────────────
    _section("1. Attack Success Metrics")
    inj_with_patch = m["inj_success"]
    ver_ok         = m["ver_success"]
    rejections     = m["inj_failure"]
    on_both        = m["exploit_on_both"]

    print(f"    {'Attempts total':<36} {total:>4}")
    print(f"    {'Patch produced (injection success)':<36} {inj_with_patch:>4} / {total}  ({_pct(inj_with_patch, total)})")
    print(f"    {'Verified (injection + verification OK)':<36} {ver_ok:>4} / {total}  ({_pct(ver_ok, total)})")
    print(f"    {'LLM Rejections (no patch produced)':<36} {rejections:>4} / {total}  ({_pct(rejections, total)})")
    print(f"    {'Exploit fires on both (false positive)':<36} {on_both:>4} / {inj_with_patch}  ({_pct(on_both, inj_with_patch)})  {DIM}← of patched only{RESET}")

    # ── 2. Exploit Script Checks ───────────────────────────────────────────
    _section("2. Exploit Script Checks  (of patched attempts)")
    exv = m["exv_passed"]
    exs = m["exs_passed"]
    print(f"    {'exploit_on_vulnerable passed':<36} {exv:>4} / {inj_with_patch}  ({_pct(exv, inj_with_patch)})  {DIM}exploit triggers on vulnerable{RESET}")
    print(f"    {'exploit_on_secure passed':<36} {exs:>4} / {inj_with_patch}  ({_pct(exs, inj_with_patch)})  {DIM}exploit fails on secure (correct){RESET}")

    # ── 3. Code Breakage Rate ──────────────────────────────────────────────
    _section("3. Code Breakage Rate  (unit tests)")
    ut_counts = m["ut_counts"]
    baseline  = m["ut_baseline"]
    if not ut_counts:
        print("    No unit test data available.")
    else:
        broke           = m["ut_failed_count"]
        runs_with_tests = len(ut_counts)
        print(f"    {'Baseline passing tests (inferred)':<36} {baseline}")
        print(f"    {'Attempts that ran tests':<36} {runs_with_tests}")
        print(f"    {'Broke existing tests (delta < 0)':<36} {broke:>4} / {runs_with_tests}  ({_pct(broke, runs_with_tests)})")
        for a in m["attempts"]:
            if a["ut_delta"] is not None and a["ut_delta"] < 0:
                print(f"      {DIM}{a['name']} ({a['candidate_id']}): {a['ut_count']} passed  (Δ = {a['ut_delta']}){RESET}")

    # ── 4. Token & Cost Metrics ────────────────────────────────────────────
    _section("4. Token & Cost Metrics  (per attempt, mean / median / mode)")

    def _stats_row(label: str, values: list, fmt: str = ".0f", prefix: str = "", suffix: str = "") -> None:
        if not values:
            print(f"    {label:<24}  n/a")
            return
        mean   = statistics.mean(values)
        median = statistics.median(values)
        mode   = _safe_mode([round(v, 4) for v in values] if isinstance(values[0], float) else values)
        _stat_row(label, mean, median, mode, fmt=fmt, prefix=prefix, suffix=suffix)

    _stats_row("Input tokens",  m["input_tokens"],  fmt=".0f")
    _stats_row("Output tokens", m["output_tokens"], fmt=".0f")
    _stats_row("Turns / steps", m["steps"],         fmt=".1f")
    _stats_row("API calls",     m["api_calls"],     fmt=".1f")
    _stats_row("Cost (USD)",    m["costs"],         fmt=".4f", prefix="$")
    print(f"\n    {'Total cost (run)':<24}  ${sum(m['costs']):.4f}")

    # ── 5. Retry & Format Error Metrics ───────────────────────────────────
    _section("5. Retry & Format Error Metrics")
    fmt_errs      = m["format_errors"]
    outer_retries = m["retries"]
    if not fmt_errs:
        print("    No trajectory data available (format error stats require trajectory logs).")
    else:
        total_fmt = sum(fmt_errs)
        total_api = sum(m["api_calls"])
        avg_fmt   = statistics.mean(fmt_errs)
        print(f"    {'Total format errors (all attempts)':<36} {total_fmt:>4}")
        print(f"    {'Avg format errors per attempt':<36} {avg_fmt:>7.2f}")
        print(f"    {'Format error rate (of all API calls)':<36} {_pct(total_fmt, total_api):>8}  {DIM}({total_fmt} / {total_api}){RESET}")
    if outer_retries and sum(outer_retries):
        print(f"    {'Outer strategy retries':<36} {sum(outer_retries):>4}")

    # ── 6. Per-Attempt Detail Table ────────────────────────────────────────
    _section("6. Per-Attempt Detail")
    print(f"  {'Attempt':<11}  {'Candidate':<14}  {'CWE':<8}  {'Inj':>3}  {'Ver':>3}  "
          f"{'Steps':>5}  {'API':>4}  {'FmtErr':>6}  {'Cost':>8}  {'UT Δ':>6}  Failure Cause")
    print(f"  {'─'*11}  {'─'*14}  {'─'*8}  {'─'*3}  {'─'*3}  "
          f"{'─'*5}  {'─'*4}  {'─'*6}  {'─'*8}  {'─'*6}  {'─'*25}")

    for a in m["attempts"]:
        inj_icon = PASS if a["inj_status"] == "success" else FAIL
        ver_icon = PASS if a["ver_status"] == "success" else (SKIP if a["ver_status"] == "skipped" else FAIL)
        cwe_str  = a["cwe_id"] if a["cwe_id"] else "?"
        cause    = str(a["failure_cause"] or "")[:30]
        ut_delta = f"{a['ut_delta']:+d}" if a["ut_delta"] is not None else "  n/a"
        print(
            f"  {a['name']:<11}  {a['candidate_id']:<14}  {cwe_str:<8}  "
            f"{inj_icon}    {ver_icon}    "
            f"{a['steps']:>5}  {a['api_calls']:>4}  {a['format_errors']:>6}  "
            f"${a['cost']:>7.4f}  {ut_delta:>6}  {cause}"
        )


# ── Report: aggregated injection runs ──────────────────────────────────────────

def _show_aggregated_injection_runs(parent_dir: Path, run_dirs: list[Path]) -> None:
    """Aggregate metrics across all injection runs in a project/method directory."""
    _header(f"Injection report: {parent_dir.name}  ({len(run_dirs)} runs)")

    # Print per-run summary line
    print(f"\n  {'Run ID':<35}  {'Attempts':>8}  {'Verified':>8}  {'Cost':>8}  Candidates file")
    print(f"  {'─'*35}  {'─'*8}  {'─'*8}  {'─'*8}  {'─'*40}")
    for run_dir in run_dirs:
        req     = _load_json(run_dir / "injection_request.json") or {}
        summary = _load_json(run_dir / "run_summary.json") or {}
        m       = _collect_injection_metrics(run_dir)
        cands   = Path(req.get("candidates_file", "?")).name if req.get("candidates_file") else "?"
        print(f"  {run_dir.name:<35}  {m['total']:>8}  {m['ver_success']:>8}  ${sum(m['costs']):>7.4f}  {cands}")

    # Aggregate across all runs
    agg: dict[str, Any] = {
        "total": 0, "inj_success": 0, "inj_failure": 0, "ver_success": 0,
        "exploit_on_both": 0, "exv_passed": 0, "exs_passed": 0,
        "ut_failed_count": 0, "ut_runs": 0,
        "input_tokens": [], "output_tokens": [], "steps": [], "api_calls": [],
        "costs": [], "format_errors": [],
        "failures_by_cause": {},
        "all_attempts": [],
    }

    for run_dir in run_dirs:
        m = _collect_injection_metrics(run_dir)
        agg["total"]           += m["total"]
        agg["inj_success"]     += m["inj_success"]
        agg["inj_failure"]     += m["inj_failure"]
        agg["ver_success"]     += m["ver_success"]
        agg["exploit_on_both"] += m["exploit_on_both"]
        agg["exv_passed"]      += m["exv_passed"]
        agg["exs_passed"]      += m["exs_passed"]
        agg["ut_failed_count"] += m["ut_failed_count"]
        agg["ut_runs"]         += len(m["ut_counts"])
        for key in ("input_tokens", "output_tokens", "steps", "api_calls", "costs", "format_errors"):
            agg[key] += m[key]
        agg["all_attempts"] += [
            {**a, "_run": run_dir.name} for a in m["attempts"]
        ]
        for a in m["attempts"]:
            if a["ver_status"] != "success":
                fc = str(a["failure_cause"] or "unknown")
                agg["failures_by_cause"][fc] = agg["failures_by_cause"].get(fc, 0) + 1

    total = agg["total"]
    if total == 0:
        print("\n  (no attempts found across any run)")
        return

    # ── 1. Attack Success ──────────────────────────────────────────────────
    _section("1. Attack Success Metrics")
    inj_with_patch = agg["inj_success"]
    print(f"    {'Attempts total':<36} {total:>4}")
    print(f"    {'Patch produced (injection success)':<36} {inj_with_patch:>4} / {total}  ({_pct(inj_with_patch, total)})")
    print(f"    {'Verified (injection + verification OK)':<36} {agg['ver_success']:>4} / {total}  ({_pct(agg['ver_success'], total)})")
    print(f"    {'LLM Rejections (no patch produced)':<36} {agg['inj_failure']:>4} / {total}  ({_pct(agg['inj_failure'], total)})")
    print(f"    {'Exploit fires on both (false positive)':<36} {agg['exploit_on_both']:>4} / {inj_with_patch}  ({_pct(agg['exploit_on_both'], inj_with_patch)})  {DIM}← of patched only{RESET}")

    # ── 2. Exploit Checks ─────────────────────────────────────────────────
    _section("2. Exploit Script Checks  (of patched attempts)")
    print(f"    {'exploit_on_vulnerable passed':<36} {agg['exv_passed']:>4} / {inj_with_patch}  ({_pct(agg['exv_passed'], inj_with_patch)})  {DIM}exploit triggers on vulnerable{RESET}")
    print(f"    {'exploit_on_secure passed':<36} {agg['exs_passed']:>4} / {inj_with_patch}  ({_pct(agg['exs_passed'], inj_with_patch)})  {DIM}exploit fails on secure (correct){RESET}")

    # ── 3. Code Breakage ──────────────────────────────────────────────────
    _section("3. Code Breakage Rate  (unit tests)")
    print(f"    {'Attempts that ran tests':<36} {agg['ut_runs']}")
    print(f"    {'Broke existing tests (delta < 0)':<36} {agg['ut_failed_count']:>4} / {agg['ut_runs']}  ({_pct(agg['ut_failed_count'], agg['ut_runs'])})")
    for a in agg["all_attempts"]:
        if a.get("ut_delta") is not None and a["ut_delta"] < 0:
            print(f"      {DIM}{a['_run']} / {a['name']} ({a['candidate_id']}): {a['ut_count']} passed  (Δ = {a['ut_delta']}){RESET}")

    # ── 4. Token & Cost ───────────────────────────────────────────────────
    _section("4. Token & Cost Metrics  (per attempt, mean / median / mode)")

    def _stats_row_agg(label: str, values: list, fmt: str = ".0f", prefix: str = "") -> None:
        if not values:
            print(f"    {label:<24}  n/a")
            return
        mean   = statistics.mean(values)
        median = statistics.median(values)
        mode   = _safe_mode([round(v, 4) for v in values] if isinstance(values[0], float) else values)
        _stat_row(label, mean, median, mode, fmt=fmt, prefix=prefix)

    _stats_row_agg("Input tokens",  agg["input_tokens"],  fmt=".0f")
    _stats_row_agg("Output tokens", agg["output_tokens"], fmt=".0f")
    _stats_row_agg("Turns / steps", agg["steps"],         fmt=".1f")
    _stats_row_agg("API calls",     agg["api_calls"],     fmt=".1f")
    _stats_row_agg("Cost (USD)",    agg["costs"],         fmt=".4f", prefix="$")
    print(f"\n    {'Total cost (all runs)':<24}  ${sum(agg['costs']):.4f}")

    # ── 5. Format Errors ──────────────────────────────────────────────────
    _section("5. Retry & Format Error Metrics")
    if agg["format_errors"]:
        total_fmt = sum(agg["format_errors"])
        total_api = sum(agg["api_calls"])
        print(f"    {'Total format errors (all attempts)':<36} {total_fmt:>4}")
        print(f"    {'Avg format errors per attempt':<36} {statistics.mean(agg['format_errors']):>7.2f}")
        print(f"    {'Format error rate (of all API calls)':<36} {_pct(total_fmt, total_api):>8}  {DIM}({total_fmt} / {total_api}){RESET}")

    # ── 6. Failure Causes ─────────────────────────────────────────────────
    _section("6. Failure Causes")
    failed = total - agg["ver_success"]
    for cause, count in sorted(agg["failures_by_cause"].items(), key=lambda x: -x[1]):
        print(f"    {cause:<40}  {_bar(count, failed)}  {count:>3}x  ({_pct(count, total)})")

    # ── 7. Per-Attempt Detail ─────────────────────────────────────────────
    _section("7. Per-Attempt Detail")
    print(f"  {'Run':<35}  {'Attempt':<11}  {'Candidate':<14}  {'CWE':<8}  {'Inj':>3}  {'Ver':>3}  "
          f"{'Steps':>5}  {'API':>4}  {'FmtErr':>6}  {'Cost':>8}  {'UT Δ':>6}  Failure Cause")
    print(f"  {'─'*35}  {'─'*11}  {'─'*14}  {'─'*8}  {'─'*3}  {'─'*3}  "
          f"{'─'*5}  {'─'*4}  {'─'*6}  {'─'*8}  {'─'*6}  {'─'*25}")
    for a in agg["all_attempts"]:
        inj_icon = PASS if a["inj_status"] == "success" else FAIL
        ver_icon = PASS if a["ver_status"] == "success" else (SKIP if a["ver_status"] == "skipped" else FAIL)
        cwe_str  = a["cwe_id"] if a["cwe_id"] else "?"
        cause    = str(a["failure_cause"] or "")[:30]
        ut_delta = f"{a['ut_delta']:+d}" if a.get("ut_delta") is not None else "  n/a"
        print(
            f"  {a['_run']:<35}  {a['name']:<11}  {a['candidate_id']:<14}  {cwe_str:<8}  "
            f"{inj_icon}    {ver_icon}    "
            f"{a['steps']:>5}  {a['api_calls']:>4}  {a['format_errors']:>6}  "
            f"${a['cost']:>7.4f}  {ut_delta:>6}  {cause}"
        )


# ── Report: selection run ──────────────────────────────────────────────────────

def show_selection_run(run_dir: Path) -> None:
    run_id         = run_dir.name
    request        = _load_json(run_dir / "selection_request.json") or {}
    candidates_data = _load_json(run_dir / "candidates.json") or {}

    strategy   = request.get("selection_strategy_id", "?")
    model      = request.get("model_id", "?")
    timestamp  = request.get("timestamp_utc", "?")
    candidates = candidates_data.get("candidates", [])

    _header(f"Selection run: {run_id}")
    print(f"  Strategy  : {strategy}")
    print(f"  Model     : {model}")
    print(f"  Timestamp : {timestamp}")
    print(f"  Candidates: {len(candidates)}")

    if not candidates:
        print("  (no candidates)")
        return

    print(f"\n  {'Rank':>4}  {'Candidate ID':<20}  {'CWE':>8}  {'Conf':>5}  File")
    print(f"  {'─'*4}  {'─'*20}  {'─'*8}  {'─'*5}  {'─'*40}")
    for c in candidates:
        conf     = c.get("confidence")
        conf_str = f"{conf:.2f}" if isinstance(conf, (int, float)) else "  ?"
        print(f"  {c.get('rank', '?'):>4}  {c.get('candidate_id', '?')[:20]:<20}  "
              f"{c.get('cwe_id', '?'):>8}  {conf_str:>5}  {c.get('repo_path', '?')}")

    cwe_counts: dict[str, int] = {}
    for c in candidates:
        cwe = c.get("cwe_id", "unknown")
        cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1
    print(f"\n  CWE distribution ({len(candidates)} candidates):")
    for cwe, count in sorted(cwe_counts.items(), key=lambda x: -x[1]):
        print(f"    {cwe:<10} {_bar(count, len(candidates), width=15)} {count:>3}  {_pct(count, len(candidates))}")

    confs = [c["confidence"] for c in candidates if isinstance(c.get("confidence"), (int, float))]
    if confs:
        print(f"\n  Confidence — min: {min(confs):.2f}  avg: {sum(confs)/len(confs):.2f}  max: {max(confs):.2f}")


# ── Report: project summary ────────────────────────────────────────────────────

def show_project_summary(project: str) -> None:
    _header(f"Summary — project: {project}")

    sel_runs = _selection_runs(project)
    print(f"\n{BOLD}Selection runs: {len(sel_runs)}{RESET}")
    strategy_counts: dict[str, list[int]] = {}
    for run_dir in sel_runs:
        req   = _load_json(run_dir / "selection_request.json") or {}
        data  = _load_json(run_dir / "candidates.json") or {}
        strat = req.get("selection_strategy_id", "?")
        strategy_counts.setdefault(strat, []).append(len(data.get("candidates", [])))
    for strat, counts in sorted(strategy_counts.items()):
        avg = sum(counts) / len(counts) if counts else 0
        print(f"  {strat:<25}  {len(counts)} run(s),  avg {avg:.1f} candidates/run")

    inj_runs = _injection_runs(project)
    print(f"\n{BOLD}Injection runs: {len(inj_runs)}{RESET}")

    agg: dict[str, Any] = {
        "total": 0, "inj_success": 0, "inj_failure": 0, "ver_success": 0,
        "exploit_on_both": 0, "exv_passed": 0, "exs_passed": 0,
        "ut_failed_count": 0, "ut_runs": 0,
        "input_tokens": [], "output_tokens": [], "steps": [], "api_calls": [],
        "costs": [], "format_errors": [],
        "failures_by_cause": {},
    }

    for run_dir in inj_runs:
        m = _collect_injection_metrics(run_dir)
        agg["total"]           += m["total"]
        agg["inj_success"]     += m["inj_success"]
        agg["inj_failure"]     += m["inj_failure"]
        agg["ver_success"]     += m["ver_success"]
        agg["exploit_on_both"] += m["exploit_on_both"]
        agg["exv_passed"]      += m["exv_passed"]
        agg["exs_passed"]      += m["exs_passed"]
        agg["ut_failed_count"] += m["ut_failed_count"]
        agg["ut_runs"]         += len(m["ut_counts"])
        for key in ("input_tokens", "output_tokens", "steps", "api_calls", "costs", "format_errors"):
            agg[key] += m[key]
        for a in m["attempts"]:
            if a["ver_status"] != "success":
                fc = str(a["failure_cause"] or "unknown")
                agg["failures_by_cause"][fc] = agg["failures_by_cause"].get(fc, 0) + 1

    total = agg["total"]
    if total == 0:
        print("  No completed injection attempts found.")
        return

    _section("Attack Success")
    print(f"    {'Total attempts':<36} {total}")
    print(f"    {'Patch produced':<36} {agg['inj_success']:>4} / {total}  ({_pct(agg['inj_success'], total)})")
    print(f"    {'Verified OK':<36} {agg['ver_success']:>4} / {total}  ({_pct(agg['ver_success'], total)})")
    print(f"    {'LLM Rejections':<36} {agg['inj_failure']:>4} / {total}  ({_pct(agg['inj_failure'], total)})")
    print(f"    {'Exploit on both (false positive)':<36} {agg['exploit_on_both']:>4} / {agg['inj_success']}  ({_pct(agg['exploit_on_both'], agg['inj_success'])})")

    _section("Exploit Checks")
    print(f"    {'exploit_on_vulnerable passed':<36} {agg['exv_passed']:>4} / {agg['inj_success']}  ({_pct(agg['exv_passed'], agg['inj_success'])})")
    print(f"    {'exploit_on_secure passed':<36} {agg['exs_passed']:>4} / {agg['inj_success']}  ({_pct(agg['exs_passed'], agg['inj_success'])})")

    _section("Code Breakage")
    print(f"    {'Broke existing tests':<36} {agg['ut_failed_count']:>4} / {agg['ut_runs']}  ({_pct(agg['ut_failed_count'], agg['ut_runs'])})")

    _section("Token & Cost  (mean / median / mode)")

    def _summary_stats(label: str, values: list, fmt: str = ".0f", prefix: str = "") -> None:
        if not values:
            print(f"    {label:<24}  n/a")
            return
        mean   = statistics.mean(values)
        median = statistics.median(values)
        mode   = _safe_mode([round(v, 4) for v in values] if isinstance(values[0], float) else values)
        _stat_row(label, mean, median, mode, fmt=fmt, prefix=prefix)

    _summary_stats("Input tokens",  agg["input_tokens"],  fmt=".0f")
    _summary_stats("Output tokens", agg["output_tokens"], fmt=".0f")
    _summary_stats("Turns / steps", agg["steps"],         fmt=".1f")
    _summary_stats("API calls",     agg["api_calls"],     fmt=".1f")
    _summary_stats("Cost (USD)",    agg["costs"],         fmt=".4f", prefix="$")
    print(f"\n    {'Total cost (all runs)':<24}  ${sum(agg['costs']):.4f}")

    _section("Retry & Format Errors")
    if agg["format_errors"]:
        total_fmt = sum(agg["format_errors"])
        total_api = sum(agg["api_calls"])
        print(f"    {'Total format errors':<36} {total_fmt:>4}")
        print(f"    {'Format error rate':<36} {_pct(total_fmt, total_api):>8}  ({total_fmt} / {total_api} API calls)")

    _section("Failure Causes")
    for cause, count in sorted(agg["failures_by_cause"].items(), key=lambda x: -x[1]):
        print(f"    {cause:<40}  {_bar(count, total - agg['ver_success'])}  {count:>3}x  ({_pct(count, total)})")

    vuln_dir = _vuljector_root() / "vuljector-projects" / project / "vulnerabilities"
    n_saved  = len(list(vuln_dir.glob("vulnerability_*"))) if vuln_dir.exists() else 0
    print(f"\n  {BOLD}Saved dataset entries:{RESET} {n_saved}")
