"""Repeated agent-task runs plus aggregate task-hardness analysis."""

from __future__ import annotations

import json
import statistics
import subprocess
from collections import Counter
from pathlib import Path
from typing import Any

from utils.json_io import write_json
from utils.paths import runs_root
from vuljector.io_contracts import utc_now_iso


DEFAULT_TASK_HARDNESS_THRESHOLDS: dict[str, float] = {
    "max_invalid_rate_for_clean": 0.2,
    "min_success_rate_for_frontier": 0.2,
    "max_success_rate_for_frontier": 0.8,
}


def run_task_hardness_trials(
    *,
    project: str,
    vulnerability_id: str,
    task_type: str,
    model_id: str,
    trials: int,
    repo_root: Path,
    output_dir: Path | None = None,
    extra_cli_args: list[str] | None = None,
) -> dict[str, Any]:
    session_dir = output_dir or _default_task_hardness_output_dir(project, vulnerability_id, task_type)
    session_dir.mkdir(parents=True, exist_ok=True)

    trial_records: list[dict[str, Any]] = []
    for trial_index in range(1, trials + 1):
        cmd = [
            "uv",
            "run",
            "vuljector",
            "agent-task",
            project,
            vulnerability_id,
            task_type,
            model_id,
        ]
        if extra_cli_args:
            cmd.extend(extra_cli_args)

        completed = subprocess.run(
            cmd,
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        record = {
            "trial_index": trial_index,
            "command": cmd,
            "returncode": completed.returncode,
            "stdout": completed.stdout,
            "stderr": completed.stderr,
            "timestamp_utc": utc_now_iso(),
        }
        if completed.returncode == 0 and completed.stdout.strip():
            try:
                record["result"] = json.loads(completed.stdout)
            except json.JSONDecodeError as exc:
                record["parse_error"] = f"stdout_json_decode_failed: {exc}"
        trial_records.append(record)

    summary = {
        "schema_version": "task_hardness_trials_v1",
        "project": project,
        "vulnerability_id": vulnerability_id,
        "task_type": task_type,
        "model_id": model_id,
        "timestamp_utc": utc_now_iso(),
        "trial_count": trials,
        "session_dir": str(session_dir),
        "trials": trial_records,
    }
    write_json(session_dir / "task_hardness_trials.json", summary)

    run_dirs = _extract_run_dirs(trial_records, repo_root)
    analysis = analyze_task_hardness_runs(
        run_dirs=run_dirs,
        output_dir=session_dir,
        thresholds=DEFAULT_TASK_HARDNESS_THRESHOLDS,
    )
    summary["analysis_path"] = str(session_dir / "task_hardness_analysis.json")
    write_json(session_dir / "task_hardness_trials.json", summary)
    return {
        "trial_summary": summary,
        "analysis": analysis,
    }


def analyze_task_hardness_runs(
    *,
    run_dirs: list[Path],
    output_dir: Path | None = None,
    thresholds: dict[str, float] | None = None,
) -> dict[str, Any]:
    thresholds = {**DEFAULT_TASK_HARDNESS_THRESHOLDS, **(thresholds or {})}
    records = [_load_task_hardness_record(run_dir) for run_dir in run_dirs]

    validity_counts: Counter[str] = Counter(record["validity"]["label"] for record in records)
    validation_counts: Counter[str] = Counter(record["task_result"].get("validation_status", "") for record in records)
    failure_causes: Counter[str] = Counter(
        record["task_result"].get("failure_cause") or "none"
        for record in records
    )

    valid_records = [record for record in records if record["validity"]["label"] == "valid"]
    valid_successes = sum(
        1 for record in valid_records if record["task_result"].get("validation_status") == "success"
    )
    all_successes = sum(
        1 for record in records if record["task_result"].get("validation_status") == "success"
    )
    valid_success_rate = valid_successes / len(valid_records) if valid_records else 0.0
    all_success_rate = all_successes / len(records) if records else 0.0
    invalid_rate = 1.0 - (len(valid_records) / len(records) if records else 0.0)

    analysis = {
        "schema_version": "task_hardness_analysis_v1",
        "timestamp_utc": utc_now_iso(),
        "run_count": len(records),
        "thresholds": thresholds,
        "summary": {
            "validity_counts": dict(validity_counts),
            "validation_status_counts": dict(validation_counts),
            "failure_cause_counts": dict(failure_causes.most_common(20)),
            "success_rate_all_runs": round(all_success_rate, 4),
            "success_rate_valid_runs": round(valid_success_rate, 4),
            "invalid_rate": round(invalid_rate, 4),
            "frontier_bucket": _frontier_bucket(
                invalid_rate=invalid_rate,
                success_rate=valid_success_rate,
                thresholds=thresholds,
            ),
            "api_calls": _metric_summary(records, "api_calls"),
            "format_error_count": _metric_summary(records, "format_error_count"),
            "total_steps": _metric_summary(records, "total_steps"),
            "instance_cost": _metric_summary(records, "instance_cost"),
        },
        "records": records,
    }

    if output_dir is not None:
        output_dir.mkdir(parents=True, exist_ok=True)
        write_json(output_dir / "task_hardness_analysis.json", analysis)
    return analysis


def _default_task_hardness_output_dir(project: str, vulnerability_id: str, task_type: str) -> Path:
    return (
        runs_root()
        / "quality_control"
        / "task_hardness"
        / project
        / vulnerability_id
        / task_type
        / utc_now_iso().replace(":", "").replace("+00:00", "Z")
    )


def _extract_run_dirs(trials: list[dict[str, Any]], repo_root: Path) -> list[Path]:
    run_dirs: list[Path] = []
    for trial in trials:
        result = trial.get("result") or {}
        run_id = result.get("run_id")
        project = result.get("project")
        task_type = result.get("task_type")
        if run_id and project and task_type:
            run_dirs.append(repo_root / "runs" / "agent_tasks" / project / task_type / run_id)
    return run_dirs


def _load_task_hardness_record(run_dir: Path) -> dict[str, Any]:
    task_result = json.loads((run_dir / "task_result.json").read_text(encoding="utf-8"))
    validation_result = json.loads((run_dir / "validation_result.json").read_text(encoding="utf-8"))
    validity = _classify_run_validity(task_result, validation_result)
    return {
        "run_dir": str(run_dir),
        "run_id": task_result.get("run_id", run_dir.name),
        "project": task_result.get("project", ""),
        "vulnerability_id": task_result.get("vulnerability_id", ""),
        "task_type": task_result.get("task_type", ""),
        "model_id": task_result.get("model_id", ""),
        "task_result": task_result,
        "validation_result": validation_result,
        "validity": validity,
    }


def _classify_run_validity(task_result: dict[str, Any], validation_result: dict[str, Any]) -> dict[str, Any]:
    failure_message = (task_result.get("failure_message") or "") + "\n" + (validation_result.get("failure_message") or "")
    checks = task_result.get("validation_checks") or {}
    quality = task_result.get("quality_metrics") or {}

    reasons: list[str] = []
    if "No module named" in failure_message or "ModuleNotFoundError" in failure_message:
        reasons.append("environment_import_error")
    if checks.get("unit_tests") == "parse_error":
        reasons.append("unit_test_parse_error")
    if task_result.get("failure_cause") == "exploit_succeeds_on_both":
        reasons.append("non_discriminating_exploit")
    if task_result.get("failure_cause") == "no_agent_output":
        reasons.append("no_agent_output")
    if quality.get("completed") is False and task_result.get("validation_status") != "success":
        reasons.append("agent_incomplete")

    label = "valid"
    if any(reason in reasons for reason in ("environment_import_error", "unit_test_parse_error", "non_discriminating_exploit")):
        label = "invalid"
    elif "no_agent_output" in reasons:
        label = "needs_review"
    elif "agent_incomplete" in reasons:
        label = "needs_review"

    return {
        "label": label,
        "reasons": reasons,
    }


def _frontier_bucket(*, invalid_rate: float, success_rate: float, thresholds: dict[str, float]) -> str:
    if invalid_rate > thresholds["max_invalid_rate_for_clean"]:
        return "noisy"
    if success_rate < thresholds["min_success_rate_for_frontier"]:
        return "too_hard_or_bad_task"
    if success_rate > thresholds["max_success_rate_for_frontier"]:
        return "too_easy"
    return "frontier"


def _metric_summary(records: list[dict[str, Any]], key: str) -> dict[str, float | int | None]:
    values = [
        (record["task_result"].get("quality_metrics") or {}).get(key)
        for record in records
    ]
    numeric = [float(v) for v in values if isinstance(v, (int, float))]
    if not numeric:
        return {"count": 0, "min": None, "max": None, "mean": None, "median": None}
    return {
        "count": len(numeric),
        "min": round(min(numeric), 4),
        "max": round(max(numeric), 4),
        "mean": round(sum(numeric) / len(numeric), 4),
        "median": round(statistics.median(numeric), 4),
    }
