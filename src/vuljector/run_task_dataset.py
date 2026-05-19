"""Export and execute SEC-bench-style task datasets from vulnerability bundles."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_tasks.assets import build_task_dataset_rows
from utils.json_io import write_json
from utils.paths import (
    new_run_id,
    project_root,
    task_dataset_export_run_dir,
    task_dataset_run_dir,
)
from vuljector.run_agent_tasks import run_agent_task_pipeline


def export_task_dataset_jsonl(
    *,
    project: str,
    model_id: str,
    output_path: Path | None = None,
    vulnerability_id: str | None = None,
) -> dict[str, Any]:
    run_id = new_run_id("task_dataset_export")
    run_dir = task_dataset_export_run_dir(project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    resolved_output = output_path or (run_dir / "dataset.jsonl")
    vulnerabilities = (
        [vulnerability_id]
        if vulnerability_id
        else _list_vulnerability_ids(project)
    )
    rows: list[dict[str, Any]] = []
    for vuln_id in vulnerabilities:
        rows.extend(
            build_task_dataset_rows(
                project=project,
                vulnerability_id=vuln_id,
                model_id=model_id,
            )
        )

    resolved_output.parent.mkdir(parents=True, exist_ok=True)
    with resolved_output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")

    payload = {
        "status": "success",
        "project": project,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "output_path": str(resolved_output),
        "row_count": len(rows),
        "vulnerability_count": len(vulnerabilities),
    }
    write_json(run_dir / "export_summary.json", payload)
    return payload


def run_task_dataset_jsonl(
    *,
    dataset_jsonl: Path,
    model_id: str,
    instance_id: str | None = None,
    project: str | None = None,
    task_mode: str | None = None,
    producer: str | None = None,
    limit: int | None = None,
    include_hints: bool = False,
) -> dict[str, Any]:
    rows = _load_rows(dataset_jsonl)
    selected = [
        row
        for row in rows
        if (not instance_id or row.get("instance_id") == instance_id)
        and (not project or row.get("project") == project)
        and (not task_mode or row.get("task_mode") == task_mode)
        and (not producer or row.get("producer") == producer)
    ]
    if limit is not None:
        selected = selected[:limit]

    run_project = project or (str(selected[0]["project"]) if selected else "_mixed")
    run_id = new_run_id("task_dataset_run")
    run_dir = task_dataset_run_dir(run_project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    results: list[dict[str, Any]] = []
    for row in selected:
        variant_id = row.get("bug_description_variant_id") or None
        result = run_agent_task_pipeline(
            project=str(row["project"]),
            vulnerability_id=str(row["vulnerability_id"]),
            task_type=str(row["task_mode"]),
            model_id=model_id,
            variant_id=None if variant_id == "v0" else str(variant_id),
            include_hints=include_hints,
        )
        results.append(result)

    payload = {
        "status": "success",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "dataset_jsonl": str(dataset_jsonl),
        "selected_count": len(selected),
        "completed_count": len(results),
        "include_hints": include_hints,
        "results": results,
    }
    write_json(run_dir / "run_summary.json", payload)
    return payload


def _load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def _list_vulnerability_ids(project: str) -> list[str]:
    base = project_root(project) / "vulnerabilities"
    if not base.exists():
        return []
    return sorted(path.name for path in base.iterdir() if path.is_dir())
