"""Rank exported vulnerabilities for likely SEC-bench task solvability."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent_tasks.assets import ensure_task_assets
from agent_tasks.contract_analysis import ensure_task_contract
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, project_root, projects_root, task_scout_run_dir


def scout_task_instances(
    *,
    project: str | None = None,
    task_modes: list[str] | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    selected_task_modes = task_modes or ["poc-san", "patch"]
    projects = [project] if project else _list_projects()
    run_id = new_run_id("task_scout")
    run_project = project or "_all"
    run_dir = task_scout_run_dir(run_project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    rankings: list[dict[str, Any]] = []
    for project_name in projects:
        for vulnerability_id in _list_vulnerabilities(project_name):
            try:
                assets = ensure_task_assets(project_name, vulnerability_id, model_id=None)
                metadata = assets["metadata"]
                context = assets["context"]
                hints = assets["hints"]
                task_contract = ensure_task_contract(
                    project_name,
                    vulnerability_id,
                    assets=assets,
                )
                sanitizer_report = str(assets.get("sanitizer_report", ""))
                vuln_dir = project_root(project_name) / "vulnerabilities" / vulnerability_id
                for task_mode in selected_task_modes:
                    rankings.append(
                        _score_bundle(
                            project=project_name,
                            vulnerability_id=vulnerability_id,
                            vuln_dir=vuln_dir,
                            task_mode=task_mode,
                            metadata=metadata,
                            context=context,
                            hints=hints,
                            task_contract=task_contract,
                            sanitizer_report=sanitizer_report,
                        )
                    )
            except Exception as exc:
                rankings.append(
                    {
                        "project": project_name,
                        "vulnerability_id": vulnerability_id,
                        "task_mode": "unknown",
                        "score": -999,
                        "recommendation": "skip",
                        "reasons": [f"asset preparation failed: {exc}"],
                    }
                )

    rankings.sort(key=lambda item: (-int(item.get("score", -9999)), item["project"], item["vulnerability_id"], item["task_mode"]))
    if limit is not None:
        rankings = rankings[:limit]

    summary = {
        "status": "success",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "project_scope": run_project,
        "task_modes": selected_task_modes,
        "candidate_count": len(rankings),
        "rankings": rankings,
    }
    write_json(run_dir / "scout_summary.json", summary)
    with (run_dir / "rankings.jsonl").open("w", encoding="utf-8") as handle:
        for row in rankings:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return summary


def _score_bundle(
    *,
    project: str,
    vulnerability_id: str,
    vuln_dir: Path,
    task_mode: str,
    metadata: dict[str, Any],
    context: dict[str, Any],
    hints: dict[str, Any],
    task_contract: dict[str, Any],
    sanitizer_report: str,
) -> dict[str, Any]:
    score = 0
    reasons: list[str] = []

    producer = str(metadata.get("producer") or context.get("producer") or "")
    if producer == "fuzz_poc_guided":
        score += 8
        reasons.append("guided-validated export")

    patch_diff = (vuln_dir / "inject_vulnerability.diff").read_text(encoding="utf-8", errors="ignore") if (vuln_dir / "inject_vulnerability.diff").exists() else ""
    if patch_diff.strip():
        score += 8
        reasons.append("non-empty patch bundle")

    affected_files = _affected_files_from_patch(patch_diff)
    if affected_files:
        score += 6
        reasons.append(f"patch touches {len(affected_files)} file(s)")
        if len(affected_files) == 1:
            score += 4
            reasons.append("localized patch scope")

    target_file = str(hints.get("target_file") or context.get("target_file") or "")
    if target_file:
        score += 8
        reasons.append("target file known")

    target_function = str(hints.get("target_function") or context.get("target_function") or "")
    if target_function:
        score += 6
        reasons.append("target function known")

    selected_fuzzer = str(hints.get("selected_fuzzer") or context.get("selected_fuzzer") or "")
    if selected_fuzzer:
        score += 12
        reasons.append(f"selected fuzzer: {selected_fuzzer}")

    if sanitizer_report.strip():
        score += 25
        reasons.append("sanitizer report extracted")
        if "AddressSanitizer" in sanitizer_report:
            score += 4
            reasons.append("asan-style crash evidence")
        if target_file and Path(target_file).name in sanitizer_report:
            score += 5
            reasons.append("sanitizer references target file")
    elif task_mode == "poc-san":
        score -= 30
        reasons.append("missing sanitizer report for poc-san")

    example_summary = dict(task_contract.get("repo_example_summary") or {})
    example_count = int(example_summary.get("matching_file_count") or 0)
    example_dirs = list(example_summary.get("matching_dirs") or [])
    if example_count:
        score += min(example_count, 20)
        reasons.append(f"{example_count} repo-visible example files match the testcase format")
        if example_dirs:
            score += min(len(example_dirs), 8)
            reasons.append(f"{len(example_dirs)} likely example directories")
    else:
        reasons.append("no repo-visible example files detected for testcase format")

    success_mode = str(context.get("success_mode") or metadata.get("success_mode") or "")
    if success_mode == "replay":
        score += 6
        reasons.append("validated replay path exists")

    seed_provenance = str(context.get("seed_provenance") or metadata.get("seed_provenance") or "")
    if seed_provenance == "builtin_corpus_member":
        score += 10
        reasons.append("benchmark-faithful builtin corpus provenance")
    elif seed_provenance.startswith("builtin_derived"):
        score += 4
        reasons.append("derived from builtin corpus")
    elif seed_provenance.startswith("source_template"):
        score -= 6
        reasons.append("depends on source-template-derived seed")

    slice_excerpt = str(context.get("slice_excerpt") or "")
    if slice_excerpt:
        score += 6
        reasons.append("localized slice excerpt available")

    instruction_hints = context.get("instruction_hints") or []
    if instruction_hints:
        score += min(len(instruction_hints), 6)
        reasons.append(f"{len(instruction_hints)} structured instruction hints")

    format_family = str(hints.get("format_family") or context.get("format_family") or "")
    if format_family:
        score += 4
        reasons.append(f"format family: {format_family}")

    if task_mode == "patch":
        score += 12
        reasons.append("patch tasks are easier to validate and distill")
        if (vuln_dir / "exploit_files").exists():
            score += 6
            reasons.append("reference exploit bundle available")
    elif task_mode == "poc-san":
        if example_count >= 5:
            score += 10
            reasons.append("enough repo-visible examples for iterative repro")
        if task_contract.get("primary_testcase_filename"):
            score += 8
            reasons.append("task contract has a concrete testcase filename")
        if not selected_fuzzer:
            score -= 15
            reasons.append("missing fuzzer selection for poc-san")

    recommendation = _recommendation_for_score(score, task_mode)
    return {
        "project": project,
        "vulnerability_id": vulnerability_id,
        "instance_prefix": f"{project}.{vulnerability_id}.{task_mode}",
        "task_mode": task_mode,
        "score": score,
        "recommendation": recommendation,
        "producer": producer,
        "selected_fuzzer": selected_fuzzer,
        "target_file": target_file,
        "seed_provenance": seed_provenance,
        "has_sanitizer_report": bool(sanitizer_report.strip()),
        "repo_example_file_count": example_count,
        "repo_example_dirs": example_dirs[:5],
        "task_contract_path": str(vuln_dir / "task_contract.json"),
        "primary_testcase_filename": task_contract.get("primary_testcase_filename", ""),
        "reasons": reasons,
    }


def _recommendation_for_score(score: int, task_mode: str) -> str:
    if task_mode == "patch":
        if score >= 65:
            return "run_first"
        if score >= 40:
            return "run_after_easy"
        return "defer"
    if score >= 75:
        return "run_first"
    if score >= 50:
        return "run_after_easy"
    return "defer"


def _list_projects() -> list[str]:
    root = projects_root()
    if not root.exists():
        return []
    return sorted(path.name for path in root.iterdir() if path.is_dir())


def _list_vulnerabilities(project: str) -> list[str]:
    base = project_root(project) / "vulnerabilities"
    if not base.exists():
        return []
    return sorted(path.name for path in base.iterdir() if path.is_dir())


def _affected_files_from_patch(patch_diff: str) -> list[str]:
    files: list[str] = []
    for line in patch_diff.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3][2:] if parts[3].startswith("b/") else parts[3]
                if path not in files:
                    files.append(path)
    return files
