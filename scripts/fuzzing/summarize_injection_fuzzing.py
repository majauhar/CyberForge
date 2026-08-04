#!/usr/bin/env python3
"""Summarize injection runs for fuzzing-oriented validation research."""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_ROOT = REPO_ROOT / "runs" / "injection"
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"

# Legacy absolute-path prefixes that may still appear in older run metadata.
LEGACY_WORKSPACE_ROOT = "/legacy/Vuljector-lane2-incontext/"
LEGACY_PROJECTS_ROOT = "/legacy/vuljector-projects/"

PATCH_FILE_RE = re.compile(r"^\+\+\+ b/(.+)$", re.MULTILINE)
FUZZER_RE = re.compile(r"/out/([A-Za-z0-9_.@+-]+)")
TESTCASE_RE = re.compile(r'["\']([^"\']*(?:testcase|corpus|poc|\.bin|\.otf|\.ttf|\.png|\.jpg)[^"\']*)["\']')


def load_json(path: Path) -> dict:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def load_project_images() -> dict[str, str]:
    images: dict[str, str] = {}
    for project_json in sorted(PROJECTS_ROOT.glob("*/project.json")):
        payload = load_json(project_json)
        project = payload.get("project")
        image = payload.get("dockerhub_image")
        if isinstance(project, str) and isinstance(image, str):
            images[project] = image
    return images


def normalize_workspace_path(raw_path: str) -> str | None:
    """Best-effort rerouting for stale absolute paths into this workspace."""
    if not raw_path:
        return None
    path = raw_path.strip()
    if path.startswith(LEGACY_WORKSPACE_ROOT):
        suffix = path.split(LEGACY_WORKSPACE_ROOT, 1)[1]
        candidate = REPO_ROOT / suffix
        if candidate.exists():
            return str(candidate)
    if path.startswith(LEGACY_PROJECTS_ROOT):
        suffix = path.split(LEGACY_PROJECTS_ROOT, 1)[1]
        candidate = PROJECTS_ROOT / suffix
        if candidate.exists():
            return str(candidate)
    if path.startswith("runs/"):
        candidate = REPO_ROOT / path
        if candidate.exists():
            return str(candidate)
    return None


def resolve_tmp_reference(raw_path: str, attempt_dir: Path) -> str | None:
    if not raw_path.startswith("/tmp/reference/"):
        return None
    name = Path(raw_path).name
    for rel in ("reference", "exploit_seed", "artifacts/exploit_files"):
        candidate = attempt_dir / rel / name
        if candidate.exists():
            return str(candidate)
    return None


def infer_patch_targets(patch_diff: str) -> list[str]:
    return sorted(set(PATCH_FILE_RE.findall(patch_diff or "")))


def infer_fuzzer_targets(attack_script: str) -> list[str]:
    return sorted(set(FUZZER_RE.findall(attack_script or "")))


def infer_testcase_refs(injection_result: dict) -> list[str]:
    refs: set[str] = set()
    artifacts = injection_result.get("artifacts") or {}
    testcase_artifact = artifacts.get("testcase_artifact")
    if isinstance(testcase_artifact, str) and testcase_artifact:
        refs.add(testcase_artifact)
    elif isinstance(testcase_artifact, dict):
        for value in testcase_artifact.values():
            if isinstance(value, str) and value:
                refs.add(value)
    attack_script = artifacts.get("attack_script") or ""
    refs.update(TESTCASE_RE.findall(attack_script))
    return sorted(refs)


def summarize_run(run_dir: Path, project_images: dict[str, str]) -> dict:
    request = load_json(run_dir / "injection_request.json")
    summary_path = run_dir / "run_summary.json"
    summary = load_json(summary_path) if summary_path.exists() else {}
    normalized_candidates_file = normalize_workspace_path(str(request.get("candidates_file", "")))
    attempts = []
    for attempt_dir in sorted(run_dir.glob("attempt_*")):
        injection_path = attempt_dir / "injection_result.json"
        verification_path = attempt_dir / "verification_result.json"
        if not injection_path.exists() or not verification_path.exists():
            continue
        injection = load_json(injection_path)
        verification = load_json(verification_path)
        artifacts = injection.get("artifacts") or {}
        attack_script = artifacts.get("attack_script", "")
        raw_refs = infer_testcase_refs(injection)
        normalized_refs = []
        unresolved_refs = []
        for ref in raw_refs:
            normalized = (
                resolve_tmp_reference(ref, attempt_dir)
                or normalize_workspace_path(ref)
            )
            if normalized:
                normalized_refs.append(normalized)
            else:
                unresolved_refs.append(ref)
        attempt_record = {
            "attempt_dir": attempt_dir.name,
            "injection_status": injection.get("status"),
            "verification_status": verification.get("status"),
            "failure_cause": verification.get("failure_cause"),
            "cwe_id": injection.get("cwe_id"),
            "patch_targets": infer_patch_targets(artifacts.get("patch_diff", "")),
            "fuzzer_targets": infer_fuzzer_targets(attack_script),
            "testcase_refs": raw_refs,
            "normalized_testcase_refs": sorted(set(normalized_refs)),
            "unresolved_testcase_refs": sorted(set(unresolved_refs)),
            "reference_kind": artifacts.get("reference_kind"),
            "reference_id": artifacts.get("reference_id"),
        }
        attempts.append(attempt_record)

    verification_counts = Counter((a["verification_status"] or "unknown") for a in attempts)
    failure_counts = Counter((a["failure_cause"] or "none") for a in attempts)
    inferred_fuzzers = sorted({target for attempt in attempts for target in attempt["fuzzer_targets"]})
    patch_targets = sorted({target for attempt in attempts for target in attempt["patch_targets"]})

    project = request["project"]
    return {
        "project": project,
        "run_id": request["run_id"],
        "dockerhub_image": project_images.get(project, ""),
        "model_id": request.get("model_id"),
        "selection_strategy_id": request.get("selection_strategy_id"),
        "candidates_file": request.get("candidates_file"),
        "normalized_candidates_file": normalized_candidates_file,
        "summary": {
            "attempt_count": len(attempts),
            "num_vulnerabilities_produced": summary.get("num_vulnerabilities_produced"),
            "verification_status_counts": dict(verification_counts),
            "failure_cause_counts": dict(failure_counts),
            "inferred_fuzzer_targets": inferred_fuzzers,
            "patch_targets": patch_targets,
        },
        "attempts": attempts,
    }


def build_report(project_filter: set[str] | None) -> dict:
    project_images = load_project_images()
    runs = []
    counts_by_project: dict[str, Counter] = defaultdict(Counter)
    for run_dir in sorted(RUNS_ROOT.glob("*/*")):
        if not run_dir.is_dir():
            continue
        project = run_dir.parent.name
        if project_filter and project not in project_filter:
            continue
        run_summary = summarize_run(run_dir, project_images)
        runs.append(run_summary)
        counts_by_project[project].update(run_summary["summary"]["verification_status_counts"])

    return {
        "runs_root": str(RUNS_ROOT),
        "project_count": len(counts_by_project),
        "run_count": len(runs),
        "projects": {
            project: {
                "dockerhub_image": project_images.get(project, ""),
                "verification_status_counts": dict(counter),
            }
            for project, counter in sorted(counts_by_project.items())
        },
        "runs": runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", action="append", dest="projects", help="Limit output to one or more projects.")
    parser.add_argument("--output", type=Path, help="Write JSON report to this path.")
    args = parser.parse_args()

    project_filter = set(args.projects) if args.projects else None
    report = build_report(project_filter)
    payload = json.dumps(report, indent=2, sort_keys=True)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload + "\n", encoding="utf-8")
    else:
        print(payload)


if __name__ == "__main__":
    main()
