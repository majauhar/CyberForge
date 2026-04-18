#!/usr/bin/env python3
"""
Build a reversal-input manifest by joining:
  - canonical rich OSS-Fuzz records,
  - locally materialized testcase blobs,
  - local Vuljector project configs.

The output is meant to drive historical bug reproduction directly.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_RUNS = _VULJECTOR_ROOT / "runs" / "ossfuzz"
_DEFAULT_CANONICAL = _RUNS / "csv_rich_vuln_index.jsonl"
_DEFAULT_TESTCASE_ROOT = _RUNS / "materialized_testcases"
_DEFAULT_OUT_ROOT = _RUNS / "historical_bug_reproduction_inputs"
_DEFAULT_PROJECTS_ROOT = _VULJECTOR_ROOT.parent / "vuljector-projects"
_TESTCASE_ID_RE = re.compile(r"testcase_id=(\d+)")


def utc_now_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def parse_project_list(arg_projects: str | None, projects_file: str | None) -> list[str]:
    projects: list[str] = []
    if arg_projects:
        projects.extend([p.strip() for p in arg_projects.split(",") if p.strip()])
    if projects_file:
        path = Path(projects_file).expanduser().resolve()
        projects.extend([line.strip() for line in path.read_text().splitlines() if line.strip()])
    projects = list(dict.fromkeys(projects))
    if not projects:
        raise ValueError("No projects provided. Use --projects or --projects-file.")
    return projects


def load_project_configs(projects_root: Path, projects: list[str]) -> dict[str, dict[str, Any]]:
    configs: dict[str, dict[str, Any]] = {}
    for project in projects:
        path = projects_root / project / "project.json"
        if not path.exists():
            continue
        configs[project] = json.loads(path.read_text())
    return configs


def extract_testcase_ids(record: dict[str, Any]) -> dict[str, set[str]]:
    lanes: dict[str, set[str]] = defaultdict(set)

    for testcase_id in record.get("testcase_ids") or []:
        if testcase_id:
            lanes["testcase_ids"].add(str(testcase_id))

    clusterfuzz = record.get("clusterfuzz") or {}
    if clusterfuzz.get("testcase_id"):
        lanes["clusterfuzz.testcase_id"].add(str(clusterfuzz["testcase_id"]))

    report_text = record.get("report_text") or ""
    for testcase_id in _TESTCASE_ID_RE.findall(report_text):
        lanes["report_text"].add(str(testcase_id))

    for entry in ((record.get("raw_records") or {}).get("bucket_testcases") or []):
        details = str((entry or {}).get("details") or "")
        for testcase_id in _TESTCASE_ID_RE.findall(details):
            lanes["raw_records.bucket_testcases"].add(str(testcase_id))

    return lanes


def testcase_candidates(record: dict[str, Any], testcase_root: Path) -> list[dict[str, Any]]:
    project = str(record.get("project") or "")
    issue_id = str(record.get("issue_id") or "")
    lanes = extract_testcase_ids(record)
    ordered_lanes = ["testcase_ids", "clusterfuzz.testcase_id", "report_text", "raw_records.bucket_testcases"]
    testcase_ids = sorted({tid for values in lanes.values() for tid in values})

    candidates: list[dict[str, Any]] = []
    for testcase_id in testcase_ids:
        sources = [lane for lane in ordered_lanes if testcase_id in lanes.get(lane, set())]
        blob = testcase_root / project / issue_id / f"{testcase_id}.bin"
        candidates.append(
            {
                "testcase_id": testcase_id,
                "sources": sources,
                "path": str(blob),
                "exists": blob.exists(),
                "size_bytes": blob.stat().st_size if blob.exists() else None,
            }
        )
    return candidates


def choose_primary_testcase(candidates: list[dict[str, Any]]) -> dict[str, Any] | None:
    lane_rank = {
        "testcase_ids": 0,
        "clusterfuzz.testcase_id": 1,
        "report_text": 2,
        "raw_records.bucket_testcases": 3,
    }

    existing = [c for c in candidates if c.get("exists")]
    if not existing:
        return None

    def sort_key(candidate: dict[str, Any]) -> tuple[int, int, str]:
        sources = candidate.get("sources") or []
        best = min((lane_rank.get(src, 99) for src in sources), default=99)
        return (best, 0 if "testcase_ids" in sources else 1, str(candidate["testcase_id"]))

    return sorted(existing, key=sort_key)[0]


def derived_flags(record: dict[str, Any], primary_testcase: dict[str, Any] | None) -> dict[str, bool]:
    cf = record.get("clusterfuzz") or {}
    has_local_testcase = primary_testcase is not None
    has_fix = bool(record.get("fix_commits"))
    return {
        "has_local_testcase": has_local_testcase,
        "checkout_ready": bool(record.get("repo_urls")) and has_fix,
        "reversal_seed_ready_local": has_fix and has_local_testcase,
        "reversal_ready_local_strong": has_fix and has_local_testcase and bool(cf.get("fuzz_target")),
        "range_ready": bool(record.get("introducing_commits")) or bool(cf.get("regression_range")),
        "root_cause_ready": bool(record.get("issue_page_report_found")) and bool(cf.get("crash_state")),
    }


def build_entry(
    record: dict[str, Any],
    config: dict[str, Any] | None,
    testcase_root: Path,
) -> dict[str, Any]:
    candidates = testcase_candidates(record, testcase_root)
    primary = choose_primary_testcase(candidates)
    flags = derived_flags(record, primary)
    cf = record.get("clusterfuzz") or {}
    poc = record.get("poc_artifacts") or {}

    project = str(record.get("project") or "")
    config_path = None
    if config is not None:
        config_path = str((_DEFAULT_PROJECTS_ROOT / project / "project.json").resolve())

    return {
        "project": project,
        "issue_id": str(record.get("issue_id") or ""),
        "summary": record.get("summary"),
        "published": record.get("published"),
        "modified": record.get("modified"),
        "vuln_ids": record.get("vuln_ids") or [],
        "record_kind": record.get("record_kind"),
        "repo": {
            "main_repo_url": record.get("main_repo_url"),
            "repo_urls": record.get("repo_urls") or [],
            "packages": record.get("packages") or [],
            "git_ranges": record.get("git_ranges") or [],
        },
        "commits": {
            "fix_commits": record.get("fix_commits") or [],
            "introducing_commits": record.get("introducing_commits") or [],
            "safe_commit_candidates": record.get("safe_commit_candidates") or [],
            "vulnerable_commit_candidates": record.get("vulnerable_commit_candidates") or [],
        },
        "clusterfuzz": {
            "fuzz_engine": cf.get("fuzz_engine"),
            "fuzz_target": cf.get("fuzz_target"),
            "job_type": cf.get("job_type"),
            "crash_type": cf.get("crash_type"),
            "crash_state": cf.get("crash_state"),
            "sanitizer": cf.get("sanitizer"),
            "security_severity": cf.get("security_severity"),
            "regression_range": cf.get("regression_range"),
            "testcase_id": cf.get("testcase_id"),
        },
        "reporting": {
            "report_text_source": record.get("report_text_source"),
            "issue_page_report_found": record.get("issue_page_report_found"),
            "issue_page_private": record.get("issue_page_private"),
            "report_urls": record.get("report_urls") or [],
        },
        "poc_signal": {
            "has_poc": bool(record.get("has_poc")),
            "patch_url": poc.get("patch_url"),
        },
        "local_testcases": {
            "candidate_count": len(candidates),
            "candidates": candidates,
            "primary": primary,
        },
        "local_runtime": {
            "project_config_path": config_path,
            "target_dir": config.get("target_dir") if config else None,
            "secure_base_commit": config.get("secure_base_commit") if config else None,
            "main_repo_url": config.get("main_repo_url") if config else None,
            "language": config.get("language") if config else None,
            "dockerhub_image": config.get("dockerhub_image") if config else None,
            "unit_tests": config.get("unit_tests") if config else None,
            "repo_dir_in_container": f"/src/{config.get('target_dir')}" if config and config.get("target_dir") else None,
        },
        "flags": flags,
    }


def write_outputs(
    out_dir: Path,
    entries: list[dict[str, Any]],
    projects: list[str],
) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_jsonl = out_dir / "reversal_inputs_manifest.jsonl"
    manifest_json = out_dir / "reversal_inputs_manifest.json"
    summary_json = out_dir / "reversal_inputs_summary.json"
    summary_md = out_dir / "reversal_inputs_summary.md"

    with manifest_jsonl.open("w") as handle:
        for entry in entries:
            handle.write(json.dumps(entry) + "\n")

    manifest_json.write_text(json.dumps(entries, indent=2))

    total = len(entries)
    per_project: dict[str, dict[str, Any]] = {}
    for project in projects:
        subset = [entry for entry in entries if entry["project"] == project]
        if not subset:
            continue
        counts = Counter()
        for entry in subset:
            for key, value in entry["flags"].items():
                if value:
                    counts[key] += 1
        per_project[project] = {
            "records": len(subset),
            "has_local_testcase": counts["has_local_testcase"],
            "checkout_ready": counts["checkout_ready"],
            "reversal_seed_ready_local": counts["reversal_seed_ready_local"],
            "reversal_ready_local_strong": counts["reversal_ready_local_strong"],
            "range_ready": counts["range_ready"],
            "root_cause_ready": counts["root_cause_ready"],
        }

    totals = Counter()
    for entry in entries:
        for key, value in entry["flags"].items():
            if value:
                totals[key] += 1

    summary = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "projects": projects,
        "records": total,
        "totals": dict(totals),
        "per_project": per_project,
    }
    summary_json.write_text(json.dumps(summary, indent=2))

    lines: list[str] = []
    lines.append("# Reversal Inputs Summary")
    lines.append("")
    lines.append("Scope:")
    lines.append(f"- Projects: `{', '.join(projects)}`")
    lines.append(f"- Records: `{total}`")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append("| Flag | Count | Coverage |")
    lines.append("|---|---:|---:|")
    for key in [
        "has_local_testcase",
        "checkout_ready",
        "reversal_seed_ready_local",
        "reversal_ready_local_strong",
        "range_ready",
        "root_cause_ready",
    ]:
        count = totals[key]
        lines.append(f"| `{key}` | `{count}` | `{count / total * 100:.1f}%` |")
    lines.append("")
    lines.append("## Per Project")
    lines.append("")
    lines.append("| Project | Records | Local testcase | Reversal seed local | Strong reversal local | Range ready | Root-cause ready |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for project in projects:
        row = per_project.get(project)
        if not row:
            continue
        n = row["records"]
        lines.append(
            f"| `{project}` | `{n}` | "
            f"`{row['has_local_testcase'] / n * 100:.1f}%` | "
            f"`{row['reversal_seed_ready_local'] / n * 100:.1f}%` | "
            f"`{row['reversal_ready_local_strong'] / n * 100:.1f}%` | "
            f"`{row['range_ready'] / n * 100:.1f}%` | "
            f"`{row['root_cause_ready'] / n * 100:.1f}%` |"
        )
    lines.append("")
    lines.append("Outputs:")
    lines.append(f"- [JSONL manifest]({manifest_jsonl})")
    lines.append(f"- [JSON manifest]({manifest_json})")
    lines.append(f"- [Summary JSON]({summary_json})")
    summary_md.write_text("\n".join(lines) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Build reversal input manifest from local testcase blobs")
    parser.add_argument("--projects", default=None, help="Comma-separated project list")
    parser.add_argument("--projects-file", default=None, help="Optional newline-delimited project file")
    parser.add_argument("--canonical", default=str(_DEFAULT_CANONICAL))
    parser.add_argument("--testcase-root", default=str(_DEFAULT_TESTCASE_ROOT))
    parser.add_argument("--projects-root", default=str(_DEFAULT_PROJECTS_ROOT))
    parser.add_argument("--out-root", default=str(_DEFAULT_OUT_ROOT))
    args = parser.parse_args()

    projects = parse_project_list(args.projects, args.projects_file)
    canonical = Path(args.canonical).expanduser().resolve()
    testcase_root = Path(args.testcase_root).expanduser().resolve()
    projects_root = Path(args.projects_root).expanduser().resolve()
    out_dir = Path(args.out_root).expanduser().resolve() / f"pilot_reversal_inputs_{utc_now_compact()}"

    configs = load_project_configs(projects_root, projects)
    entries: list[dict[str, Any]] = []
    with canonical.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("record_kind") != "rich_oss_fuzz":
                continue
            project = record.get("project")
            if project not in projects:
                continue
            entries.append(build_entry(record, configs.get(project), testcase_root))

    entries.sort(key=lambda entry: (entry["project"], entry["issue_id"]))
    write_outputs(out_dir, entries, projects)
    print(f"Wrote reversal inputs to {out_dir}")


if __name__ == "__main__":
    main()
