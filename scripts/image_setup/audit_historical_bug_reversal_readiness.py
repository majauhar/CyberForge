#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
import sys

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from setup.lifecycle import finish_phase, start_phase  # noqa: E402
from utils.json_io import write_json  # noqa: E402
from vuljector.core import build_runtime, load_project_config  # noqa: E402
from vuljector.run_setup import run_setup  # noqa: E402


DEFAULT_MANIFEST = (
    REPO_ROOT
    / "runs"
    / "ossfuzz"
    / "historical_bug_reproduction_inputs"
    / "pilot_reversal_inputs_20260412T215541Z"
    / "reversal_inputs_manifest.jsonl"
)


def utc_stamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def load_records(manifest_path: Path) -> list[dict]:
    records: list[dict] = []
    with manifest_path.open() as handle:
        for line in handle:
            if line.strip():
                records.append(json.loads(line))
    return records


def has_local_testcase(rec: dict) -> bool:
    primary = ((rec.get("local_testcases") or {}).get("primary") or {})
    return bool(primary.get("exists"))


def fix_present(rec: dict) -> bool:
    return bool(((rec.get("commits") or {}).get("fix_commits") or []))


def fuzz_target(rec: dict) -> str:
    return str(((rec.get("clusterfuzz") or {}).get("fuzz_target")) or "").strip()


def summarize_project(records: list[dict], executables: set[str]) -> dict:
    counts = Counter()
    distinct_targets = set()
    matched_targets = set()
    unmatched_targets = set()

    for rec in records:
        counts["records"] += 1
        if has_local_testcase(rec):
            counts["local_testcase"] += 1
        if fix_present(rec):
            counts["fix_present"] += 1

        target = fuzz_target(rec)
        if target:
            counts["has_fuzz_target"] += 1
            distinct_targets.add(target)
            if target in executables:
                counts["target_match"] += 1
                matched_targets.add(target)
            else:
                unmatched_targets.add(target)

        automatic_replay_ready = fix_present(rec) and has_local_testcase(rec)
        target_named_ready = automatic_replay_ready and bool(target)
        built_target_ready = target_named_ready and target in executables
        if automatic_replay_ready:
            counts["automatic_replay_ready"] += 1
        if target_named_ready:
            counts["target_named_ready"] += 1
        if built_target_ready:
            counts["built_target_ready"] += 1

    total = counts["records"] or 1
    return {
        "records": counts["records"],
        "local_testcase": counts["local_testcase"],
        "fix_present": counts["fix_present"],
        "has_fuzz_target": counts["has_fuzz_target"],
        "target_match": counts["target_match"],
        "automatic_replay_ready": counts["automatic_replay_ready"],
        "target_named_ready": counts["target_named_ready"],
        "built_target_ready": counts["built_target_ready"],
        "distinct_mined_targets": sorted(distinct_targets),
        "matched_targets": sorted(matched_targets),
        "unmatched_targets": sorted(unmatched_targets),
        "pcts": {
            "local_testcase": counts["local_testcase"] / total,
            "fix_present": counts["fix_present"] / total,
            "has_fuzz_target": counts["has_fuzz_target"] / total,
            "target_match": counts["target_match"] / total,
            "automatic_replay_ready": counts["automatic_replay_ready"] / total,
            "target_named_ready": counts["target_named_ready"] / total,
            "built_target_ready": counts["built_target_ready"] / total,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit historical bug reversal readiness against built project images.")
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST), help="Path to the historical bug reproduction manifest JSONL.")
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    records = load_records(manifest_path)
    grouped: dict[str, list[dict]] = defaultdict(list)
    for rec in records:
        grouped[rec["project"]].append(rec)

    projects = sorted(grouped)
    out_dir = REPO_ROOT / "runs" / "ossfuzz" / "historical_bug_reversal_readiness_audit" / f"run_{utc_stamp()}"
    out_dir.mkdir(parents=True, exist_ok=True)

    per_project: dict[str, dict] = {}
    totals = Counter()

    for project in projects:
        run_setup(project)
        config = load_project_config(project)
        runtime = build_runtime(config)
        project_dir = out_dir / project
        project_dir.mkdir(parents=True, exist_ok=True)
        start_phase(runtime, phase="historical_bug_reversal_readiness_audit", run_dir=project_dir)
        try:
            manifest = runtime.inspect_out_manifest()
            executables = sorted(manifest.get("executables") or [])
            summary = summarize_project(grouped[project], set(executables))
            summary["built_executables"] = executables
            summary["out_manifest"] = manifest
            per_project[project] = summary
            write_json(project_dir / "out_manifest.json", manifest)
            write_json(project_dir / "summary.json", summary)
            for key in [
                "records",
                "local_testcase",
                "fix_present",
                "has_fuzz_target",
                "target_match",
                "automatic_replay_ready",
                "target_named_ready",
                "built_target_ready",
            ]:
                totals[key] += int(summary[key])
        finally:
            finish_phase(runtime)

    final_summary = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "manifest": str(manifest_path),
        "projects": projects,
        "totals": dict(totals),
        "per_project": per_project,
    }
    write_json(out_dir / "summary.json", final_summary)
    print(json.dumps(final_summary, indent=2))


if __name__ == "__main__":
    main()
