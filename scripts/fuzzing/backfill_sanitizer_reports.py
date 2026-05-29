#!/usr/bin/env python3
"""Backfill missing sanitizer reports for canonical vulnerability bundles."""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

from agent_tasks.assets import _candidate_crash_log_paths, extract_sanitizer_report
from utils.paths import new_run_id, runs_root


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--projects-root",
        type=Path,
        default=Path("/home/mns67/vuljector_fuzzer_exps/vuljector-projects"),
        help="Root containing <project>/vulnerabilities/<id> bundles.",
    )
    parser.add_argument(
        "--refresh-all",
        action="store_true",
        help="Recompute sanitizer reports even when sanitizer_report.txt is already non-empty.",
    )
    parser.add_argument(
        "--project",
        action="append",
        default=[],
        help="Limit to one or more project names.",
    )
    args = parser.parse_args()

    run_id = new_run_id("sanitizer_backfill")
    run_dir = runs_root() / "sanitizer_backfill" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    summary: dict[str, Any] = {
        "run_id": run_id,
        "projects_root": str(args.projects_root),
        "refresh_all": bool(args.refresh_all),
        "project_filter": sorted(args.project),
        "validated_bundle_count": 0,
        "eligible_bundle_count": 0,
        "updated_count": 0,
        "unchanged_count": 0,
        "recovered_count": 0,
        "still_missing_count": 0,
        "updated": [],
        "still_missing": [],
    }

    project_filter = set(args.project)
    for project_dir in sorted(args.projects_root.iterdir()):
        if not project_dir.is_dir():
            continue
        if project_filter and project_dir.name not in project_filter:
            continue
        vulnerabilities_dir = project_dir / "vulnerabilities"
        if not vulnerabilities_dir.exists():
            continue
        for vuln_dir in sorted(vulnerabilities_dir.iterdir()):
            if not vuln_dir.is_dir():
                continue
            metadata_path = vuln_dir / "vulnerability_metadata.json"
            context_path = vuln_dir / "task_generation_context.json"
            if not metadata_path.exists() or not context_path.exists():
                continue
            metadata = _read_json(metadata_path)
            if metadata.get("exported_from_verification_status") != "success":
                continue
            summary["validated_bundle_count"] += 1

            sanitizer_path = vuln_dir / "sanitizer_report.txt"
            current_report = sanitizer_path.read_text(encoding="utf-8", errors="ignore") if sanitizer_path.exists() else ""
            if current_report.strip() and not args.refresh_all:
                summary["unchanged_count"] += 1
                continue

            summary["eligible_bundle_count"] += 1
            context = _read_json(context_path)
            recovered_report = ""
            winning_rel_path = ""
            for candidate_path in _candidate_crash_log_paths(vuln_dir, context):
                if not candidate_path.exists():
                    continue
                recovered_report = extract_sanitizer_report(
                    candidate_path.read_text(encoding="utf-8", errors="ignore")
                )
                if recovered_report:
                    winning_rel_path = str(candidate_path.relative_to(vuln_dir))
                    break

            if recovered_report:
                sanitizer_path.write_text(recovered_report.strip() + "\n", encoding="utf-8")
                context["successful_log_relative_path"] = winning_rel_path
                context["vulnerable_log_relative_path"] = winning_rel_path
                context_path.write_text(json.dumps(context, indent=2) + "\n", encoding="utf-8")
                metadata["has_sanitizer_report"] = True
                sanitizer_kind = _detect_sanitizer_kind(recovered_report)
                if sanitizer_kind:
                    metadata["sanitizer_kind"] = sanitizer_kind
                metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

                summary["updated_count"] += 1
                if not current_report.strip():
                    summary["recovered_count"] += 1
                summary["updated"].append(
                    {
                        "project": project_dir.name,
                        "vulnerability_id": vuln_dir.name,
                        "winning_log_relative_path": winning_rel_path,
                        "sanitizer_kind": sanitizer_kind,
                        "first_line": recovered_report.splitlines()[0] if recovered_report else "",
                    }
                )
            else:
                summary["still_missing_count"] += 1
                summary["still_missing"].append(
                    {
                        "project": project_dir.name,
                        "vulnerability_id": vuln_dir.name,
                    }
                )

    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(str(summary_path))
    print(
        json.dumps(
            {
                "validated_bundle_count": summary["validated_bundle_count"],
                "eligible_bundle_count": summary["eligible_bundle_count"],
                "updated_count": summary["updated_count"],
                "recovered_count": summary["recovered_count"],
                "still_missing_count": summary["still_missing_count"],
            },
            indent=2,
        )
    )


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _detect_sanitizer_kind(report: str) -> str:
    first_line = next((line.strip() for line in report.splitlines() if line.strip()), "")
    match = re.search(r"(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer)", first_line)
    return match.group(1) if match else ""


if __name__ == "__main__":
    main()
