#!/usr/bin/env python3
"""
Mine raw / failure-style OSS-Fuzz vulnerability records from the public
oss-fuzz-osv-vulns bucket.

The public bucket contains issue-keyed records under `issue/<issue_id>.json`
that are broader than the published OSS-Fuzz OSV dump. This script isolates
records that look like failure / non-exported cases, plus sparse issue records
that are missing package or fix metadata.

Writes one JSON per candidate record under:
  runs/ossfuzz/oss_fuzz_vulns_failures/<project_or__unresolved>/<issue_id>.json
"""

from __future__ import annotations

import argparse
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from fetch_sources.mine_oss_fuzz_osv_records import extract_issue_id as extract_issue_id_from_refs
from mining_helpers.fetch_oss_fuzz_vulns_bucket import (
    choose_better_record,
    extract_issue_id,
    extract_package_names,
    extract_repo_url,
    has_any_package,
    has_any_git_repo,
    has_fix_range,
    iter_bucket_records,
)
from mining_helpers.resolve_project_metadata import ProjectResolver


_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_CSV = _VULJECTOR_ROOT / "scripts" / "oss_fuzz_full.csv"
_DEFAULT_OSV_ZIP = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv" / "all.zip"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "oss_fuzz_vulns_failures"
_DEFAULT_BUCKET_CACHE_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "oss_fuzz_vulns_bucket_cache"


def load_resolver(projects_dir: Path | None, csv_path: Path | None) -> ProjectResolver:
    if csv_path and csv_path.exists():
        return ProjectResolver.from_csv_path(csv_path)
    if projects_dir and projects_dir.exists():
        return ProjectResolver.from_projects_dir(projects_dir)
    raise FileNotFoundError("Need either an existing --projects-dir or --csv input")


def load_published_osv_index(osv_zip_path: Path) -> tuple[set[str], set[str]]:
    vuln_ids: set[str] = set()
    issue_ids: set[str] = set()
    if not osv_zip_path.exists():
        return vuln_ids, issue_ids

    with zipfile.ZipFile(osv_zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                entry = json.loads(zf.read(name))
            except Exception:
                continue
            vuln_id = entry.get("id")
            if vuln_id:
                vuln_ids.add(str(vuln_id))
            issue_id = extract_issue_id_from_refs(entry.get("references", []))
            if issue_id:
                issue_ids.add(issue_id)
    return vuln_ids, issue_ids


def build_testcase_index(cache_dir: Path | None = None, sync_bucket: bool = False) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for key, record in iter_bucket_records("testcase/", cache_root=cache_dir, sync=sync_bucket):
        issue_id = extract_issue_id(record)
        if not issue_id:
            continue
        index[issue_id] = choose_better_record(index.get(issue_id), record)
    return index


def resolve_project(record: dict, resolver: ProjectResolver) -> str | None:
    repo_url = extract_repo_url(record)
    package_names = extract_package_names(record, ecosystem="OSS-Fuzz")
    for package_name in package_names:
        project = resolver.resolve(package_name, repo_url)
        if project:
            return project
    if repo_url:
        return resolver.resolve(None, repo_url)
    return None


def classify_failure(record: dict, published_vuln_ids: set[str]) -> list[str]:
    reasons: list[str] = []
    vuln_id = record.get("id")
    if vuln_id not in published_vuln_ids:
        reasons.append("not_in_published_oss_fuzz_osv")
    if not has_any_package(record):
        reasons.append("missing_package")
    if not has_any_git_repo(record):
        reasons.append("missing_repo")
    if not has_fix_range(record):
        reasons.append("missing_fix_range")
    return reasons


def write_record(record: dict, out_dir: Path) -> None:
    project = record["project"] or "_unresolved"
    out_path = out_dir / project / f"{record['issue_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))


def mine_oss_fuzz_vulns_failures(
    resolver: ProjectResolver,
    osv_zip_path: Path,
    out_dir: Path,
    include_resolved_published: bool = False,
    include_unresolved: bool = True,
    project_filter: str | None = None,
    bucket_cache_dir: Path | None = None,
    sync_bucket: bool = False,
) -> dict:
    published_vuln_ids, published_issue_ids = load_published_osv_index(osv_zip_path)
    testcase_index = build_testcase_index(cache_dir=bucket_cache_dir, sync_bucket=sync_bucket)

    stats = {
        "bucket_issue_records": 0,
        "failure_candidates": 0,
        "written": 0,
        "resolved_to_projects": 0,
        "used_testcase_fallback": 0,
        "published_issue_ids": len(published_issue_ids),
    }
    by_reason = Counter()
    per_project = Counter()

    for key, issue_record in iter_bucket_records("issue/", cache_root=bucket_cache_dir, sync=sync_bucket):
        stats["bucket_issue_records"] += 1
        issue_id = extract_issue_id(issue_record, key)
        if not issue_id:
            continue

        enriched_record = issue_record
        project = resolve_project(enriched_record, resolver)
        if project is None and issue_id in testcase_index:
            enriched_record = testcase_index[issue_id]
            project = resolve_project(enriched_record, resolver)
            if project:
                stats["used_testcase_fallback"] += 1

        if project_filter and project != project_filter:
            continue

        reasons = classify_failure(enriched_record, published_vuln_ids)
        if not reasons and not include_resolved_published:
            continue
        if project is None and not include_unresolved:
            continue

        stats["failure_candidates"] += 1
        if project:
            stats["resolved_to_projects"] += 1
            per_project[project] += 1
        for reason in reasons:
            by_reason[reason] += 1

        out_record = {
            "issue_id": issue_id,
            "project": project,
            "vuln_id": enriched_record.get("id"),
            "summary": enriched_record.get("summary"),
            "published": enriched_record.get("published"),
            "modified": enriched_record.get("modified"),
            "package_names": extract_package_names(enriched_record, ecosystem="OSS-Fuzz"),
            "repo_url": extract_repo_url(enriched_record),
            "has_package": has_any_package(enriched_record),
            "has_repo": has_any_git_repo(enriched_record),
            "has_fix_range": has_fix_range(enriched_record),
            "in_published_oss_fuzz_osv": enriched_record.get("id") in published_vuln_ids,
            "in_published_seed_issue_ids": issue_id in published_issue_ids,
            "failure_reasons": reasons,
            "used_testcase_fallback": enriched_record is not issue_record,
            "source": "oss_fuzz_vulns_issue_bucket_failure_candidate",
            "references": enriched_record.get("references", []),
        }
        write_record(out_record, out_dir)
        stats["written"] += 1

    print("[OSS-FUZZ-VULNS-FAILURES] Done.")
    print(f"  Bucket issue records   : {stats['bucket_issue_records']}")
    print(f"  Failure candidates     : {stats['failure_candidates']}")
    print(f"  Resolved to projects   : {stats['resolved_to_projects']}")
    print(f"  Used testcase fallback : {stats['used_testcase_fallback']}")
    print(f"  Written                : {stats['written']}")
    print("  Failure reasons:")
    for reason, count in by_reason.most_common():
        print(f"    {reason:<28} {count:>5}")
    print("  Top projects:")
    for project, count in per_project.most_common(15):
        print(f"    {project:<24} {count:>5}")

    stats["by_reason"] = dict(by_reason)
    stats["per_project"] = dict(per_project)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Mine raw / failure-style records from the public oss-fuzz-osv-vulns bucket")
    parser.add_argument("--projects-dir", default=str(_DEFAULT_PROJECTS_DIR), help=f"Path to vuljector-projects root (default: {_DEFAULT_PROJECTS_DIR})")
    parser.add_argument("--csv", default=str(_DEFAULT_CSV), help=f"Fallback full CSV path (default: {_DEFAULT_CSV})")
    parser.add_argument("--osv-zip", default=str(_DEFAULT_OSV_ZIP), help=f"Published OSS-Fuzz OSV zip (default: {_DEFAULT_OSV_ZIP})")
    parser.add_argument("--out-dir", default=str(_DEFAULT_OUT_DIR), help=f"Output directory (default: {_DEFAULT_OUT_DIR})")
    parser.add_argument("--bucket-cache-dir", default=str(_DEFAULT_BUCKET_CACHE_DIR), help=f"Local cache dir for public bucket JSON (default: {_DEFAULT_BUCKET_CACHE_DIR})")
    parser.add_argument("--no-bucket-sync", action="store_true", help="Skip pre-syncing bucket objects and read sequentially instead")
    parser.add_argument("--project", help="Only keep records resolved to this project")
    parser.add_argument("--include-resolved-published", action="store_true", help="Also include issue records that look fully published/complete")
    parser.add_argument("--exclude-unresolved", action="store_true", help="Skip unresolved records instead of writing _unresolved/")
    args = parser.parse_args()

    resolver = load_resolver(
        projects_dir=Path(args.projects_dir).expanduser().resolve() if args.projects_dir else None,
        csv_path=Path(args.csv).expanduser().resolve() if args.csv else None,
    )
    mine_oss_fuzz_vulns_failures(
        resolver=resolver,
        osv_zip_path=Path(args.osv_zip).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        include_resolved_published=args.include_resolved_published,
        include_unresolved=not args.exclude_unresolved,
        project_filter=args.project,
        bucket_cache_dir=Path(args.bucket_cache_dir).expanduser().resolve(),
        sync_bucket=not args.no_bucket_sync,
    )


if __name__ == "__main__":
    main()
