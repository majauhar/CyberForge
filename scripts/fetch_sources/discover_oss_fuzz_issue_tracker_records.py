#!/usr/bin/env python3
"""
Discover OSS-Fuzz issue IDs from the public oss-fuzz-osv-vulns bucket.

The public tracker UI does not expose anonymous search results reliably, but the
public GCS bucket `oss-fuzz-osv-vulns` exposes issue-keyed JSON records under
`issue/<issue_id>.json`. This script treats that bucket as a discovery surface:

  1. list public issue-keyed bucket objects
  2. resolve them back to Vuljector projects using package name / repo URL
  3. compare against the current seed universe (published OSS-Fuzz OSV + ARVO)
  4. optionally use `testcase/` bucket records as fallback when `issue/` is sparse

Writes one JSON per discovered issue under:
  runs/ossfuzz/issue_tracker_discovery/<project>/<issue_id>.json
"""

from __future__ import annotations

import argparse
import csv
import json
import sqlite3
import sys
import zipfile
from collections import Counter, defaultdict
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
    has_fix_range,
    iter_bucket_records,
)
from mining_helpers.resolve_project_metadata import ProjectResolver


_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_CSV = _VULJECTOR_ROOT / "scripts" / "oss_fuzz_full.csv"
_DEFAULT_OSV_ZIP = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv" / "all.zip"
_DEFAULT_ARVO_DB = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "arvo" / "arvo.db"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "issue_tracker_discovery"
_DEFAULT_BUCKET_CACHE_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "oss_fuzz_vulns_bucket_cache"


def load_resolver(projects_dir: Path | None, csv_path: Path | None) -> ProjectResolver:
    if csv_path and csv_path.exists():
        return ProjectResolver.from_csv_path(csv_path)
    if projects_dir and projects_dir.exists():
        return ProjectResolver.from_projects_dir(projects_dir)
    raise FileNotFoundError("Need either an existing --projects-dir or --csv input")


def load_seed_issue_ids(osv_zip_path: Path, arvo_db_path: Path) -> tuple[set[str], set[str]]:
    osv_ids: set[str] = set()
    arvo_ids: set[str] = set()

    if osv_zip_path.exists():
        with zipfile.ZipFile(osv_zip_path, "r") as zf:
            for name in zf.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    entry = json.loads(zf.read(name))
                except Exception:
                    continue
                iid = extract_issue_id_from_refs(entry.get("references", []))
                if iid:
                    osv_ids.add(iid)

    if arvo_db_path.exists():
        conn = sqlite3.connect(f"file:{arvo_db_path}?mode=ro", uri=True)
        try:
            cur = conn.cursor()
            for (local_id,) in cur.execute("SELECT DISTINCT localId FROM arvo WHERE localId IS NOT NULL"):
                arvo_ids.add(str(local_id))
        finally:
            conn.close()

    return osv_ids, arvo_ids


def build_testcase_index(cache_dir: Path | None = None, sync_bucket: bool = False) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for key, record in iter_bucket_records("testcase/", cache_root=cache_dir, sync=sync_bucket):
        issue_id = extract_issue_id(record, key=None)
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


def write_record(record: dict, out_dir: Path) -> None:
    project = record["project"] or "_unresolved"
    out_path = out_dir / project / f"{record['issue_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))


def mine_issue_tracker_discovery(
    resolver: ProjectResolver,
    out_dir: Path,
    osv_zip_path: Path,
    arvo_db_path: Path,
    include_known: bool = False,
    include_unresolved: bool = False,
    project_filter: str | None = None,
    bucket_cache_dir: Path | None = None,
    sync_bucket: bool = False,
) -> dict:
    osv_seed_ids, arvo_seed_ids = load_seed_issue_ids(osv_zip_path, arvo_db_path)
    testcase_index = build_testcase_index(cache_dir=bucket_cache_dir, sync_bucket=sync_bucket)

    stats = {
        "bucket_issue_records": 0,
        "resolved_to_projects": 0,
        "written": 0,
        "new_vs_seed_union": 0,
        "known_vs_seed_union": 0,
        "used_testcase_fallback": 0,
        "unresolved": 0,
        "published_like": 0,
        "with_fix_range": 0,
    }
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
        if project is None and not include_unresolved:
            stats["unresolved"] += 1
            continue

        seeded_by: list[str] = []
        if issue_id in osv_seed_ids:
            seeded_by.append("osv")
        if issue_id in arvo_seed_ids:
            seeded_by.append("arvo")
        is_known = bool(seeded_by)

        if is_known and not include_known:
            stats["known_vs_seed_union"] += 1
            continue

        if project is None:
            stats["unresolved"] += 1
        else:
            stats["resolved_to_projects"] += 1
            per_project[project] += 1

        if has_fix_range(enriched_record):
            stats["with_fix_range"] += 1
        if extract_package_names(enriched_record, ecosystem="OSS-Fuzz"):
            stats["published_like"] += 1

        if not is_known:
            stats["new_vs_seed_union"] += 1

        out_record = {
            "issue_id": issue_id,
            "project": project,
            "vuln_id": enriched_record.get("id"),
            "summary": enriched_record.get("summary"),
            "published": enriched_record.get("published"),
            "modified": enriched_record.get("modified"),
            "package_names": extract_package_names(enriched_record, ecosystem="OSS-Fuzz"),
            "repo_url": extract_repo_url(enriched_record),
            "has_fix_range": has_fix_range(enriched_record),
            "seed_known": is_known,
            "seeded_by": "+".join(seeded_by) if seeded_by else "",
            "used_testcase_fallback": enriched_record is not issue_record,
            "source": "oss_fuzz_vulns_issue_bucket",
            "references": enriched_record.get("references", []),
        }
        write_record(out_record, out_dir)
        stats["written"] += 1

    print("[IT-DISCOVERY] Done.")
    print(f"  Bucket issue records   : {stats['bucket_issue_records']}")
    print(f"  New vs seed union      : {stats['new_vs_seed_union']}")
    print(f"  Known vs seed union    : {stats['known_vs_seed_union']}")
    print(f"  Resolved to projects   : {stats['resolved_to_projects']}")
    print(f"  Used testcase fallback : {stats['used_testcase_fallback']}")
    print(f"  Unresolved             : {stats['unresolved']}")
    print(f"  Written                : {stats['written']}")
    print(f"  With fix range         : {stats['with_fix_range']}")
    print("  Top projects:")
    for project, count in per_project.most_common(15):
        print(f"    {project:<24} {count:>5}")

    stats["per_project"] = dict(per_project)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Discover OSS-Fuzz issue IDs from the public oss-fuzz-osv-vulns bucket")
    parser.add_argument("--projects-dir", default=str(_DEFAULT_PROJECTS_DIR), help=f"Path to vuljector-projects root (default: {_DEFAULT_PROJECTS_DIR})")
    parser.add_argument("--csv", default=str(_DEFAULT_CSV), help=f"Fallback full CSV path (default: {_DEFAULT_CSV})")
    parser.add_argument("--osv-zip", default=str(_DEFAULT_OSV_ZIP), help=f"Published OSS-Fuzz OSV zip for seed comparison (default: {_DEFAULT_OSV_ZIP})")
    parser.add_argument("--arvo-db", default=str(_DEFAULT_ARVO_DB), help=f"ARVO DB for seed comparison (default: {_DEFAULT_ARVO_DB})")
    parser.add_argument("--out-dir", default=str(_DEFAULT_OUT_DIR), help=f"Output directory (default: {_DEFAULT_OUT_DIR})")
    parser.add_argument("--bucket-cache-dir", default=str(_DEFAULT_BUCKET_CACHE_DIR), help=f"Local cache dir for public bucket JSON (default: {_DEFAULT_BUCKET_CACHE_DIR})")
    parser.add_argument("--no-bucket-sync", action="store_true", help="Skip pre-syncing bucket objects and read sequentially instead")
    parser.add_argument("--project", help="Only keep records resolved to this project")
    parser.add_argument("--include-known", action="store_true", help="Also write issue IDs already present in the current OSV/ARVO seed union")
    parser.add_argument("--include-unresolved", action="store_true", help="Write unresolved records under _unresolved/")
    args = parser.parse_args()

    resolver = load_resolver(
        projects_dir=Path(args.projects_dir).expanduser().resolve() if args.projects_dir else None,
        csv_path=Path(args.csv).expanduser().resolve() if args.csv else None,
    )
    mine_issue_tracker_discovery(
        resolver=resolver,
        out_dir=Path(args.out_dir).expanduser().resolve(),
        osv_zip_path=Path(args.osv_zip).expanduser().resolve(),
        arvo_db_path=Path(args.arvo_db).expanduser().resolve(),
        include_known=args.include_known,
        include_unresolved=args.include_unresolved,
        project_filter=args.project,
        bucket_cache_dir=Path(args.bucket_cache_dir).expanduser().resolve(),
        sync_bucket=not args.no_bucket_sync,
    )


if __name__ == "__main__":
    main()
