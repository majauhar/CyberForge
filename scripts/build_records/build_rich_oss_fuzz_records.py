#!/usr/bin/env python3
"""
Build a richer OSS-Fuzz vulnerability corpus by merging:
  - published OSS-Fuzz OSV records
  - public oss-fuzz-osv-vulns issue/ + testcase/ bucket records
  - ARVO reproduction metadata
  - fetched public issue pages from issues.oss-fuzz.com

The output is one JSON per issue under:
  runs/ossfuzz/rich_records/<project>/<issue_id>.json

Each record keeps normalized top-level fields for analysis plus nested raw source
records so downstream steps can recover as much detail as possible.
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Iterable

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.parse_clusterfuzz_report import parse_clusterfuzz_report
from fetch_sources.mine_oss_fuzz_issue_tracker_records import extract_report_text, fetch_issue_page, is_private_issue
from fetch_sources.mine_oss_fuzz_osv_records import extract_issue_id as extract_issue_id_from_refs
from mining_helpers.fetch_oss_fuzz_vulns_bucket import (
    extract_issue_id,
    extract_package_names,
    extract_repo_url,
    iter_bucket_records,
)
from mining_helpers.resolve_project_metadata import ProjectResolver


_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_CSV = _VULJECTOR_ROOT / "scripts" / "oss_fuzz_full.csv"
_DEFAULT_OSV_ZIP = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv" / "all.zip"
_DEFAULT_ARVO_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "arvo"
_DEFAULT_BUCKET_CACHE_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "oss_fuzz_vulns_bucket_cache"
_DEFAULT_ISSUE_PAGE_CACHE_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "issue_page_cache"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "rich_records"
_DEFAULT_SUMMARY_PATH = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "rich_records_summary.json"

_ISSUE_URL_RE = re.compile(r"(?:detail\?id=|issues/)(\d+)")


def load_target_projects(
    projects_dir: Path,
    csv_path: Path | None = None,
    project_filter: str | None = None,
    language_filter: set[str] | None = None,
) -> tuple[ProjectResolver, dict[str, dict], set[str]]:
    metadata: dict[str, dict] = {}
    if csv_path and csv_path.exists():
        with csv_path.open(newline="") as handle:
            for row in csv.DictReader(handle):
                name = row.get("name")
                if not name:
                    continue
                metadata[name] = {
                    "project": name,
                    "language": row.get("language"),
                    "main_repo_url": row.get("main_repo") or row.get("main_repo_url"),
                    "github_slug": row.get("github_slug"),
                }
        resolver = ProjectResolver.from_csv_path(csv_path)
    else:
        for proj_json in sorted(projects_dir.glob("*/project.json")):
            try:
                data = json.loads(proj_json.read_text())
            except Exception:
                continue
            name = data.get("project")
            if not name:
                continue
            metadata[name] = data
        resolver = ProjectResolver.from_projects_dir(projects_dir)
    target = set(metadata)
    if project_filter:
        target &= {project_filter}
    if language_filter:
        target = {
            name
            for name in target
            if (metadata.get(name, {}).get("language") or "").lower() in language_filter
        }
    return resolver, metadata, target


def resolve_project(record: dict, resolver: ProjectResolver) -> tuple[str | None, str | None]:
    repo_url = extract_repo_url(record)
    package_names = extract_package_names(record, ecosystem="OSS-Fuzz")
    for package_name in package_names:
        project, reason = resolver.resolve_with_reason(package_name, repo_url)
        if project:
            return project, reason
    if repo_url:
        return resolver.resolve_with_reason(None, repo_url)
    return None, None


def load_raw_published_osv(
    osv_zip_path: Path,
    resolver: ProjectResolver,
    target_projects: set[str],
) -> dict[str, dict[str, dict]]:
    per_project: dict[str, dict[str, dict]] = defaultdict(dict)
    if not osv_zip_path.exists():
        return per_project

    with zipfile.ZipFile(osv_zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                entry = json.loads(zf.read(name))
            except Exception:
                continue

            repo_url = extract_repo_url(entry)
            project_name = None
            for affected_entry in entry.get("affected", []):
                pkg = affected_entry.get("package", {})
                if pkg.get("ecosystem") != "OSS-Fuzz":
                    continue
                project_name = resolver.resolve(pkg.get("name"), repo_url)
                if project_name:
                    break
            if not project_name or project_name not in target_projects:
                continue

            issue_id = extract_issue_id_from_refs(entry.get("references", []))
            if not issue_id:
                continue
            per_project[project_name][issue_id] = entry

    return per_project


def load_arvo_records(arvo_dir: Path, target_projects: set[str]) -> dict[str, dict[str, dict]]:
    per_project: dict[str, dict[str, dict]] = defaultdict(dict)
    if not arvo_dir.is_dir():
        return per_project
    for project in sorted(target_projects):
        proj_dir = arvo_dir / project
        if not proj_dir.is_dir():
            continue
        for json_file in sorted(proj_dir.glob("*.json")):
            try:
                record = json.loads(json_file.read_text())
            except Exception:
                continue
            issue_id = str(record.get("issue_id") or "")
            if issue_id:
                per_project[project][issue_id] = record
    return per_project


def build_bucket_indexes(
    resolver: ProjectResolver,
    target_projects: set[str],
    bucket_cache_dir: Path,
) -> tuple[dict[str, dict[str, dict]], dict[str, dict[str, list[dict]]], dict[str, int]]:
    issue_by_project: dict[str, dict[str, dict]] = defaultdict(dict)
    testcase_by_project: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    mapping_stats = Counter()

    for key, record in iter_bucket_records("issue/", cache_root=bucket_cache_dir, sync=False):
        issue_id = extract_issue_id(record, key)
        if not issue_id:
            continue
        project, reason = resolve_project(record, resolver)
        if not project or project not in target_projects:
            continue
        mapping_stats[f"issue:{reason or 'unknown'}"] += 1
        issue_by_project[project][issue_id] = {
            "key": key,
            "record": record,
            "mapping_reason": reason,
        }

    for key, record in iter_bucket_records("testcase/", cache_root=bucket_cache_dir, sync=False):
        issue_id = extract_issue_id(record)
        if not issue_id:
            continue
        project, reason = resolve_project(record, resolver)
        if not project or project not in target_projects:
            continue
        testcase_id = Path(key).stem
        mapping_stats[f"testcase:{reason or 'unknown'}"] += 1
        testcase_by_project[project][issue_id].append(
            {
                "key": key,
                "testcase_id": testcase_id,
                "record": record,
                "mapping_reason": reason,
            }
        )

    return issue_by_project, testcase_by_project, dict(mapping_stats)


def extract_git_ranges(record: dict) -> list[dict]:
    ranges: list[dict] = []
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        versions = [str(v) for v in affected.get("versions", []) if v]
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            entry = {
                "package_name": pkg.get("name"),
                "package_ecosystem": pkg.get("ecosystem"),
                "package_purl": pkg.get("purl"),
                "repo_url": rng.get("repo"),
                "introduced": None,
                "fixed": None,
                "last_affected": None,
                "limit": None,
                "versions": versions,
            }
            for event in rng.get("events", []):
                if event.get("introduced") and event.get("introduced") != "0":
                    entry["introduced"] = event["introduced"]
                if event.get("fixed") and event.get("fixed") != "0":
                    entry["fixed"] = event["fixed"]
                if event.get("last_affected"):
                    entry["last_affected"] = event["last_affected"]
                if event.get("limit"):
                    entry["limit"] = event["limit"]
            ranges.append(entry)
    return ranges


def extract_packages(record: dict) -> list[dict]:
    packages: list[dict] = []
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        packages.append(
            {
                "name": pkg.get("name"),
                "ecosystem": pkg.get("ecosystem"),
                "purl": pkg.get("purl"),
                "versions": [str(v) for v in affected.get("versions", []) if v],
                "ecosystem_severity": (affected.get("ecosystem_specific") or {}).get("severity"),
            }
        )
    deduped = []
    seen = set()
    for package in packages:
        key = (
            package.get("name"),
            package.get("ecosystem"),
            package.get("purl"),
            tuple(package.get("versions") or []),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(package)
    return deduped


def extract_reference_urls(record: dict) -> list[str]:
    urls: list[str] = []
    for ref in record.get("references", []):
        if isinstance(ref, dict) and ref.get("url"):
            urls.append(str(ref["url"]))
    return list(dict.fromkeys(urls))


def extract_vuln_ids(*records: dict | None) -> list[str]:
    ids: list[str] = []
    for record in records:
        if not record:
            continue
        vuln_id = record.get("id") or record.get("vuln_id")
        if vuln_id:
            ids.append(str(vuln_id))
        for alias in record.get("aliases", []) or []:
            ids.append(str(alias))
        for alias in record.get("related", []) or []:
            ids.append(str(alias))
    return list(dict.fromkeys(ids))


def extract_fix_commits(*records: dict | None) -> list[str]:
    commits: list[str] = []
    for record in records:
        if not record:
            continue
        if "fix_commits" in record:
            commits.extend(str(c) for c in record.get("fix_commits") or [] if c)
        for rng in extract_git_ranges(record):
            if rng.get("fixed"):
                commits.append(str(rng["fixed"]))
    return list(dict.fromkeys(commits))


def extract_introducing_commits(*records: dict | None) -> list[str]:
    commits: list[str] = []
    for record in records:
        if not record:
            continue
        if "introducing_commits" in record:
            commits.extend(str(c) for c in record.get("introducing_commits") or [] if c)
        vul_commit = record.get("vul_commit")
        if vul_commit:
            commits.append(str(vul_commit))
        for rng in extract_git_ranges(record):
            if rng.get("introduced"):
                commits.append(str(rng["introduced"]))
    return list(dict.fromkeys(commits))


def extract_report_urls(*records: dict | None) -> list[str]:
    urls: list[str] = []
    for record in records:
        if not record:
            continue
        if record.get("report_url"):
            urls.append(str(record["report_url"]))
        urls.extend(extract_reference_urls(record))
        details = record.get("details") or ""
        urls.extend(re.findall(r"https?://\S+", details))
    cleaned = [url.rstrip("`),.;") for url in urls]
    return list(dict.fromkeys(cleaned))


def extract_crash_blob(
    bucket_issue: dict | None,
    testcase_records: list[dict],
    arvo_record: dict | None,
    issue_page_report: str | None,
) -> tuple[str | None, str]:
    if issue_page_report:
        return issue_page_report, "issue_page"
    if arvo_record and arvo_record.get("expected_crash_output"):
        return str(arvo_record["expected_crash_output"]), "arvo"
    for testcase in testcase_records:
        details = testcase.get("details")
        if details:
            return str(details), "bucket_testcase"
    if bucket_issue and bucket_issue.get("details"):
        return str(bucket_issue["details"]), "bucket_issue"
    return None, "none"


def fetch_and_cache_issue_page(
    project: str,
    issue_id: str,
    cache_dir: Path,
    fetch: bool,
    delay: float,
) -> dict:
    html_path = cache_dir / project / f"{issue_id}.html"
    html_path.parent.mkdir(parents=True, exist_ok=True)

    html = None
    if html_path.exists():
        try:
            html = html_path.read_text()
        except Exception:
            html = None
    if html is None and fetch:
        html = fetch_issue_page(issue_id, delay)
        if html:
            html_path.write_text(html)

    if not html:
        return {
            "html_path": str(html_path) if html_path.exists() else None,
            "fetched": False,
            "private": None,
            "report_found": False,
            "report_text": None,
            "parsed": {},
        }

    private = is_private_issue(html)
    report_text = None if private else extract_report_text(html)
    parsed = parse_clusterfuzz_report(report_text or "") if report_text else {}
    return {
        "html_path": str(html_path),
        "fetched": True,
        "private": private,
        "report_found": bool(report_text),
        "report_text": report_text,
        "parsed": parsed,
    }


def build_issue_record(
    project: str,
    issue_id: str,
    project_meta: dict,
    published_osv: dict | None,
    bucket_issue: dict | None,
    testcase_records: list[dict],
    arvo_record: dict | None,
    issue_page_info: dict,
) -> dict:
    testcase_raw = [entry["record"] for entry in testcase_records]
    report_text, report_source = extract_crash_blob(
        bucket_issue=bucket_issue,
        testcase_records=testcase_raw,
        arvo_record=arvo_record,
        issue_page_report=issue_page_info.get("report_text"),
    )

    crash_fields = {}
    for source in (
        issue_page_info.get("parsed") or {},
        parse_clusterfuzz_report(report_text or ""),
        arvo_record or {},
    ):
        for key, value in source.items():
            if value not in (None, "", [], {}):
                crash_fields.setdefault(key, value)

    packages = []
    for record in [published_osv, bucket_issue, *testcase_raw]:
        if record:
            packages.extend(extract_packages(record))
    package_dedup = []
    seen_packages = set()
    for package in packages:
        key = (
            package.get("name"),
            package.get("ecosystem"),
            package.get("purl"),
            tuple(package.get("versions") or []),
        )
        if key in seen_packages:
            continue
        seen_packages.add(key)
        package_dedup.append(package)

    git_ranges = []
    for record in [published_osv, bucket_issue, *testcase_raw]:
        if record:
            git_ranges.extend(extract_git_ranges(record))
    deduped_ranges = []
    seen_ranges = set()
    for rng in git_ranges:
        key = (
            rng.get("package_name"),
            rng.get("repo_url"),
            rng.get("introduced"),
            rng.get("fixed"),
            rng.get("last_affected"),
            rng.get("limit"),
            tuple(rng.get("versions") or []),
        )
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        deduped_ranges.append(rng)

    fix_commits = extract_fix_commits(published_osv, bucket_issue, *testcase_raw, arvo_record)
    introducing_commits = extract_introducing_commits(published_osv, bucket_issue, *testcase_raw, arvo_record)
    repo_urls = []
    for record in [published_osv, bucket_issue, *testcase_raw, arvo_record]:
        if not record:
            continue
        repo_url = record.get("repo_url") or extract_repo_url(record)
        if repo_url:
            repo_urls.append(str(repo_url))
        for git_range in extract_git_ranges(record):
            if git_range.get("repo_url"):
                repo_urls.append(str(git_range["repo_url"]))

    vuln_ids = extract_vuln_ids(published_osv, bucket_issue, *testcase_raw)
    summary = None
    for source in [published_osv, bucket_issue, *testcase_raw]:
        if source and source.get("summary"):
            summary = source.get("summary")
            break

    report_urls = extract_report_urls(published_osv, bucket_issue, *testcase_raw, arvo_record)
    if not report_urls:
        report_urls.append(f"https://issues.oss-fuzz.com/issues/{issue_id}")

    testcase_ids = [entry["testcase_id"] for entry in testcase_records]
    published_values = [r.get("published") for r in [published_osv, bucket_issue, *testcase_raw] if r and r.get("published")]
    modified_values = [r.get("modified") for r in [published_osv, bucket_issue, *testcase_raw] if r and r.get("modified")]

    return {
        "project": project,
        "language": project_meta.get("language"),
        "main_repo_url": project_meta.get("main_repo_url"),
        "issue_id": issue_id,
        "vuln_ids": vuln_ids,
        "summary": summary,
        "published": min(published_values) if published_values else None,
        "modified": max(modified_values) if modified_values else None,
        "report_urls": list(dict.fromkeys(report_urls)),
        "issue_page_html_path": issue_page_info.get("html_path"),
        "issue_page_private": issue_page_info.get("private"),
        "issue_page_report_found": issue_page_info.get("report_found"),
        "report_text_source": report_source,
        "report_text": report_text,
        "clusterfuzz": {
            "project": crash_fields.get("project"),
            "fuzz_engine": crash_fields.get("fuzz_engine"),
            "fuzz_target": crash_fields.get("fuzz_target"),
            "job_type": crash_fields.get("job_type"),
            "crash_type": crash_fields.get("crash_type"),
            "crash_address": crash_fields.get("crash_address"),
            "crash_state": crash_fields.get("crash_state"),
            "sanitizer": crash_fields.get("sanitizer"),
            "security_severity": crash_fields.get("security_severity"),
            "regression_range": crash_fields.get("regression_range"),
            "testcase_id": crash_fields.get("testcase_id"),
        },
        "testcase_ids": testcase_ids,
        "packages": package_dedup,
        "git_ranges": deduped_ranges,
        "repo_urls": list(dict.fromkeys(repo_urls)),
        "fix_commits": fix_commits,
        "introducing_commits": introducing_commits,
        "safe_commit_candidates": fix_commits,
        "vulnerable_commit_candidates": introducing_commits,
        "affected_versions": sorted(
            {
                version
                for package in package_dedup
                for version in package.get("versions") or []
                if version
            }
        ),
        "has_poc": bool(arvo_record and arvo_record.get("has_poc")),
        "poc_artifacts": {
            "arvo_image": (arvo_record or {}).get("arvo_image"),
            "docker_vul": (arvo_record or {}).get("docker_vul"),
            "docker_fix": (arvo_record or {}).get("docker_fix"),
            "vul_commit": (arvo_record or {}).get("vul_commit"),
            "patch_url": (arvo_record or {}).get("patch_url"),
        },
        "source_presence": {
            "published_osv": bool(published_osv),
            "bucket_issue": bool(bucket_issue),
            "bucket_testcase": bool(testcase_records),
            "arvo": bool(arvo_record),
            "issue_page": bool(issue_page_info.get("fetched")),
        },
        "raw_records": {
            "published_osv": published_osv,
            "bucket_issue": bucket_issue,
            "bucket_testcases": testcase_raw,
            "arvo": arvo_record,
        },
    }


def write_issue_record(record: dict, out_dir: Path) -> None:
    out_path = out_dir / record["project"] / f"{record['issue_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))


def build_rich_records(
    projects_dir: Path,
    csv_path: Path | None,
    osv_zip_path: Path,
    arvo_dir: Path,
    bucket_cache_dir: Path,
    issue_page_cache_dir: Path,
    out_dir: Path,
    summary_path: Path,
    project_filter: str | None = None,
    language_filter: set[str] | None = None,
    fetch_issue_pages: bool = True,
    page_delay: float = 0.2,
) -> dict:
    resolver, project_metadata, target_projects = load_target_projects(
        projects_dir=projects_dir,
        csv_path=csv_path,
        project_filter=project_filter,
        language_filter=language_filter,
    )
    published_osv = load_raw_published_osv(osv_zip_path, resolver, target_projects)
    arvo_records = load_arvo_records(arvo_dir, target_projects)
    bucket_issue, bucket_testcases, mapping_stats = build_bucket_indexes(
        resolver=resolver,
        target_projects=target_projects,
        bucket_cache_dir=bucket_cache_dir,
    )

    stats = {
        "target_projects": len(target_projects),
        "written_records": 0,
        "projects_with_records": 0,
        "issue_page_fetch_attempted": 0,
        "issue_page_report_found": 0,
        "mapping_stats": mapping_stats,
        "per_project": {},
    }

    for project in sorted(target_projects):
        issue_ids = set()
        issue_ids.update(published_osv.get(project, {}))
        issue_ids.update(arvo_records.get(project, {}))
        issue_ids.update(bucket_issue.get(project, {}))
        issue_ids.update(bucket_testcases.get(project, {}))
        if not issue_ids:
            continue

        per_project = {
            "issue_count": len(issue_ids),
            "with_published_osv": 0,
            "with_arvo": 0,
            "with_bucket_issue": 0,
            "with_bucket_testcase": 0,
            "with_fix_commits": 0,
            "with_introducing_commits": 0,
            "with_report_text": 0,
        }

        for issue_id in sorted(issue_ids, key=lambda value: int(value)):
            stats["issue_page_fetch_attempted"] += 1
            issue_page_info = fetch_and_cache_issue_page(
                project=project,
                issue_id=issue_id,
                cache_dir=issue_page_cache_dir,
                fetch=fetch_issue_pages,
                delay=page_delay,
            )
            if issue_page_info.get("report_found"):
                stats["issue_page_report_found"] += 1

            record = build_issue_record(
                project=project,
                issue_id=issue_id,
                project_meta=project_metadata[project],
                published_osv=published_osv.get(project, {}).get(issue_id),
                bucket_issue=(bucket_issue.get(project, {}).get(issue_id) or {}).get("record"),
                testcase_records=bucket_testcases.get(project, {}).get(issue_id, []),
                arvo_record=arvo_records.get(project, {}).get(issue_id),
                issue_page_info=issue_page_info,
            )
            write_issue_record(record, out_dir)
            stats["written_records"] += 1

            if record["source_presence"]["published_osv"]:
                per_project["with_published_osv"] += 1
            if record["source_presence"]["arvo"]:
                per_project["with_arvo"] += 1
            if record["source_presence"]["bucket_issue"]:
                per_project["with_bucket_issue"] += 1
            if record["source_presence"]["bucket_testcase"]:
                per_project["with_bucket_testcase"] += 1
            if record["fix_commits"]:
                per_project["with_fix_commits"] += 1
            if record["introducing_commits"]:
                per_project["with_introducing_commits"] += 1
            if record["report_text"]:
                per_project["with_report_text"] += 1

        stats["per_project"][project] = per_project

    stats["projects_with_records"] = len(stats["per_project"])
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text(json.dumps(stats, indent=2))
    return stats


def parse_language_filter(raw: str | None) -> set[str] | None:
    if not raw:
        return None
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a rich OSS-Fuzz vulnerability corpus from public sources")
    parser.add_argument("--projects-dir", default=str(_DEFAULT_PROJECTS_DIR))
    parser.add_argument(
        "--csv",
        help=f"Optional CSV project universe (example: {_DEFAULT_CSV})",
    )
    parser.add_argument("--osv-zip", default=str(_DEFAULT_OSV_ZIP))
    parser.add_argument("--arvo-dir", default=str(_DEFAULT_ARVO_DIR))
    parser.add_argument("--bucket-cache-dir", default=str(_DEFAULT_BUCKET_CACHE_DIR))
    parser.add_argument("--issue-page-cache-dir", default=str(_DEFAULT_ISSUE_PAGE_CACHE_DIR))
    parser.add_argument("--out-dir", default=str(_DEFAULT_OUT_DIR))
    parser.add_argument("--summary-path", default=str(_DEFAULT_SUMMARY_PATH))
    parser.add_argument("--project")
    parser.add_argument(
        "--language-filter",
        help="Comma-separated language filter (example: c,c++)",
    )
    parser.add_argument(
        "--no-fetch-issue-pages",
        action="store_true",
        help="Do not fetch new issue pages; only use cached HTML if present",
    )
    parser.add_argument(
        "--page-delay",
        type=float,
        default=0.2,
        help="Delay before each issue-page request when fetching (default: 0.2)",
    )
    args = parser.parse_args()

    stats = build_rich_records(
        projects_dir=Path(args.projects_dir).expanduser().resolve(),
        csv_path=Path(args.csv).expanduser().resolve() if args.csv else None,
        osv_zip_path=Path(args.osv_zip).expanduser().resolve(),
        arvo_dir=Path(args.arvo_dir).expanduser().resolve(),
        bucket_cache_dir=Path(args.bucket_cache_dir).expanduser().resolve(),
        issue_page_cache_dir=Path(args.issue_page_cache_dir).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        summary_path=Path(args.summary_path).expanduser().resolve(),
        project_filter=args.project,
        language_filter=parse_language_filter(args.language_filter),
        fetch_issue_pages=not args.no_fetch_issue_pages,
        page_delay=args.page_delay,
    )

    print("[RICH-OSS-FUZZ] Done.")
    print(f"  Target projects       : {stats['target_projects']}")
    print(f"  Projects with records : {stats['projects_with_records']}")
    print(f"  Written records       : {stats['written_records']}")
    print(f"  Issue page attempts   : {stats['issue_page_fetch_attempted']}")
    print(f"  Issue reports found   : {stats['issue_page_report_found']}")
    print("  Mapping stats:")
    for key, value in sorted(stats["mapping_stats"].items()):
        print(f"    {key:<24} {value:>5}")


if __name__ == "__main__":
    main()
