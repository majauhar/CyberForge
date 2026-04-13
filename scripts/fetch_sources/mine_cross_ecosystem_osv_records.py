#!/usr/bin/env python3
"""
Mine the full OSV database across ecosystems and map records back to shortlisted
Vuljector projects using repo URLs first and package aliases second.

This complements `mine_oss_fuzz_osv_records.py`, which is intentionally restricted to the
`OSS-Fuzz` ecosystem. The goal here is coverage: many Python and JavaScript
projects have OSV records in ecosystems like `PyPI` or `npm`, even when they
have zero OSS-Fuzz-specific OSV records.

Writes one normalized JSON file per vulnerability under:
  runs/ossfuzz/osv_cross_ecosystem/<project>/<vuln_id>.json
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path
from typing import Iterator

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.resolve_project_metadata import (
    ProjectInfo,
    ProjectResolver,
    normalize_project_key,
    normalize_repo_url,
)


_OSV_ALL_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_CSV = _VULJECTOR_ROOT / "scripts" / "oss_fuzz_full.csv"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv_cross_ecosystem"

_ALIAS_ECOSYSTEMS_BY_LANGUAGE: dict[str, set[str]] = {
    "python": {"PyPI", "Python", "GitHub"},
    "javascript": {"npm", "GitHub"},
    "c": {"GitHub", "GIT"},
    "c++": {"GitHub", "GIT"},
}


def download_osv_bulk(cache_path: Path, force: bool = False) -> Path:
    if cache_path.exists() and not force:
        size_mb = cache_path.stat().st_size // (1024 * 1024)
        print(f"[OSV-X] Using cached full DB ZIP: {cache_path} ({size_mb} MB)")
        return cache_path

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[OSV-X] Downloading from {_OSV_ALL_URL} ...")

    def _progress(count: int, block_size: int, total: int) -> None:
        if total > 0:
            pct = min(100, int(count * block_size * 100 / total))
            mb = count * block_size // (1024 * 1024)
            print(f"\r  {pct}% ({mb} MB)   ", end="", flush=True)

    tmp_path = cache_path.with_suffix(".tmp")
    try:
        urllib.request.urlretrieve(_OSV_ALL_URL, tmp_path, reporthook=_progress)
        print()
        tmp_path.rename(cache_path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        print(f"\n[OSV-X] Download failed: {e}", file=sys.stderr)
        sys.exit(1)

    return cache_path


def iter_osv_entries(zip_path: Path) -> Iterator[dict]:
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                yield json.loads(zf.read(name))
            except Exception:
                continue


def extract_fix_commits(affected: list[dict]) -> list[str]:
    commits: list[str] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed != "0":
                    commits.append(fixed)
    return list(dict.fromkeys(commits))


def extract_introducing_commits(affected: list[dict]) -> list[str]:
    commits: list[str] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for event in rng.get("events", []):
                introduced = event.get("introduced")
                if introduced and introduced != "0":
                    commits.append(introduced)
    return list(dict.fromkeys(commits))


def extract_repo_url(affected_entry: dict) -> str | None:
    for rng in affected_entry.get("ranges", []):
        if rng.get("type") == "GIT":
            repo = rng.get("repo")
            if repo:
                return repo
    return None


def extract_severity_cvss(entry: dict) -> str | None:
    for sev in entry.get("severity", []):
        score = sev.get("score")
        if score:
            return score
    return None


def build_alias_index(resolver: ProjectResolver) -> dict[tuple[str, str], str]:
    alias_to_projects: dict[tuple[str, str], set[str]] = defaultdict(set)
    for info in resolver.iter_projects():
        language = (info.language or "").lower()
        ecosystems = _ALIAS_ECOSYSTEMS_BY_LANGUAGE.get(language, set())
        for ecosystem in ecosystems:
            for alias in info.package_aliases:
                alias_to_projects[(ecosystem, alias.lower())].add(info.name)
                normalized = normalize_project_key(alias)
                if normalized:
                    alias_to_projects[(ecosystem, normalized)].add(info.name)

    resolved: dict[tuple[str, str], str] = {}
    for key, projects in alias_to_projects.items():
        if len(projects) == 1:
            resolved[key] = next(iter(projects))
    return resolved


def resolve_project_for_affected(
    affected_entry: dict,
    resolver: ProjectResolver,
    alias_index: dict[tuple[str, str], str],
) -> str | None:
    pkg = affected_entry.get("package", {})
    raw_name = pkg.get("name")
    ecosystem = pkg.get("ecosystem")
    repo_url = extract_repo_url(affected_entry)

    project = resolver.resolve(raw_name, repo_url)
    if project:
        return project

    if not raw_name or not ecosystem:
        return None

    lower_name = str(raw_name).lower()
    normalized_name = normalize_project_key(raw_name)
    for key in ((ecosystem, lower_name), (ecosystem, normalized_name or "")):
        if key in alias_index:
            return alias_index[key]

    return None


def normalize_record(entry: dict, affected_entry: dict, project: str) -> dict:
    pkg = affected_entry.get("package", {})
    affected = entry.get("affected", [])
    return {
        "vuln_id": entry.get("id"),
        "project": project,
        "package_name": pkg.get("name"),
        "package_ecosystem": pkg.get("ecosystem"),
        "summary": (entry.get("summary") or entry.get("details", ""))[:300],
        "aliases": list(dict.fromkeys(entry.get("aliases", []) + entry.get("related", []))),
        "fix_commits": extract_fix_commits(affected),
        "introducing_commits": extract_introducing_commits(affected),
        "repo_url": extract_repo_url(affected_entry),
        "severity_cvss": extract_severity_cvss(entry),
        "published": entry.get("published"),
        "modified": entry.get("modified"),
        "source": f"osv:{pkg.get('ecosystem')}",
    }


def write_record(record: dict, out_dir: Path) -> None:
    out_path = out_dir / record["project"] / f"{record['vuln_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))


def mine_osv_cross_ecosystem(
    projects_dir: Path | None,
    csv_path: Path | None,
    out_dir: Path,
    force: bool = False,
    project_filter: str | None = None,
) -> dict:
    if csv_path and csv_path.exists():
        resolver = ProjectResolver.from_csv_path(csv_path)
    elif projects_dir and projects_dir.exists():
        resolver = ProjectResolver.from_projects_dir(projects_dir)
    else:
        raise FileNotFoundError("Need either --csv or --projects-dir")
    project_names = resolver.project_names()
    if project_filter:
        project_names = project_names & {project_filter}
        resolver = ProjectResolver(
            {
                name: resolver.get_project(name)
                for name in project_names
                if resolver.get_project(name) is not None
            }
        )

    alias_index = build_alias_index(resolver)
    zip_path = out_dir / "all.zip"
    download_osv_bulk(zip_path, force=force)

    stats = {
        "total": 0,
        "matched": 0,
        "written": 0,
        "skipped": 0,
        "per_ecosystem": {},
        "per_project": {},
    }

    for entry in iter_osv_entries(zip_path):
        stats["total"] += 1
        for affected_entry in entry.get("affected", []):
            project = resolve_project_for_affected(affected_entry, resolver, alias_index)
            if not project or project not in project_names:
                continue

            record = normalize_record(entry, affected_entry, project)
            ecosystem = record["package_ecosystem"] or "unknown"
            stats["matched"] += 1
            stats["per_ecosystem"][ecosystem] = stats["per_ecosystem"].get(ecosystem, 0) + 1
            stats["per_project"][project] = stats["per_project"].get(project, 0) + 1

            out_path = out_dir / project / f"{record['vuln_id']}.json"
            if out_path.exists() and not force:
                stats["skipped"] += 1
            else:
                write_record(record, out_dir)
                stats["written"] += 1

            break

    print("[OSV-X] Done.")
    print(f"  Total entries scanned : {stats['total']}")
    print(f"  Matched to shortlist  : {stats['matched']}")
    print(f"  Written               : {stats['written']}")
    print(f"  Skipped (cached)      : {stats['skipped']}")
    print("  Ecosystem breakdown:")
    for ecosystem, count in sorted(stats["per_ecosystem"].items(), key=lambda x: (-x[1], x[0]))[:20]:
        print(f"    {ecosystem:<20} {count:>5}")

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine the full OSV DB across ecosystems for shortlisted projects."
    )
    parser.add_argument(
        "--projects-dir",
        default=str(_DEFAULT_PROJECTS_DIR),
        help=f"Path to vuljector-projects/ root (default: {_DEFAULT_PROJECTS_DIR})",
    )
    parser.add_argument(
        "--csv",
        help=f"Optional CSV project universe (example: {_DEFAULT_CSV})",
    )
    parser.add_argument(
        "--out-dir",
        default=str(_DEFAULT_OUT_DIR),
        help=f"Output directory (default: {_DEFAULT_OUT_DIR})",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download and re-process even if cached",
    )
    parser.add_argument(
        "--project",
        help="Process only this project name",
    )
    args = parser.parse_args()

    mine_osv_cross_ecosystem(
        projects_dir=Path(args.projects_dir).expanduser().resolve() if args.projects_dir else None,
        csv_path=Path(args.csv).expanduser().resolve() if args.csv else None,
        out_dir=Path(args.out_dir).expanduser().resolve(),
        force=args.force,
        project_filter=args.project,
    )


if __name__ == "__main__":
    main()
