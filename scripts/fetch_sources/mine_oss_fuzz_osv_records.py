#!/usr/bin/env python3
"""
Mine OSV (Open Source Vulnerabilities) bulk data for OSS-Fuzz projects.

Downloads the OSS-Fuzz OSV bulk archive and filters entries to only those
projects shortlisted in vuljector-projects/. Writes one normalized JSON
file per vulnerability under runs/ossfuzz/osv/<project>/<vuln_id>.json.

Usage:
    python scripts/mine_oss_fuzz_osv_records.py
    python scripts/mine_oss_fuzz_osv_records.py --project flask
    python scripts/mine_oss_fuzz_osv_records.py --force   # re-download and re-process
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Iterator

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.resolve_project_metadata import ProjectResolver

# ─── Constants ───────────────────────────────────────────────────────────────

_OSV_BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/OSS-Fuzz/all.zip"

_ISSUE_ID_RE = re.compile(
    r"(?:bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=|"
    r"issues\.oss-fuzz\.com/issues/)(\d+)"
)

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv"


# ─── Download ────────────────────────────────────────────────────────────────

def download_osv_bulk(cache_path: Path, force: bool = False) -> Path:
    """Download the OSS-Fuzz OSV bulk ZIP to cache_path if not already cached."""
    if cache_path.exists() and not force:
        size_mb = cache_path.stat().st_size // (1024 * 1024)
        print(f"[OSV] Using cached bulk ZIP: {cache_path} ({size_mb} MB)")
        return cache_path

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[OSV] Downloading from {_OSV_BULK_URL} ...")

    def _progress(count: int, block_size: int, total: int) -> None:
        if total > 0:
            pct = min(100, int(count * block_size * 100 / total))
            mb = count * block_size // (1024 * 1024)
            print(f"\r  {pct}% ({mb} MB)   ", end="", flush=True)

    tmp_path = cache_path.with_suffix(".tmp")
    try:
        urllib.request.urlretrieve(_OSV_BULK_URL, tmp_path, reporthook=_progress)
        print()  # newline after progress bar
        tmp_path.rename(cache_path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        print(f"\n[OSV] Download failed: {e}", file=sys.stderr)
        print(f"  You can manually download with:", file=sys.stderr)
        print(f"    wget {_OSV_BULK_URL} -O {cache_path}", file=sys.stderr)
        sys.exit(1)

    size_mb = cache_path.stat().st_size // (1024 * 1024)
    print(f"[OSV] Saved to {cache_path} ({size_mb} MB)")
    return cache_path


# ─── Parsing ─────────────────────────────────────────────────────────────────

def iter_osv_entries(zip_path: Path) -> Iterator[dict]:
    """Stream OSV JSON entries from the bulk ZIP without full extraction to disk."""
    with zipfile.ZipFile(zip_path, "r") as zf:
        for name in zf.namelist():
            if not name.endswith(".json"):
                continue
            try:
                data = json.loads(zf.read(name))
                yield data
            except Exception as e:
                print(f"  [warn] Failed to parse {name}: {e}", file=sys.stderr)


def extract_issue_id(references: list[dict]) -> str | None:
    """Return numeric OSS-Fuzz issue ID from the REPORT-type reference URL.

    Handles both URL patterns:
      - https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=NNNNN  (old Monorail)
      - https://issues.oss-fuzz.com/issues/NNNNN  (new Buganizer)
    """
    for ref in references:
        url = ref.get("url", "")
        m = _ISSUE_ID_RE.search(url)
        if m:
            return m.group(1)
    return None


def extract_fix_commits(affected: list[dict]) -> list[str]:
    """Extract all 'fixed' git commit hashes from affected[].ranges[type=GIT].events."""
    commits: list[str] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and fixed != "0":
                    commits.append(fixed)
    return list(dict.fromkeys(commits))  # deduplicate, preserve order


def extract_introducing_commits(affected: list[dict]) -> list[str]:
    """Extract all 'introduced' git commit hashes from affected[].ranges[type=GIT].events."""
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


def extract_repo_url(affected: list[dict]) -> str | None:
    """Extract the upstream git repo URL from affected[].ranges[type=GIT].repo."""
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") == "GIT":
                repo = rng.get("repo")
                if repo:
                    return repo
    return None


def extract_severity_cvss(entry: dict) -> str | None:
    """Extract CVSS vector string from the severity field."""
    for sev in entry.get("severity", []):
        score = sev.get("score")
        if score:
            return score
    return None


def parse_osv_entry(entry: dict, resolver: ProjectResolver) -> dict | None:
    """Normalize one raw OSV entry to the intermediate schema.

    Returns None if the entry has no OSS-Fuzz ecosystem package in our shortlist.
    """
    vuln_id = entry.get("id", "")
    affected = entry.get("affected", [])
    references = entry.get("references", [])
    repo_url = extract_repo_url(affected)

    # Find the OSS-Fuzz ecosystem package that matches our shortlist
    project_name: str | None = None
    for pkg_entry in affected:
        pkg = pkg_entry.get("package", {})
        if pkg.get("ecosystem") == "OSS-Fuzz":
            name = pkg.get("name", "")
            resolved = resolver.resolve(name, repo_url)
            if resolved:
                project_name = resolved
                break

    if project_name is None:
        return None

    aliases = list(dict.fromkeys(entry.get("aliases", []) + entry.get("related", [])))

    return {
        "vuln_id": vuln_id,
        "project": project_name,
        "issue_id": extract_issue_id(references),
        "summary": (entry.get("summary") or entry.get("details", ""))[:300],
        "fix_commits": extract_fix_commits(affected),
        "introducing_commits": extract_introducing_commits(affected),
        "repo_url": repo_url,
        "aliases": aliases,
        "severity_cvss": extract_severity_cvss(entry),
        "source": "osv",
    }


# ─── Output ───────────────────────────────────────────────────────────────────

def write_osv_record(record: dict, out_dir: Path) -> Path:
    """Write record to out_dir/<project>/<vuln_id>.json. Creates directories."""
    out_path = out_dir / record["project"] / f"{record['vuln_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))
    return out_path


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def mine_osv(
    projects_dir: Path,
    out_dir: Path,
    force: bool = False,
    project_filter: str | None = None,
) -> dict:
    """Download OSV bulk, filter to shortlist, write records. Returns stats."""
    print(f"[OSV] Loading project names from {projects_dir} ...")
    resolver = ProjectResolver.from_projects_dir(projects_dir)
    project_names = resolver.project_names()

    if project_filter:
        if project_filter not in project_names:
            print(f"[OSV] WARNING: --project {project_filter!r} not in shortlist.", file=sys.stderr)
        project_names = project_names & {project_filter}
        resolver = ProjectResolver(
            {
                name: resolver.get_project(name)
                for name in project_names
                if resolver.get_project(name) is not None
            }
        )

    print(f"[OSV] Shortlist: {len(project_names)} project(s)")

    zip_path = out_dir / "all.zip"
    download_osv_bulk(zip_path, force=force)

    stats: dict[str, int] = {"total": 0, "matched": 0, "written": 0, "skipped": 0}
    per_project: dict[str, int] = {}

    print("[OSV] Scanning bulk ZIP ...")
    for entry in iter_osv_entries(zip_path):
        stats["total"] += 1
        record = parse_osv_entry(entry, resolver)
        if record is None:
            continue
        stats["matched"] += 1

        project = record["project"]
        vuln_id = record["vuln_id"]
        out_path = out_dir / project / f"{vuln_id}.json"

        if out_path.exists() and not force:
            stats["skipped"] += 1
        else:
            write_osv_record(record, out_dir)
            stats["written"] += 1

        per_project[project] = per_project.get(project, 0) + 1

    print(f"\n[OSV] Done.")
    print(f"  Total entries scanned : {stats['total']}")
    print(f"  Matched to shortlist  : {stats['matched']}")
    print(f"  Written               : {stats['written']}")
    print(f"  Skipped (cached)      : {stats['skipped']}")
    if per_project:
        print(f"\n  Projects with data ({len(per_project)}):")
        for proj in sorted(per_project):
            print(f"    {proj:<40} {per_project[proj]:>4} vulns")

    return stats


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine OSV bulk data for OSS-Fuzz projects in the Vuljector shortlist."
    )
    parser.add_argument(
        "--projects-dir",
        default=str(_DEFAULT_PROJECTS_DIR),
        help=f"Path to vuljector-projects/ root (default: {_DEFAULT_PROJECTS_DIR})",
    )
    parser.add_argument(
        "--out-dir",
        default=str(_DEFAULT_OUT_DIR),
        help=f"Output directory (default: {_DEFAULT_OUT_DIR})",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-download and re-process even if cached",
    )
    parser.add_argument(
        "--project",
        help="Process only this project name (for debugging)",
    )
    args = parser.parse_args()

    mine_osv(
        projects_dir=Path(args.projects_dir).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        force=args.force,
        project_filter=args.project,
    )


if __name__ == "__main__":
    main()
