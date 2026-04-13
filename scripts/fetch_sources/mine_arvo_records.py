#!/usr/bin/env python3
"""
Mine the ARVO dataset for OSS-Fuzz projects in the Vuljector shortlist.

ARVO (Automated Reproduction of Vulnerabilities through OSS-Fuzz) is a dataset
of ~6,000+ OSS-Fuzz bugs with pre-built Docker images (vul+fix pairs), verified
PoCs, and fix commit metadata. Each ARVO entry's issue_id equals the OSS-Fuzz
bug number, making it the join key to OSV and the issue tracker.

Downloads arvo.db (SQLite) and writes one JSON per matching entry under
runs/ossfuzz/arvo/<project>/<issue_id>.json.

Usage:
    python scripts/mine_arvo_records.py
    python scripts/mine_arvo_records.py --project libpng
    python scripts/mine_arvo_records.py --force   # re-download arvo.db
"""

from __future__ import annotations

import argparse
import json
import sqlite3
import sys
import urllib.request
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.resolve_project_metadata import ProjectResolver

# ─── Constants ───────────────────────────────────────────────────────────────

_ARVO_DB_URL = "https://github.com/n132/ARVO-Meta/releases/latest/download/arvo.db"

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "arvo"

# Priority-ordered candidate column names for each output field.
# The ARVO DB schema is undocumented — we try each name in order.
_ARVO_COLUMN_MAP: dict[str, list[str]] = {
    "issue_id":        ["localId", "issue_id", "id", "bug_id", "oss_fuzz_id", "number"],
    "fix_commit":      ["fix_commit", "commit_fix", "fixed_commit", "hash_fix", "fix"],
    "vul_commit":      ["commit_vul", "vul_commit", "vuln_commit", "hash_vul", "vul"],
    "docker_fix":      ["reproducer_fix", "docker_fix", "image_fix", "fix_image"],
    "docker_vul":      ["reproducer_vul", "docker_vul", "image_vul", "vul_image"],
    "poc":             ["reproducer_vul", "poc", "poc_path", "poc_file", "testcase"],
    "reproduced":      ["reproduced"],
    "verified":        ["verified"],
    "patch_located":   ["patch_located"],
    "patch_url":       ["patch_url"],
    "crash_type":      ["crash_type", "bug_type", "type", "crash", "error_type"],
    "project":         ["project", "component", "target", "fuzzing_engine_project"],
    "expected_output": ["crash_output", "expected_output", "expected_crash", "output"],
    "sanitizer":       ["sanitizer", "san", "memory_tool"],
    "fuzz_target":     ["fuzz_target", "fuzzer", "target_binary"],
    "fuzz_engine":     ["fuzz_engine", "fuzzing_engine", "engine"],
    "severity":        ["severity", "security_severity", "impact"],
    "report_url":      ["report", "report_url", "issue_url"],
    "repo_url":        ["repo_addr", "repo_url", "repo", "main_repo"],
    "language":        ["language", "lang"],
}

# ─── Download ────────────────────────────────────────────────────────────────

def download_arvo_db(cache_path: Path, force: bool = False) -> Path:
    """Download arvo.db from ARVO-Meta releases to cache_path if not cached."""
    if cache_path.exists() and not force:
        size_mb = cache_path.stat().st_size // (1024 * 1024)
        print(f"[ARVO] Using cached DB: {cache_path} ({size_mb} MB)")
        return cache_path

    cache_path.parent.mkdir(parents=True, exist_ok=True)
    print(f"[ARVO] Downloading from {_ARVO_DB_URL} ...")

    def _progress(count: int, block_size: int, total: int) -> None:
        if total > 0:
            pct = min(100, int(count * block_size * 100 / total))
            mb = count * block_size // (1024 * 1024)
            print(f"\r  {pct}% ({mb} MB)   ", end="", flush=True)

    tmp_path = cache_path.with_suffix(".tmp")
    try:
        urllib.request.urlretrieve(_ARVO_DB_URL, tmp_path, reporthook=_progress)
        print()
        tmp_path.rename(cache_path)
    except Exception as e:
        if tmp_path.exists():
            tmp_path.unlink()
        print(f"\n[ARVO] Download failed: {e}", file=sys.stderr)
        print(f"  You can manually download with:", file=sys.stderr)
        print(f"    wget {_ARVO_DB_URL} -O {cache_path}", file=sys.stderr)
        return cache_path  # caller checks existence

    size_mb = cache_path.stat().st_size // (1024 * 1024)
    print(f"[ARVO] Saved to {cache_path} ({size_mb} MB)")
    return cache_path


# ─── Schema introspection ────────────────────────────────────────────────────

def introspect_schema(db_path: Path) -> dict[str, list[str]]:
    """Return {table_name: [column_names]} for all tables in arvo.db.

    Logs the full schema to stderr on first call so the operator can verify
    the actual column names if the adaptive mapping needs tuning.
    """
    schema: dict[str, list[str]] = {}
    with sqlite3.connect(str(db_path)) as conn:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        ]
        for table in tables:
            cols = [
                row[1]
                for row in conn.execute(f"PRAGMA table_info({table})").fetchall()
            ]
            schema[table] = cols

    print("[ARVO] Database schema:", file=sys.stderr)
    for table, cols in schema.items():
        print(f"  {table}: {cols}", file=sys.stderr)

    return schema


def _resolve_column(available: list[str], candidates: list[str]) -> str | None:
    """Return the first candidate column name that exists in available."""
    avail_lower = {c.lower(): c for c in available}
    for candidate in candidates:
        if candidate.lower() in avail_lower:
            return avail_lower[candidate.lower()]
    return None


def build_column_mapping(columns: list[str]) -> dict[str, str | None]:
    """Map our field names to actual column names in the DB table."""
    return {
        field: _resolve_column(columns, candidates)
        for field, candidates in _ARVO_COLUMN_MAP.items()
    }


def _find_main_table(
    schema: dict[str, list[str]],
) -> tuple[str | None, dict[str, str | None]]:
    """Find the primary vulnerability table and its column mapping."""
    # Prefer tables that have an issue_id-like column and a project-like column
    for table, cols in schema.items():
        col_map = build_column_mapping(cols)
        if col_map.get("issue_id") and col_map.get("project"):
            return table, col_map
    # Fallback: first table with an issue_id
    for table, cols in schema.items():
        col_map = build_column_mapping(cols)
        if col_map.get("issue_id"):
            return table, col_map
    return None, {}


# ─── Record extraction ────────────────────────────────────────────────────────

def _extract_image_from_docker_cmd(docker_cmd: str | None) -> str | None:
    """Extract image name from a 'docker run --rm -it n132/arvo:ID-vul arvo' command."""
    if not docker_cmd:
        return None
    # Find the n132/arvo:... token
    import re as _re
    m = _re.search(r"(n132/arvo:\S+)", docker_cmd)
    return m.group(1) if m else docker_cmd.strip()


def normalize_arvo_record(row: dict, project: str, col_map: dict[str, str | None]) -> dict:
    """Map raw ARVO DB row to our intermediate schema."""

    def _get(field: str) -> str | None:
        col = col_map.get(field)
        if col is None:
            return None
        val = row.get(col)
        return str(val) if val is not None else None

    issue_id = _get("issue_id")
    fix_commit = _get("fix_commit")

    # Docker fields are stored as full "docker run ..." commands — extract image name
    docker_vul_raw = _get("docker_vul")
    docker_fix_raw = _get("docker_fix")
    docker_vul = _extract_image_from_docker_cmd(docker_vul_raw) or (f"n132/arvo:{issue_id}-vul" if issue_id else None)
    docker_fix = _extract_image_from_docker_cmd(docker_fix_raw) or (f"n132/arvo:{issue_id}-fix" if issue_id else None)

    # Canonical base image (without -vul/-fix suffix)
    arvo_image: str | None = None
    if issue_id:
        arvo_image = f"n132/arvo:{issue_id}"
    elif docker_vul:
        import re as _re
        arvo_image = _re.sub(r"-(vul|fix)$", "", docker_vul)

    return {
        "issue_id": issue_id,
        "project": project,
        "fix_commits": [fix_commit] if fix_commit else [],
        "vul_commit": _get("vul_commit"),
        "arvo_image": arvo_image,
        "docker_vul": docker_vul,
        "docker_fix": docker_fix,
        "has_poc": True,  # ARVO only indexes bugs with verified PoCs
        "reproduced": _get("reproduced"),
        "verified": _get("verified"),
        "patch_located": _get("patch_located"),
        "patch_url": _get("patch_url"),
        "crash_type": _get("crash_type"),
        "sanitizer": _get("sanitizer"),
        "security_severity": _get("severity"),
        "fuzz_target": _get("fuzz_target"),
        "fuzz_engine": _get("fuzz_engine"),
        "repo_url": _get("repo_url"),
        "language": _get("language"),
        "report_url": _get("report_url"),
        "expected_crash_output": _get("expected_output"),
        "source": "arvo",
    }


def iter_arvo_entries(
    db_path: Path,
    schema: dict[str, list[str]],
    resolver: ProjectResolver,
    project_filter: str | None = None,
) -> list[tuple[dict, str]]:
    """Yield (normalized_record, vuljector_project_name) for matching entries."""
    main_table, col_map = _find_main_table(schema)
    if main_table is None:
        print("[ARVO] No suitable table found in DB.", file=sys.stderr)
        return []

    proj_col = col_map.get("project")
    repo_col = col_map.get("repo_url")
    results: list[tuple[dict, str]] = []

    with sqlite3.connect(str(db_path)) as conn:
        conn.row_factory = sqlite3.Row
        all_rows = conn.execute(f"SELECT * FROM {main_table}").fetchall()

    for row in all_rows:
        row_dict = dict(row)
        arvo_proj = row_dict.get(proj_col) if proj_col else None
        repo_url = row_dict.get(repo_col) if repo_col else None
        vuljector_proj = resolver.resolve(
            str(arvo_proj) if arvo_proj is not None else None,
            str(repo_url) if repo_url is not None else None,
        )

        if vuljector_proj is None:
            continue
        if project_filter and vuljector_proj != project_filter:
            continue

        record = normalize_arvo_record(row_dict, vuljector_proj, col_map)
        results.append((record, vuljector_proj))

    return results


# ─── Output ───────────────────────────────────────────────────────────────────

def write_arvo_record(record: dict, out_dir: Path) -> Path:
    """Write to out_dir/<project>/<issue_id>.json."""
    issue_id = record.get("issue_id") or "unknown"
    project = record["project"]
    out_path = out_dir / project / f"{issue_id}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))
    return out_path


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def mine_arvo(
    projects_dir: Path,
    out_dir: Path,
    force: bool = False,
    project_filter: str | None = None,
) -> dict:
    """Download ARVO DB, filter to shortlist, write records. Returns stats."""
    print(f"[ARVO] Loading project names from {projects_dir} ...")
    resolver = ProjectResolver.from_projects_dir(projects_dir)
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
    print(f"[ARVO] Shortlist: {len(project_names)} project(s)")

    db_path = out_dir / "arvo.db"
    db_path = download_arvo_db(db_path, force=force)

    if not db_path.exists():
        print("[ARVO] arvo.db not available; skipping.", file=sys.stderr)
        return {"total": 0, "matched": 0, "written": 0, "skipped": 0, "arvo_available": False}

    schema = introspect_schema(db_path)

    print("[ARVO] Extracting matching records ...")
    entries = iter_arvo_entries(db_path, schema, resolver, project_filter)

    stats: dict[str, int] = {"total": len(entries), "written": 0, "skipped": 0}
    per_project: dict[str, int] = {}

    for record, project in entries:
        issue_id = record.get("issue_id") or "unknown"
        out_path = out_dir / project / f"{issue_id}.json"

        if out_path.exists() and not force:
            stats["skipped"] += 1
        else:
            write_arvo_record(record, out_dir)
            stats["written"] += 1

        per_project[project] = per_project.get(project, 0) + 1

    print(f"\n[ARVO] Done.")
    print(f"  Entries matched  : {stats['total']}")
    print(f"  Written          : {stats['written']}")
    print(f"  Skipped (cached) : {stats['skipped']}")
    if per_project:
        print(f"\n  Projects with data ({len(per_project)}):")
        for proj in sorted(per_project):
            print(f"    {proj:<40} {per_project[proj]:>4} entries")

    return stats


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine the ARVO dataset for OSS-Fuzz projects in the Vuljector shortlist."
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
        help="Re-download arvo.db even if cached",
    )
    parser.add_argument(
        "--project",
        help="Process only this project name (for debugging)",
    )
    args = parser.parse_args()

    mine_arvo(
        projects_dir=Path(args.projects_dir).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        force=args.force,
        project_filter=args.project,
    )


if __name__ == "__main__":
    main()
