#!/usr/bin/env python3
"""
Mine the OSS-Fuzz Issue Tracker (issues.oss-fuzz.com) for crash metadata.

All public bugs (disclosed after 90 days) are accessible without a Google
account. The ClusterFuzz crash report text is embedded verbatim in the HTML
response (inside the `defrostedResourcesJspb` JavaScript variable), so no
JS rendering is required — plain urllib.request works.

For each OSV entry with a known issue_id, fetches the issue page and extracts:
  crash_type, crash_address, crash_state, sanitizer, security_severity,
  fuzz_target, fuzz_engine, job_type, testcase_id, regression_range

Writes one JSON per issue to runs/ossfuzz/issue_tracker/<project>/<issue_id>.json.

Usage:
    python scripts/mine_oss_fuzz_issue_tracker_records.py
    python scripts/mine_oss_fuzz_issue_tracker_records.py --project flask
    python scripts/mine_oss_fuzz_issue_tracker_records.py --rate-limit-delay 2.0
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.parse_clusterfuzz_report import parse_clusterfuzz_report

# ─── Constants ───────────────────────────────────────────────────────────────

_ISSUE_URL = "https://issues.oss-fuzz.com/issues/{issue_id}"
_USER_AGENT = "Vuljector/1.0 (OSS-Fuzz vulnerability mining; research use)"

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_OSV_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv"
_DEFAULT_ARVO_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "arvo"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "issue_tracker"

def load_project_names(projects_dir: Path) -> set[str]:
    names: set[str] = set()
    for proj_json in projects_dir.glob("*/project.json"):
        try:
            data = json.loads(proj_json.read_text())
        except Exception:
            continue
        name = data.get("project")
        if name:
            names.add(name)
    return names


# ─── HTML fetching and extraction ─────────────────────────────────────────────

def fetch_issue_page(issue_id: str, delay: float) -> str | None:
    """Fetch the issue page HTML from issues.oss-fuzz.com.

    Sleeps `delay` seconds before the request (rate limiting).
    Returns the HTML string or None on failure.
    """
    url = _ISSUE_URL.format(issue_id=issue_id)
    time.sleep(delay)
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        if e.code == 429:
            retry_after = int(e.headers.get("Retry-After", "60"))
            print(f"\n  [ARVO] HTTP 429 — sleeping {retry_after}s before retry ...", file=sys.stderr)
            time.sleep(retry_after)
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return resp.read().decode("utf-8", errors="replace")
            except Exception:
                return None
        elif e.code in (403, 401):
            return None  # private issue
        print(f"  [warn] HTTP {e.code} for issue {issue_id}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [warn] Failed to fetch issue {issue_id}: {e}", file=sys.stderr)
        return None


def _unescape_js(text: str) -> str:
    """Unescape JSON/JS string escapes so line-based regexes work correctly."""
    import codecs
    # Handle \\uXXXX unicode escapes (e.g. \\u003d → =, \\u0026 → &)
    text = re.sub(
        r"\\u([0-9a-fA-F]{4})",
        lambda m: chr(int(m.group(1), 16)),
        text,
    )
    return (
        text
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace('\\"', '"')
        .replace("\\/", "/")
        .replace("\\\\", "\\")
    )


def extract_report_text(html: str) -> str | None:
    """Extract the ClusterFuzz crash report from the issue page HTML.

    The report text is embedded inside the `defrostedResourcesJspb` JS blob
    as a JSON-escaped string. 'Detailed Report:' appears literally in the HTML
    (not re-escaped), but newlines are \\n and special chars are \\uXXXX.
    """
    idx = html.find("Detailed Report:")
    if idx == -1:
        return None

    # Take a generous window (reports can be long with stack traces)
    chunk = html[idx : idx + 6000]
    chunk = _unescape_js(chunk)

    # Verify we have actual ClusterFuzz content
    if "Crash Type:" in chunk or "Sanitizer:" in chunk:
        return chunk

    return None


def is_private_issue(html: str) -> bool:
    """Return True if the page content indicates a non-public (private) issue.

    Private issues return a minimal defrostedResourcesJspb = [null,true] blob
    (no issue data), or redirect to a login page.
    """
    # Minimal blob = private/inaccessible issue
    if "defrostedResourcesJspb = [null,true]" in html:
        return True
    private_signals = [
        "accounts.google.com/signin",
        "You don't have access",
        "Sign in to continue",
        "403 Forbidden",
        "Access denied",
    ]
    return any(signal in html for signal in private_signals)


# ─── Issue ID loading ─────────────────────────────────────────────────────────

def load_issue_ids(osv_dir: Path, project: str) -> list[str]:
    """Read all OSV records for a project and return non-null issue_ids."""
    proj_dir = osv_dir / project
    if not proj_dir.is_dir():
        return []
    ids: list[str] = []
    for json_file in sorted(proj_dir.glob("*.json")):
        try:
            record = json.loads(json_file.read_text())
            issue_id = record.get("issue_id")
            if issue_id:
                ids.append(str(issue_id))
        except Exception:
            pass
    return ids


def load_arvo_issue_ids(
    arvo_dir: Path,
    valid_projects: set[str] | None = None,
    project_filter: str | None = None,
) -> dict[str, list[str]]:
    """Return {project: [issue_id, ...]} from ARVO output (localId = OSS-Fuzz issue number)."""
    result: dict[str, list[str]] = {}
    if not arvo_dir.is_dir():
        return result
    for proj_dir in sorted(arvo_dir.iterdir()):
        if not proj_dir.is_dir():
            continue
        project = proj_dir.name
        if valid_projects is not None and project not in valid_projects:
            continue
        if project_filter and project != project_filter:
            continue
        ids: list[str] = []
        for json_file in sorted(proj_dir.glob("*.json")):
            try:
                record = json.loads(json_file.read_text())
                issue_id = record.get("issue_id")
                if issue_id:
                    ids.append(str(issue_id))
            except Exception:
                pass
        if ids:
            result[project] = ids
    return result


def load_all_issue_ids(
    osv_dir: Path,
    arvo_dir: Path | None = None,
    valid_projects: set[str] | None = None,
    project_filter: str | None = None,
) -> dict[str, list[str]]:
    """Return {project: [issue_id, ...]} merging OSV and ARVO sources (deduplicated)."""
    result: dict[str, list[str]] = {}

    # Load from OSV
    if osv_dir.is_dir():
        for proj_dir in sorted(osv_dir.iterdir()):
            if not proj_dir.is_dir():
                continue
            project = proj_dir.name
            if valid_projects is not None and project not in valid_projects:
                continue
            if project_filter and project != project_filter:
                continue
            ids = load_issue_ids(osv_dir, project)
            if ids:
                result.setdefault(project, [])
                result[project].extend(ids)

    # Merge ARVO issue IDs (many crash bugs not in OSV)
    if arvo_dir and arvo_dir.is_dir():
        arvo_ids = load_arvo_issue_ids(arvo_dir, valid_projects, project_filter)
        for project, ids in arvo_ids.items():
            result.setdefault(project, [])
            result[project].extend(ids)

    # Deduplicate while preserving order
    for project in result:
        seen: set[str] = set()
        deduped: list[str] = []
        for iid in result[project]:
            if iid not in seen:
                seen.add(iid)
                deduped.append(iid)
        result[project] = deduped

    return result


# ─── Output ───────────────────────────────────────────────────────────────────

def write_issue_record(record: dict, out_dir: Path) -> Path:
    """Write to out_dir/<project>/<issue_id>.json."""
    out_path = out_dir / record["project"] / f"{record['issue_id']}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))
    return out_path


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def mine_issue_tracker(
    projects_dir: Path,
    osv_dir: Path,
    out_dir: Path,
    arvo_dir: Path | None = None,
    delay: float = 1.0,
    project_filter: str | None = None,
    force: bool = False,
) -> dict:
    """Fetch issue pages for all issue_ids from OSV + ARVO, parse crash metadata."""
    print(f"[IT] Loading issue IDs from OSV at {osv_dir} ...")
    if arvo_dir and arvo_dir.is_dir():
        print(f"[IT] Also loading issue IDs from ARVO at {arvo_dir} ...")
    valid_projects = load_project_names(projects_dir)
    project_issue_ids = load_all_issue_ids(
        osv_dir,
        arvo_dir,
        valid_projects=valid_projects,
        project_filter=project_filter,
    )

    total_issues = sum(len(ids) for ids in project_issue_ids.values())
    print(f"[IT] Found {total_issues} issue IDs across {len(project_issue_ids)} projects")

    if delay > 0:
        est_min = total_issues * delay / 60
        print(f"[IT] Estimated time at {delay}s/req: {est_min:.1f} min")

    stats: dict[str, int] = {
        "total": total_issues,
        "fetched": 0,
        "parsed": 0,
        "private": 0,
        "no_report": 0,
        "skipped": 0,
        "errors": 0,
    }

    count = 0
    for project, issue_ids in sorted(project_issue_ids.items()):
        for issue_id in issue_ids:
            count += 1
            out_path = out_dir / project / f"{issue_id}.json"

            if out_path.exists() and not force:
                stats["skipped"] += 1
                continue

            print(
                f"\r[IT] [{count}/{total_issues}] {project}/{issue_id}  "
                f"(parsed={stats['parsed']}, private={stats['private']})   ",
                end="",
                flush=True,
            )

            html = fetch_issue_page(issue_id, delay)
            if html is None:
                stats["errors"] += 1
                continue

            stats["fetched"] += 1

            if is_private_issue(html):
                stats["private"] += 1
                # Write a minimal record so we don't re-fetch
                write_issue_record(
                    {"issue_id": issue_id, "project": project,
                     "public": False, "source": "issue_tracker"},
                    out_dir,
                )
                continue

            report_text = extract_report_text(html)
            if report_text is None:
                stats["no_report"] += 1
                write_issue_record(
                    {"issue_id": issue_id, "project": project,
                     "public": True, "report_found": False, "source": "issue_tracker"},
                    out_dir,
                )
                continue

            fields = parse_clusterfuzz_report(report_text)
            stats["parsed"] += 1

            record = {
                "issue_id": issue_id,
                "project": project,
                "public": True,
                "report_found": True,
                **fields,
                "source": "issue_tracker",
            }
            write_issue_record(record, out_dir)

    print()  # newline after progress line

    print(f"\n[IT] Done.")
    print(f"  Total issue IDs   : {stats['total']}")
    print(f"  Skipped (cached)  : {stats['skipped']}")
    print(f"  Fetched           : {stats['fetched']}")
    print(f"  Parsed (report OK): {stats['parsed']}")
    print(f"  Private (skipped) : {stats['private']}")
    print(f"  No report found   : {stats['no_report']}")
    print(f"  Fetch errors      : {stats['errors']}")

    return stats


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine the OSS-Fuzz Issue Tracker for crash metadata (public issues only)."
    )
    parser.add_argument(
        "--projects-dir",
        default=str(_DEFAULT_PROJECTS_DIR),
        help="Path to vuljector-projects/ root (used for project name validation)",
    )
    parser.add_argument(
        "--osv-dir",
        default=str(_DEFAULT_OSV_DIR),
        help=f"OSV output directory to read issue IDs from (default: {_DEFAULT_OSV_DIR})",
    )
    parser.add_argument(
        "--arvo-dir",
        default=str(_DEFAULT_ARVO_DIR),
        help=f"ARVO output directory to also read issue IDs from (default: {_DEFAULT_ARVO_DIR})",
    )
    parser.add_argument(
        "--out-dir",
        default=str(_DEFAULT_OUT_DIR),
        help=f"Output directory (default: {_DEFAULT_OUT_DIR})",
    )
    parser.add_argument(
        "--rate-limit-delay",
        type=float,
        default=1.0,
        metavar="SECONDS",
        help="Seconds to sleep between HTTP requests (default: 1.0)",
    )
    parser.add_argument(
        "--project",
        help="Process only this project name (for debugging)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-fetch even if output file already exists",
    )
    args = parser.parse_args()

    mine_issue_tracker(
        projects_dir=Path(args.projects_dir).expanduser().resolve(),
        osv_dir=Path(args.osv_dir).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        arvo_dir=Path(args.arvo_dir).expanduser().resolve(),
        delay=args.rate_limit_delay,
        project_filter=args.project,
        force=args.force,
    )


if __name__ == "__main__":
    main()
