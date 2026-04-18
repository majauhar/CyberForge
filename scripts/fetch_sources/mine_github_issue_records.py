#!/usr/bin/env python3
"""
Mine upstream GitHub issues for OSS-Fuzz crash reports (mirrored projects).

Some OSS-Fuzz projects have `file_github_issue: true` in their project.yaml,
which causes ClusterFuzz to mirror crash reports directly to the project's
GitHub repository. These issues contain the same structured crash report as
the OSS-Fuzz Issue Tracker, plus developer discussion about root cause.

This script:
  1. Parses oss-fuzz/projects/<project>/project.yaml for each shortlisted project
  2. Identifies projects with `file_github_issue: true`
  3. Searches their GitHub issues for ClusterFuzz crash reports
  4. Parses the structured report text from issue bodies
  5. Writes one JSON per issue to runs/ossfuzz/github_issues/<project>/<issue_id>.json

Requires GITHUB_TOKEN env var for 5000 req/hr (falls back to 60 req/hr unauthed).

Usage:
    python scripts/mine_github_issue_records.py
    python scripts/mine_github_issue_records.py --project behaviortreecpp
    GITHUB_TOKEN=ghp_... python scripts/mine_github_issue_records.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import quote_plus
from pathlib import Path

try:
    import yaml  # pyyaml — already in uv.lock
    _YAML_AVAILABLE = True
except ImportError:
    _YAML_AVAILABLE = False

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from mining_helpers.parse_clusterfuzz_report import parse_clusterfuzz_report

# ─── Constants ───────────────────────────────────────────────────────────────

_GITHUB_API_BASE = "https://api.github.com"
_USER_AGENT = "Vuljector/1.0 (OSS-Fuzz vulnerability mining; research use)"

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_PROJECTS_DIR = _VULJECTOR_ROOT.parent / "vuljector-projects"
_DEFAULT_OSS_FUZZ_DIR = Path("/Users/manansuri/Projects/oss-fuzz")
_DEFAULT_OSV_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "osv"
_DEFAULT_OUT_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "github_issues"

# Extract OSS-Fuzz issue number from issue body backlinks
_OSS_FUZZ_ISSUE_RE = re.compile(
    r"(?:issues\.oss-fuzz\.com/issues/|bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=)(\d+)"
)


def extract_oss_fuzz_issue_id(body: str) -> str | None:
    """Extract the OSS-Fuzz issue number from a GitHub issue body."""
    m = _OSS_FUZZ_ISSUE_RE.search(body)
    return m.group(1) if m else None


# ─── OSS-Fuzz project.yaml parsing ───────────────────────────────────────────

def load_oss_fuzz_yaml(oss_fuzz_dir: Path, project: str) -> dict:
    """Load oss-fuzz/projects/<project>/project.yaml. Returns {} on any error."""
    yaml_path = oss_fuzz_dir / "projects" / project / "project.yaml"
    if not yaml_path.exists():
        return {}
    if not _YAML_AVAILABLE:
        # Fallback: grep for file_github_issue without pyyaml
        text = yaml_path.read_text(errors="replace")
        if re.search(r"file_github_issue\s*:\s*true", text, re.IGNORECASE):
            return {"file_github_issue": True}
        return {}
    try:
        import yaml
        return yaml.safe_load(yaml_path.read_text()) or {}
    except Exception:
        return {}


def extract_github_slug(main_repo_url: str) -> str | None:
    """Parse 'https://github.com/<owner>/<repo>[.git]' → 'owner/repo'."""
    m = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:\.git)?/?$", main_repo_url or "")
    return m.group(1) if m else None


def load_shortlist_project_repos(projects_dir: Path) -> dict[str, str | None]:
    result: dict[str, str | None] = {}
    for proj_json in projects_dir.glob("*/project.json"):
        try:
            data = json.loads(proj_json.read_text())
        except Exception:
            continue
        name = data.get("project")
        if name:
            result[name] = data.get("main_repo_url")
    return result


def get_github_mirrored_projects(
    oss_fuzz_dir: Path,
    projects_dir: Path,
    project_names: set[str],
) -> dict[str, str]:
    """Return {project: github_slug} for shortlisted projects with file_github_issue: true."""
    result: dict[str, str] = {}

    for project in sorted(project_names):
        cfg = load_oss_fuzz_yaml(oss_fuzz_dir, project)
        if not cfg.get("file_github_issue"):
            continue

        # Get the GitHub slug from the oss-fuzz project.yaml 'main_repo'
        slug = extract_github_slug(cfg.get("main_repo", ""))

        # Fallback: read main_repo_url from vuljector-projects project.json
        if not slug:
            proj_json = projects_dir / project / "project.json"
            if proj_json.exists():
                try:
                    vj_cfg = json.loads(proj_json.read_text())
                    slug = extract_github_slug(vj_cfg.get("main_repo_url", ""))
                except Exception:
                    pass

        if slug:
            result[project] = slug
        else:
            print(f"  [warn] {project}: file_github_issue=true but could not determine GitHub slug",
                  file=sys.stderr)

    return result


def get_github_search_targets(
    oss_fuzz_dir: Path,
    projects_dir: Path,
    shortlist_repos: dict[str, str | None],
    search_all_github_repos: bool,
) -> dict[str, dict]:
    project_names = set(shortlist_repos)
    mirrored = (
        get_github_mirrored_projects(oss_fuzz_dir, projects_dir, project_names)
        if oss_fuzz_dir.is_dir()
        else {}
    )

    targets: dict[str, dict] = {}
    if search_all_github_repos:
        for project, repo_url in shortlist_repos.items():
            slug = extract_github_slug(repo_url or "")
            if not slug:
                continue
            targets[project] = {
                "slug": slug,
                "mirrored": project in mirrored,
                "repo_url": repo_url,
            }
    else:
        for project, slug in mirrored.items():
            targets[project] = {
                "slug": slug,
                "mirrored": True,
                "repo_url": shortlist_repos.get(project),
            }

    return targets


# ─── GitHub API ───────────────────────────────────────────────────────────────

def make_github_request(
    url: str,
    token: str | None,
    delay: float,
) -> dict | list | None:
    """Rate-limited GitHub API GET request. Returns parsed JSON or None on error."""
    time.sleep(delay)
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": _USER_AGENT,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            remaining = resp.headers.get("X-RateLimit-Remaining", "?")
            if remaining != "?" and int(remaining) < 5:
                reset_at = int(resp.headers.get("X-RateLimit-Reset", 0))
                wait = max(0, reset_at - int(time.time())) + 2
                print(f"\n  [GH] Rate limit low ({remaining} remaining) — sleeping {wait}s",
                      file=sys.stderr)
                time.sleep(wait)
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 403:
            reset_at = int(e.headers.get("X-RateLimit-Reset", 0))
            wait = max(60, reset_at - int(time.time())) + 2
            print(f"\n  [GH] 403 rate limit hit — sleeping {wait}s", file=sys.stderr)
            time.sleep(wait)
            # Retry once
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    return json.loads(resp.read().decode("utf-8"))
            except Exception:
                return None
        print(f"  [warn] GitHub API HTTP {e.code} for {url}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"  [warn] GitHub API error for {url}: {e}", file=sys.stderr)
        return None


def search_github_issues(
    slug: str,
    raw_query: str,
    token: str | None,
    delay: float,
    max_pages: int = 10,
) -> list[dict]:
    """Search a project's GitHub issues for ClusterFuzz crash reports.

    Uses the query: repo:<slug> ClusterFuzz in:body
    Returns list of raw GitHub issue objects.
    """
    issues: list[dict] = []
    per_page = 30

    for page in range(1, max_pages + 1):
        encoded_query = quote_plus(f"repo:{slug} {raw_query}")
        url = (
            f"{_GITHUB_API_BASE}/search/issues"
            f"?q={encoded_query}&per_page={per_page}&page={page}"
        )
        data = make_github_request(url, token, delay)
        if not isinstance(data, dict):
            break

        items = data.get("items", [])
        issues.extend(items)

        if len(items) < per_page:
            break  # last page

    return issues


def fetch_issue_body(
    slug: str,
    issue_number: int,
    token: str | None,
    delay: float,
) -> str | None:
    """Fetch the full body text of a specific GitHub issue."""
    url = f"{_GITHUB_API_BASE}/repos/{slug}/issues/{issue_number}"
    data = make_github_request(url, token, delay)
    if isinstance(data, dict):
        return data.get("body")
    return None


# ─── Issue ID loading ─────────────────────────────────────────────────────────

def load_known_issue_ids(osv_dir: Path, project: str) -> set[str]:
    """Return issue IDs already known from OSV output for a project."""
    ids: set[str] = set()
    proj_dir = osv_dir / project
    if not proj_dir.is_dir():
        return ids
    for f in proj_dir.glob("*.json"):
        try:
            record = json.loads(f.read_text())
            iid = record.get("issue_id")
            if iid:
                ids.add(str(iid))
        except Exception:
            pass
    return ids


# ─── Output ───────────────────────────────────────────────────────────────────

def write_github_record(record: dict, out_dir: Path) -> Path:
    """Write to out_dir/<project>/<issue_id>.json."""
    issue_id = record.get("issue_id") or f"gh_{record.get('github_issue_number', 'unknown')}"
    out_path = out_dir / record["project"] / f"{issue_id}.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(record, indent=2))
    return out_path


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def mine_github_issues(
    projects_dir: Path,
    oss_fuzz_dir: Path,
    osv_dir: Path,
    out_dir: Path,
    delay: float = 1.0,
    project_filter: str | None = None,
    search_all_github_repos: bool = False,
    max_pages: int = 2,
) -> dict:
    """Search GitHub mirrored issues and write crash metadata records."""
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        print("[GH] Using GITHUB_TOKEN (5000 req/hr limit)")
    else:
        print("[GH] No GITHUB_TOKEN set — using unauthenticated (60 req/hr)", file=sys.stderr)
        print("     Set GITHUB_TOKEN env var for higher rate limits.", file=sys.stderr)

    shortlist_repos = load_shortlist_project_repos(projects_dir)
    project_names = set(shortlist_repos)
    if project_filter:
        project_names = project_names & {project_filter}
        shortlist_repos = {
            project: repo_url
            for project, repo_url in shortlist_repos.items()
            if project in project_names
        }

    if not oss_fuzz_dir.is_dir():
        print(f"[GH] WARNING: oss-fuzz dir not found at {oss_fuzz_dir}", file=sys.stderr)

    targets = get_github_search_targets(
        oss_fuzz_dir,
        projects_dir,
        shortlist_repos,
        search_all_github_repos=search_all_github_repos,
    )

    mode_label = "all shortlist GitHub repos" if search_all_github_repos else "file_github_issue=true only"
    print(f"[GH] Search mode: {mode_label}")
    print(f"[GH] Search targets: {len(targets)}")
    for proj, meta in sorted(targets.items()):
        mirrored_label = " mirrored" if meta["mirrored"] else ""
        print(f"  {proj} → {meta['slug']}{mirrored_label}")

    stats: dict[str, int] = {
        "projects_checked": len(targets),
        "issues_found": 0,
        "parsed": 0,
        "written": 0,
        "skipped": 0,
    }

    search_queries = ['"Detailed Report:" in:body']

    for project, meta in sorted(targets.items()):
        slug = meta["slug"]
        print(f"\n[GH] Searching {slug} for ClusterFuzz issues ...")
        known_ids = load_known_issue_ids(osv_dir, project)

        raw_issues_by_number: dict[int, dict] = {}
        for query in search_queries:
            raw_issues = search_github_issues(slug, query, token, delay, max_pages=max_pages)
            for raw in raw_issues:
                number = raw.get("number")
                if isinstance(number, int):
                    raw_issues_by_number[number] = raw

        raw_issues = list(raw_issues_by_number.values())
        print(f"  Found {len(raw_issues)} candidate issues")
        stats["issues_found"] += len(raw_issues)

        for raw in raw_issues:
            gh_number = raw.get("number")
            body = raw.get("body") or ""

            # If body is truncated in search results, fetch the full issue
            if len(body) < 200 and gh_number:
                body = fetch_issue_body(slug, gh_number, token, delay) or body

            if "Detailed Report:" not in body and "Crash Type:" not in body:
                continue  # not a crash report issue

            fields = parse_clusterfuzz_report(body)
            if not fields:
                continue

            stats["parsed"] += 1

            # Resolve the OSS-Fuzz issue_id from the body backlink
            issue_id = extract_oss_fuzz_issue_id(body)

            out_path_id = issue_id or f"gh_{gh_number}"
            out_path = out_dir / project / f"{out_path_id}.json"

            if out_path.exists():
                stats["skipped"] += 1
                continue

            record = {
                "issue_id": issue_id,
                "project": project,
                "repo_url": meta.get("repo_url"),
                "github_slug": slug,
                "github_issue_number": gh_number,
                "github_issue_url": raw.get("html_url"),
                **fields,
                "source": "github_issue",
            }
            write_github_record(record, out_dir)
            stats["written"] += 1

    print(f"\n[GH] Done.")
    print(f"  Projects with mirroring : {stats['projects_checked']}")
    print(f"  Issues found            : {stats['issues_found']}")
    print(f"  Crash reports parsed    : {stats['parsed']}")
    print(f"  Records written         : {stats['written']}")
    print(f"  Skipped (cached)        : {stats['skipped']}")

    return stats


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Mine upstream GitHub issues for OSS-Fuzz crash reports (mirrored projects)."
    )
    parser.add_argument(
        "--projects-dir",
        default=str(_DEFAULT_PROJECTS_DIR),
        help=f"Path to vuljector-projects/ root (default: {_DEFAULT_PROJECTS_DIR})",
    )
    parser.add_argument(
        "--oss-fuzz-dir",
        default=str(_DEFAULT_OSS_FUZZ_DIR),
        help=f"Path to local oss-fuzz clone (default: {_DEFAULT_OSS_FUZZ_DIR})",
    )
    parser.add_argument(
        "--osv-dir",
        default=str(_DEFAULT_OSV_DIR),
        help=f"OSV output dir for known issue IDs (default: {_DEFAULT_OSV_DIR})",
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
        help="Seconds to sleep between GitHub API calls (default: 1.0)",
    )
    parser.add_argument(
        "--project",
        help="Process only this project name (for debugging)",
    )
    parser.add_argument(
        "--search-all-github-repos",
        action="store_true",
        help="Search all shortlist GitHub repos, not only file_github_issue=true projects",
    )
    parser.add_argument(
        "--max-pages",
        type=int,
        default=2,
        metavar="N",
        help="Maximum GitHub search-result pages per query (default: 2)",
    )
    args = parser.parse_args()

    mine_github_issues(
        projects_dir=Path(args.projects_dir).expanduser().resolve(),
        oss_fuzz_dir=Path(args.oss_fuzz_dir).expanduser().resolve(),
        osv_dir=Path(args.osv_dir).expanduser().resolve(),
        out_dir=Path(args.out_dir).expanduser().resolve(),
        delay=args.rate_limit_delay,
        project_filter=args.project,
        search_all_github_repos=args.search_all_github_repos,
        max_pages=args.max_pages,
    )


if __name__ == "__main__":
    main()
