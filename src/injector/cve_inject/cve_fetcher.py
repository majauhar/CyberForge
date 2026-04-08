"""
Fetch real CVEs for a project from OSV.dev and resolve the fixing commit diff
via the GitHub API.

No container access required — all HTTP only.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.request
from dataclasses import dataclass

logger = logging.getLogger(__name__)

_OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_GITHUB_COMMIT_URL = "https://api.github.com/repos/{slug}/commits/{sha}"

# Files whose paths match these patterns are stripped from fix diffs.
_NOISE_PATTERNS = re.compile(
    r"(?:^|/)(?:test|tests|testing|docs?|documentation|changelog|CHANGES|NEWS|AUTHORS)",
    re.IGNORECASE,
)
_NOISE_EXTENSIONS = re.compile(r"\.(md|rst|txt|html|xml|json|yaml|yml|toml|cfg)$", re.IGNORECASE)

# Max characters of fix diff passed to the agent (avoids flooding the context window).
_MAX_DIFF_CHARS = 8_000


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class CVEData:
    vuln_id: str          # CVE-YYYY-NNNNN or GHSA-xxxx (OSV ID)
    cve_id: str           # extracted CVE alias, or same as vuln_id
    description: str
    cvss: str             # CVSS vector string or "unknown"
    severity: str         # CRITICAL / HIGH / MEDIUM / LOW / unknown
    published: str        # ISO-8601 date string from OSV
    cwes: list[str]
    fix_commit_sha: str
    fix_diff: str         # pre-filtered, capped at _MAX_DIFF_CHARS


# ─── OSV query ────────────────────────────────────────────────────────────────

def _post_json(url: str, payload: dict) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _query_osv(name: str, ecosystem: str) -> list[dict]:
    try:
        result = _post_json(_OSV_QUERY_URL, {"package": {"name": name, "ecosystem": ecosystem}})
        return result.get("vulns") or []
    except Exception as exc:
        logger.debug("OSV query failed (%s/%s): %s", ecosystem, name, exc)
        return []


def _osv_packages(project: str, language: str | None, github_slug: str | None = None) -> list[tuple[str, str]]:
    """Return (name, ecosystem) pairs to try, most reliable first."""
    lang = (language or "").lower()
    pairs: list[tuple[str, str]] = [
        (project, "OSS-Fuzz"),  # most reliable for OSS-Fuzz projects
    ]
    if lang in ("python", "python3"):
        pairs.append((project, "PyPI"))
    elif lang == "go":
        pairs.append((f"github.com/{project}", "Go"))
    elif lang in ("javascript", "typescript", "js", "ts"):
        pairs.append((project, "npm"))
        # npm package name often matches the GitHub org name (e.g. protobufjs/protobuf.js → protobufjs)
        if github_slug:
            org = github_slug.split("/")[0]
            if org.lower() != project.lower():
                pairs.append((org, "npm"))
    elif lang in ("rust",):
        pairs.append((project, "crates.io"))
    return pairs


# ─── CVE ID / severity extraction ─────────────────────────────────────────────

def _extract_cve_id(record: dict) -> str:
    """Return the CVE-YYYY-NNNNN alias if present, otherwise the OSV id."""
    for alias in record.get("aliases") or []:
        if alias.startswith("CVE-"):
            return alias
    return record.get("id", "")


def _extract_cvss(record: dict) -> str:
    for sev in record.get("severity") or []:
        if sev.get("type", "").startswith("CVSS"):
            return sev.get("score", "unknown")
    return "unknown"


def _extract_severity(record: dict) -> str:
    """Return normalised severity label (CRITICAL/HIGH/MEDIUM/LOW) from database_specific."""
    db = record.get("database_specific") or {}
    label = (db.get("severity") or "").upper()
    # GitHub Advisory DB uses "MODERATE" instead of "MEDIUM"
    label = "MEDIUM" if label == "MODERATE" else label
    return label if label in _SEVERITY_RANK else "unknown"


def _extract_cwes(record: dict) -> list[str]:
    cwes: list[str] = []
    # OSV often surfaces CWEs in database_specific or in the details text
    db = record.get("database_specific") or {}
    for key in ("cwe_ids", "cwes"):
        val = db.get(key)
        if isinstance(val, list):
            cwes.extend(str(c) for c in val)
    if not cwes:
        # Scan details/summary text for CWE-NNN references
        text = (record.get("details") or "") + " " + (record.get("summary") or "")
        cwes = re.findall(r"CWE-\d+", text)
    return list(dict.fromkeys(cwes))  # deduplicate, preserve order


# ─── Fix commit resolution ─────────────────────────────────────────────────────

_COMMIT_URL_RE = re.compile(r"github\.com/[^/]+/[^/]+/(?:pull/\d+/)?commits?/([0-9a-f]{7,40})")


def _extract_fix_sha(record: dict) -> str | None:
    # Primary: GIT range with an explicit "fixed" event
    for affected in record.get("affected") or []:
        for r in affected.get("ranges") or []:
            if r.get("type") == "GIT":
                for event in r.get("events") or []:
                    sha = event.get("fixed")
                    if sha and len(sha) >= 7:
                        return sha
    # Fallback: GitHub commit URL in references (common for npm/JS advisories)
    for ref in record.get("references") or []:
        m = _COMMIT_URL_RE.search(ref.get("url") or "")
        if m:
            return m.group(1)
    return None


def _github_slug_from_url(url: str) -> str | None:
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(?:\.git)?(?:/|$)", url)
    return m.group(1) if m else None


def _fetch_github_diff(slug: str, sha: str) -> str:
    url = _GITHUB_COMMIT_URL.format(slug=slug, sha=sha)
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/vnd.github.v3.diff", "User-Agent": "vuljector"},
    )
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as exc:
        logger.debug("GitHub diff fetch failed (%s@%s): %s", slug, sha[:8], exc)
        return ""


# ─── Diff filtering ───────────────────────────────────────────────────────────

def _filter_diff(diff_text: str) -> str:
    """Remove test/doc file hunks; cap total length."""
    if not diff_text:
        return ""

    # Split into per-file hunks at "diff --git" boundaries
    parts = re.split(r"(?=^diff --git )", diff_text, flags=re.MULTILINE)
    kept: list[str] = []
    for part in parts:
        if not part.strip():
            continue
        # Extract both a/ and b/ paths from "diff --git a/<path> b/<path>"
        header_m = re.match(r"diff --git a/(\S+)", part)
        if not header_m:
            kept.append(part)
            continue
        path = header_m.group(1)
        if _NOISE_PATTERNS.search(path) or _NOISE_EXTENSIONS.search(path):
            continue
        kept.append(part)

    filtered = "".join(kept)
    if len(filtered) > _MAX_DIFF_CHARS:
        filtered = filtered[:_MAX_DIFF_CHARS] + "\n... (diff truncated)"
    return filtered


# ─── Public entry point ───────────────────────────────────────────────────────

def fetch_cve_candidates(
    main_repo_url: str,
    language: str | None,
    project: str,
    max_cves: int = 10,
) -> list[CVEData]:
    """
    Fetch up to max_cves CVEs with resolvable fix diffs for the given project.

    Returns CVEData list sorted by CVSS score descending (unknown scores last).
    """
    github_slug = _github_slug_from_url(main_repo_url)

    # Collect OSV records, deduplicating by OSV id
    seen_ids: set[str] = set()
    records: list[dict] = []
    for name, ecosystem in _osv_packages(project, language, github_slug):
        for rec in _query_osv(name, ecosystem):
            rid = rec.get("id", "")
            if rid not in seen_ids:
                seen_ids.add(rid)
                records.append(rec)

    if not records:
        logger.info("[%s] No OSV records found", project)
        return []

    logger.info("[%s] Found %d OSV records; resolving fix diffs ...", project, len(records))

    # Build CVE-ID → best severity across all records (GHSA records have severity
    # but not fix SHAs; PYSEC records have fix SHAs but not severity — cross-link them).
    cve_severity: dict[str, str] = {}
    for rec in records:
        sev = _extract_severity(rec)
        if sev == "unknown":
            continue
        cve_id = _extract_cve_id(rec)
        if cve_id and cve_id not in cve_severity:
            cve_severity[cve_id] = sev

    results: list[CVEData] = []
    for record in records:
        if len(results) >= max_cves:
            break

        fix_sha = _extract_fix_sha(record)
        if not fix_sha:
            continue

        # Prefer GitHub API for diff; only works when repo is on GitHub
        if not github_slug:
            logger.debug("[%s] No GitHub slug; skipping %s", project, record.get("id"))
            continue

        raw_diff = _fetch_github_diff(github_slug, fix_sha)
        filtered = _filter_diff(raw_diff)
        if not filtered:
            logger.debug("[%s] Empty filtered diff for %s@%s", project, record.get("id"), fix_sha[:8])
            continue

        cve_id = _extract_cve_id(record)
        severity = _extract_severity(record)
        if severity == "unknown":
            severity = cve_severity.get(cve_id, "unknown")
        results.append(CVEData(
            vuln_id=record.get("id", cve_id),
            cve_id=cve_id,
            description=(record.get("summary") or record.get("details") or "")[:500],
            cvss=_extract_cvss(record),
            severity=severity,
            published=record.get("published") or "",
            cwes=_extract_cwes(record),
            fix_commit_sha=fix_sha,
            fix_diff=filtered,
        ))
        logger.info("[%s] Resolved fix diff for %s severity=%s (%d chars)", project, cve_id, _extract_severity(record), len(filtered))

    # Sort: highest severity first, then most recently published first.
    # CVEs without a severity label (rank 0) go last.
    # Two-pass stable sort: secondary key first, then primary.
    results.sort(key=lambda c: c.published or "", reverse=True)          # most recent first
    results.sort(key=lambda c: _SEVERITY_RANK.get(c.severity, 0), reverse=True)  # highest severity first
    return results[:max_cves]
