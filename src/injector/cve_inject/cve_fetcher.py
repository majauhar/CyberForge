"""
Fetch real CVEs for a project from OSV.dev and resolve the fixing commit diff
via the GitHub API.

No container access required — all HTTP only.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
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


@dataclass
class CVEStub:
    vuln_id: str
    cve_id: str
    description: str
    cvss: str
    severity: str
    published: str
    cwes: list[str]
    records: list[dict]


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


def _best_severity(records: list[dict]) -> str:
    best = "unknown"
    best_rank = 0
    for record in records:
        sev = _extract_severity(record)
        rank = _SEVERITY_RANK.get(sev, 0)
        if rank > best_rank:
            best = sev
            best_rank = rank
    return best


def _pick_preferred_record(records: list[dict]) -> dict:
    def key(record: dict) -> tuple[int, str, int, int]:
        summary = record.get("summary") or ""
        details = record.get("details") or ""
        return (
            _SEVERITY_RANK.get(_extract_severity(record), 0),
            str(record.get("published") or ""),
            1 if _extract_cvss(record) != "unknown" else 0,
            len(summary) + len(details),
        )

    return max(records, key=key)


def _records_for_resolution(records: list[dict]) -> list[dict]:
    def key(record: dict) -> tuple[int, int, str]:
        return (
            1 if _extract_fix_sha(record) else 0,
            _SEVERITY_RANK.get(_extract_severity(record), 0),
            str(record.get("published") or ""),
        )

    return sorted(records, key=key, reverse=True)


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


def _github_auth_headers() -> dict[str, str]:
    headers: dict[str, str] = {
        "Accept": "application/vnd.github.v3.diff",
        "User-Agent": "vuljector",
    }
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"
    return headers


def _fetch_github_diff(slug: str, sha: str) -> str:
    url = _GITHUB_COMMIT_URL.format(slug=slug, sha=sha)
    req = urllib.request.Request(url, headers=_github_auth_headers())
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            remaining = exc.headers.get("X-RateLimit-Remaining", "?")
            reset = exc.headers.get("X-RateLimit-Reset", "?")
            if remaining == "0" or remaining == b"0":
                logger.warning(
                    "GitHub API rate limit exhausted (resets at epoch %s). "
                    "Set GITHUB_TOKEN env var to raise the limit to 5 000 req/hr.",
                    reset,
                )
            else:
                logger.debug("GitHub diff fetch 403 (%s@%s): %s", slug, sha[:8], exc)
        else:
            logger.debug("GitHub diff fetch failed (%s@%s): %s", slug, sha[:8], exc)
        return ""
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

def discover_cves(
    main_repo_url: str,
    language: str | None,
    project: str,
) -> list[CVEStub]:
    """
    Discover CVEs for the project using OSV metadata only.

    Returns unique CVEs sorted by severity descending, then most recent first.
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

    logger.info("[%s] Found %d OSV records; building ranked CVE list ...", project, len(records))

    grouped: dict[str, list[dict]] = {}
    for rec in records:
        cve_id = _extract_cve_id(rec)
        grouped.setdefault(cve_id, []).append(rec)

    results: list[CVEStub] = []
    for cve_id, cve_records in grouped.items():
        preferred = _pick_preferred_record(cve_records)
        severity = _best_severity(cve_records)
        cvss = "unknown"
        for record in cve_records:
            cvss = _extract_cvss(record)
            if cvss != "unknown":
                break
        cwes: list[str] = []
        for record in cve_records:
            cwes.extend(_extract_cwes(record))
        results.append(CVEStub(
            vuln_id=str(preferred.get("id", cve_id)),
            cve_id=cve_id,
            description=((preferred.get("summary") or preferred.get("details") or "")[:500]),
            cvss=cvss,
            severity=severity,
            published=str(preferred.get("published") or ""),
            cwes=list(dict.fromkeys(cwes)),
            records=_records_for_resolution(cve_records),
        ))

    # Sort: highest severity first, then most recently published first.
    # CVEs without a severity label (rank 0) go last.
    # Two-pass stable sort: secondary key first, then primary.
    results.sort(key=lambda c: c.published or "", reverse=True)          # most recent first
    results.sort(key=lambda c: _SEVERITY_RANK.get(c.severity, 0), reverse=True)  # highest severity first
    return results


def prepare_cve_candidates(
    main_repo_url: str,
    language: str | None,
    project: str,
    max_cves: int = 10,
) -> list[CVEData]:
    """
    Build the ordered, usable CVE list for this run before injection starts.

    The project-wide CVE list is discovered and ranked first. Then commit diffs are
    fetched only for the highest-ranked CVEs needed to prepare up to ``max_cves``
    usable entries.
    """
    github_slug = _github_slug_from_url(main_repo_url)
    if not github_slug:
        logger.info("[%s] No GitHub slug; cannot resolve CVE fix diffs", project)
        return []

    stubs = discover_cves(main_repo_url=main_repo_url, language=language, project=project)
    results: list[CVEData] = []
    for stub in stubs:
        if len(results) >= max_cves:
            break

        resolved: CVEData | None = None
        for record in stub.records:
            fix_sha = _extract_fix_sha(record)
            if not fix_sha:
                continue

            raw_diff = _fetch_github_diff(github_slug, fix_sha)
            filtered = _filter_diff(raw_diff)
            if not filtered:
                logger.debug("[%s] Empty filtered diff for %s@%s", project, stub.cve_id, fix_sha[:8])
                continue

            resolved = CVEData(
                vuln_id=stub.vuln_id,
                cve_id=stub.cve_id,
                description=stub.description,
                cvss=stub.cvss,
                severity=stub.severity,
                published=stub.published,
                cwes=stub.cwes,
                fix_commit_sha=fix_sha,
                fix_diff=filtered,
            )
            break

        if resolved is None:
            logger.debug("[%s] No usable fix diff found for %s", project, stub.cve_id)
            continue

        results.append(resolved)
        logger.info(
            "[%s] Prepared CVE %s severity=%s (%d chars)",
            project, resolved.cve_id, resolved.severity, len(resolved.fix_diff),
        )
    return results
