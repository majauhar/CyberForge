"""
OSS-Fuzz project selector — equal thirds: Python / C+C++ / JavaScript
======================================================================
Self-contained; share as-is.  Requires only the standard library.
No API key or network access needed — GitHub data is baked into the CSV.

HOW IT WORKS
------------
Hard filters  (project is dropped if any fail):
  1. has_dockerfile = Yes          can't build without it
  2. language ∈ {python, c, c++, javascript}
  3. 4,000 ≤ LOC ≤ 1,000,000      too small / too large for the pipeline
  4. has_asan = Yes  (c / c++ only)  exploit oracle requires a sanitizer
                      JavaScript projects use a different runtime model and
                      never carry ASAN, so they are exempt from this check.

Priority ranking  (no weighted score — lexicographic, criterion 1 wins):
  Within each language group candidates are ranked by this tuple.
  The best project has the lowest tuple value.

    1. LOC in sweet zone [25k–200k]    0 = in-zone, 1 = out-of-zone
    2. GitHub stars                    more = better  (column: github_stars)
    3. Days since last push            fewer = more actively maintained
                                       (column: last_pushed_at)
    4. NVD CVE count                   more historical vulns = richer signal
    5. Quality score                   OSS-Fuzz integration quality (1–3)

Domain balancing  (applied during selection, not ranking):
  Before filling language quotas we guarantee minimum coverage for
  crypto, networking, data-parsing, web-framework, and database.
  These passes respect the priority order within each domain.

Quotas:
  Pass --total N (default 300).  N is split equally across the three groups
  (N//3 each).  If a group cannot fill its ideal share (JS is the usual
  bottleneck at ~20 projects), all available candidates from that group are
  taken and the shortfall is redistributed to the groups that still have
  supply.  The final total will always equal N unless the entire candidate
  pool is smaller than N.

USAGE
-----
  python select_projects.py
  python select_projects.py --total 300 --out selected.json

OPTIONS
-------
  --csv     Path to oss_fuzz_full.csv   [oss_fuzz_full.csv]
  --out     Output JSON path            [selected_projects.json]
  --total   Total projects to select    [300]
"""

import argparse
import csv
import json
import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

LOC_FLOOR    = 4_000
LOC_CEIL     = 1_000_000
LOC_SWEET_LO = 25_000
LOC_SWEET_HI = 200_000

TARGET_LANGUAGES = {"python", "c", "c++", "javascript"}

# Map individual language → group name used for quota tracking
LANG_GROUP = {
    "python":     "python",
    "c":          "c_cpp",
    "c++":        "c_cpp",
    "javascript": "javascript",
}

# JavaScript uses a JS runtime sanitizer model — standard ASAN doesn't apply
ASAN_NOT_APPLICABLE = {"javascript"}

# Minimum projects per domain across the whole selection
# (applied before language quotas; lowered to be achievable in a ~54-project set)
DOMAIN_MINIMUMS = {
    "crypto":        4,
    "networking":    4,
    "data-parsing":  3,
    "web-framework": 3,
    "database":      2,
}


# ─────────────────────────────────────────────────────────────────────────────
# Data model
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Project:
    # ── from CSV ──────────────────────────────────────────────────────────────
    name:              str
    github_slug:       str
    main_repo:         str
    language:          str
    lang_group:        str        # "python" | "c_cpp" | "javascript"
    domains:           list
    loc:               Optional[int]
    fuzz_target_count: Optional[int]
    has_dockerfile:    bool
    has_asan:          bool
    quality_score:     int
    nvd_cve_count:     Optional[int]
    nvd_mean_cvss:     Optional[float]
    nvd_cwes:          list
    sanitizers:        list
    # ── from CSV columns github_stars / last_pushed_at ───────────────────────
    github_stars:           Optional[int]  = None
    days_since_last_commit: Optional[int]  = None
    # ── set during selection ──────────────────────────────────────────────────
    discard_reason:    str = ""
    selection_reason:  str = ""


def _days_since(iso_str: Optional[str]) -> Optional[int]:
    if not iso_str:
        return None
    try:
        from datetime import datetime, timezone
        dt  = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return (now - dt).days
    except Exception:
        return None


def parse_row(row: dict) -> Project:
    def i(v):
        try: return int(v)
        except: return None
    def f(v):
        try: return float(v)
        except: return None
    def lst(v):
        return [x.strip() for x in v.split("|") if x.strip()]

    lang = row["language"].strip().lower()
    return Project(
        name              = row["name"].strip(),
        github_slug       = row["github_slug"].strip(),
        main_repo         = row["main_repo"].strip(),
        language          = lang,
        lang_group        = LANG_GROUP.get(lang, "other"),
        domains           = lst(row["domains"]),
        loc               = i(row["loc_estimate"]),
        fuzz_target_count = i(row["fuzz_target_count"]),
        has_dockerfile    = row["has_dockerfile"].strip().lower() == "yes",
        has_asan          = row["has_asan"].strip().lower() == "yes",
        quality_score     = i(row["quality_score"]) or 0,
        nvd_cve_count     = i(row["nvd_cve_count"]),
        nvd_mean_cvss     = f(row["nvd_mean_cvss"]),
        nvd_cwes          = lst(row["nvd_cwes"]),
        sanitizers        = lst(row["sanitizers"]),
        github_stars      = i(row.get("github_stars", "")),
        days_since_last_commit = _days_since(row.get("last_pushed_at", "").strip() or None),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Hard filters
# ─────────────────────────────────────────────────────────────────────────────

def hard_filter(p: Project) -> Optional[str]:
    """Return rejection reason string, or None if the project passes."""
    if not p.has_dockerfile:
        return "no dockerfile"
    if p.lang_group == "other":
        return f"language '{p.language}' not in target set"
    if p.loc is not None and p.loc < LOC_FLOOR:
        return f"loc {p.loc:,} < floor {LOC_FLOOR:,}"
    if p.loc is not None and p.loc > LOC_CEIL:
        return f"loc {p.loc:,} > ceiling {LOC_CEIL:,}"
    if p.language not in ASAN_NOT_APPLICABLE and not p.has_asan:
        return "no ASAN (required for c/c++ exploit oracle)"
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Priority key  (lower tuple = higher priority)
# ─────────────────────────────────────────────────────────────────────────────

def priority_key(p: Project):
    """
    Lexicographic sort tuple.  Lower value = higher priority.

    Criteria in order:
      1. LOC in sweet zone [25k–200k]     0 = in-zone (better)
      2. GitHub stars                     negated so more stars sorts first
      3. Days since last push             fewer days = more active
      4. NVD CVE count                    negated so more CVEs sorts first
      5. Quality score                    negated so higher score sorts first
    """
    in_sweet = int(not (LOC_SWEET_LO <= (p.loc or 0) <= LOC_SWEET_HI))
    stars    = -(p.github_stars or 0)
    days     = p.days_since_last_commit if p.days_since_last_commit is not None else 9_999
    cves     = -(p.nvd_cve_count or 0)
    qs       = -p.quality_score
    return (in_sweet, stars, days, cves, qs)


# ─────────────────────────────────────────────────────────────────────────────
# Constrained selection
# ─────────────────────────────────────────────────────────────────────────────

def compute_quotas(total_n: int, supply: dict) -> dict:
    """
    Distribute total_n slots equally across groups.
    If a group can't fill its ideal share, take all available from it
    and redistribute the shortfall to the groups that have surplus supply.

    Example (total=200, supply={python:169, c_cpp:347, javascript:18}):
      ideal  → python:67  c_cpp:67  javascript:66
      JS can only supply 18  → shortfall = 66 - 18 = 48
      redistribute 48 equally to python + c_cpp:
      final  → python:91  c_cpp:91  javascript:18  (total=200)

    Returns dict: group → quota
    """
    groups = sorted(supply.keys())
    n      = len(groups)

    # Equal ideal split with remainder distributed to first groups
    ideal    = {g: total_n // n for g in groups}
    leftover = total_n % n
    for g in groups[:leftover]:
        ideal[g] += 1

    # First pass: clamp to available, track shortfall
    quotas   : dict = {}
    shortfall: int  = 0
    have_surplus    : list = []

    for g in groups:
        avail = supply.get(g, 0)
        if avail < ideal[g]:
            quotas[g] = avail
            shortfall += ideal[g] - avail
        else:
            quotas[g] = ideal[g]
            have_surplus.append(g)

    # Second pass: distribute shortfall to surplus groups
    if shortfall and have_surplus:
        extra_each = shortfall // len(have_surplus)
        remainder  = shortfall % len(have_surplus)
        for idx, g in enumerate(have_surplus):
            bonus      = extra_each + (1 if idx < remainder else 0)
            quotas[g]  = min(supply.get(g, 0), quotas[g] + bonus)

    return quotas


def select(candidates: list, total_n: int) -> tuple:
    """
    Three-pass constrained selection.  Returns (selected, quotas).

    Pass 1 — domain minimums
      Guarantee DOMAIN_MINIMUMS coverage.  Picks the highest-priority
      project per domain that still fits within its language quota.

    Pass 2 — fill language quotas
      Fill each group up to its computed quota from the remaining pool.

    Pass 3 — top-up to reach total_n
      If some groups are still short after passes 1+2 (shouldn't happen
      in normal operation), fill any remaining slots by pure priority
      order regardless of language group.
    """
    # Compute supply per group
    supply    = Counter(p.lang_group for p in candidates)
    quotas    = compute_quotas(total_n, dict(supply))

    # Sort all candidates globally by priority
    pool      = sorted(candidates, key=priority_key)
    selected  = []
    seen      = set()
    domain_ct : dict = defaultdict(int)
    group_ct  : dict = defaultdict(int)

    def accept(p: Project, reason: str) -> None:
        selected.append(p)
        seen.add(p.name)
        p.selection_reason = reason
        group_ct[p.lang_group] += 1
        for d in p.domains:
            domain_ct[d] += 1

    def has_room(p: Project) -> bool:
        return group_ct[p.lang_group] < quotas.get(p.lang_group, 0)

    # ── Pass 1: domain minimums ───────────────────────────────────────────────
    for domain, minimum in sorted(DOMAIN_MINIMUMS.items(), key=lambda x: -x[1]):
        for p in pool:
            if domain_ct[domain] >= minimum:
                break
            if p.name not in seen and domain in p.domains and has_room(p):
                accept(p, f"domain_min:{domain}")

    # ── Pass 2: fill language quotas ─────────────────────────────────────────
    for p in pool:
        if p.name not in seen and has_room(p):
            accept(p, f"quota:{p.lang_group}")

    # ── Pass 3: top-up any remaining slots (pure priority) ───────────────────
    for p in pool:
        if len(selected) >= total_n:
            break
        if p.name not in seen:
            accept(p, "topup")

    return selected, quotas


# ─────────────────────────────────────────────────────────────────────────────
# GitHub API enrichment
# ─────────────────────────────────────────────────────────────────────────────

def _gh_request(slug: str, token: Optional[str]) -> Optional[dict]:
    """Single GitHub API call for one slug. Returns parsed JSON or None."""
    url = f"https://api.github.com/repos/{slug}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 403:
            reset = int(e.headers.get("X-RateLimit-Reset", time.time() + 60))
            wait  = max(reset - time.time() + 2, 1)
            print(f"    [rate-limit] sleeping {wait:.0f}s …", flush=True)
            time.sleep(wait)
            return _gh_request(slug, token)   # retry once
        if e.code != 404:
            print(f"    [HTTP {e.code}] {slug}", flush=True)
        return None
    except Exception as exc:
        print(f"    [error] {slug}: {exc}", flush=True)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Reporting helpers
# ─────────────────────────────────────────────────────────────────────────────

def _fmt(v, fmt=","):
    return format(v, fmt) if v is not None else "n/a"


def print_summary(selected: list, discarded: list, quotas: dict, total_n: int) -> None:
    W = 70
    print("\n" + "═" * W)
    print("  OSS-FUZZ PROJECT SELECTION SUMMARY")
    print("═" * W)

    # Discard breakdown
    discard_by = Counter(p.discard_reason.split(" ")[0] for p in discarded)
    print(f"\nDISCARDED  {len(discarded)} projects")
    for reason, n in discard_by.most_common():
        print(f"  {n:4d}  {reason}")

    # Language distribution
    print(f"\nSELECTED  {len(selected)} / {total_n} target")
    group_dist = Counter(p.lang_group for p in selected)
    lang_dist  = Counter(p.language   for p in selected)
    for grp in ("python", "c_cpp", "javascript"):
        langs_in_group = [
            f"{l}:{n}" for l, n in lang_dist.items() if LANG_GROUP.get(l) == grp
        ]
        quota = quotas.get(grp, 0)
        print(f"  {grp:12s} {group_dist[grp]:3d} / {quota:3d} quota  "
              f"({', '.join(langs_in_group)})")

    # Selection pass breakdown
    pass_dist = Counter(p.selection_reason.split(":")[0] for p in selected)
    print("\nSelection passes:")
    for r, n in pass_dist.most_common():
        print(f"  {r:20s} {n:3d}")

    # Domain coverage
    domain_ct: Counter = Counter()
    for p in selected:
        for d in p.domains:
            domain_ct[d] += 1
    print("\nDomain coverage:")
    for d, n in domain_ct.most_common(12):
        min_mark = " ✓" if d in DOMAIN_MINIMUMS and n >= DOMAIN_MINIMUMS[d] else ""
        print(f"  {d:22s} {n:3d}{min_mark}")

    # Priority stats
    import statistics as s
    in_sweet = [p for p in selected if p.loc and LOC_SWEET_LO <= p.loc <= LOC_SWEET_HI]
    locs     = [p.loc for p in selected if p.loc]
    stars    = [p.github_stars for p in selected if p.github_stars is not None]
    days     = [p.days_since_last_commit for p in selected if p.days_since_last_commit is not None]
    cves     = [p.nvd_cve_count for p in selected if p.nvd_cve_count]
    print(f"\nPriority-criterion stats:")
    print(f"  LOC sweet zone  {len(in_sweet):3d}/{len(selected)} projects  "
          f"(median LOC {_fmt(int(s.median(locs)))} of those with data)")
    if stars:
        print(f"  GitHub stars    enriched={len(stars)}  "
              f"median={_fmt(int(s.median(stars)))}  max={_fmt(max(stars))}")
    else:
        print(f"  GitHub stars    not enriched — run with --fetch to add")
    if days:
        print(f"  Days since push enriched={len(days)}  median={int(s.median(days))}d")
    else:
        print(f"  Days since push not enriched — run with --fetch to add")
    print(f"  NVD CVEs        {sum(1 for p in selected if p.nvd_cve_count)} projects with CVE data  "
          f"(median count {_fmt(int(s.median(cves))) if cves else 'n/a'})")

    # CWE coverage
    cwe_ct: Counter = Counter()
    for p in selected:
        for cwe in p.nvd_cwes:
            cwe_ct[cwe] += 1
    print(f"\nDistinct CWEs covered: {len(cwe_ct)}")
    for cwe, n in cwe_ct.most_common(10):
        print(f"  {cwe:12s} {n:3d} projects")

    print("═" * W + "\n")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Select OSS-Fuzz projects — equal thirds: Python / C+C++ / JavaScript",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--csv",   default="oss_fuzz_full.csv",
                        help="Input CSV  [oss_fuzz_full.csv]")
    parser.add_argument("--out",   default="selected_projects.json",
                        help="Output JSON  [selected_projects.json]")
    parser.add_argument("--total", type=int, default=300,
                        help="Total projects to select  [300]")
    args = parser.parse_args()

    # ── Load CSV ──────────────────────────────────────────────────────────────
    with open(args.csv) as f:
        rows = list(csv.DictReader(f))
    all_projects = [parse_row(r) for r in rows]
    print(f"Loaded {len(all_projects)} projects from {args.csv}")

    # ── Hard filter ───────────────────────────────────────────────────────────
    candidates, discarded = [], []
    for p in all_projects:
        reason = hard_filter(p)
        if reason:
            p.discard_reason = reason
            discarded.append(p)
        else:
            candidates.append(p)

    print(f"After hard filters: {len(candidates)} candidates  "
          f"({len(discarded)} discarded)")
    by_group = Counter(p.lang_group for p in candidates)
    for g in ("python", "c_cpp", "javascript"):
        print(f"  {g:12s}  {by_group[g]:3d} available")

    enriched = sum(1 for p in candidates if p.github_stars is not None)
    print(f"GitHub data (stars + last push) present for {enriched}/{len(candidates)} candidates")

    # ── Show how N will be split ───────────────────────────────────────────────
    quotas = compute_quotas(args.total, dict(by_group))
    print(f"\nQuota split for --total {args.total}:")
    for g in ("python", "c_cpp", "javascript"):
        avail = by_group.get(g, 0)
        flag  = "  ← bottleneck, shortfall redistributed" if avail < quotas[g] else ""
        print(f"  {g:12s}  quota={quotas[g]:3d}  available={avail:3d}{flag}")

    # ── Select ────────────────────────────────────────────────────────────────
    selected, quotas = select(candidates, args.total)

    # ── Report ────────────────────────────────────────────────────────────────
    print_summary(selected, discarded, quotas, args.total)

    # ── Write JSON ────────────────────────────────────────────────────────────
    from datetime import datetime, timezone
    output = {
        "meta": {
            "total_selected": len(selected),
            "total_target":   args.total,
            "quotas":         quotas,
            "source_csv":     args.csv,
            "generated_at":   datetime.now(timezone.utc).isoformat(),
            "hard_filters": {
                "languages":         sorted(TARGET_LANGUAGES),
                "loc_floor":         LOC_FLOOR,
                "loc_ceil":          LOC_CEIL,
                "asan_required_for": ["c", "c++"],
            },
            "priority_order": [
                "loc_in_sweet_zone [25k–200k]",
                "github_stars (desc)",
                "days_since_last_commit (asc)",
                "nvd_cve_count (desc)",
                "quality_score (desc)",
            ],
            "domain_minimums": DOMAIN_MINIMUMS,
        },
        "projects": [
            {
                "name":                   p.name,
                "github_slug":            p.github_slug,
                "main_repo":              p.main_repo,
                "language":               p.language,
                "lang_group":             p.lang_group,
                "domains":                p.domains,
                "loc":                    p.loc,
                "loc_in_sweet_zone":      p.loc is not None and LOC_SWEET_LO <= p.loc <= LOC_SWEET_HI,
                "github_stars":           p.github_stars,
                "days_since_last_commit": p.days_since_last_commit,
                "nvd_cve_count":          p.nvd_cve_count,
                "nvd_mean_cvss":          p.nvd_mean_cvss,
                "nvd_cwes":               p.nvd_cwes,
                "fuzz_target_count":      p.fuzz_target_count,
                "quality_score":          p.quality_score,
                "sanitizers":             p.sanitizers,
                "selection_reason":       p.selection_reason,
            }
            for p in selected
        ],
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Wrote {len(selected)} projects to {args.out}")


if __name__ == "__main__":
    main()
