#!/usr/bin/env python3
"""Characterize injected vulnerabilities for quality/structural comparison.

Usage: python3 analyze_vulns.py <vulnerabilities_dir> [label]
Computes per-vuln + aggregate metrics: target file (library vs harness/test),
CWE, edit locality (files/hunks/+/-), fix location (function), bug location
(crash function from sanitizer trace), bug depth (project frames on the stack),
and bug-vs-fix locality (whether crash != fix site, and the stack gap).
Emits JSON to stdout.
"""
import json, re, sys, os
from pathlib import Path

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@(.*)$")
DIFFGIT = re.compile(r"^diff --git a/(.+?) b/(.+)$")
FRAME = re.compile(r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(\S+)\s+(\S+?):(\d+)(?::\d+)?")
SUMMARY = re.compile(r"SUMMARY:\s*(AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer)?:?\s*(.+)")

HARNESS_HINT = re.compile(r"(^|/)(fuzz|fuzzing|fuzzer|test|tests|example|examples)(/|$)|fuzzer|harness|LLVMFuzzer", re.I)

def _func_from_hunk_context(ctx: str) -> str:
    # git puts the enclosing function signature after the @@; grab an identifier
    ctx = ctx.strip()
    m = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(", ctx)
    return m.group(1) if m else ""

def parse_diff(path: Path):
    files, hunks, added, removed = [], 0, 0, 0
    fix_funcs, fix_files = set(), set()
    cur_file = None
    for line in path.read_text(errors="ignore").splitlines():
        mg = DIFFGIT.match(line)
        if mg:
            cur_file = mg.group(2)
            files.append(cur_file)
            continue
        mh = HUNK.match(line)
        if mh:
            hunks += 1
            fn = _func_from_hunk_context(mh.group(3))
            if fn:
                fix_funcs.add(fn)
            if cur_file:
                fix_files.add(cur_file)
            continue
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return {
        "files": files, "n_files": len(set(files)), "n_hunks": hunks,
        "added": added, "removed": removed, "net": added - removed,
        "churn": added + removed, "fix_funcs": sorted(fix_funcs), "fix_files": sorted(set(fix_files)),
    }

def parse_sanitizer(path: Path, project: str):
    if not path.exists():
        return {}
    text = path.read_text(errors="ignore")
    frames = []  # (idx, func, file, line)
    for line in text.splitlines():
        m = FRAME.match(line)
        if m:
            frames.append((int(m.group(1)), m.group(2), m.group(3), int(m.group(4))))
    # project frames: file path under /src/<project>/ and not the driver/harness
    def is_proj(fr):
        f = fr[2]
        return (f"/src/{project}/" in f or f"/{project}/" in f) and not HARNESS_HINT.search(f) and not f.endswith("driver.c")
    proj_frames = [fr for fr in frames if is_proj(fr)]
    crash_func = proj_frames[0][1] if proj_frames else (frames[0][1] if frames else "")
    crash_file = proj_frames[0][2] if proj_frames else (frames[0][2] if frames else "")
    crash_line = proj_frames[0][3] if proj_frames else (frames[0][3] if frames else None)
    # crash type
    ctype = ""
    sanitizer = ""
    for line in text.splitlines():
        ms = SUMMARY.search(line)
        if ms:
            sanitizer = ms.group(1) or ""
            ctype = ms.group(2).strip()
            break
    if ctype:
        # normalize to the signal class only (strip file:line/addresses)
        ctype = ctype.split()[0].rstrip(":")
    if not ctype:
        if "heap-buffer-overflow" in text: ctype = "heap-buffer-overflow"
        elif "SEGV" in text: ctype = "SEGV"
        elif "heap-use-after-free" in text: ctype = "heap-use-after-free"
    return {
        "n_stack_frames": len(frames), "n_project_frames": len(proj_frames),
        "crash_func": crash_func, "crash_file": os.path.basename(crash_file), "crash_line": crash_line,
        "crash_type": ctype, "sanitizer": sanitizer,
        "proj_frame_funcs": [fr[1] for fr in proj_frames],
    }

def analyze_one(vdir: Path, project: str):
    meta = {}
    mp = vdir / "vulnerability_metadata.json"
    if mp.exists():
        meta = json.loads(mp.read_text())
    diff = parse_diff(vdir / "inject_vulnerability.diff") if (vdir / "inject_vulnerability.diff").exists() else {}
    san = parse_sanitizer(vdir / "sanitizer_report.txt", project)
    target_files = diff.get("fix_files") or diff.get("files") or []
    in_library = bool(target_files) and not any(HARNESS_HINT.search(f) for f in target_files)
    # bug vs fix locality
    fix_funcs = set(diff.get("fix_funcs", []))
    crash_func = san.get("crash_func", "")
    nonlocal_bug = bool(crash_func) and bool(fix_funcs) and (crash_func not in fix_funcs)
    # stack gap: index of first frame whose func is a fix func
    gap = None
    for i, fn in enumerate(san.get("proj_frame_funcs", [])):
        if fn in fix_funcs:
            gap = i
            break
    return {
        "id": meta.get("id", vdir.name),
        "cwe_id": meta.get("cwe_id", ""),
        "cwe_group": meta.get("cwe_group", ""),
        "target_files": target_files,
        "in_library": in_library,
        "n_files": diff.get("n_files"), "n_hunks": diff.get("n_hunks"),
        "added": diff.get("added"), "removed": diff.get("removed"), "churn": diff.get("churn"),
        "fix_funcs": diff.get("fix_funcs"),
        "crash_func": crash_func, "crash_file": san.get("crash_file"), "crash_line": san.get("crash_line"),
        "crash_type": san.get("crash_type"), "sanitizer": san.get("sanitizer"),
        "bug_depth_frames": san.get("n_project_frames"),
        "total_stack_frames": san.get("n_stack_frames"),
        "nonlocal_bug": nonlocal_bug,
        "fix_on_stack_gap": gap,
        "has_sanitizer_report": bool(san),
    }

def main():
    vdir_root = Path(sys.argv[1])
    label = sys.argv[2] if len(sys.argv) > 2 else vdir_root.parent.name
    name_filter = re.compile(sys.argv[3]) if len(sys.argv) > 3 else None
    project = os.environ.get("PROJECT", "cjson")
    dirs = [d for d in sorted(vdir_root.iterdir()) if d.is_dir() and (not name_filter or name_filter.search(d.name))]
    rows = [analyze_one(d, project) for d in dirs]
    import statistics as st
    def agg(key):
        vals = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
        return {"mean": round(st.mean(vals), 2), "median": st.median(vals), "min": min(vals), "max": max(vals), "n": len(vals)} if vals else {}
    summary = {
        "label": label, "n_vulns": len(rows),
        "pct_in_library": round(100 * sum(1 for r in rows if r["in_library"]) / len(rows), 1) if rows else 0,
        "pct_with_sanitizer": round(100 * sum(1 for r in rows if r["has_sanitizer_report"]) / len(rows), 1) if rows else 0,
        "pct_nonlocal_bug": round(100 * sum(1 for r in rows if r["nonlocal_bug"]) / len(rows), 1) if rows else 0,
        "edit_churn": agg("churn"), "n_hunks": agg("n_hunks"),
        "bug_depth_frames": agg("bug_depth_frames"),
        "fix_on_stack_gap": agg("fix_on_stack_gap"),
        "cwe_distribution": dict(sorted(((c, sum(1 for r in rows if r["cwe_id"] == c)) for c in set(r["cwe_id"] for r in rows)), key=lambda x: -x[1])),
        "crash_types": dict(sorted(((c, sum(1 for r in rows if (r["crash_type"] or 'none') == c)) for c in set((r["crash_type"] or 'none') for r in rows)), key=lambda x: -x[1])),
    }
    print(json.dumps({"summary": summary, "rows": rows}, indent=2))

if __name__ == "__main__":
    main()
