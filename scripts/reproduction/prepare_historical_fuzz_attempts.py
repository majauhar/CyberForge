#!/usr/bin/env python3
"""Prepare injection-shaped attempt dirs for historical fuzz validation.

This bridges historical OSS-Fuzz / reversal-style manifest entries into the
same attempt layout consumed by the fuzz PoC stages:

  <out>/<project>/<run_id>/
    run_summary.json
    attempt_00/
      injection_result.json
      request.json
      source_manifest_record.json
      reference/
        testcase.bin

The downstream fuzz-guided PoC pipeline expects an ``injection_result.json``
with a vuln-introducing ``patch_diff``. For historical cases we synthesize
that patch from git history:

- if a vulnerable commit candidate exists, diff ``secure_base_commit..vulnerable``
- otherwise, reverse the fix commit(s) onto ``secure_base_commit``

This preparation step keeps its own isolated clone under the configured runs
root when needed. It may reset or modify that isolated checkout, but does not
touch user project repos.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"
DEFAULT_SHARED_WORKSPACES_ROOT = (REPO_ROOT / "runs" / "workspaces").resolve()


def utc_now_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")


def configured_runs_root() -> Path:
    override = os.environ.get("VULJECTOR_RUNS_ROOT") or os.environ.get("RUNS_ROOT")
    if not override:
        return REPO_ROOT / "runs"
    path = Path(override).expanduser()
    if not path.is_absolute():
        path = (REPO_ROOT / path).resolve()
    return path


DEFAULT_OUT_ROOT = configured_runs_root() / "historical_injection_bridge"


def load_manifest(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.strip():
                continue
            records.append(json.loads(line))
    return records


def parse_projects(value: str | None) -> set[str] | None:
    if not value:
        return None
    projects = {part.strip() for part in value.split(",") if part.strip()}
    return projects or None


def parse_selectors(values: list[str] | None) -> set[tuple[str, str]] | None:
    if not values:
        return None
    selectors: set[tuple[str, str]] = set()
    for value in values:
        project, issue_id = value.split(":", 1)
        selectors.add((project, issue_id))
    return selectors


def normalize_commit_list(value: Any) -> list[str]:
    if isinstance(value, list):
        raw = value
    else:
        raw = [value]
    commits: list[str] = []
    for item in raw:
        text = str(item or "").strip()
        if text and all(ch in "0123456789abcdefABCDEF" for ch in text) and len(text) == 40:
            commits.append(text.lower())
    return list(dict.fromkeys(commits))


def primary_testcase(record: dict[str, Any]) -> dict[str, Any] | None:
    primary = ((record.get("local_testcases") or {}).get("primary") or {})
    if primary.get("exists") and primary.get("path"):
        return primary
    return None


def historical_candidates(
    records: list[dict[str, Any]],
    *,
    projects: set[str] | None,
    selectors: set[tuple[str, str]] | None,
    include_strong: bool,
    include_weak: bool,
    require_testcase: bool,
) -> list[dict[str, Any]]:
    picked: list[dict[str, Any]] = []
    for record in records:
        project = str(record.get("project") or "")
        issue_id = str(record.get("issue_id") or "")
        if projects is not None and project not in projects:
            continue
        if selectors is not None and (project, issue_id) not in selectors:
            continue
        flags = record.get("flags") or {}
        strong = bool(flags.get("reversal_ready_local_strong"))
        weak = bool(flags.get("reversal_seed_ready_local")) and not strong
        if strong and not include_strong:
            continue
        if weak and not include_weak:
            continue
        if not strong and not weak:
            continue
        if require_testcase and primary_testcase(record) is None:
            continue
        picked.append(record)
    return picked


def find_project_repo(projects_root: Path, workspaces_root: Path, record: dict[str, Any]) -> Path:
    project = str(record.get("project") or "")
    runtime = record.get("local_runtime") or {}
    target_dir = runtime.get("target_dir") or project
    candidates = [
        (projects_root / project / str(target_dir)).resolve(),
        (workspaces_root / project / str(target_dir)).resolve(),
    ]
    for candidate in candidates:
        if (candidate / ".git").exists():
            return candidate
    main_repo_url = str(runtime.get("main_repo_url") or "").strip()
    if not main_repo_url:
        raise FileNotFoundError(
            "unable to locate git checkout and no main_repo_url available for "
            f"{project}; checked {', '.join(str(path) for path in candidates)}"
        )
    clone_dest = (workspaces_root / project / str(target_dir)).resolve()
    clone_dest.parent.mkdir(parents=True, exist_ok=True)
    if not clone_dest.exists():
        git(["clone", "--no-checkout", main_repo_url, str(clone_dest)], cwd=clone_dest.parent)
    elif not (clone_dest / ".git").exists():
        raise FileNotFoundError(f"workspace path exists but is not a git repo: {clone_dest}")
    return clone_dest


def git(args: list[str], *, cwd: Path, timeout: int = 300, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=timeout,
    )
    if check and result.returncode != 0:
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        raise RuntimeError(f"git {' '.join(args)} failed in {cwd}: {detail}")
    return result


def ensure_commit_available(repo_dir: Path, commit: str) -> None:
    probe = subprocess.run(
        ["git", "cat-file", "-e", f"{commit}^{{commit}}"],
        cwd=str(repo_dir),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=60,
    )
    if probe.returncode == 0:
        return
    subprocess.run(
        ["git", "fetch", "--unshallow", "--tags", "origin"],
        cwd=str(repo_dir),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=300,
    )
    fetch = subprocess.run(
        ["git", "fetch", "origin", commit],
        cwd=str(repo_dir),
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        timeout=300,
    )
    if fetch.returncode != 0:
        detail = ((fetch.stdout or "") + "\n" + (fetch.stderr or "")).strip()
        raise RuntimeError(f"unable to fetch commit {commit} in {repo_dir}: {detail}")


def reset_hard(repo_dir: Path, commit: str) -> None:
    ensure_commit_available(repo_dir, commit)
    git(["reset", "--hard", commit], cwd=repo_dir)
    git(["clean", "-fdx"], cwd=repo_dir)


def reverse_fix_commits_local(repo_dir: Path, fix_commits: list[str]) -> tuple[bool, str]:
    outputs: list[str] = []
    for fix_commit in reversed(fix_commits):
        ensure_commit_available(repo_dir, fix_commit)
        result = git(["revert", "--no-commit", fix_commit], cwd=repo_dir, check=False)
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            outputs.append(f"=== {fix_commit} ===\n{output}".strip())
            continue
        git(["revert", "--abort"], cwd=repo_dir, check=False)
        show = git(["show", "--binary", "--format=", fix_commit], cwd=repo_dir).stdout
        patch_path = repo_dir / ".historical_reverse.patch"
        patch_path.write_text(show, encoding="utf-8")
        fallback = git(["apply", "-R", "--3way", str(patch_path)], cwd=repo_dir, check=False)
        fallback_output = ((fallback.stdout or "") + "\n" + (fallback.stderr or "")).strip()
        combined = output
        if fallback_output:
            combined = f"{combined}\n\n=== reverse_apply_fallback ===\n{fallback_output}".strip()
        outputs.append(f"=== {fix_commit} ===\n{combined}".strip())
        patch_path.unlink(missing_ok=True)
        if fallback.returncode != 0:
            return False, "\n\n".join(item for item in outputs if item)
    return True, "\n\n".join(item for item in outputs if item)


def patch_mode_and_diff(record: dict[str, Any], repo_dir: Path) -> tuple[str, str]:
    commits = record.get("commits") or {}
    runtime = record.get("local_runtime") or {}
    secure_commit = str(runtime.get("secure_base_commit") or "").strip()
    if not secure_commit:
        raise RuntimeError("missing secure_base_commit")
    ensure_commit_available(repo_dir, secure_commit)

    vulnerable = normalize_commit_list(commits.get("vulnerable_commit_candidates") or [])
    if vulnerable:
        vuln_commit = vulnerable[0]
        ensure_commit_available(repo_dir, vuln_commit)
        diff = git(["diff", "--binary", f"{secure_commit}..{vuln_commit}"], cwd=repo_dir).stdout
        if not diff.strip():
            raise RuntimeError(f"empty patch diff from {secure_commit}..{vuln_commit}")
        return "direct_vulnerable_commit", diff

    fix_commits = normalize_commit_list(commits.get("fix_commits") or [])
    if not fix_commits:
        raise RuntimeError("missing fix_commits")
    reset_hard(repo_dir, secure_commit)
    ok, output = reverse_fix_commits_local(repo_dir, fix_commits)
    if not ok:
        raise RuntimeError(f"reverse_fix_failed: {output}")
    reverse_diff = git(["diff", "--binary", "HEAD"], cwd=repo_dir).stdout
    if not reverse_diff.strip():
        raise RuntimeError("empty patch diff after reverse_fix")
    reset_hard(repo_dir, secure_commit)
    return "reverse_fix", reverse_diff


def copy_testcase(src: Path, dst_dir: Path, testcase_id: str | None) -> Path:
    dst_dir.mkdir(parents=True, exist_ok=True)
    suffix = src.suffix or ".bin"
    name = f"historical_testcase_{testcase_id or 'seed'}{suffix}"
    dest = dst_dir / name
    shutil.copy2(src, dest)
    return dest


def selector_metadata(record: dict[str, Any]) -> dict[str, Any]:
    clusterfuzz = record.get("clusterfuzz") or {}
    fuzz_target = clusterfuzz.get("fuzz_target")
    if not fuzz_target:
        return {}
    return {
        "preferred_fuzzer": fuzz_target,
        "alternate_fuzzers": [],
        "source": "clusterfuzz_manifest",
    }


def build_injection_result(
    *,
    record: dict[str, Any],
    mode: str,
    patch_diff: str,
    staged_testcase: Path,
    source_testcase: Path,
) -> dict[str, Any]:
    project = str(record.get("project") or "")
    issue_id = str(record.get("issue_id") or "")
    clusterfuzz = record.get("clusterfuzz") or {}
    testcase = primary_testcase(record) or {}
    return {
        "project": project,
        "run_id": "",
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "status": "success",
        "selected_candidate_id": f"historical:{project}:{issue_id}",
        "cwe_group": "Historical",
        "cwe_id": "CWE-UNKNOWN",
        "strategy": {
            "id": "historical_manifest_bridge",
            "historical_testcase": {
                "issue_id": issue_id,
                "testcase_id": testcase.get("testcase_id") or clusterfuzz.get("testcase_id"),
                "host_path": str(source_testcase),
                "staged_path": str(staged_testcase),
            },
            "selection_candidate": {
                "candidate_id": f"historical:{issue_id}",
                "extra": {
                    "fuzz_native": selector_metadata(record),
                },
            },
            "historical_reconstruction": {
                "mode": mode,
                "secure_base_commit": ((record.get("local_runtime") or {}).get("secure_base_commit")),
                "fix_commits": (record.get("commits") or {}).get("fix_commits") or [],
                "vulnerable_commit_candidates": (record.get("commits") or {}).get("vulnerable_commit_candidates") or [],
            },
        },
        "artifacts": {
            "patch_diff": patch_diff,
            "attack_script": "",
        },
        "paths": {
            "historical_manifest_issue_id": issue_id,
        },
        "failure": None,
    }


def write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def prepare_project_run(
    *,
    project: str,
    records: list[dict[str, Any]],
    projects_root: Path,
    workspaces_root: Path,
    out_root: Path,
) -> dict[str, Any]:
    run_id = f"historical_prepare_{utc_now_compact()}"
    run_dir = out_root / project / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    attempts: list[dict[str, Any]] = []
    statuses = Counter()
    for index, record in enumerate(records):
        issue_id = str(record.get("issue_id") or "")
        attempt_dir = run_dir / f"attempt_{index:02d}"
        payload: dict[str, Any]
        try:
            testcase = primary_testcase(record)
            if testcase is None:
                raise RuntimeError("missing primary testcase")
            testcase_path = Path(str(testcase["path"])).expanduser().resolve()
            repo_dir = find_project_repo(projects_root, workspaces_root, record)
            mode, patch_diff = patch_mode_and_diff(record, repo_dir)
            staged = copy_testcase(
                testcase_path,
                attempt_dir / "reference",
                str(testcase.get("testcase_id") or ""),
            )
            injection = build_injection_result(
                record=record,
                mode=mode,
                patch_diff=patch_diff,
                staged_testcase=staged,
                source_testcase=testcase_path,
            )
            injection["run_id"] = run_id
            write_json(attempt_dir / "injection_result.json", injection)
            write_json(
                attempt_dir / "request.json",
                {
                    "project": project,
                    "issue_id": issue_id,
                    "mode": mode,
                    "source_manifest": "historical_bug_reproduction_manifest",
                    "timestamp_utc": datetime.now(UTC).isoformat(),
                },
            )
            write_json(attempt_dir / "source_manifest_record.json", record)
            payload = {
                "project": project,
                "issue_id": issue_id,
                "status": "prepared",
                "mode": mode,
                "attempt_dir": str(attempt_dir),
                "testcase_path": str(testcase_path),
            }
        except Exception as exc:
            payload = {
                "project": project,
                "issue_id": issue_id,
                "status": "failed",
                "failure_message": str(exc),
                "attempt_dir": str(attempt_dir),
            }
        attempts.append(payload)
        statuses[payload["status"]] += 1

    summary = {
        "project": project,
        "run_id": run_id,
        "run_dir": str(run_dir),
        "attempted": len(records),
        "prepared": statuses.get("prepared", 0),
        "failed": statuses.get("failed", 0),
        "statuses": dict(statuses),
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare historical fuzz attempt dirs from a reversal-style manifest.")
    parser.add_argument("--manifest", required=True, help="Path to reversal_inputs_manifest.jsonl")
    parser.add_argument("--projects-root", default=str(DEFAULT_PROJECTS_ROOT))
    parser.add_argument(
        "--workspace-root",
        default=str(DEFAULT_SHARED_WORKSPACES_ROOT),
        help="Root containing reusable local git clones under <project>/<target_dir>.",
    )
    parser.add_argument("--out-root", default=str(DEFAULT_OUT_ROOT))
    parser.add_argument("--projects", default=None, help="Comma-separated project allow-list.")
    parser.add_argument("--case", action="append", help="Case selector in project:issue_id form.")
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument(
        "--only-weak",
        action="store_true",
        help="Only include seed-ready historical cases that are not strong.",
    )
    parser.add_argument(
        "--include-strong",
        action="store_true",
        help="Include already-strong historical cases in addition to weak ones.",
    )
    args = parser.parse_args()

    manifest = Path(args.manifest).expanduser().resolve()
    projects_root = Path(args.projects_root).expanduser().resolve()
    workspaces_root = Path(args.workspace_root).expanduser().resolve()
    out_root = Path(args.out_root).expanduser().resolve()

    records = load_manifest(manifest)
    selected = historical_candidates(
        records,
        projects=parse_projects(args.projects),
        selectors=parse_selectors(args.case),
        include_strong=not args.only_weak or args.include_strong,
        include_weak=True,
        require_testcase=True,
    )
    if args.only_weak:
        selected = [record for record in selected if not bool((record.get("flags") or {}).get("reversal_ready_local_strong"))]
    if args.max_cases is not None:
        selected = selected[: args.max_cases]
    if not selected:
        raise SystemExit("No matching historical records to prepare.")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in selected:
        grouped[str(record.get("project") or "")].append(record)

    batch_id = f"historical_prepare_batch_{utc_now_compact()}"
    batch_dir = out_root / "_batches" / batch_id
    batch_dir.mkdir(parents=True, exist_ok=True)

    summaries = []
    for project, project_records in sorted(grouped.items()):
        summaries.append(
            prepare_project_run(
                project=project,
                records=project_records,
                projects_root=projects_root,
                workspaces_root=workspaces_root,
                out_root=out_root,
            )
        )

    batch_summary = {
        "batch_id": batch_id,
        "manifest": str(manifest),
        "projects_root": str(projects_root),
        "workspace_root": str(workspaces_root),
        "out_root": str(out_root),
        "project_count": len(summaries),
        "projects": [
            {
                "project": item["project"],
                "run_dir": item["run_dir"],
                "prepared": item["prepared"],
                "failed": item["failed"],
            }
            for item in summaries
        ],
    }
    write_json(batch_dir / "batch_summary.json", batch_summary)
    print(f"Wrote historical fuzz preparation batch to {batch_dir}")
    for item in summaries:
        print(f"{item['project']}: {item['run_dir']} prepared={item['prepared']} failed={item['failed']}")


if __name__ == "__main__":
    main()
