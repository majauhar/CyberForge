#!/usr/bin/env python3
"""
Materialize OSS-Fuzz testcase blobs locally from canonical rich records.

This script:
  1. reads canonical rich records from a JSONL corpus,
  2. extracts testcase IDs from multiple lanes,
  3. downloads testcase blobs from oss-fuzz.com,
  4. stores them locally under runs/ossfuzz/materialized_testcases/,
  5. writes a run manifest + summary for later reproduction work.

Primary extraction lanes:
  - top-level testcase_ids
  - clusterfuzz.testcase_id
  - testcase_id=... embedded in report_text

The script is resumable: if a testcase blob already exists locally, it is
reported as `exists` instead of being downloaded again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
import re

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_RUNS = _VULJECTOR_ROOT / "runs" / "ossfuzz"
_DEFAULT_CANONICAL = _RUNS / "csv_rich_vuln_index.jsonl"
_DEFAULT_BLOB_ROOT = _RUNS / "materialized_testcases"
_DEFAULT_RUNS_ROOT = _RUNS / "testcase_materialization_runs"
_DEFAULT_PROJECTS_FILE = _RUNS / "c_cpp_rich_ossfuzz_non_secbench_20plus.txt"

_TESTCASE_URL = "https://oss-fuzz.com/download?testcase_id={testcase_id}"
_USER_AGENT = "Vuljector/1.0 testcase materializer"
_TESTCASE_ID_RE = re.compile(r"testcase_id=(\d+)")


@dataclass(frozen=True)
class TestcaseTarget:
    project: str
    issue_id: str
    testcase_id: str
    sources: tuple[str, ...]
    fuzz_target: str | None
    sanitizer: str | None


class GlobalRateLimiter:
    def __init__(self, min_interval: float) -> None:
        self.min_interval = min_interval
        self._lock = threading.Lock()
        self._next_allowed = 0.0

    def wait(self) -> None:
        if self.min_interval <= 0:
            return
        with self._lock:
            now = time.monotonic()
            if now < self._next_allowed:
                time.sleep(self._next_allowed - now)
                now = time.monotonic()
            self._next_allowed = now + self.min_interval


def utc_now_compact() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def extract_testcase_ids(record: dict[str, Any]) -> dict[str, set[str]]:
    lanes: dict[str, set[str]] = defaultdict(set)

    for testcase_id in record.get("testcase_ids") or []:
        if testcase_id:
            lanes["testcase_ids"].add(str(testcase_id))

    clusterfuzz = record.get("clusterfuzz") or {}
    if clusterfuzz.get("testcase_id"):
        lanes["clusterfuzz.testcase_id"].add(str(clusterfuzz["testcase_id"]))

    report_text = record.get("report_text") or ""
    for testcase_id in _TESTCASE_ID_RE.findall(report_text):
        lanes["report_text"].add(str(testcase_id))

    raw_bucket = (record.get("raw_records") or {}).get("bucket_testcases") or []
    for entry in raw_bucket:
        details = str((entry or {}).get("details") or "")
        for testcase_id in _TESTCASE_ID_RE.findall(details):
            lanes["raw_records.bucket_testcases"].add(str(testcase_id))

    return lanes


def load_targets(canonical_path: Path, project_filter: set[str] | None) -> list[TestcaseTarget]:
    dedup: dict[tuple[str, str, str], TestcaseTarget] = {}

    with canonical_path.open() as handle:
        for line in handle:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("record_kind") != "rich_oss_fuzz":
                continue

            project = str(record.get("project") or "")
            if not project:
                continue
            if project_filter is not None and project not in project_filter:
                continue

            issue_id = str(record.get("issue_id") or "")
            if not issue_id:
                continue

            lanes = extract_testcase_ids(record)
            all_ids = sorted({tid for values in lanes.values() for tid in values})
            if not all_ids:
                continue

            cf = record.get("clusterfuzz") or {}
            for testcase_id in all_ids:
                sources = tuple(sorted(name for name, ids in lanes.items() if testcase_id in ids))
                key = (project, issue_id, testcase_id)
                dedup[key] = TestcaseTarget(
                    project=project,
                    issue_id=issue_id,
                    testcase_id=testcase_id,
                    sources=sources,
                    fuzz_target=cf.get("fuzz_target"),
                    sanitizer=cf.get("sanitizer"),
                )

    return sorted(dedup.values(), key=lambda t: (t.project, t.issue_id, t.testcase_id))


def blob_path(blob_root: Path, target: TestcaseTarget) -> Path:
    return blob_root / target.project / target.issue_id / f"{target.testcase_id}.bin"


def load_project_filter(projects_file: Path | None) -> set[str] | None:
    if projects_file is None:
        return None
    return {
        line.strip()
        for line in projects_file.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def download_testcase(
    target: TestcaseTarget,
    blob_root: Path,
    limiter: GlobalRateLimiter,
    timeout: float,
    max_bytes: int,
) -> dict[str, Any]:
    out_path = blob_path(blob_root, target)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists() and out_path.stat().st_size > 0:
        return {
            "project": target.project,
            "issue_id": target.issue_id,
            "testcase_id": target.testcase_id,
            "url": _TESTCASE_URL.format(testcase_id=target.testcase_id),
            "status": "exists",
            "path": str(out_path),
            "size_bytes": out_path.stat().st_size,
            "sha256": sha256_file(out_path),
            "sources": list(target.sources),
            "fuzz_target": target.fuzz_target,
            "sanitizer": target.sanitizer,
        }

    url = _TESTCASE_URL.format(testcase_id=target.testcase_id)
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})

    limiter.wait()
    tmp_path = out_path.with_suffix(".tmp")
    bytes_written = 0
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content_type = resp.headers.get("Content-Type", "")
            with tmp_path.open("wb") as out:
                while True:
                    chunk = resp.read(1024 * 256)
                    if not chunk:
                        break
                    bytes_written += len(chunk)
                    if bytes_written > max_bytes:
                        raise ValueError(f"max_bytes exceeded ({max_bytes})")
                    out.write(chunk)
        tmp_path.replace(out_path)
        return {
            "project": target.project,
            "issue_id": target.issue_id,
            "testcase_id": target.testcase_id,
            "url": url,
            "status": "downloaded",
            "path": str(out_path),
            "size_bytes": out_path.stat().st_size,
            "sha256": sha256_file(out_path),
            "content_type": content_type,
            "sources": list(target.sources),
            "fuzz_target": target.fuzz_target,
            "sanitizer": target.sanitizer,
        }
    except urllib.error.HTTPError as exc:
        if tmp_path.exists():
            tmp_path.unlink()
        status = {
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            429: "rate_limited",
        }.get(exc.code, "http_error")
        return {
            "project": target.project,
            "issue_id": target.issue_id,
            "testcase_id": target.testcase_id,
            "url": url,
            "status": status,
            "http_status": exc.code,
            "error": str(exc),
            "sources": list(target.sources),
            "fuzz_target": target.fuzz_target,
            "sanitizer": target.sanitizer,
        }
    except Exception as exc:
        if tmp_path.exists():
            tmp_path.unlink()
        return {
            "project": target.project,
            "issue_id": target.issue_id,
            "testcase_id": target.testcase_id,
            "url": url,
            "status": "error",
            "error": str(exc),
            "sources": list(target.sources),
            "fuzz_target": target.fuzz_target,
            "sanitizer": target.sanitizer,
        }


def materialize(
    canonical_path: Path,
    blob_root: Path,
    run_root: Path,
    projects_file: Path | None,
    workers: int,
    min_interval: float,
    timeout: float,
    max_bytes: int,
    limit: int | None,
) -> dict[str, Any]:
    project_filter = load_project_filter(projects_file)
    targets = load_targets(canonical_path, project_filter)
    if limit is not None:
        targets = targets[:limit]

    run_dir = run_root / f"run_{utc_now_compact()}"
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = run_dir / "manifest.jsonl"
    summary_path = run_dir / "summary.json"

    limiter = GlobalRateLimiter(min_interval=min_interval)
    stats = Counter()
    by_project = Counter()
    by_source = Counter()
    by_status_and_project: dict[str, Counter[str]] = defaultdict(Counter)

    with manifest_path.open("w") as manifest, ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [
            executor.submit(download_testcase, target, blob_root, limiter, timeout, max_bytes)
            for target in targets
        ]
        total = len(futures)
        for idx, future in enumerate(as_completed(futures), start=1):
            result = future.result()
            manifest.write(json.dumps(result) + "\n")
            manifest.flush()

            status = result["status"]
            stats[status] += 1
            by_project[result["project"]] += 1
            by_status_and_project[result["project"]][status] += 1
            for source in result.get("sources") or []:
                by_source[source] += 1

            if idx == 1 or idx % 50 == 0 or idx == total:
                print(
                    f"[TESTCASE-MATERIALIZE] {idx}/{total} "
                    f"downloaded={stats['downloaded']} exists={stats['exists']} "
                    f"forbidden={stats['forbidden']} not_found={stats['not_found']} "
                    f"errors={stats['error'] + stats['http_error'] + stats['rate_limited'] + stats['unauthorized']}",
                    flush=True,
                )

    summary = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "canonical_path": str(canonical_path),
        "projects_file": str(projects_file) if projects_file else None,
        "blob_root": str(blob_root),
        "run_dir": str(run_dir),
        "targets": len(targets),
        "statuses": dict(stats),
        "source_hits": dict(by_source),
        "per_project": {
            project: {
                "targets": count,
                "statuses": dict(by_status_and_project[project]),
            }
            for project, count in sorted(by_project.items())
        },
    }
    summary_path.write_text(json.dumps(summary, indent=2))
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Materialize OSS-Fuzz testcase blobs locally")
    parser.add_argument("--canonical", default=str(_DEFAULT_CANONICAL))
    parser.add_argument(
        "--projects-file",
        default=str(_DEFAULT_PROJECTS_FILE),
        help="Optional newline-delimited project filter list; pass '' to disable filtering",
    )
    parser.add_argument("--blob-root", default=str(_DEFAULT_BLOB_ROOT))
    parser.add_argument("--run-root", default=str(_DEFAULT_RUNS_ROOT))
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--min-interval", type=float, default=0.10)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=50 * 1024 * 1024,
        help="Abort a single download if it exceeds this many bytes",
    )
    parser.add_argument("--limit", type=int, default=None, help="Optional cap on testcase targets")
    args = parser.parse_args()

    projects_file = None
    if args.projects_file:
        projects_file = Path(args.projects_file).expanduser().resolve()

    summary = materialize(
        canonical_path=Path(args.canonical).expanduser().resolve(),
        blob_root=Path(args.blob_root).expanduser().resolve(),
        run_root=Path(args.run_root).expanduser().resolve(),
        projects_file=projects_file,
        workers=args.workers,
        min_interval=args.min_interval,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        limit=args.limit,
    )

    print("[TESTCASE-MATERIALIZE] Done.")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
