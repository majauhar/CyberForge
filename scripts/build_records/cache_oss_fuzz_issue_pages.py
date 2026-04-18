#!/usr/bin/env python3
"""
Prefetch public OSS-Fuzz issue pages into a local HTML cache.

This is intended to speed up richer corpus builds:
  1. fetch issue pages concurrently into cache
  2. rerun build_rich_oss_fuzz_records.py with --no-fetch-issue-pages

Requests are globally rate-limited so concurrency hides network latency without
spiking request rate.
"""

from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from fetch_sources.mine_oss_fuzz_issue_tracker_records import fetch_issue_page, is_private_issue


_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_RECORDS_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "rich_records_full_csv"
_DEFAULT_CACHE_DIR = _VULJECTOR_ROOT / "runs" / "ossfuzz" / "issue_page_cache_full_csv"


def iter_issue_targets(records_dir: Path) -> list[tuple[str, str]]:
    targets: list[tuple[str, str]] = []
    for json_file in sorted(records_dir.glob("*/*.json")):
        try:
            record = json.loads(json_file.read_text())
        except Exception:
            continue
        project = record.get("project") or json_file.parent.name
        issue_id = record.get("issue_id") or json_file.stem
        if project and issue_id:
            targets.append((str(project), str(issue_id)))
    return targets


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


def prefetch_issue_pages(
    records_dir: Path,
    cache_dir: Path,
    workers: int,
    min_interval: float,
    force: bool = False,
) -> dict:
    targets = iter_issue_targets(records_dir)
    limiter = GlobalRateLimiter(min_interval=min_interval)

    stats = {
        "targets": len(targets),
        "cached": 0,
        "fetched": 0,
        "private": 0,
        "errors": 0,
    }

    def _fetch(project: str, issue_id: str) -> tuple[str, str, str]:
        html_path = cache_dir / project / f"{issue_id}.html"
        if html_path.exists() and not force:
            return project, issue_id, "cached"

        html_path.parent.mkdir(parents=True, exist_ok=True)
        limiter.wait()
        html = fetch_issue_page(issue_id, delay=0.0)
        if not html:
            return project, issue_id, "error"

        html_path.write_text(html)
        if is_private_issue(html):
            return project, issue_id, "private"
        return project, issue_id, "fetched"

    with ThreadPoolExecutor(max_workers=max(1, workers)) as executor:
        futures = [executor.submit(_fetch, project, issue_id) for project, issue_id in targets]
        total = len(futures)
        for idx, future in enumerate(as_completed(futures), start=1):
            _, _, status = future.result()
            if status in stats:
                stats[status] += 1
            if idx == 1 or idx % 250 == 0 or idx == total:
                print(
                    f"[PREFETCH-ISSUES] {idx}/{total} "
                    f"fetched={stats['fetched']} cached={stats['cached']} "
                    f"private={stats['private']} errors={stats['errors']}",
                    flush=True,
                )

    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description="Prefetch OSS-Fuzz issue pages into a local cache")
    parser.add_argument("--records-dir", default=str(_DEFAULT_RECORDS_DIR))
    parser.add_argument("--cache-dir", default=str(_DEFAULT_CACHE_DIR))
    parser.add_argument("--workers", type=int, default=6, help="Number of concurrent fetch workers")
    parser.add_argument(
        "--min-interval",
        type=float,
        default=0.15,
        help="Global minimum interval between requests in seconds",
    )
    parser.add_argument("--force", action="store_true", help="Refetch even if HTML cache already exists")
    args = parser.parse_args()

    stats = prefetch_issue_pages(
        records_dir=Path(args.records_dir).expanduser().resolve(),
        cache_dir=Path(args.cache_dir).expanduser().resolve(),
        workers=args.workers,
        min_interval=args.min_interval,
        force=args.force,
    )

    print("[PREFETCH-ISSUES] Done.")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
