from __future__ import annotations

import json
import re
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterator


_BUCKET_LIST_URL = "https://storage.googleapis.com/storage/v1/b/oss-fuzz-osv-vulns/o"
_BUCKET_OBJECT_URL = "https://oss-fuzz-osv-vulns.storage.googleapis.com/{key}"

_ISSUE_URL_RE = re.compile(
    r"(?:bugs\.chromium\.org/p/oss-fuzz/issues/detail\?id=|issues\.oss-fuzz\.com/issues/)(\d+)"
)


def iter_bucket_items(prefix: str) -> Iterator[dict]:
    token: str | None = None
    while True:
        params = {"prefix": prefix, "maxResults": "1000"}
        if token:
            params["pageToken"] = token
        url = f"{_BUCKET_LIST_URL}?{urllib.parse.urlencode(params)}"
        with urllib.request.urlopen(url, timeout=30) as resp:
            data = json.load(resp)

        for item in data.get("items", []):
            name = item.get("name")
            if name:
                yield item

        token = data.get("nextPageToken")
        if not token:
            break


def list_bucket_objects(prefix: str) -> Iterator[str]:
    for item in iter_bucket_items(prefix):
        name = item.get("name")
        if name:
            yield str(name)


def fetch_bucket_json(key: str) -> dict:
    url = _BUCKET_OBJECT_URL.format(key=key)
    with urllib.request.urlopen(url, timeout=30) as resp:
        return json.load(resp)


def sync_bucket_prefix(prefix: str, cache_root: Path, workers: int = 16) -> Path:
    prefix_dir = cache_root / prefix.rstrip("/")
    prefix_dir.mkdir(parents=True, exist_ok=True)

    pending: list[tuple[str, str, Path]] = []
    for item in iter_bucket_items(prefix):
        key = str(item["name"])
        media_link = item.get("mediaLink")
        if not media_link:
            continue
        local_path = cache_root / key
        if local_path.exists():
            continue
        local_path.parent.mkdir(parents=True, exist_ok=True)
        pending.append((key, str(media_link), local_path))

    def _download(media_link: str, local_path: Path) -> bool:
        tmp_path = local_path.with_suffix(local_path.suffix + ".tmp")
        try:
            with urllib.request.urlopen(media_link, timeout=30) as resp:
                data = resp.read()
        except Exception:
            return False
        tmp_path.write_bytes(data)
        tmp_path.replace(local_path)
        return True

    if pending:
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(_download, media_link, local_path): key
                for key, media_link, local_path in pending
            }
            completed = 0
            total = len(futures)
            for future in as_completed(futures):
                future.result()
                completed += 1
                if completed == 1 or completed % 500 == 0 or completed == total:
                    print(f"[OSS-FUZZ-VULNS-BUCKET] Synced {prefix} {completed}/{total}", flush=True)

    return prefix_dir


def iter_bucket_records(
    prefix: str,
    cache_root: Path | None = None,
    sync: bool = False,
    workers: int = 16,
) -> Iterator[tuple[str, dict]]:
    if cache_root is not None:
        prefix_dir = cache_root / prefix.rstrip("/")
        if sync:
            prefix_dir = sync_bucket_prefix(prefix, cache_root, workers=workers)
        if prefix_dir.exists():
            for local_path in sorted(prefix_dir.glob("*.json")):
                try:
                    yield f"{prefix.rstrip('/')}/{local_path.name}", json.loads(local_path.read_text())
                except Exception:
                    continue
            return

    for key in list_bucket_objects(prefix):
        try:
            yield key, fetch_bucket_json(key)
        except Exception:
            continue


def extract_issue_id(record: dict, key: str | None = None) -> str | None:
    if key:
        path = Path(key)
        if path.parent.as_posix() == "issue" and path.suffix == ".json":
            return path.stem

    texts: list[str] = []
    texts.append(record.get("details") or "")
    for ref in record.get("references", []):
        if isinstance(ref, dict):
            texts.append(ref.get("url") or "")

    for match in _ISSUE_URL_RE.finditer(" ".join(texts)):
        return match.group(1)
    return None


def extract_repo_url(record: dict) -> str | None:
    for affected in record.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") == "GIT":
                repo = rng.get("repo")
                if repo:
                    return str(repo)
    return None


def extract_package_names(record: dict, ecosystem: str | None = "OSS-Fuzz") -> list[str]:
    names: list[str] = []
    for affected in record.get("affected", []):
        pkg = affected.get("package", {})
        if ecosystem and pkg.get("ecosystem") != ecosystem:
            continue
        name = pkg.get("name")
        if name:
            names.append(str(name))
    return list(dict.fromkeys(names))


def has_fix_range(record: dict) -> bool:
    for affected in record.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            for event in rng.get("events", []):
                if event.get("fixed") and event.get("fixed") != "0":
                    return True
    return False


def has_any_git_repo(record: dict) -> bool:
    return extract_repo_url(record) is not None


def has_any_package(record: dict) -> bool:
    return bool(extract_package_names(record, ecosystem=None))


def choose_better_record(current: dict | None, candidate: dict) -> dict:
    if current is None:
        return candidate

    def score(record: dict) -> tuple[int, int, int]:
        return (
            1 if extract_package_names(record, ecosystem=None) else 0,
            1 if extract_repo_url(record) else 0,
            1 if has_fix_range(record) else 0,
        )

    return candidate if score(candidate) > score(current) else current
