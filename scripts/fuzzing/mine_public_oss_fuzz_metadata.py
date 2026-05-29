#!/usr/bin/env python3
"""Mine public OSS-Fuzz Introspector/coverage data into a local offline cache."""

from __future__ import annotations

import argparse
import csv
import json
import re
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"
DEFAULT_OUT = REPO_ROOT / "runs" / "ossfuzz_metadata"

INTROSPECTOR_BUCKET = "oss-fuzz-introspector"
COVERAGE_BUCKET = "oss-fuzz-coverage"


def gcs_list_prefixes(bucket: str, prefix: str) -> list[str]:
    prefixes: list[str] = []
    page_token: str | None = None
    while True:
        params = {"prefix": prefix, "delimiter": "/"}
        if page_token:
            params["pageToken"] = page_token
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?{urllib.parse.urlencode(params)}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            payload = json.load(resp)
        prefixes.extend(payload.get("prefixes", []))
        page_token = payload.get("nextPageToken")
        if not page_token:
            break
    return prefixes


def gcs_list_objects(bucket: str, prefix: str) -> list[str]:
    names: list[str] = []
    page_token: str | None = None
    while True:
        params = {"prefix": prefix}
        if page_token:
            params["pageToken"] = page_token
        url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o?{urllib.parse.urlencode(params)}"
        with urllib.request.urlopen(url, timeout=60) as resp:
            payload = json.load(resp)
        names.extend(item["name"] for item in payload.get("items", []))
        page_token = payload.get("nextPageToken")
        if not page_token:
            break
    return names


def gcs_fetch_text(bucket: str, object_name: str) -> str:
    quoted = urllib.parse.quote(object_name, safe="")
    url = f"https://storage.googleapis.com/storage/v1/b/{bucket}/o/{quoted}?alt=media"
    with urllib.request.urlopen(url, timeout=60) as resp:
        return resp.read().decode("utf-8", errors="replace")


def gcs_fetch_json(bucket: str, object_name: str) -> Any:
    return json.loads(gcs_fetch_text(bucket, object_name))


def latest_date(bucket: str, prefix: str) -> str | None:
    dates: list[str] = []
    for entry in gcs_list_prefixes(bucket, prefix):
        m = re.search(r"/(\d{8})/$", entry)
        if m:
            dates.append(m.group(1))
    return max(dates) if dates else None


def normalize_source_path(path: str, project: str) -> str:
    clean = path.strip()
    clean = clean.replace("/work/build/../../src/", "/src/")
    clean = clean.replace("/workspace/source-code/", "/src/")
    clean = clean.replace("/workspace/", "/")
    clean = clean.replace("//", "/")
    return clean


def strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", text or "")).strip()


def parse_pairings_yaml(text: str) -> list[dict[str, str]]:
    pairings: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        if line.startswith("- executable_path:"):
            if current:
                pairings.append(current)
            current = {"executable_path": line.split(":", 1)[1].strip()}
        elif current is not None and line.strip().startswith("fuzzer_log_file:"):
            current["fuzzer_log_file"] = line.split(":", 1)[1].strip()
    if current:
        pairings.append(current)
    return pairings


def parse_fuzzer_names_from_objects(objects: set[str], prefix: str) -> list[str]:
    names: set[str] = set()
    pattern = re.compile(rf"^{re.escape(prefix)}fuzzerLogFile-(.+)\.data(?:\.yaml)?$")
    for object_name in objects:
        match = pattern.match(object_name)
        if match:
            names.add(match.group(1))
    return sorted(names)


def load_project_list(project_args: list[str] | None) -> list[str]:
    if project_args:
        return sorted(set(project_args))
    projects = []
    for project_json in sorted(PROJECTS_ROOT.glob("*/project.json")):
        data = json.loads(project_json.read_text())
        if data.get("project"):
            projects.append(str(data["project"]))
    return projects


def fetch_introspector_cache(project: str) -> dict[str, Any]:
    base_prefix = f"{project}/inspector-report/"
    date = latest_date(INTROSPECTOR_BUCKET, base_prefix)
    if not date:
        return {"available": False}

    date_prefix = f"{base_prefix}{date}/"
    objects = set(gcs_list_objects(INTROSPECTOR_BUCKET, date_prefix))
    required = {
        "functions": f"{date_prefix}all-fuzz-introspector-functions.json",
        "blockers": f"{date_prefix}branch-blockers.json",
        "pairings": f"{date_prefix}exe_to_fuzz_introspector_logs.yaml",
        "files": f"{date_prefix}all-files.json",
        "light_files": f"{date_prefix}light/all_files.json",
    }

    raw_functions: list[dict[str, Any]] = []
    blockers: dict[str, Any] = {}
    pairings: list[dict[str, str]] = []
    all_files: list[str] = []
    errors: list[str] = []

    if required["functions"] in objects:
        try:
            raw_functions = gcs_fetch_json(INTROSPECTOR_BUCKET, required["functions"])
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append(f"functions: {exc}")

    if required["blockers"] in objects:
        try:
            blockers = gcs_fetch_json(INTROSPECTOR_BUCKET, required["blockers"])
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append(f"blockers: {exc}")

    if required["pairings"] in objects:
        try:
            pairings = parse_pairings_yaml(gcs_fetch_text(INTROSPECTOR_BUCKET, required["pairings"]))
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            errors.append(f"pairings: {exc}")
    else:
        for fuzzer_name in parse_fuzzer_names_from_objects(objects, date_prefix):
            pairings.append(
                {
                    "executable_path": f"/out/{fuzzer_name}",
                    "fuzzer_log_file": f"{date_prefix}fuzzerLogFile-{fuzzer_name}.data",
                }
            )

    files_object = required["files"] if required["files"] in objects else required["light_files"]
    if files_object in objects:
        try:
            all_files = gcs_fetch_json(INTROSPECTOR_BUCKET, files_object)
        except (urllib.error.HTTPError, urllib.error.URLError, json.JSONDecodeError) as exc:
            errors.append(f"all_files: {exc}")

    if not raw_functions and not all_files and not pairings:
        payload: dict[str, Any] = {"available": False, "date": date}
        if errors:
            payload["error"] = "; ".join(errors)
        return payload

    functions = []
    for entry in raw_functions:
        functions.append(
            {
                "name": strip_html(entry.get("Func name", "")),
                "raw_name": entry.get("raw-function-name", ""),
                "source_file": normalize_source_path(entry.get("Functions filename", ""), project),
                "source_line_begin": entry.get("source_line_begin"),
                "source_line_end": entry.get("source_line_end"),
                "reached_by_fuzzers": entry.get("Reached by Fuzzers", []) or [],
                "runtime_reached_by_fuzzers": entry.get("Runtime reached by Fuzzers", []) or [],
                "combined_reached_by_fuzzers": entry.get("Combined reached by Fuzzers", []) or [],
                "call_depth": entry.get("Function call depth"),
                "cyclomatic_complexity": entry.get("Cyclomatic complexity"),
                "undiscovered_complexity": entry.get("Undiscovered complexity"),
                "functions_reached_count": entry.get("Functions reached"),
                "function_signature": entry.get("function_signature", ""),
                "callsites": entry.get("callsites", {}) or {},
            }
        )

    fuzzers = []
    for pairing in pairings:
        executable_path = pairing.get("executable_path", "")
        fuzzer_name = Path(executable_path).name
        fuzzers.append(
            {
                "name": fuzzer_name,
                "executable_path": executable_path,
                "log_base": pairing.get("fuzzer_log_file", ""),
                "blockers": blockers.get(fuzzer_name, []) or [],
            }
        )

    return {
        "available": True,
        "date": date,
        "fuzzers": fuzzers,
        "functions": functions,
        "all_files": [normalize_source_path(path, project) for path in all_files],
        **({"warnings": errors} if errors else {}),
    }


def fetch_coverage_cache(project: str, fuzzer_names: list[str]) -> dict[str, Any]:
    base_prefix = f"{project}/fuzzer_stats/"
    date = latest_date(COVERAGE_BUCKET, base_prefix)
    if not date:
        return {"available": False}

    requested_names = sorted(set(fuzzer_names))
    if not requested_names:
        object_names = gcs_list_objects(COVERAGE_BUCKET, f"{base_prefix}{date}/")
        requested_names = sorted(
            {
                Path(name).stem
                for name in object_names
                if name.endswith(".json") and name.startswith(f"{base_prefix}{date}/")
            }
        )

    fuzzer_stats: dict[str, Any] = {}
    for fuzzer_name in requested_names:
        object_name = f"{base_prefix}{date}/{fuzzer_name}.json"
        try:
            payload = json.loads(gcs_fetch_text(COVERAGE_BUCKET, object_name))
        except Exception:
            continue
        files = []
        for block in payload.get("data", []):
            for entry in block.get("files", []):
                files.append(
                    {
                        "filename": normalize_source_path(entry.get("filename", ""), project),
                        "summary": entry.get("summary", {}),
                    }
                )
        fuzzer_stats[fuzzer_name] = {"files": files}

    return {"available": True, "date": date, "fuzzer_stats": fuzzer_stats}


def mine_project(project: str) -> dict[str, Any]:
    introspector = fetch_introspector_cache(project)
    fuzzer_names = [f["name"] for f in introspector.get("fuzzers", [])] if introspector.get("available") else []
    coverage = fetch_coverage_cache(project, fuzzer_names)
    if introspector.get("available") and not introspector.get("fuzzers"):
        introspector["fuzzers"] = [
            {
                "name": name,
                "executable_path": f"/out/{name}",
                "log_base": "",
                "blockers": [],
            }
            for name in sorted((coverage.get("fuzzer_stats") or {}).keys())
        ]
    project_json = json.loads((PROJECTS_ROOT / project / "project.json").read_text())
    return {
        "project": project,
        "dockerhub_image": project_json.get("dockerhub_image", ""),
        "main_repo_url": project_json.get("main_repo_url", ""),
        "introspector": introspector,
        "coverage": coverage,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", action="append", help="Project(s) to mine. Default: all local projects.")
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    projects = load_project_list(args.project)
    args.out_dir.mkdir(parents=True, exist_ok=True)
    index = []
    for project in projects:
        payload = mine_project(project)
        out_path = args.out_dir / f"{project}.json"
        out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        index.append(
            {
                "project": project,
                "cache_file": str(out_path),
                "introspector_date": payload.get("introspector", {}).get("date"),
                "coverage_date": payload.get("coverage", {}).get("date"),
                "fuzzer_count": len(payload.get("introspector", {}).get("fuzzers", [])),
            }
        )
    (args.out_dir / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
