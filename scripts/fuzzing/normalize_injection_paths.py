#!/usr/bin/env python3
"""Normalize reroutable path references in injection-run metadata."""

from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
RUNS_ROOT = REPO_ROOT / "runs" / "injection"
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"
# Legacy absolute-path prefixes that may still appear in older run metadata.
# Override via env if your archived runs used a different original location.
OLD_WORKSPACE_ROOT = os.environ.get("VULJECTOR_LEGACY_WORKSPACE_ROOT", "/legacy/Vuljector-lane2-incontext")
OLD_PROJECTS_ROOT = os.environ.get("VULJECTOR_LEGACY_PROJECTS_ROOT", "/legacy/vuljector-projects")


@dataclass
class FileReport:
    path: str
    updated_fields: list[str] = field(default_factory=list)
    unresolved_fields: list[str] = field(default_factory=list)


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def dump_json(path: Path, payload: Any) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def resolve_local_reference(raw_path: str, file_path: Path) -> str | None:
    name = Path(raw_path).name
    attempt_dir = file_path.parent
    for rel in ("reference", "exploit_seed", "artifacts/exploit_files"):
        candidate = attempt_dir / rel / name
        if candidate.exists():
            return str(candidate)
    return None


def normalize_known_path(raw_path: str, file_path: Path) -> tuple[str | None, str | None]:
    value = raw_path.strip()
    if value.startswith(OLD_WORKSPACE_ROOT + "/"):
        suffix = value.split(OLD_WORKSPACE_ROOT + "/", 1)[1]
        candidate = REPO_ROOT / suffix
        if candidate.exists():
            return str(candidate), None
        local_ref = resolve_local_reference(value, file_path)
        if local_ref:
            return local_ref, None
        return None, "missing_local_workspace_target"
    if value.startswith(OLD_PROJECTS_ROOT + "/"):
        suffix = value.split(OLD_PROJECTS_ROOT + "/", 1)[1]
        candidate = PROJECTS_ROOT / suffix
        return (str(candidate), None) if candidate.exists() else (None, "missing_local_project_target")
    if value.startswith("runs/"):
        candidate = REPO_ROOT / value
        return (str(candidate), None) if candidate.exists() else (None, "missing_relative_runs_target")
    if value.startswith("/tmp/reference/"):
        candidate = resolve_local_reference(value, file_path)
        return (candidate, None) if candidate else (None, "missing_local_reference_copy")
    return (None, None)


def walk_and_normalize(node: Any, file_path: Path, *, apply: bool, trail: str = "") -> tuple[Any, list[str], list[str]]:
    updated_fields: list[str] = []
    unresolved_fields: list[str] = []

    if isinstance(node, dict):
        result: dict[str, Any] = {}
        for key, value in node.items():
            child_trail = f"{trail}.{key}" if trail else key
            new_value, child_updates, child_unresolved = walk_and_normalize(value, file_path, apply=apply, trail=child_trail)
            result[key] = new_value
            updated_fields.extend(child_updates)
            unresolved_fields.extend(child_unresolved)
        return result, updated_fields, unresolved_fields

    if isinstance(node, list):
        result = []
        for idx, value in enumerate(node):
            child_trail = f"{trail}[{idx}]"
            new_value, child_updates, child_unresolved = walk_and_normalize(value, file_path, apply=apply, trail=child_trail)
            result.append(new_value)
            updated_fields.extend(child_updates)
            unresolved_fields.extend(child_unresolved)
        return result, updated_fields, unresolved_fields

    if isinstance(node, str):
        normalized, reason = normalize_known_path(node, file_path)
        if normalized and normalized != node:
            updated_fields.append(f"{trail}: {node} -> {normalized}")
            return normalized if apply else node, updated_fields, unresolved_fields
        if reason:
            unresolved_fields.append(f"{trail}: {node} [{reason}]")
        return node, updated_fields, unresolved_fields

    return node, updated_fields, unresolved_fields


def normalize_file(path: Path, *, apply: bool) -> FileReport | None:
    payload = load_json(path)
    new_payload, updated_fields, unresolved_fields = walk_and_normalize(payload, path, apply=apply)
    if apply and updated_fields:
        dump_json(path, new_payload)
    if not updated_fields and not unresolved_fields:
        return None
    return FileReport(path=str(path), updated_fields=updated_fields, unresolved_fields=unresolved_fields)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true", help="Rewrite reroutable JSON string fields in place.")
    parser.add_argument("--project", action="append", help="Limit to one or more projects.")
    parser.add_argument("--output", type=Path, help="Write a JSON report to this path.")
    args = parser.parse_args()

    project_filter = set(args.project or [])
    reports: list[dict[str, Any]] = []
    for path in sorted(RUNS_ROOT.rglob("*.json")):
        if project_filter and path.parts[len(RUNS_ROOT.parts)] not in project_filter:
            continue
        report = normalize_file(path, apply=args.apply)
        if report is None:
            continue
        reports.append(
            {
                "path": report.path,
                "updated_fields": report.updated_fields,
                "unresolved_fields": report.unresolved_fields,
            }
        )

    payload = {
        "runs_root": str(RUNS_ROOT),
        "apply": args.apply,
        "file_count": len(reports),
        "reports": reports,
    }

    text = json.dumps(payload, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text)


if __name__ == "__main__":
    main()
