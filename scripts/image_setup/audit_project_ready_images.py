#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "src"))

from setup.lifecycle import finish_phase, start_phase  # noqa: E402
from utils.json_io import write_json  # noqa: E402
from utils.paths import projects_root  # noqa: E402
from vuljector.core import build_runtime, load_project_config  # noqa: E402
from vuljector.run_setup import run_setup  # noqa: E402


def _timestamp() -> str:
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _load_projects(csv_path: Path) -> list[str]:
    with csv_path.open() as handle:
        return [row["projects"] for row in csv.DictReader(handle) if row.get("projects")]


def main() -> None:
    default_csv = Path(__file__).resolve().parent / "evaluation_projects.csv"
    parser = argparse.ArgumentParser(description="Build and inspect ready images for a list of projects.")
    parser.add_argument("--projects-csv", default=str(default_csv), help="CSV file with a 'projects' column.")
    args = parser.parse_args()

    csv_path = Path(args.projects_csv).expanduser().resolve()
    projects = _load_projects(csv_path)

    out_root = REPO_ROOT / "runs" / "project_ready_image_audit" / f"run_{_timestamp()}"
    out_root.mkdir(parents=True, exist_ok=True)

    results: list[dict] = []
    for project in projects:
        project_json = projects_root() / project / "project.json"
        if not project_json.exists():
            results.append(
                {
                    "project": project,
                    "status": "skipped",
                    "reason": "missing_project_json",
                    "executable_count": 0,
                    "executables": [],
                    "active_image_tag": "",
                }
            )
            continue

        run_setup(project)
        config = load_project_config(project)
        runtime = build_runtime(config)
        project_run_dir = out_root / project
        project_run_dir.mkdir(parents=True, exist_ok=True)
        start_phase(runtime, phase="ready_image_audit", run_dir=project_run_dir)
        try:
            manifest = runtime.inspect_out_manifest()
            result = {
                "project": project,
                "status": "ok",
                "secure_base_commit": config.secure_base_commit,
                "active_image_tag": runtime.active_image_tag,
                "executable_count": manifest.get("executable_count", 0),
                "executables": manifest.get("executables", []),
                "out_manifest": manifest,
            }
            write_json(project_run_dir / "out_manifest.json", manifest)
            results.append(result)
        finally:
            finish_phase(runtime)

    summary = {
        "timestamp_utc": datetime.now(UTC).isoformat(),
        "projects_csv": str(csv_path),
        "requested_projects": projects,
        "results": results,
    }
    write_json(out_root / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
