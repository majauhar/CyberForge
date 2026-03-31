"""Snapshot generation from git diff and copy to dataset directories."""

from __future__ import annotations

from pathlib import Path

from setup.container_runtime import ContainerRuntime
from utils.json_io import write_json
from vuljector.io_contracts import SnapshotFile, SnapshotManifest


def build_snapshot_from_container(
    runtime: ContainerRuntime,
    *,
    project: str,
    vulnerability_id: str,
    repo_dir: str,
    snapshot_dir: Path,
) -> SnapshotManifest:
    snapshot_files_root = snapshot_dir / "files"
    snapshot_files_root.mkdir(parents=True, exist_ok=True)

    status = runtime.exec("git diff --name-status", workdir=repo_dir)
    status.raise_for_status("git diff --name-status failed")

    files: list[SnapshotFile] = []
    for line in status.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        change_code, repo_path = parts[0].strip(), parts[1].strip()
        change_type = _map_change_type(change_code)
        snap_path = Path("snapshot/files") / repo_path
        files.append(
            SnapshotFile(
                repo_path=repo_path,
                snapshot_path=snap_path.as_posix(),
                change_type=change_type,
            )
        )
        if change_type != "deleted":
            host_target = snapshot_files_root / repo_path
            host_target.parent.mkdir(parents=True, exist_ok=True)
            runtime.copy_from(f"{repo_dir}/{repo_path}", host_target)

    manifest = SnapshotManifest(
        project=project,
        vulnerability_id=vulnerability_id,
        files=files,
    )
    write_json(snapshot_dir / "manifest.json", manifest.to_dict())
    return manifest


def _map_change_type(code: str) -> str:
    c = code[:1]
    if c == "A":
        return "added"
    if c == "D":
        return "deleted"
    if c == "R":
        return "renamed"
    return "modified"

