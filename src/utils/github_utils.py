"""Git helpers for in-container repository operations."""

from __future__ import annotations

from pathlib import Path

from setup.container_runtime import ContainerRuntime


def reset_to_secure_commit(
    runtime: ContainerRuntime,
    *,
    repo_dir: str,
    secure_base_commit: str,
    git_backup_dir: Path | None = None,  # kept for call-site compatibility, unused
) -> None:
    # .git is always present in the container (baked into the OSS-Fuzz image).
    # No backup/restore needed — reset directly.
    runtime.exec(f"git config --global --add safe.directory {repo_dir}")
    if secure_base_commit:
        runtime.exec(
            f"git reset --hard {secure_base_commit}",
            workdir=repo_dir,
        ).raise_for_status("git reset to secure_base_commit failed")
    runtime.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean failed")
