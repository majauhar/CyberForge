"""Git helpers for in-container repository operations and .git access control."""

from __future__ import annotations

import shutil
from pathlib import Path

from setup.container_runtime import ContainerRuntime


def remove_git_dir(runtime: ContainerRuntime, repo_dir: str) -> None:
    runtime.exec("rm -rf .git", workdir=repo_dir).raise_for_status("remove .git failed")


def backup_git_dir(runtime: ContainerRuntime, repo_dir: str, backup_dir: Path) -> None:
    if backup_dir.exists():
        shutil.rmtree(backup_dir)
    backup_dir.parent.mkdir(parents=True, exist_ok=True)
    runtime.copy_from(f"{repo_dir}/.git", backup_dir)


def restore_git_dir(runtime: ContainerRuntime, repo_dir: str, backup_dir: Path) -> None:
    if not backup_dir.exists():
        raise FileNotFoundError(f"Missing .git backup: {backup_dir}")
    runtime.exec("rm -rf .git", workdir=repo_dir).raise_for_status("cleanup .git failed")
    runtime.copy_to(backup_dir, f"{repo_dir}/.git")


def reset_to_secure_commit(
    runtime: ContainerRuntime,
    *,
    repo_dir: str,
    secure_base_commit: str,
    git_backup_dir: Path,
) -> None:
    # Restore git metadata only for the reset operation.
    restore_git_dir(runtime, repo_dir, git_backup_dir)
    if secure_base_commit:
        runtime.exec(
            f"git reset --hard {secure_base_commit}",
            workdir=repo_dir,
        ).raise_for_status("git reset to secure_base_commit failed")
    runtime.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean failed")
    # Remove git metadata from agent-visible state immediately after reset.
    remove_git_dir(runtime, repo_dir)

