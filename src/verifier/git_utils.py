"""Git helpers for snapshotting, reverting, and restoring repository changes."""

import logging
import shutil
import subprocess
from pathlib import Path


logger = logging.getLogger(__name__)


def save_modifications_snapshot(directory: str) -> str:
    """Copy git-modified source files and exploit.sh into exploit_files/snapshot/.

    Returns the absolute path to the snapshot directory.
    """
    root = Path(directory)
    snapshot_dir = root / "exploit_files" / "snapshot"

    modifs_dir = snapshot_dir / "modifs"
    modifs_dir.mkdir(parents=True, exist_ok=True)

    result = subprocess.run(
        ["git", "diff", "--name-only"],
        cwd=directory,
        capture_output=True,
        text=True,
    )
    modified_files = [f.strip() for f in result.stdout.splitlines() if f.strip()]

    saved: list[str] = []
    for rel_path in modified_files:
        src = root / rel_path
        dst = modifs_dir / rel_path
        if src.exists():
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            saved.append(rel_path)

    exploit_sh = root / "exploit_files" / "exploit.sh"
    if exploit_sh.exists():
        shutil.copy2(exploit_sh, snapshot_dir / "exploit.sh")
        saved.append("exploit_files/exploit.sh")

    logger.info("Snapshot saved %d file(s) to %s", len(saved), snapshot_dir)
    return str(snapshot_dir)


def revert_codebase_changes(directory: str) -> None:
    """Revert all tracked modifications using git restore.

    Untracked files (e.g. exploit_files/) are left untouched.
    """
    subprocess.run(
        ["git", "restore", "."],
        cwd=directory,
        capture_output=True,
        check=True,
    )
    logger.info("Reverted tracked changes in %s", directory)


def restore_modifications_from_snapshot(directory: str, snapshot_path: str) -> None:
    """Re-apply modified source files from a previous snapshot back into the codebase."""
    root = Path(directory)
    modifs_dir = Path(snapshot_path) / "modifs"

    restored: list[str] = []
    for src in modifs_dir.rglob("*"):
        if src.is_file():
            rel = src.relative_to(modifs_dir)
            dst = root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            restored.append(str(rel))

    logger.info("Restored %d file(s) from snapshot %s", len(restored), snapshot_path)
