"""Mount helpers for phase runs."""

from __future__ import annotations

from pathlib import Path


def phase_mount_dir(run_dir: Path) -> Path:
    """Return host directory mounted as /workspace/run for this phase run."""
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir

