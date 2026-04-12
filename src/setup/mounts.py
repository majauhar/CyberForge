"""Mount helpers for phase runs."""

from __future__ import annotations

from pathlib import Path

RUN_ROOT = "/workspace/run"
RUN_MOUNT_POINT = f"{RUN_ROOT}/attempt"


def phase_mount_dir(run_dir: Path) -> Path:
    """Return host directory mounted as /workspace/run/attempt for this phase run."""
    run_dir.mkdir(parents=True, exist_ok=True)
    return run_dir
