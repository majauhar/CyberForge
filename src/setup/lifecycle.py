"""Lifecycle helpers for setup/selection/injection phases."""

from __future__ import annotations

from pathlib import Path

from setup.container_runtime import ContainerRuntime
from setup.mounts import phase_mount_dir


def start_phase(runtime: ContainerRuntime, *, phase: str, run_dir: Path) -> None:
    runtime.start_for_run(phase=phase, run_mount_dir=phase_mount_dir(run_dir))
    runtime.ensure_repo_exists()


def finish_phase(runtime: ContainerRuntime) -> None:
    runtime.stop()

