"""Path helpers for runs/workspaces/project layout."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path


def src_root() -> Path:
    return Path(__file__).resolve().parents[1]


def workspace_root() -> Path:
    # src/ is under VulInjector/, which is sibling of vuljector-projects/.
    return src_root().parents[1]


def vulinjector_root() -> Path:
    return src_root().parents[0]


def projects_root() -> Path:
    return workspace_root() / "vuljector-projects"


def runs_root() -> Path:
    return vulinjector_root() / "runs"


def workspaces_root() -> Path:
    return runs_root() / "workspaces"


def project_root(project: str) -> Path:
    return projects_root() / project


def workspace_for_project(project: str) -> Path:
    return workspaces_root() / project


def new_run_id(prefix: str) -> str:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{ts}"


def setup_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "setup" / project / run_id


def selection_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "selection" / project / run_id


def injection_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "injection" / project / run_id

