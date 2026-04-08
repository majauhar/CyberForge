"""Path helpers for runs/workspaces/project layout."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import re


def src_root() -> Path:
    return Path(__file__).resolve().parents[1]


def cwe_categories_csv() -> Path:
    return Path(__file__).resolve().parent / "cwe" / "cwe_categories.csv"


def workspace_root() -> Path:
    # src/ is under Vuljector/, which is sibling of vuljector-projects/.
    return src_root().parents[1]


def vuljector_root() -> Path:
    return src_root().parents[0]


def projects_root() -> Path:
    return workspace_root() / "vuljector-projects"


def runs_root() -> Path:
    return vuljector_root() / "runs"


def workspaces_root() -> Path:
    return runs_root() / "workspaces"


def project_root(project: str) -> Path:
    return projects_root() / project


def workspace_for_project(project: str) -> Path:
    return workspaces_root() / project


def new_run_id(prefix: str, suffix: str | None = None) -> str:
    # Parallel eval runs can start multiple phases within the same second.
    # Include microseconds, and optionally append a readable suffix such as the
    # model alias for easier inspection of run directories.
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    if suffix:
        clean = re.sub(r"[^A-Za-z0-9._-]+", "_", suffix.strip())
        clean = re.sub(r"_+", "_", clean).strip("._-")
        if clean:
            return f"{prefix}_{ts}_{clean}"
    return f"{prefix}_{ts}"


def init_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "init" / project / run_id


def setup_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "setup" / project / run_id


def selection_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "selection" / project / run_id


def injection_run_dir(project: str, run_id: str) -> Path:
    return runs_root() / "injection" / project / run_id


def agent_task_run_dir(project: str, task_type: str, run_id: str) -> Path:
    return runs_root() / "agent_tasks" / project / task_type / run_id
