"""Shared plumbing used by setup/selection/injection phase runners."""

from __future__ import annotations

from pathlib import Path

from setup.container_runtime import ContainerRuntime
from utils.json_io import read_json, write_json
from utils.paths import project_root, workspace_for_project
from vuljector.io_contracts import ProjectConfig


def load_project_config(project: str) -> ProjectConfig:
    cfg_path = project_root(project) / "project.json"
    if not cfg_path.exists():
        raise FileNotFoundError(f"Missing project.json: {cfg_path}")
    payload = read_json(cfg_path)
    target_dir = str(payload["target_dir"])
    main_repo_url = str(payload.get("main_repo_url", "")).strip()
    if not main_repo_url:
        raise ValueError(f"Missing main_repo_url in project.json: {cfg_path}")
    return ProjectConfig(
        project=project,
        target_dir=target_dir,
        secure_base_commit=str(payload.get("secure_base_commit", "")),
        main_repo_url=main_repo_url,
        unit_tests=payload.get("unit_tests"),
    )


def validate_project_config(config: ProjectConfig) -> None:
    """
    Lightweight validation for all ProjectConfig attributes.

    Notes:
    - secure_base_commit may be empty before setup auto-detects it.
    - unit_tests may be None or a dict.
    """
    problems: list[str] = []

    if not isinstance(config.project, str) or not config.project.strip():
        problems.append("project must be a non-empty")
    if not isinstance(config.target_dir, str) or not config.target_dir.strip():
        problems.append("target_dir must be a non-empty string")
    if not isinstance(config.main_repo_url, str) or not config.main_repo_url.strip():
        problems.append("main_repo_url must be a non-empty string")
    if not isinstance(config.secure_base_commit, str):
        problems.append("secure_base_commit must be a string (may be empty pre-setup)")
    if config.unit_tests is not None and not isinstance(config.unit_tests, dict):
        problems.append("unit_tests must be a dict or None")

    if problems:
        raise ValueError(f"Invalid ProjectConfig for project={config.project!r}: " + "; ".join(problems))


def save_project_config(project: str, payload: dict) -> None:
    write_json(project_root(project) / "project.json", payload)


def build_runtime(config: ProjectConfig) -> ContainerRuntime:
    return ContainerRuntime(
        project=config.project,
        setup_dir=project_root(config.project) / "setup",
        target_dir=config.target_dir,
        secure_base_commit=config.secure_base_commit,
        workspace_dir=workspace_for_project(config.project),
        main_repo_url=config.main_repo_url,
    )


def ensure_setup_completed(runtime: ContainerRuntime, project: str) -> None:
    if not runtime.setup_completed():
        raise RuntimeError(
            f"Setup not completed for project '{project}'. "
            "Run: python3 -m vuljector.cli setup <project>"
        )


def next_vulnerability_id(base_dir: Path) -> str:
    base_dir.mkdir(parents=True, exist_ok=True)
    used: list[int] = []
    for p in base_dir.iterdir():
        if p.is_dir() and p.name.startswith("vulnerability_"):
            try:
                used.append(int(p.name.split("_", 1)[1]))
            except (ValueError, IndexError):
                continue
    next_idx = max(used) + 1 if used else 0
    return f"vulnerability_{next_idx}"

