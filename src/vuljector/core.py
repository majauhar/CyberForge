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
    return ProjectConfig(
        schema_version=str(payload.get("schema_version", "v2")),
        project=project,
        target_dir=str(payload["target_dir"]),
        secure_base_commit=str(payload.get("secure_base_commit", "")),
        repos=dict(payload.get("repos", {})),
        source=dict(payload.get("source", {})),
        unit_tests=payload.get("unit_tests"),
        oss_fuzz_path=payload.get("oss_fuzz_path") or None,
        dockerhub_image=payload.get("dockerhub_image") or None,
        language=payload.get("language") or None,
    )


def save_project_config(project: str, payload: dict) -> None:
    write_json(project_root(project) / "project.json", payload)


def build_runtime(config: ProjectConfig) -> ContainerRuntime:
    oss_fuzz = Path(config.oss_fuzz_path) if config.oss_fuzz_path else None
    return ContainerRuntime(
        project=config.project,
        setup_dir=project_root(config.project) / "setup",
        target_dir=config.target_dir,
        secure_base_commit=config.secure_base_commit,
        workspace_dir=workspace_for_project(config.project),
        oss_fuzz_path=oss_fuzz,
        repos=config.repos,
        dockerhub_image=config.dockerhub_image,
        language=config.language,
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

