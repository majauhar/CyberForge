"""Initialize a new project config from oss-fuzz metadata."""

from __future__ import annotations

import sys
from pathlib import Path

from utils.json_io import write_json
from utils.paths import project_root


def run_init(
    project: str,
    *,
    oss_fuzz_path: str,
    target_dir: str | None = None,
) -> dict:
    oss_fuzz = Path(oss_fuzz_path).resolve()
    proj_dir = oss_fuzz / "projects" / project
    if not proj_dir.exists():
        raise ValueError(
            f"Project '{project}' not found in {oss_fuzz}/projects/. "
            "Check the project name and oss_fuzz_path."
        )

    # Resolve target_dir: try project.yaml first, then default to project name.
    resolved_target_dir = target_dir or _read_target_dir(proj_dir, project)

    out_dir = project_root(project)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = out_dir / "project.json"

    if cfg_path.exists():
        raise FileExistsError(
            f"project.json already exists at {cfg_path}. "
            "Delete it first if you want to reinitialize."
        )

    payload = {
        "schema_version": "v2",
        "target_dir": resolved_target_dir,
        "secure_base_commit": "",   # auto-detected by `setup`
        "oss_fuzz_path": str(oss_fuzz),
    }
    write_json(cfg_path, payload)

    return {
        "project": project,
        "config_path": str(cfg_path),
        "target_dir": resolved_target_dir,
        "oss_fuzz_path": str(oss_fuzz),
        "note": "secure_base_commit is empty — run `setup` to auto-detect it from the container",
    }


def _read_target_dir(proj_dir: Path, default: str) -> str:
    """Try to read the source subdirectory from oss-fuzz project.yaml."""
    yaml_path = proj_dir / "project.yaml"
    if not yaml_path.exists():
        return default
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        # Some projects declare 'primary_language' or 'main_repo' but not a
        # src dir — default to project name in that case.
        if stripped.startswith("fuzzing_engines:") or stripped.startswith("sanitizers:"):
            break
    # oss-fuzz doesn't have a canonical "src_dir" field; the source is always
    # at /src/<project> by convention unless the Dockerfile overrides it.
    return default
