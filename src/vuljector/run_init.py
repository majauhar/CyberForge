"""Initialize project.json from OSS-Fuzz metadata (bootstrap only)."""

from __future__ import annotations

import re
import shutil
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
            f"Project '{project}' not found under {oss_fuzz}/projects/. "
            "Check the project name and oss_fuzz_path."
        )

    repo_url = _main_repo_url(proj_dir)
    resolved_target_dir = target_dir or _infer_target_dir(proj_dir, repo_url, project)

    out_dir = project_root(project)
    out_dir.mkdir(parents=True, exist_ok=True)
    cfg_path = out_dir / "project.json"
    setup_dir = out_dir / "setup"

    if cfg_path.exists():
        raise FileExistsError(
            f"project.json already exists at {cfg_path}. "
            "Delete it first if you want to reinitialize."
        )
    # Extract OSS-Fuzz project files into local setup/ build context.
    setup_dir.mkdir(parents=True, exist_ok=True)
    for f in proj_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, setup_dir / f.name)

    payload = {
        "project": project,
        "main_repo_url": repo_url,
        "target_dir": resolved_target_dir,
        "secure_base_commit": "",   # auto-detected by `setup`
    }
    write_json(cfg_path, payload)

    return {
        "project": project,
        "config_path": str(cfg_path),
        "target_dir": resolved_target_dir,
        "note": "secure_base_commit is empty; run `setup` to auto-detect it from the container.",
    }


def _main_repo_url(oss_fuzz_project_dir: Path) -> str:
    yaml_path = oss_fuzz_project_dir / "project.yaml"
    if not yaml_path.exists():
        raise ValueError(f"Missing project.yaml: {yaml_path}")
    for line in yaml_path.read_text(encoding="utf-8").splitlines():
        if line.strip().startswith("main_repo:"):
            url = line.split("main_repo:", 1)[1].strip().strip('"').strip("'")
            if url:
                return url
            raise ValueError(f"Empty main_repo in {yaml_path}")
    raise ValueError(f"No main_repo in {yaml_path}")


def _infer_target_dir(oss_fuzz_project_dir: Path, repo_url: str, default: str) -> str:
    # Infer target_dir as the path relative to /src where the main repo lands.
    dockerfile = oss_fuzz_project_dir / "Dockerfile"
    if not dockerfile.exists():
        return default

    text = dockerfile.read_text(encoding="utf-8")
    # Join backslash-continued Dockerfile lines so clone commands parse as one command.
    joined = re.sub(r"\\\s*\n", " ", text)
    main_norm = _normalize_repo_url(repo_url)
    clone_re = re.compile(
        r"git\s+clone\s+(?:(?:--[^\s=]+(?:=[^\s]+)?|-[A-Za-z])\s+[^\s]+\s+|(?:--[^\s=]+(?:=[^\s]+)?|-[A-Za-z])\s+)*([^\s]+)(?:\s+([^\s;&|]+))?",
        re.IGNORECASE,
    )

    for line in joined.splitlines():
        for m in clone_re.finditer(line):
            clone_url = _normalize_repo_url(m.group(1))
            if clone_url != main_norm:
                continue
            dest = (m.group(2) or "").strip().strip("'\"")
            if dest:
                return _target_dir_from_dest(dest, default)
            # No explicit destination -> git clone default folder is repo basename.
            return _repo_basename(repo_url) or default
    return default


def _normalize_repo_url(url: str) -> str:
    u = url.strip().strip("'\"").rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    if u.startswith("git@") and ":" in u:
        # git@github.com:owner/repo -> github.com/owner/repo
        host, path = u[4:].split(":", 1)
        return f"{host}/{path}".lower()
    return u.lower()


def _repo_basename(url: str) -> str:
    cleaned = url.strip().strip("'\"").rstrip("/")
    if cleaned.endswith(".git"):
        cleaned = cleaned[:-4]
    return cleaned.rsplit("/", 1)[-1]


def _target_dir_from_dest(dest: str, default: str) -> str:
    rel = dest.strip().strip("'\"").rstrip("/")
    for prefix in ("$SRC/", "${SRC}/", "/src/"):
        if rel.startswith(prefix):
            rel = rel[len(prefix):]
            break
    if rel.startswith("./"):
        rel = rel[2:]
    rel = rel.lstrip("/")
    return rel or default
