"""Initialize a project: metadata, image build, commit detection, test harness."""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from setup.setup_test_harness import (
    copy_default_parser_template,
    run_baseline_unit_tests,
    try_agent_harness,
    try_heuristic_harness,
    validate_unit_tests_dir,
)
from utils.json_io import write_json
from utils.paths import init_run_dir, new_run_id, project_root
from vuljector.core import build_runtime, load_project_config
from vuljector.io_contracts import ProjectConfig

logger = logging.getLogger(__name__)


def run_init(
    project: str,
    *,
    oss_fuzz_path: str,
    target_dir: str | None = None,
    model_id: str = "claude-sonnet-4-6",
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
    cfg_path = out_dir / "project.json"
    if cfg_path.exists():
        raise FileExistsError(
            f"project.json already exists at {cfg_path}. "
            "Delete it first if you want to reinitialize."
        )

    out_dir.mkdir(parents=True, exist_ok=True)
    setup_dir = out_dir / "setup"
    setup_dir.mkdir(parents=True, exist_ok=True)
    for f in proj_dir.iterdir():
        if f.is_file():
            shutil.copy2(f, setup_dir / f.name)

    payload: dict = {
        "project": project,
        "main_repo_url": repo_url,
        "target_dir": resolved_target_dir,
        "secure_base_commit": "",
    }
    write_json(cfg_path, payload)

    config = load_project_config(project)
    runtime = build_runtime(config)
    runtime.ensure_image()

    commit = _detect_commit(runtime)
    config.secure_base_commit = commit
    runtime.secure_base_commit = commit
    runtime.main_repo_url = repo_url
    payload["secure_base_commit"] = commit
    write_json(cfg_path, payload)
    logger.info("[%s] secure_base_commit: %s", project, commit)

    run_id = new_run_id("init")
    run_dir = init_run_dir(project, run_id)

    unit_tests_dir = out_dir / "unit_tests"
    copy_default_parser_template(unit_tests_dir)
    if not try_heuristic_harness(
        runtime=runtime, project=project,
        src_dir=resolved_target_dir, unit_tests_dir=unit_tests_dir,
    ):
        try_agent_harness(
            runtime=runtime, project=project,
            run_dir=run_dir,
            model_id=model_id,
            src_dir=resolved_target_dir,
            unit_tests_dir=unit_tests_dir,
        )

    ok, msg = validate_unit_tests_dir(unit_tests_dir)
    if not ok:
        raise RuntimeError(f"[{project}] Test harness invalid after init: {msg}")

    expected_count, unit_tests_enabled = run_baseline_unit_tests(runtime=runtime, project=project)

    payload["unit_tests"] = {
        "enabled": unit_tests_enabled,
        "expected_passing_count": expected_count,
    }
    write_json(cfg_path, payload)

    return {
        "project": project,
        "run_id": run_id,
        "config_path": str(cfg_path),
        "target_dir": resolved_target_dir,
        "secure_base_commit": commit,
        "unit_tests": payload["unit_tests"],
    }


def _detect_commit(runtime) -> str:
    result = subprocess.run(
        ["docker", "run", "--rm", runtime.image_tag,
         "git", "-C", runtime.repo_dir_in_container, "rev-parse", "HEAD"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"[{runtime.project}] Could not detect commit from image: {result.stderr.strip()}"
        )
    return result.stdout.strip()


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
    dockerfile = oss_fuzz_project_dir / "Dockerfile"
    if not dockerfile.exists():
        return default

    text = dockerfile.read_text(encoding="utf-8")
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
            return _repo_basename(repo_url) or default
    return default


def _normalize_repo_url(url: str) -> str:
    u = url.strip().strip("'\"").rstrip("/")
    if u.endswith(".git"):
        u = u[:-4]
    if u.startswith("git@") and ":" in u:
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
