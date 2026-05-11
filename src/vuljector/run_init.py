"""Initialize a project: metadata, image build, commit detection, test harness."""

from __future__ import annotations

import csv
import logging
import shutil
import subprocess
from pathlib import Path

from setup.oss_fuzz_project import infer_target_dir
from setup.setup_test_harness import (
    copy_default_parser_template,
    run_baseline_unit_tests,
    try_agent_harness,
    try_heuristic_harness,
    validate_unit_tests_dir,
)
from setup.dockerhub_image import dockerhub_image_ref, dockerhub_tag_for_engine, publish_ready_image
from utils.json_io import write_json
from utils.paths import init_run_dir, new_run_id, project_root, vuljector_root
from vuljector.core import build_runtime, fuzzing_engine_supports_language, load_project_config, normalize_fuzzing_engine
from vuljector.io_contracts import ProjectConfig

logger = logging.getLogger(__name__)


def run_init(
    project: str,
    *,
    oss_fuzz_path: str,
    target_dir: str | None = None,
    model_id: str = "claude-sonnet-4-6",
    fuzzing_engine: str = "libfuzzer",
    publish_dockerhub_namespace: str | None = None,
) -> dict:
    oss_fuzz = Path(oss_fuzz_path).resolve()
    proj_dir = oss_fuzz / "projects" / project
    if not proj_dir.exists():
        raise ValueError(
            f"Project '{project}' not found under {oss_fuzz}/projects/. "
            "Check the project name and oss_fuzz_path."
        )

    repo_url = _main_repo_url(proj_dir)
    resolved_target_dir = target_dir or infer_target_dir(proj_dir, repo_url, project)
    language = _project_language(project)
    normalized_engine = normalize_fuzzing_engine(fuzzing_engine)
    if not fuzzing_engine_supports_language(normalized_engine, language):
        raise ValueError(
            f"fuzzing_engine={normalized_engine!r} is only supported for native C/C++ projects; "
            f"language={language!r}"
        )

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
    for entry in proj_dir.iterdir():
        dst = setup_dir / entry.name
        if entry.is_dir():
            shutil.copytree(entry, dst)
        elif entry.is_file():
            shutil.copy2(entry, dst)

    payload: dict = {
        "project": project,
        "main_repo_url": repo_url,
        "target_dir": resolved_target_dir,
        "secure_base_commit": "",
        "language": language,
        "fuzzing_engine": normalized_engine,
    }
    write_json(cfg_path, payload)

    config = load_project_config(project)
    runtime = build_runtime(config)
    runtime.ensure_setup_image()

    commit = runtime.detect_commit()
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

    runtime.build_ready_image(unit_tests_dir=unit_tests_dir)
    expected_count, unit_tests_enabled = run_baseline_unit_tests(
        runtime=runtime,
        project=project,
        image_tag=runtime.ready_image_tag,
        baked_harness=True,
    )

    payload["unit_tests"] = {
        "enabled": unit_tests_enabled,
        "expected_passing_count": expected_count,
    }

    if publish_dockerhub_namespace:
        image_ref = dockerhub_image_ref(
            namespace=publish_dockerhub_namespace,
            project=project,
            tag=dockerhub_tag_for_engine(normalized_engine),
        )
        publish_ready_image(source_image=runtime.ready_image_tag, image_ref=image_ref)
        payload["dockerhub_image"] = image_ref

    write_json(cfg_path, payload)

    return {
        "project": project,
        "run_id": run_id,
        "config_path": str(cfg_path),
        "target_dir": resolved_target_dir,
        "language": language,
        "fuzzing_engine": normalized_engine,
        "secure_base_commit": commit,
        "dockerhub_image": payload.get("dockerhub_image", ""),
        "unit_tests": payload["unit_tests"],
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


def _project_language(project: str) -> str | None:
    csv_path = vuljector_root() / "scripts" / "oss_fuzz_full.csv"
    if not csv_path.exists():
        logger.warning("[%s] Missing language catalog: %s", project, csv_path)
        return None

    with csv_path.open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if (row.get("name") or "").strip() != project:
                continue
            language = (row.get("language") or "").strip().lower()
            return language or None

    logger.warning("[%s] Project not found in %s; leaving language unset", project, csv_path)
    return None
