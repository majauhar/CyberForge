"""Run setup phase: validate project, build/cache image, mark ready."""

from __future__ import annotations

import logging

from utils.json_io import read_json
from setup.setup_test_harness import validate_unit_tests_dir
from utils.json_io import write_json
from utils.paths import new_run_id, project_root, setup_run_dir
from vuljector.core import (
    build_runtime,
    fuzzing_engine_supports_language,
    load_project_config,
    normalize_fuzzing_engine,
    save_project_config,
)
from vuljector.io_contracts import ProjectConfig, utc_now_iso

logger = logging.getLogger(__name__)


def run_setup(project: str, fuzzing_engine: str | None = None) -> dict:
    if fuzzing_engine is not None:
        _persist_fuzzing_engine(project, fuzzing_engine)
    config = load_project_config(project)
    if not fuzzing_engine_supports_language(config.fuzzing_engine, config.language):
        raise RuntimeError(
            f"[{project}] fuzzing_engine={config.fuzzing_engine!r} is only supported for native C/C++ projects; "
            f"language={config.language!r}"
        )
    _validate_project_ready(config, project)

    run_id = new_run_id("setup")
    run_dir = setup_run_dir(project, run_id)
    write_json(run_dir / "setup_request.json", {
        "project": project,
        "run_id": run_id,
        "fuzzing_engine": config.fuzzing_engine,
        "timestamp_utc": utc_now_iso(),
    })

    runtime = build_runtime(config)
    ready_image = runtime.ensure_ready_image(unit_tests_dir=project_root(project) / "unit_tests")
    logger.info("[%s] Ready image available: %s", project, ready_image)

    runtime.mark_setup_completed(True)

    result = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "status": "success",
        "fuzzing_engine": config.fuzzing_engine,
        "ready_image_tag": ready_image,
        "secure_base_commit": config.secure_base_commit,
        "unit_tests": config.unit_tests,
    }
    write_json(run_dir / "setup_result.json", result)
    return result


def _validate_project_ready(config: ProjectConfig, project: str) -> None:
    """Raise if the project hasn't been fully initialized yet."""
    errors: list[str] = []

    if not config.secure_base_commit:
        errors.append("secure_base_commit is missing — run `init` first")

    unit_tests = config.unit_tests
    if unit_tests is None:
        errors.append("unit_tests config is missing — run `init` first")

    unit_tests_dir = project_root(project) / "unit_tests"
    ok, msg = validate_unit_tests_dir(unit_tests_dir)
    if not ok:
        errors.append(f"unit_tests/ invalid: {msg} — run `init` first")

    if errors:
        raise RuntimeError(
            f"[{project}] Project not fully initialized:\n" +
            "\n".join(f"  - {e}" for e in errors)
        )


def _persist_fuzzing_engine(project: str, fuzzing_engine: str) -> None:
    cfg_path = project_root(project) / "project.json"
    payload = read_json(cfg_path)
    payload["fuzzing_engine"] = normalize_fuzzing_engine(fuzzing_engine)
    save_project_config(project, payload)
