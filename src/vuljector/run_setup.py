"""Run setup phase independently."""

from __future__ import annotations

import logging
import shutil
import subprocess

from setup.setup_test_harness import (
    copy_default_parser_template,
    run_baseline_unit_tests,
    try_agent_harness,
    try_heuristic_harness,
    validate_unit_tests_dir,
)
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, project_root, setup_run_dir
from vuljector.core import (
    ProjectConfig,
    build_runtime,
    load_project_config,
    save_project_config,
    validate_project_config,
)
from vuljector.io_contracts import utc_now_iso

logger = logging.getLogger(__name__)


def run_setup(project: str, model_id: str = "claude-sonnet-4-6") -> dict:
    config = load_project_config(project)
    validate_project_config(config)
    run_id = new_run_id("setup")
    run_dir = setup_run_dir(project, run_id)
    request = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
    }
    write_json(run_dir / "setup_request.json", request)

    runtime = build_runtime(config)
    # Ensure the Docker image exists before issuing docker run commands.
    runtime.ensure_image()

    try:
        # Auto-detect secure_base_commit from the image if not set.
        _extract_secure_base_commit(config, runtime)
        runtime.secure_base_commit = config.secure_base_commit
        runtime.main_repo_url = config.main_repo_url

        # Discover test harness if not already present, then run baseline.
        _ensure_test_harness(runtime, project, run_dir, model_id)
        expected_count, unit_tests_enabled = run_baseline_unit_tests(runtime=runtime, project=project)
        _persist_expected_count(project, expected_count, unit_tests_enabled)

        runtime.mark_setup_completed(True)

        # Build ready image: commits post-build.sh container state so future
        # selection/injection agent runs skip the full build step.
        # Skipped automatically if a ready image for this setup hash already exists.
        if runtime.has_ready_image():
            logger.info("[%s] Ready image already up-to-date: %s", project, runtime.ready_image_tag)
        else:
            logger.info("[%s] Building ready image with pre-compiled artifacts ...", project)
            try:
                runtime.build_ready_image()
                logger.info("[%s] Ready image built: %s", project, runtime.ready_image_tag)
            except Exception as exc:
                logger.warning("[%s] Ready image build failed (non-fatal): %s", project, exc)

        result = {
            "project": project,
            "run_id": run_id,
            "timestamp_utc": utc_now_iso(),
            "status": "success",
            "secure_base_commit": config.secure_base_commit,
            "unit_tests": {
                "enabled": unit_tests_enabled,
                "expected_passing_count": expected_count,
            },
        }
        write_json(run_dir / "setup_result.json", result)
        (run_dir / "setup_log.txt").write_text("setup completed\n", encoding="utf-8")
        return result
    except Exception:
        raise


def _ensure_test_harness(runtime, project: str, run_dir, model_id: str) -> None:
    """Validate or replace unit_tests/; then heuristics, then agent; finally assert layout."""
    unit_tests_dir = project_root(project) / "unit_tests"
    src_dir = runtime.target_dir

    if unit_tests_dir.exists():
        ok, msg = validate_unit_tests_dir(unit_tests_dir)
        if ok:
            return
        if (unit_tests_dir / "test.sh").exists():
            logger.warning(
                "[%s] unit_tests/test.sh exists but validation failed (%s) — deleting unit_tests/ and regenerating.",
                project,
                msg,
            )
            shutil.rmtree(unit_tests_dir)
        # Directory exists but no test.sh — fall through to generate.

    copy_default_parser_template(unit_tests_dir)

    if not try_heuristic_harness(runtime=runtime, project=project, src_dir=src_dir, unit_tests_dir=unit_tests_dir):
        try_agent_harness(
            runtime=runtime,
            project=project,
            run_dir=run_dir,
            model_id=model_id,
            src_dir=src_dir,
            unit_tests_dir=unit_tests_dir,
        )
    ok, msg = validate_unit_tests_dir(unit_tests_dir)
    if not ok:
        raise RuntimeError(msg)


def _backup_git_from_image(runtime) -> None:
    """
    Backup the .git directory from the Docker image to the host.

    Uses `docker create` (no running container) + `docker cp` to extract .git.
    The backup is used by the injection/verifier phase to reset to the secure
    base commit between vulnerability attempts.
    """
    git_backup_dir = runtime.workspace_dir / ".git_backup"
    if git_backup_dir.exists():
        logger.info("[%s] .git backup already exists at %s — skipping.", runtime.project, git_backup_dir)
        return

    logger.info("[%s] Backing up .git from image %s ...", runtime.project, runtime.image_tag)
    # Create a stopped container (no `docker run`, just `docker create`).
    create_result = subprocess.run(
        ["docker", "create", runtime.image_tag],
        capture_output=True, text=True,
    )
    if create_result.returncode != 0:
        raise RuntimeError(
            f"docker create failed while backing up .git: {create_result.stderr.strip()}"
        )
    container_id = create_result.stdout.strip()
    try:
        git_backup_dir.parent.mkdir(parents=True, exist_ok=True)
        # docker cp copies the directory itself — destination should be the parent.
        cp_result = subprocess.run(
            ["docker", "cp",
             f"{container_id}:{runtime.repo_dir_in_container}/.git",
             str(git_backup_dir)],
            capture_output=True, text=True,
        )
        if cp_result.returncode != 0:
            raise RuntimeError(
                f"docker cp .git failed: {cp_result.stderr.strip()}"
            )
    except Exception:
        if git_backup_dir.exists():
            shutil.rmtree(git_backup_dir)
        raise
    finally:
        subprocess.run(["docker", "rm", container_id], capture_output=True, text=True)

    logger.info("[%s] .git backed up to %s.", runtime.project, git_backup_dir)


def _extract_secure_base_commit(config: ProjectConfig, runtime) -> None:
    """
    If secure_base_commit is missing, detect it from the image via a one-shot
    container run (no persistent container required). Updates `config` and
    project.json when detection succeeds.
    """
    if not config.secure_base_commit:

        result = subprocess.run(
            [
                "docker", "run", "--rm", runtime.image_tag,
                "git", "-C", runtime.repo_dir_in_container, "rev-parse", "HEAD",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"[{config.project}] Could not detect commit from image: {result.stderr.strip()}")
        
        commit = result.stdout.strip()
        config.secure_base_commit = commit
        logger.info(f"[{config.project}] Detected secure_base_commit from image: {commit}")

        cfg_path = project_root(config.project) / "project.json"
        payload = read_json(cfg_path)
        payload["secure_base_commit"] = commit
        write_json(cfg_path, payload)


def _persist_expected_count(project: str, expected_count: int | None, enabled: bool) -> None:
    cfg_path = project_root(project) / "project.json"
    payload = read_json(cfg_path)
    if not enabled:
        write_json(cfg_path, payload)
        return
    payload["unit_tests"] = {
        "enabled": True,
        "expected_passing_count": expected_count,
    }
    save_project_config(project, payload)
