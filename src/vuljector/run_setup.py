"""Run setup phase independently."""

from __future__ import annotations

import re

from setup.lifecycle import finish_phase, start_phase
from utils.github_utils import backup_git_dir, remove_git_dir
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, project_root, setup_run_dir
from vuljector.core import build_runtime, load_project_config, save_project_config
from vuljector.io_contracts import utc_now_iso


def run_setup(project: str) -> dict:
    config = load_project_config(project)
    run_id = new_run_id("setup")
    run_dir = setup_run_dir(project, run_id)
    request = {
        "schema_version": "v2",
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
    }
    write_json(run_dir / "setup_request.json", request)

    runtime = build_runtime(config)
    start_phase(runtime, phase="setup", run_dir=run_dir)
    try:
        # Initial baseline reset to secure commit while .git is still present.
        if config.secure_base_commit:
            runtime.exec(
                f"git reset --hard {config.secure_base_commit}",
                workdir=runtime.repo_dir_in_container,
            ).raise_for_status("setup git reset failed")
        runtime.exec("git clean -fdx", workdir=runtime.repo_dir_in_container).raise_for_status(
            "setup git clean failed"
        )

        git_backup_dir = runtime.workspace_dir / ".git_backup"
        backup_git_dir(runtime, runtime.repo_dir_in_container, git_backup_dir)
        remove_git_dir(runtime, runtime.repo_dir_in_container)

        expected_count, unit_tests_enabled = _baseline_unit_tests(runtime, project)
        _persist_expected_count(project, expected_count, unit_tests_enabled)

        runtime.mark_setup_completed(True)
        result = {
            "schema_version": "v2",
            "project": project,
            "run_id": run_id,
            "timestamp_utc": utc_now_iso(),
            "status": "success",
            "container_id": runtime.meta.get("container_id", ""),
            "secure_base_commit": config.secure_base_commit,
            "git_backup_dir": f"runs/workspaces/{project}/.git_backup",
            "unit_tests": {
                "enabled": unit_tests_enabled,
                "expected_passing_count": expected_count,
            },
        }
        write_json(run_dir / "setup_result.json", result)
        (run_dir / "setup_log.txt").write_text("setup completed\n", encoding="utf-8")
        return result
    finally:
        finish_phase(runtime)


def _baseline_unit_tests(runtime, project: str) -> tuple[int | None, bool]:
    proj_root = project_root(project)
    script_host = proj_root / "unit_tests" / "test.sh"
    if not script_host.exists():
        return None, False
    runtime.exec("mkdir -p /workspace/run/unit_tests").raise_for_status("mkdir run/unit_tests failed")
    runtime.copy_to(script_host, "/workspace/run/unit_tests/test.sh")
    runtime.exec("chmod +x /workspace/run/unit_tests/test.sh").raise_for_status("chmod test script failed")
    result = runtime.exec("bash /workspace/run/unit_tests/test.sh", workdir=runtime.repo_dir_in_container)
    out = (result.stdout or "") + "\n" + (result.stderr or "")
    match = re.search(r"PASSING_TESTS\s*=\s*(\d+)", out)
    if match:
        return int(match.group(1)), True
    if result.returncode == 0:
        return 1, True
    return 0, True


def _persist_expected_count(project: str, expected_count: int | None, enabled: bool) -> None:
    cfg_path = project_root(project) / "project.json"
    payload = read_json(cfg_path)
    if not enabled:
        write_json(cfg_path, payload)
        return
    payload["unit_tests"] = {
        "enabled": True,
        "script": "unit_tests/test.sh",
        "expected_passing_count": expected_count,
    }
    save_project_config(project, payload)

