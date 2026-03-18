"""Run selection phase independently."""

from __future__ import annotations

from selector.base import SelectionRequest
from selector.registry import get_selection_strategy
from setup.lifecycle import finish_phase, start_phase
from utils.github_utils import remove_git_dir
from utils.json_io import write_json
from utils.paths import new_run_id, selection_run_dir
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.io_contracts import utc_now_iso


def run_selection(
    *,
    project: str,
    strategy_id: str,
    model_id: str,
    cwe_groups: list[str] | None = None,
    cwe_ids: list[str] | None = None,
) -> dict:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)

    run_id = new_run_id("selection")
    run_dir = selection_run_dir(project, run_id)
    request_payload = {
        "schema_version": "v2",
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "selection_strategy_id": strategy_id,
        "model_id": model_id,
        "filters": {"cwe_groups": cwe_groups or [], "cwe_ids": cwe_ids or []},
        "max_candidates": 30,
    }
    write_json(run_dir / "selection_request.json", request_payload)

    start_phase(runtime, phase="selection", run_dir=run_dir)
    try:
        remove_git_dir(runtime, runtime.repo_dir_in_container)
        strategy = get_selection_strategy(strategy_id)
        if not runtime.is_strategy_setup_done(phase="selection", strategy_id=strategy.id):
            strategy.setup(runtime)
            runtime.mark_strategy_setup_done(phase="selection", strategy_id=strategy.id)
        request = SelectionRequest(
            project=project,
            run_id=run_id,
            strategy_id=strategy_id,
            model_id=model_id,
            cwe_groups=cwe_groups,
            cwe_ids=cwe_ids,
        )
        result = strategy.run(runtime, request)
        payload = result.to_dict()
        write_json(run_dir / "candidates.json", payload)
        (run_dir / "selection_log.txt").write_text("selection completed\n", encoding="utf-8")
        return payload
    finally:
        finish_phase(runtime)

