"""Run selection phase independently."""

from __future__ import annotations

from collections.abc import Callable

from selector.base import SelectionRequest
from selector.registry import get_selection_strategy
from utils.json_io import write_json
from utils.paths import new_run_id, selection_run_dir
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.io_contracts import utc_now_iso


_DEFAULT_MAX_CANDIDATES = 30


def run_selection(
    *,
    project: str,
    strategy_id: str,
    model_id: str,
    cwe_groups: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    max_candidates: int | None = None,
    on_run_initialized: Callable[[dict], None] | None = None,
) -> dict:
    config = load_project_config(project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, project)

    if max_candidates is not None:
        _max = max_candidates
    elif strategy_id == "fuzz_guided":
        _max = None
    else:
        _max = _DEFAULT_MAX_CANDIDATES

    run_id = new_run_id("selection")
    run_dir = selection_run_dir(project, run_id)
    request_payload = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "selection_strategy_id": strategy_id,
        "model_id": model_id,
        "filters": {"cwe_groups": cwe_groups or [], "cwe_ids": cwe_ids or []},
        "max_candidates": _max,
    }
    write_json(run_dir / "selection_request.json", request_payload)
    if on_run_initialized is not None:
        on_run_initialized(request_payload)

    strategy = get_selection_strategy(strategy_id)
    # setup() clones the repo locally if not already present — idempotent.
    strategy.setup(runtime)
    request = SelectionRequest(
        project=project,
        run_id=run_id,
        strategy_id=strategy_id,
        model_id=model_id,
        cwe_groups=cwe_groups,
        cwe_ids=cwe_ids,
        target_dir=config.target_dir,
        max_candidates=_max,
        filters={"cwe_groups": cwe_groups or [], "cwe_ids": cwe_ids or []},
    )
    result = strategy.run(runtime, request)
    payload = result.to_dict()
    write_json(run_dir / "candidates.json", payload)
    (run_dir / "selection_log.txt").write_text("selection completed\n", encoding="utf-8")
    return payload
