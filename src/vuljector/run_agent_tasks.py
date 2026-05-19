"""Top-level orchestration for running swe-agent-mini on synthetic vulnerability tasks."""

from __future__ import annotations

import logging
from pathlib import Path

from agent_tasks.create_task import load_vulnerability
from agent_tasks.models import AgentTaskResult, TaskType
from agent_tasks.run_task import get_artifact_path, run_agent_on_task
from agent_tasks.trajectory_quality import compute_quality_metrics, sft_tier
from agent_tasks.validate import validate_agent_output
from setup.lifecycle import finish_phase, start_phase
from utils.json_io import write_json
from utils.paths import agent_task_run_dir, new_run_id
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.io_contracts import utc_now_iso

logger = logging.getLogger(__name__)


def run_agent_task_pipeline(
    *,
    project: str,
    vulnerability_id: str,
    task_type: str,
    model_id: str,
    variant_id: str | None = None,
    include_hints: bool = False,
    teacher_regime: str = "faithful",
    teacher_assistance: dict | None = None,
) -> dict:
    """
    Full pipeline: load vulnerability → run agent → validate → save trajectory + results.

    Args:
        project: project name (must exist in vuljector-projects/)
        vulnerability_id: e.g. "vulnerability_0"
        task_type: one of "patch", "poc-repo", "poc-desc", "poc-san"
        model_id: LiteLLM model identifier (e.g. "claude-sonnet-4-6")

    Returns:
        Summary dict (also written to task_result.json in run_dir).
    """
    task_type_enum = TaskType.from_input(task_type)
    spec = load_vulnerability(
        project,
        vulnerability_id,
        task_type_enum,
        model_id,
        variant_id=variant_id,
        include_hints=include_hints,
        teacher_regime=teacher_regime,
        teacher_assistance=teacher_assistance,
    )
    return run_agent_task_pipeline_for_spec(
        spec,
        requested_task_type=task_type,
        include_hints=include_hints,
        teacher_regime=teacher_regime,
        teacher_assistance=teacher_assistance,
    )


def run_agent_task_pipeline_for_spec(
    spec,
    *,
    requested_task_type: str | None = None,
    include_hints: bool | None = None,
    teacher_regime: str | None = None,
    teacher_assistance: dict | None = None,
) -> dict:
    """Run the task pipeline for a pre-materialized spec."""
    project = spec.project
    config = load_project_config(spec.project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, spec.project)

    run_id = new_run_id("agent_task")
    run_dir = agent_task_run_dir(project, spec.task_type.value, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)

    # Persist task request for reproducibility
    write_json(run_dir / "task_request.json", {
        "schema_version": "v2",
        "project": project,
        "vulnerability_id": spec.vulnerability_id,
        "task_type": requested_task_type or spec.task_type.value,
        "resolved_task_type": spec.task_type.value,
        "model_id": spec.model_id,
        "variant_id": spec.bug_description_variant_id,
        "include_hints": spec.include_hints if include_hints is None else include_hints,
        "teacher_regime": teacher_regime or spec.teacher_regime,
        "teacher_assistance": dict(teacher_assistance or spec.teacher_assistance or {}),
        "instance_id": spec.instance_id,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
    })
    write_json(run_dir / "task_spec.json", spec.to_dict())

    start_phase(runtime, phase="agent_task", run_dir=run_dir)
    try:
        return _run(
            runtime=runtime,
            spec=spec,
            run_id=run_id,
            run_dir=run_dir,
        )
    finally:
        finish_phase(runtime)


# ── Internal ──────────────────────────────────────────────────────────────────

def _run(*, runtime, spec, run_id: str, run_dir: Path) -> dict:
    # ── Step 1: run agent ─────────────────────────────────────────────────────
    logger.info(
        "[%s] Starting agent task: type=%s vuln=%s",
        spec.project, spec.task_type.value, spec.vulnerability_id,
    )
    response, traj_path = run_agent_on_task(runtime, spec, run_dir)

    # ── Step 2: quality metrics from trajectory ───────────────────────────────
    quality = compute_quality_metrics(traj_path)
    logger.info(
        "[%s] Agent finished: exit_status=%s steps=%d cost=$%.4f format_errors=%d",
        spec.project,
        quality["exit_status"],
        quality["total_steps"],
        quality["instance_cost"],
        quality["format_error_count"],
    )

    # ── Step 3: validate if agent produced an artifact ────────────────────────
    artifact_path = get_artifact_path(run_dir, spec)
    if artifact_path is None:
        logger.warning("[%s] Agent produced no artifact — skipping validation", spec.project)
        validation_result = _no_output_result(spec, run_id)
    else:
        logger.info("[%s] Validating agent artifact: %s", spec.project, artifact_path)
        validation_result = validate_agent_output(runtime, spec, artifact_path, run_id)

    write_json(run_dir / "validation_result.json", validation_result.to_dict())

    # ── Step 4: assemble final result ─────────────────────────────────────────
    tier = sft_tier(quality, validation_result.status)
    logger.info("[%s] SFT tier: %s (validation=%s)", spec.project, tier, validation_result.status)

    paths: dict[str, str] = {
        "trajectory": str(traj_path.relative_to(run_dir)) if traj_path.exists() else "",
        "validation_result": "validation_result.json",
        "task_spec": "task_spec.json",
        "task_prompt": "task_prompt.txt",
        "task_system_prompt": "task_system_prompt.txt",
    }
    if artifact_path:
        paths["artifact"] = str(artifact_path.relative_to(run_dir))

    result = AgentTaskResult(
        schema_version="v2",
        project=spec.project,
        vulnerability_id=spec.vulnerability_id,
        instance_id=spec.instance_id,
        task_type=spec.task_type.value,
        model_id=spec.model_id,
        run_id=run_id,
        timestamp_utc=utc_now_iso(),
        include_hints=spec.include_hints,
        bug_description_variant_id=spec.bug_description_variant_id,
        validation_status=validation_result.status,
        teacher_regime=spec.teacher_regime,
        validation_checks=validation_result.checks,
        failure_cause=validation_result.failure_cause,
        failure_message=validation_result.failure_message,
        quality_metrics={**quality, "sft_tier": tier},
        paths=paths,
    )
    write_json(run_dir / "task_result.json", result.to_dict())

    logger.info(
        "[%s] Agent task complete: validation=%s tier=%s run_dir=%s",
        spec.project, validation_result.status, tier, run_dir,
    )
    return result.to_dict()


def _no_output_result(spec, run_id: str):
    """Return a VerificationResult-compatible stub when the agent produced nothing."""
    from vuljector.io_contracts import VerificationResult
    return VerificationResult(
        project=spec.project,
        run_id=run_id,
        timestamp_utc=utc_now_iso(),
        status="failure",
        checks={
            "exploit_on_vulnerable": "skipped",
            "exploit_on_secure": "skipped",
        },
        failure_cause="no_agent_output",
        failure_message="Agent did not produce the expected output file.",
    )
