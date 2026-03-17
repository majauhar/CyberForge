"""End-to-end vuljector orchestration."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from setup import ContainerRuntime
from verifier import run_verification
from vuljector.strategies import InjectionContext, InjectionResult, get_strategy


def _sanitize_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_")


def _next_vulnerability_id(base_dir: Path) -> str:
    base_dir.mkdir(parents=True, exist_ok=True)
    used = []
    for p in base_dir.iterdir():
        if p.is_dir() and p.name.startswith("vulnerability_"):
            try:
                used.append(int(p.name.split("_", 1)[1]))
            except (IndexError, ValueError):
                continue
    next_idx = (max(used) + 1) if used else 0
    return f"vulnerability_{next_idx}"


def _commit_and_push(
    *,
    runtime: ContainerRuntime,
    branch: str,
    commit_message: str,
) -> str:
    runtime.exec("git config user.email 'vuljector@local'", workdir=runtime.repo_dir_in_container)
    runtime.exec("git config user.name 'Vuljector Bot'", workdir=runtime.repo_dir_in_container)
    runtime.exec(f"git checkout -B {branch}", workdir=runtime.repo_dir_in_container)
    runtime.exec("git add -A", workdir=runtime.repo_dir_in_container)
    runtime.exec(f"git commit -m {json.dumps(commit_message)}", workdir=runtime.repo_dir_in_container)
    sha = runtime.exec("git rev-parse HEAD", workdir=runtime.repo_dir_in_container).stdout.strip()
    runtime.exec(f"git push -u origin {branch}", workdir=runtime.repo_dir_in_container)
    return sha


def _save_history(
    *,
    vulinjector_root: Path,
    method_id: str,
    model_id: str,
    project: str,
    payload: dict,
) -> Path:
    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    history_dir = vulinjector_root / "runs" / "history"
    history_dir.mkdir(parents=True, exist_ok=True)
    name = (
        f"{_sanitize_filename(method_id)}_"
        f"{_sanitize_filename(model_id)}_"
        f"{ts}_"
        f"{_sanitize_filename(project)}.json"
    )
    out = history_dir / name
    out.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return out


def run_end_to_end(
    *,
    project: str,
    method_id: str,
    model_id: str,
    cwe_groups: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    debug: bool = False,
) -> dict:
    # Resolve paths for the checked-out project and its configuration.
    vulinjector_root = Path(__file__).resolve().parents[2]
    project_root = vulinjector_root.parent / "vuljector-projects" / project
    project_json_path = project_root / "project.json"
    if not project_json_path.exists():
        raise FileNotFoundError(f"Missing project.json: {project_json_path}")

    # Load high-level project configuration: repo location and base commit.
    project_data = json.loads(project_json_path.read_text(encoding="utf-8"))
    secure_base_commit = project_data.get("secure_base_commit", "")
    target_dir = project_data.get("target_dir")
    if not target_dir:
        raise KeyError(
            "project.json is missing required field 'target_dir'. "
            "This should be set by the oss-fuzz vuljector init script."
        )
    # Optional command to run unit / integration tests inside the container.
    unit_test_cmd = (
        project_data.get("verification", {}).get("unit_test_cmd")
        if isinstance(project_data.get("verification"), dict)
        else None
    )

    # Spin up (or connect to) the container that hosts the target repo.
    runtime = ContainerRuntime(
        project=project,
        setup_dir=project_root / "setup",
        vulinjector_root=vulinjector_root,
        target_dir=target_dir,
        secure_base_commit=secure_base_commit,
    )
    # Ensure the container, repo checkout and tools are ready to use.
    runtime.ensure_ready()

    # Pick the injection strategy (LLM prompting / workflow) and bind run metadata.
    strategy = get_strategy(method_id)
    run_id = uuid4().hex
    context = InjectionContext(
        project=project,
        run_id=run_id,
        method_id=method_id,
        model_id=model_id,
        target_dir=target_dir,
        secure_base_commit=secure_base_commit,
        cwe_groups=cwe_groups,
        cwe_ids=cwe_ids,
        debug=debug,
        project_root=str(project_root),
        repo_dir_in_container=runtime.repo_dir_in_container,
        unit_test_cmd=unit_test_cmd,
    )

    # Perform one-time strategy-specific setup the first time it runs for this project.
    if not runtime.is_strategy_setup_done(strategy.id):
        strategy.setup(runtime, context)
        runtime.mark_strategy_setup_done(strategy.id)

    # Ask the strategy to inject a vulnerability and then verify the result.
    result: InjectionResult = strategy.run(runtime, context)
    result = run_verification(runtime=runtime, context=context, result=result)

    # If the run succeeded (or we are in debug mode), persist the exploit artifacts
    # and publish a branch that points at the vulnerable commit.
    vulnerability_ref = ""
    vulnerable_commit = ""
    if result.status == "success" or debug:
        if result.status == "success" and not debug:
            base_dir = project_root / "vulnerabilities"
            vulnerability_ref = _next_vulnerability_id(base_dir)
            branch = f"vuljector/{vulnerability_ref}"
        elif result.status == "success":
            base_dir = project_root / "debug" / "vulnerabilities" / "success"
            vulnerability_ref = _next_vulnerability_id(base_dir)
            branch = f"debug/success/{run_id}"
        else:
            base_dir = project_root / "debug" / "vulnerabilities" / "failed"
            vulnerability_ref = _next_vulnerability_id(base_dir)
            branch = f"debug/failed/{run_id}"

        vuln_dir = base_dir / vulnerability_ref
        vuln_dir.mkdir(parents=True, exist_ok=True)
        runtime.copy_from(result.exploit_dir_in_container, vuln_dir)
        vulnerable_commit = _commit_and_push(
            runtime=runtime,
            branch=branch,
            commit_message=f"vuljector {vulnerability_ref}",
        )
        # Store a small JSON file alongside the exploit for quick lookup later.
        metadata = {
            "id": vulnerability_ref,
            "cwe_group": result.cwe_group or "",
            "cwe_id": result.cwe_id or "",
            "vulnerable_commit": vulnerable_commit,
            "secure_base_commit": secure_base_commit,
        }
        if result.complexity:
            metadata["complexity"] = result.complexity
        (vuln_dir / "vulnerability_metadata.json").write_text(
            json.dumps(metadata, indent=2) + "\n",
            encoding="utf-8",
        )

    # Record a machine-readable summary of the run (success or failure) under
    # `runs/history` so callers can inspect or aggregate past executions.
    payload = {
        "run_id": run_id,
        "project": project,
        "method_id": method_id,
        "model_id": model_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "status": result.status,
        "failure_cause": result.failure_cause.value if result.failure_cause else None,
        "failure_message": result.failure_message,
        "cwe_group": result.cwe_group,
        "cwe_id": result.cwe_id,
        "vulnerability_ref": vulnerability_ref,
        "vulnerable_commit": vulnerable_commit,
        "secure_base_commit": secure_base_commit,
        "retries": result.retries,
        "models_used": result.models_used,
        "token_usage": result.token_usage,
        "cost": result.cost,
        "container_id": runtime.meta.get("container_id"),
    }
    history_path = _save_history(
        vulinjector_root=vulinjector_root,
        method_id=method_id,
        model_id=model_id,
        project=project,
        payload=payload,
    )
    payload["history_path"] = str(history_path)
    return payload
