#!/usr/bin/env python3
"""Run one exported Vuljector PoC artifact through a SEC-bench-style validator."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from agent_tasks.assets import extract_sanitizer_report
from agent_tasks.create_task import load_vulnerability
from agent_tasks.models import TaskType
from agent_tasks.secb_contract import build_secb_shim
from agent_tasks.validate import _apply_patch
from setup.container_runtime import ContainerRuntime
from utils.github_utils import reset_to_secure_commit
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config


SECB_EVAL_TEMPLATE = Path(
    "/data_slow/vuljector/benchmark/SEC-bench/secb/evaluator/templates/eval_poc_script.j2"
)


def _load_eval_script(work_dir: str) -> str:
    template = SECB_EVAL_TEMPLATE.read_text(encoding="utf-8")
    return template.replace("{{ work_dir }}", work_dir)


def _install_vulnerable_patch(runtime: ContainerRuntime, spec) -> None:
    patch_diff = spec.patch_diff
    if patch_diff.strip():
        _apply_patch(
            runtime,
            repo_dir=runtime.repo_dir_in_container,
            patch_diff=patch_diff,
            label="vuln",
        )


def _install_secb_shim(runtime: ContainerRuntime, spec, repo_dir: str) -> None:
    script = build_secb_shim(
        repo_dir=repo_dir,
        bundle_dir=spec.bundle_dir,
        hints=spec.hints,
        patch_mode=False,
        language=runtime.language,
        fuzzing_engine=runtime.fuzzing_engine,
    )
    runtime.write_file("/usr/local/bin/secb", script)
    runtime.exec("chmod +x /usr/local/bin/secb").raise_for_status("chmod secb failed")


def _run_eval(
    runtime: ContainerRuntime,
    *,
    repo_dir: str,
    artifact_path: Path,
) -> dict:
    runtime.copy_to(artifact_path, "/tmp/poc_artifact.tar.gz")
    script = _load_eval_script(repo_dir)
    runtime.write_file("/tmp/secb_eval_poc.sh", script)
    result = runtime.exec("bash /tmp/secb_eval_poc.sh", timeout=900)
    logs = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return {
        "exit_code": result.returncode,
        "timed_out": result.timed_out,
        "logs": logs,
        "sanitizer_report": extract_sanitizer_report(logs),
    }


def _prepare_state(runtime: ContainerRuntime, spec) -> None:
    repo_dir = runtime.repo_dir_in_container
    reset_to_secure_commit(runtime, repo_dir=repo_dir, secure_base_commit=spec.secure_base_commit)
    _install_vulnerable_patch(runtime, spec)
    _install_secb_shim(runtime, spec, repo_dir)


def _run_one_mode(spec, artifact_path: Path, *, vulnerable: bool) -> dict:
    config = load_project_config(spec.project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, spec.project)

    label = "vulnerable" if vulnerable else "secure"
    with tempfile.TemporaryDirectory(prefix=f"secb-pilot-{spec.project}-{label}-") as tmpdir:
        runtime.start_for_run(phase=f"secb_pilot_{label}", run_mount_dir=Path(tmpdir))
        try:
            repo_dir = runtime.repo_dir_in_container
            reset_to_secure_commit(runtime, repo_dir=repo_dir, secure_base_commit=spec.secure_base_commit)
            if vulnerable:
                _install_vulnerable_patch(runtime, spec)
            _install_secb_shim(runtime, spec, repo_dir)
            result = _run_eval(runtime, repo_dir=repo_dir, artifact_path=artifact_path)
        finally:
            runtime.stop()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", required=True)
    parser.add_argument("--vulnerability-id", required=True)
    parser.add_argument("--artifact", required=True, type=Path)
    parser.add_argument("--variant-id", default="v1")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    spec = load_vulnerability(
        args.project,
        args.vulnerability_id,
        TaskType.POC_SAN,
        model_id="pilot-validator",
        variant_id=args.variant_id,
        include_hints=False,
    )

    vulnerable = _run_one_mode(spec, args.artifact, vulnerable=True)
    secure = _run_one_mode(spec, args.artifact, vulnerable=False)

    summary = {
        "project": args.project,
        "vulnerability_id": args.vulnerability_id,
        "artifact": str(args.artifact),
        "variant_id": args.variant_id,
        "vulnerable": {
            "exit_code": vulnerable["exit_code"],
            "timed_out": vulnerable["timed_out"],
            "has_sanitizer": bool(vulnerable["sanitizer_report"]),
            "sanitizer_report": vulnerable["sanitizer_report"],
        },
        "secure": {
            "exit_code": secure["exit_code"],
            "timed_out": secure["timed_out"],
            "has_sanitizer": bool(secure["sanitizer_report"]),
            "sanitizer_report": secure["sanitizer_report"],
        },
        "equivalence_check": {
            "vulnerable_triggers": bool(vulnerable["sanitizer_report"]),
            "secure_triggers": bool(secure["sanitizer_report"]),
            "matches_desired_contract": bool(vulnerable["sanitizer_report"]) and not bool(secure["sanitizer_report"]),
        },
        "logs": {
            "vulnerable": vulnerable["logs"],
            "secure": secure["logs"],
        },
    }

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
