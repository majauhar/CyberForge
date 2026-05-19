"""Compare ready-image rebuilds against setup-image-clean rebuilds for one attempt."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from utils.json_io import read_json
from verifier import run_verification, run_verification_from_setup_image
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config


def _load_exploit_text(attempt_dir: Path, injection_result: dict) -> str:
    exploit_file = attempt_dir / "artifacts" / "exploit_files" / "exploit.sh"
    if exploit_file.exists():
        return exploit_file.read_text(encoding="utf-8")
    attack_script = str(((injection_result.get("artifacts") or {}).get("attack_script") or "")).strip()
    if attack_script:
        return attack_script
    raise FileNotFoundError(f"No exploit.sh or attack_script found for {attempt_dir}")


def _run_ready_path(*, runtime, config, project: str, patch_diff: str, exploit_text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as handle:
        handle.write(exploit_text)
        exploit_host = Path(handle.name)
    session = runtime.new_session()
    try:
        session.write_file("/tmp/exploit.sh", exploit_text)
        session.exec("chmod +x /tmp/exploit.sh").raise_for_status("chmod exploit failed")
        result = run_verification(
            runtime=session,
            project=project,
            run_id="rebuild_eval_ready",
            repo_dir=runtime.repo_dir_in_container,
            patch_diff=patch_diff,
            unit_tests=config.unit_tests,
            project_root=Path(__file__).resolve().parents[3] / "vuljector-projects" / project,
            exploit_path="/tmp/exploit.sh",
            rebuild_command=f"FUZZING_LANGUAGE={config.language or 'c++'} FUZZING_ENGINE={runtime.fuzzing_engine} compile",
        )
        return result.to_dict()
    finally:
        session.stop()
        exploit_host.unlink(missing_ok=True)


def _run_setup_clean_path(*, runtime, config, project: str, patch_diff: str, exploit_text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, encoding="utf-8") as handle:
        handle.write(exploit_text)
        exploit_host = Path(handle.name)
    try:
        result = run_verification_from_setup_image(
            runtime=runtime,
            project=project,
            run_id="rebuild_eval_setup_clean",
            repo_dir=runtime.repo_dir_in_container,
            patch_diff=patch_diff,
            unit_tests=config.unit_tests,
            project_root=Path(__file__).resolve().parents[3] / "vuljector-projects" / project,
            exploit_path=str(exploit_host),
            rebuild_command=f"FUZZING_LANGUAGE={config.language or 'c++'} FUZZING_ENGINE={runtime.fuzzing_engine} compile",
        )
        return result.to_dict()
    finally:
        exploit_host.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("project")
    parser.add_argument("attempt_dir")
    args = parser.parse_args()

    attempt_dir = Path(args.attempt_dir).resolve()
    injection_result = read_json(attempt_dir / "injection_result.json")
    if injection_result.get("status") != "success":
        raise SystemExit(f"injection_result is not successful for {attempt_dir}")

    patch_diff = str(((injection_result.get("artifacts") or {}).get("patch_diff") or "")).strip()
    if not patch_diff:
        patch_path = attempt_dir / "artifacts" / "vuln.patch"
        if patch_path.exists():
            patch_diff = patch_path.read_text(encoding="utf-8")
    if not patch_diff:
        raise SystemExit(f"missing patch diff for {attempt_dir}")

    exploit_text = _load_exploit_text(attempt_dir, injection_result)
    config = load_project_config(args.project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, args.project)

    old_verification = read_json(attempt_dir / "verification_result.json") if (attempt_dir / "verification_result.json").exists() else {}
    ready_result = _run_ready_path(
        runtime=runtime,
        config=config,
        project=args.project,
        patch_diff=patch_diff,
        exploit_text=exploit_text,
    )
    setup_clean_result = _run_setup_clean_path(
        runtime=runtime,
        config=config,
        project=args.project,
        patch_diff=patch_diff,
        exploit_text=exploit_text,
    )

    summary = {
        "project": args.project,
        "attempt_dir": str(attempt_dir),
        "historical_verification": old_verification,
        "ready_path": ready_result,
        "setup_clean_path": setup_clean_result,
    }
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
