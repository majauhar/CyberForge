#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path

_VULJECTOR_ROOT = Path(__file__).resolve().parents[2]
_SRC = _VULJECTOR_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from setup.lifecycle import finish_phase, start_phase
from utils.github_utils import reset_to_secure_commit
from utils.json_io import write_json
from utils.paths import project_root
from verifier import run_verification
from vuljector.core import build_runtime, ensure_setup_completed, load_project_config
from vuljector.io_contracts import VerificationResult, utc_now_iso

_RUNS = _VULJECTOR_ROOT / "runs" / "ossfuzz"
_DEFAULT_MANIFEST = _RUNS / "historical_bug_reproduction_inputs" / "pilot_reversal_inputs_20260412T215541Z" / "reversal_inputs_manifest.jsonl"
_DEFAULT_OUT_ROOT = _RUNS / "historical_bug_reversal_experiments"
_BUILD_PRELUDE = (
    'if [ -n "${LIB_FUZZING_ENGINE:-}" ] && [ ! -f "$LIB_FUZZING_ENGINE" ]; then '
    'ALT=$(clang --print-file-name=libclang_rt.fuzzer-x86_64.a); '
    'if [ -n "$ALT" ] && [ "$ALT" != "libclang_rt.fuzzer-x86_64.a" ] && [ -f "$ALT" ]; then '
    'export LIB_FUZZING_ENGINE="$ALT"; '
    'fi; '
    'fi; '
)


@dataclass
class CaseSpec:
    project: str
    issue_id: str
    fix_commit: str
    testcase_path: str
    fuzz_target: str
    sanitizer: str | None
    summary: str | None


def load_cases(manifest_path: Path, specs: list[str]) -> list[CaseSpec]:
    wanted: set[tuple[str, str]] = set()
    for spec in specs:
        project, issue_id = spec.split(":", 1)
        wanted.add((project, issue_id))

    cases: list[CaseSpec] = []
    with manifest_path.open() as handle:
        for line in handle:
            rec = json.loads(line)
            key = (rec["project"], rec["issue_id"])
            if key not in wanted:
                continue
            primary = (rec.get("local_testcases") or {}).get("primary")
            fix_commits = ((rec.get("commits") or {}).get("fix_commits") or [])
            fuzz_target = ((rec.get("clusterfuzz") or {}).get("fuzz_target"))
            if not primary or not primary.get("exists") or not fix_commits or not fuzz_target:
                continue
            cases.append(
                CaseSpec(
                    project=rec["project"],
                    issue_id=rec["issue_id"],
                    fix_commit=str(fix_commits[0]),
                    testcase_path=str(primary["path"]),
                    fuzz_target=str(fuzz_target),
                    sanitizer=((rec.get("clusterfuzz") or {}).get("sanitizer")),
                    summary=rec.get("summary"),
                )
            )
    found = {(case.project, case.issue_id) for case in cases}
    missing = wanted - found
    if missing:
        raise RuntimeError(f"Missing or unusable cases in manifest: {sorted(missing)}")
    return cases


def _write_exploit_files(case_dir: Path, testcase_path: Path, fuzz_target: str) -> Path:
    exploit_dir = case_dir / "exploit_files"
    exploit_dir.mkdir(parents=True, exist_ok=True)
    testcase_dst = exploit_dir / "testcase.bin"
    testcase_dst.write_bytes(testcase_path.read_bytes())
    exploit_path = exploit_dir / "exploit.sh"
    exploit_path.write_text(
        "\n".join(
            [
                "#!/usr/bin/env bash",
                "set +e",
                'TESTCASE="/workspace/run/exploit_files/testcase.bin"',
                f'BINARY="/out/{fuzz_target}"',
                'if [ ! -x "$BINARY" ]; then',
                f'  BINARY=$(find /out -maxdepth 2 -type f -name "{fuzz_target}" | head -1)',
                "fi",
                'if [ -z "$BINARY" ] || [ ! -x "$BINARY" ]; then',
                '  echo "MISSING_BINARY"',
                "  exit 0",
                "fi",
                '"$BINARY" "$TESTCASE" > /tmp/reversal_exploit.out 2>&1',
                "RC=$?",
                'cat /tmp/reversal_exploit.out || true',
                'if [ "$RC" -ne 0 ]; then',
                '  echo "TRIGGERED"',
                "  exit 1",
                "fi",
                'echo "NOT_TRIGGERED"',
                "exit 0",
                "",
            ]
        ),
        encoding="utf-8",
    )
    exploit_path.chmod(0o755)
    return exploit_path


def _install_unit_tests(runtime, project: str) -> None:
    unit_tests_host = project_root(project) / "unit_tests"
    if (unit_tests_host / "test.sh").exists():
        runtime.copy_to(unit_tests_host, "/workspace/run/unit_tests")
        runtime.exec(
            "chmod -R a+rX /workspace/run/unit_tests"
            " && chmod +x /workspace/run/unit_tests/test.sh /workspace/run/unit_tests/parse_results.py"
        )


def _attempt_revert(runtime, repo_dir: str, fix_commit: str) -> tuple[bool, str]:
    runtime.exec("git fetch --unshallow --tags origin || git fetch --tags origin || true", workdir=repo_dir, timeout=300)
    runtime.exec(f"git fetch origin {fix_commit}", workdir=repo_dir)
    result = runtime.exec(f"git revert --no-commit {fix_commit}", workdir=repo_dir, timeout=300)
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    if result.returncode == 0:
        return True, output
    runtime.exec("git status --short", workdir=repo_dir)
    runtime.exec("git revert --abort || true", workdir=repo_dir)
    runtime.exec(
        f"git show --binary --format= {fix_commit} > /tmp/vuljector_reverse.patch",
        workdir=repo_dir,
        timeout=120,
    )
    reverse_apply = runtime.exec(
        "git apply -R --3way /tmp/vuljector_reverse.patch",
        workdir=repo_dir,
        timeout=300,
    )
    reverse_output = ((reverse_apply.stdout or "") + "\n" + (reverse_apply.stderr or "")).strip()
    combined_output = output
    if reverse_output:
        combined_output = f"{combined_output}\n\n=== reverse_apply_fallback ===\n{reverse_output}".strip()
    if reverse_apply.returncode == 0:
        return True, combined_output
    return False, combined_output


def run_case(case: CaseSpec, out_root: Path) -> dict:
    config = load_project_config(case.project)
    runtime = build_runtime(config)
    ensure_setup_completed(runtime, case.project)

    case_run_id = f"{case.project}_{case.issue_id}"
    case_dir = out_root / case_run_id
    case_dir.mkdir(parents=True, exist_ok=True)

    request = {
        "project": case.project,
        "issue_id": case.issue_id,
        "fix_commit": case.fix_commit,
        "testcase_path": case.testcase_path,
        "fuzz_target": case.fuzz_target,
        "sanitizer": case.sanitizer,
        "summary": case.summary,
        "timestamp_utc": utc_now_iso(),
    }
    write_json(case_dir / "request.json", request)

    start_phase(runtime, phase="reversal_experiment", run_dir=case_dir)
    try:
        _install_unit_tests(runtime, case.project)
        testcase_path = Path(case.testcase_path)
        _write_exploit_files(case_dir, testcase_path, case.fuzz_target)

        reset_to_secure_commit(
            runtime,
            repo_dir=runtime.repo_dir_in_container,
            secure_base_commit=config.secure_base_commit,
        )

        revert_ok, revert_output = _attempt_revert(runtime, runtime.repo_dir_in_container, case.fix_commit)
        (case_dir / "revert_output.txt").write_text(revert_output, encoding="utf-8")
        if not revert_ok:
            payload = {
                "project": case.project,
                "issue_id": case.issue_id,
                "status": "revert_failed",
                "verification_status": "failure",
                "reason": "git_revert_failed",
                "run_dir": str(case_dir),
            }
            write_json(case_dir / "result.json", payload)
            return payload

        verification: VerificationResult = run_verification(
            runtime=runtime,
            project=case.project,
            run_id=case_run_id,
            repo_dir=runtime.repo_dir_in_container,
            secure_base_commit=config.secure_base_commit,
            git_backup_dir=case_dir,
            unit_tests=config.unit_tests,
            project_root=project_root(case.project),
            exploit_path="/workspace/run/exploit_files/exploit.sh",
            pre_vulnerable_commands=[f"{_BUILD_PRELUDE}set -o pipefail && bash /src/build.sh 2>&1 | tee /tmp/vuljector_build_vulnerable.log"],
            pre_secure_commands=[f"{_BUILD_PRELUDE}set -o pipefail && bash /src/build.sh 2>&1 | tee /tmp/vuljector_build_secure.log"],
        )
        write_json(case_dir / "verification_result.json", verification.to_dict())
        payload = {
            "project": case.project,
            "issue_id": case.issue_id,
            "status": "completed",
            "verification_status": verification.status,
            "failure_cause": verification.failure_cause,
            "run_dir": str(case_dir),
        }
        write_json(case_dir / "result.json", payload)
        return payload
    finally:
        finish_phase(runtime)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run narrow reversal experiments using local testcase replay")
    parser.add_argument(
        "--manifest",
        default=str(_DEFAULT_MANIFEST),
        help="Path to reversal_inputs_manifest.jsonl",
    )
    parser.add_argument(
        "--case",
        action="append",
        required=True,
        help="Case selector in project:issue_id form; may be passed multiple times",
    )
    parser.add_argument("--out-root", default=str(_DEFAULT_OUT_ROOT))
    args = parser.parse_args()

    manifest_path = Path(args.manifest).expanduser().resolve()
    out_root = Path(args.out_root).expanduser().resolve() / f"run_{utc_now_iso().replace(':', '').replace('-', '')}"
    out_root.mkdir(parents=True, exist_ok=True)

    cases = load_cases(manifest_path, args.case)
    results = [run_case(case, out_root) for case in cases]
    summary = {
        "timestamp_utc": utc_now_iso(),
        "manifest": str(manifest_path),
        "cases": args.case,
        "results": results,
    }
    write_json(out_root / "summary.json", summary)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
