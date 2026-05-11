"""AFL++ backfill verification for fresh fuzz-PoC attempt directories."""

from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
from typing import Any

from setup.container_runtime import DockerSession
from utils.json_io import read_json, write_json
from utils.paths import project_root
from verifier.pipeline import run_verification
from vuljector.core import build_runtime, load_project_config
from vuljector.io_contracts import utc_now_iso
from vuljector.run_fuzz_guided_poc import generate_guided_fuzz_poc


_AFL_DRIVER_NAME = "fuzz_poc_afl.py"
_AFL_WRAPPER_NAME = "exploit_afl.sh"
_AFL_RESULTS_DIRNAME = "afl_results"


def run_guided_afl_backfill(
    *,
    source_attempt_dir: Path,
    tag: str | None = None,
    max_total_time: int = 90,
    top_fuzzers: int = 1,
    afl_seconds: int = 30,
    exploit_timeout: int = 900,
    use_curated_corpus: bool = True,
) -> dict[str, Any]:
    generated = generate_guided_fuzz_poc(
        source_attempt_dir=source_attempt_dir,
        tag=tag,
        max_total_time=max_total_time,
        top_fuzzers=top_fuzzers,
        use_curated_corpus=use_curated_corpus,
    )
    verification_results: list[dict[str, Any]] = []
    for attempt in generated.get("attempts", []):
        attempt_dir = Path(attempt["attempt_dir"]).resolve()
        result = verify_afl_generated_attempt(
            attempt_dir=attempt_dir,
            afl_seconds=afl_seconds,
            exploit_timeout=exploit_timeout,
        )
        verification_results.append(
            {
                "attempt_dir": str(attempt_dir),
                "afl_verification_result": result,
            }
        )

    run_dir = Path(generated["generated_attempt_dir"]).resolve().parent
    summary = {
        "run_dir": str(run_dir),
        "source_attempt_dir": str(source_attempt_dir.resolve()),
        "afl_seconds": afl_seconds,
        "attempts": verification_results,
        "summary": _build_afl_rollup(verification_results),
    }
    write_json(run_dir / "afl_verification_summary.json", summary)
    run_summary_path = run_dir / "run_summary.json"
    if run_summary_path.exists():
        payload = read_json(run_summary_path)
        payload["afl_verification"] = {
            "afl_seconds": afl_seconds,
            "summary_path": str(run_dir / "afl_verification_summary.json"),
            "rollup": summary["summary"],
        }
        write_json(run_summary_path, payload)
    return summary


def verify_afl_generated_attempt(
    *,
    attempt_dir: Path,
    afl_seconds: int = 30,
    exploit_timeout: int = 900,
) -> dict[str, Any]:
    if afl_seconds <= 0:
        raise ValueError("afl_seconds must be positive")

    result_path = attempt_dir / "afl_verification_result.json"
    if result_path.exists():
        cached = read_json(result_path)
        if cached.get("status") in {"success", "failure"}:
            return cached

    injection = read_json(attempt_dir / "source_injection_result.json")
    project = injection["project"]
    config = replace(load_project_config(project), fuzzing_engine="afl")
    runtime = build_runtime(config)
    image_tag = runtime.ensure_ready_image(unit_tests_dir=project_root(project) / "unit_tests")
    repo_dir = f"/src/{config.target_dir}"

    exploit_dir = attempt_dir / "artifacts" / "exploit_files"
    patch_diff = ((injection.get("artifacts") or {}).get("patch_diff") or "").strip()
    if not patch_diff:
        raise RuntimeError("missing patch diff in source injection result")

    _write_afl_driver(exploit_dir, afl_seconds=afl_seconds)
    wrapper_path = _write_afl_wrapper(exploit_dir)

    def _write_progress(payload: dict[str, Any]) -> None:
        write_json(result_path, payload)

    _write_progress(
        {
            "project": project,
            "run_id": attempt_dir.parent.name,
            "timestamp_utc": utc_now_iso(),
            "status": "running",
            "checks": {
                "unit_tests": "pending",
                "exploit_on_vulnerable": "pending",
                "exploit_on_secure": "pending",
            },
            "failure_cause": None,
            "failure_message": "",
            "unit_test_passed_count": None,
            "unit_test_message": "",
            "unit_test_raw_output": "",
            "progress_phase": "starting",
            "complete": False,
        }
    )

    session = DockerSession.start(project=project, image_tag=image_tag, run_mount_dir=attempt_dir)
    try:
        session.copy_to(wrapper_path, "/tmp/exploit.sh")
        session.exec("chmod +x /tmp/exploit.sh").raise_for_status("failed to chmod AFL exploit wrapper")
        verification = run_verification(
            runtime=session,
            project=project,
            run_id=attempt_dir.parent.name,
            repo_dir=repo_dir,
            patch_diff=patch_diff,
            unit_tests=config.unit_tests,
            skip_unit_tests=True,
            project_root=project_root(project),
            exploit_path="/tmp/exploit.sh",
            rebuild_command=f"FUZZING_LANGUAGE={config.language or 'c++'} FUZZING_ENGINE=afl compile",
            exploit_timeout=exploit_timeout,
            progress_callback=_write_progress,
        )
    finally:
        session.stop()

    payload = verification.to_dict()
    payload["metadata"] = {
        **_attempt_manifest_metadata(attempt_dir),
        "afl_seconds": afl_seconds,
        "reports": _load_afl_reports(attempt_dir),
    }
    write_json(result_path, payload)
    return payload


def _attempt_manifest_metadata(attempt_dir: Path) -> dict[str, Any]:
    manifest_path = attempt_dir / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json"
    manifest = read_json(manifest_path) if manifest_path.exists() else {}
    return {
        "selected_fuzzer": (manifest.get("selected_fuzzer") or {}).get("fuzzer"),
        "selected_fuzzer_source": manifest.get("selected_fuzzer_source"),
        "use_builtin_corpus": bool(manifest.get("use_builtin_corpus")),
        "use_curated_corpus": bool(manifest.get("use_curated_corpus")),
        "generated_input_records": manifest.get("generated_input_records") or [],
        "selected_builtin_corpus_members": manifest.get("selected_builtin_corpus_members") or [],
    }


def _load_afl_reports(attempt_dir: Path) -> dict[str, Any]:
    reports: dict[str, Any] = {}
    for phase in ("secure", "vulnerable"):
        report_path = attempt_dir / "artifacts" / "exploit_files" / _AFL_RESULTS_DIRNAME / phase / "crash_report.json"
        if report_path.exists():
            reports[phase] = read_json(report_path)
    return reports


def _build_afl_rollup(verification_results: list[dict[str, Any]]) -> dict[str, Any]:
    success_count = 0
    failure_count = 0
    success_projects: list[str] = []
    failure_buckets: dict[str, int] = {}
    attempt_summaries: list[dict[str, Any]] = []
    for item in verification_results:
        result = item.get("afl_verification_result") or {}
        status = result.get("status")
        failure_cause = result.get("failure_cause")
        metadata = result.get("metadata") or {}
        entry = {
            "attempt_dir": item.get("attempt_dir"),
            "status": status,
            "failure_cause": failure_cause,
            "selected_fuzzer": metadata.get("selected_fuzzer"),
        }
        attempt_summaries.append(entry)
        if status == "success":
            success_count += 1
            project = result.get("project")
            if isinstance(project, str) and project:
                success_projects.append(project)
        else:
            failure_count += 1
            key = str(failure_cause or "other_failure")
            failure_buckets[key] = failure_buckets.get(key, 0) + 1
    return {
        "attempt_count": len(verification_results),
        "success_count": success_count,
        "failure_count": failure_count,
        "success_projects": success_projects,
        "failure_buckets": failure_buckets,
        "attempt_summaries": attempt_summaries,
    }


def _write_afl_driver(exploit_dir: Path, *, afl_seconds: int) -> None:
    driver_path = exploit_dir / _AFL_DRIVER_NAME
    driver_path.write_text(_render_afl_driver(afl_seconds=afl_seconds), encoding="utf-8")


def _write_afl_wrapper(exploit_dir: Path) -> Path:
    wrapper_path = exploit_dir / _AFL_WRAPPER_NAME
    wrapper_path.write_text(
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f"python3 /workspace/run/attempt/artifacts/exploit_files/{_AFL_DRIVER_NAME}\n",
        encoding="utf-8",
    )
    wrapper_path.chmod(0o755)
    return wrapper_path


def _render_afl_driver(*, afl_seconds: int) -> str:
    template = """#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

ROOT = Path("/workspace/run/attempt")
MANIFEST = ROOT / "artifacts/exploit_files/fuzz_poc_manifest.json"
CFG = json.loads(MANIFEST.read_text(encoding="utf-8"))
PHASE = os.environ.get("VULJECTOR_PHASE_LABEL", "unknown")
AFL_SECONDS = __AFL_SECONDS__
EXPLOIT_DIR = ROOT / "artifacts" / "exploit_files"
RESULT_DIR = EXPLOIT_DIR / "afl_results" / PHASE
TMP_ROOT = Path("/tmp/vuljector_afl_backfill") / PHASE
INPUT_DIR = TMP_ROOT / "input"
OUTPUT_DIR = TMP_ROOT / "output"
GENERATED_DIR = EXPLOIT_DIR / "generated_inputs"

for path in (RESULT_DIR, TMP_ROOT):
    path.mkdir(parents=True, exist_ok=True)
for path in (INPUT_DIR, OUTPUT_DIR):
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)

fuzzer = (CFG.get("selected_fuzzer") or {}).get("fuzzer", "")
binary = Path("/out") / fuzzer
if not fuzzer or not binary.exists():
    (RESULT_DIR / "failure.txt").write_text("MISSING_BINARY\\n", encoding="utf-8")
    print("MISSING_BINARY")
    sys.exit(0)

def write_seed(name: str, data: bytes) -> None:
    (INPUT_DIR / name).write_bytes(data)

generated_records = [item for item in (CFG.get("generated_input_records") or []) if isinstance(item, dict) and item.get("name")]
builtin_records = [item for item in (CFG.get("selected_builtin_corpus_members") or []) if isinstance(item, dict) and item.get("name")]
seen_names = set()

corpus_zip = Path("/out") / f"{fuzzer}_seed_corpus.zip"
if CFG.get("use_builtin_corpus", False) and corpus_zip.exists():
    with zipfile.ZipFile(corpus_zip) as zf:
        records = builtin_records
        if not records:
            records = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = Path(info.filename).name
                if not name:
                    continue
                records.append({"name": name, "archive_member": info.filename, "corpus_target": True})
        for item in records:
            archive_member = item.get("archive_member") or item.get("name")
            if not archive_member or not item.get("corpus_target", True):
                continue
            try:
                data = zf.read(archive_member)
            except KeyError:
                continue
            name = item["name"]
            if name in seen_names:
                continue
            seen_names.add(name)
            write_seed(name, data)

for item in generated_records:
    rel = item.get("relative_path")
    name = item.get("name")
    if not rel or not name or not item.get("corpus_target", True):
        continue
    src = ROOT / rel
    if src.is_file() and name not in seen_names:
        seen_names.add(name)
        write_seed(name, src.read_bytes())

if GENERATED_DIR.exists():
    for src in sorted(GENERATED_DIR.glob("*")):
        if src.is_file() and src.name not in seen_names:
            seen_names.add(src.name)
            write_seed(src.name, src.read_bytes())

if not any(INPUT_DIR.iterdir()):
    (INPUT_DIR / "seed_000000").write_bytes(b"0")

cmd = [
    "/src/aflplusplus/afl-fuzz",
    "-V", str(AFL_SECONDS),
    "-m", "none",
    "-i", str(INPUT_DIR),
    "-o", str(OUTPUT_DIR),
    "--",
    str(binary),
    "@@",
]
env = os.environ.copy()
env.update(
    {
        "AFL_SKIP_CPUFREQ": "1",
        "AFL_NO_UI": "1",
        "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES": "1",
        "AFL_IGNORE_UNKNOWN_ENVS": "1",
    }
)

started = time.monotonic()
proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
duration = time.monotonic() - started
log_text = proc.stdout or ""
(RESULT_DIR / "afl.log").write_text(log_text, encoding="utf-8")

stats = {}
stats_path = OUTPUT_DIR / "default" / "fuzzer_stats"
if stats_path.exists():
    text = stats_path.read_text(encoding="utf-8", errors="replace")
    (RESULT_DIR / "fuzzer_stats").write_text(text, encoding="utf-8")
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()

for name in ("plot_data", "cmdline", "fuzzer_setup", "fastresume.bin"):
    src = OUTPUT_DIR / "default" / name
    if src.exists():
        shutil.copy2(src, RESULT_DIR / name)

crash_dir = OUTPUT_DIR / "default" / "crashes"
hang_dir = OUTPUT_DIR / "default" / "hangs"
saved_crashes = []
saved_hangs = []
for src_dir, collected, target_name in ((crash_dir, saved_crashes, "crashes"), (hang_dir, saved_hangs, "hangs")):
    if not src_dir.exists():
        continue
    dst_dir = RESULT_DIR / target_name
    dst_dir.mkdir(parents=True, exist_ok=True)
    for src in sorted(src_dir.iterdir()):
        if src.name == "README.txt" or not src.is_file():
            continue
        dst = dst_dir / src.name
        shutil.copy2(src, dst)
        collected.append(str(dst))

saved_crashes_count = int(stats.get("saved_crashes", "0") or 0)
saved_hangs_count = int(stats.get("saved_hangs", "0") or 0)
asan_like = any(marker in log_text for marker in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:"))
triggered = bool(saved_crashes or saved_crashes_count or asan_like)

report = {
    "phase": PHASE,
    "fuzzer": fuzzer,
    "mode": "afl",
    "returncode": proc.returncode,
    "log": str(RESULT_DIR / "afl.log"),
    "time_to_signal_seconds": round(duration, 4) if triggered else None,
    "saved_crashes": saved_crashes_count,
    "saved_hangs": saved_hangs_count,
    "crash_artifacts": saved_crashes,
    "hang_artifacts": saved_hangs,
    "result_kind": "real_crash" if saved_crashes else ("asan_without_artifact" if asan_like else "negative"),
    "fuzzer_stats": stats,
}
(RESULT_DIR / "crash_report.json").write_text(json.dumps(report, indent=2) + "\\n", encoding="utf-8")

if triggered:
    print("TRIGGERED")
    sys.exit(1)

print("NOT_TRIGGERED")
sys.exit(0)
"""
    return template.replace("__AFL_SECONDS__", str(afl_seconds))
