"""Minimal AFL++ smoke test for native OSS-Fuzz-style targets."""

from __future__ import annotations

from pathlib import Path
import shutil

from setup.container_runtime import DockerSession
from utils.json_io import read_json, write_json
from utils.paths import new_run_id, project_root, runs_root
from vuljector.core import build_runtime, is_native_fuzz_language, load_project_config
from vuljector.io_contracts import utc_now_iso
from vuljector.run_setup import run_setup


_AFL_SMOKE_ROOT = runs_root() / "afl_smoke"
_TOOL_PREFIXES = ("afl-", "llvm-", "jazzer")
_TOOL_NAMES = {"honggfuzz", "llvm-symbolizer"}
_NON_TARGET_SUFFIXES = (".so", ".a", ".o", ".txt")
_SUCCESS_MARKERS = (
    "All set and ready to roll!",
    "We're done here. Have a nice day!",
    "new corpus items found",
)


def run_afl_smoke(*, project: str, fuzzer: str | None = None, seconds: int = 15) -> dict:
    if seconds <= 0:
        raise ValueError("seconds must be positive")

    setup_payload = run_setup(project, fuzzing_engine="afl")
    config = load_project_config(project)
    if config.fuzzing_engine != "afl":
        raise RuntimeError(f"[{project}] expected fuzzing_engine='afl', got {config.fuzzing_engine!r}")
    if not is_native_fuzz_language(config.language):
        raise RuntimeError(
            f"[{project}] AFL++ smoke testing is only supported for native C/C++ projects; "
            f"language={config.language!r}"
        )

    runtime = build_runtime(config)
    image_tag = runtime.require_ready_image()

    run_id = new_run_id("afl_smoke")
    run_dir = _AFL_SMOKE_ROOT / project / run_id
    corpus_dir = run_dir / "input"
    output_dir = run_dir / "output"
    log_path = run_dir / "afl_fuzz.log"
    request = {
        "project": project,
        "run_id": run_id,
        "timestamp_utc": utc_now_iso(),
        "fuzzing_engine": config.fuzzing_engine,
        "image_tag": image_tag,
        "requested_fuzzer": fuzzer,
        "seconds": seconds,
    }
    write_json(run_dir / "afl_smoke_request.json", request)

    session = DockerSession.start(project=project, image_tag=image_tag, run_mount_dir=run_dir)
    try:
        available_targets = _discover_targets(session)
        selected_fuzzer = _select_fuzzer(project, available_targets, explicit=fuzzer)
        seeded = _prepare_seed_inputs(session, project=project, selected_fuzzer=selected_fuzzer)
        command = (
            "AFL_SKIP_CPUFREQ=1 "
            "AFL_NO_UI=1 "
            "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 "
            "AFL_IGNORE_UNKNOWN_ENVS=1 "
            f"/src/aflplusplus/afl-fuzz -V {seconds} -m none "
            f"-i /workspace/run/input -o /workspace/run/output -- /out/{selected_fuzzer} @@"
        )
        result = session.exec(command, timeout=max(120, seconds + 90))
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        log_path.write_text(output + "\n", encoding="utf-8")

        output_listing = _list_output_files(session)
        _materialize_output_dir(session, output_dir, output_listing=output_listing)
        summary = _summarize_output(output_dir)
        stats_path = output_dir / "default" / "fuzzer_stats"
        status = _classify_run(result=result, output=output, stats_path=stats_path, summary=summary)
        payload = {
            "project": project,
            "run_id": run_id,
            "timestamp_utc": utc_now_iso(),
            "status": status,
            "fuzzing_engine": config.fuzzing_engine,
            "image_tag": image_tag,
            "ready_image_tag": setup_payload.get("ready_image_tag", image_tag),
            "selected_fuzzer": selected_fuzzer,
            "available_targets": available_targets,
            "seed_input_count": seeded,
            "seconds": seconds,
            "command": command,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "log_path": str(log_path),
            "corpus_dir": str(corpus_dir),
            "output_dir": str(output_dir),
            "output_files_seen_in_container": output_listing,
            "fuzzer_stats_path": str(stats_path) if stats_path.exists() else "",
            "summary": summary,
        }
        if status != "success":
            payload["failure_message"] = (
                "AFL++ did not complete a recognizable successful smoke run. Check afl_fuzz.log for build/runtime errors."
            )
        write_json(run_dir / "afl_smoke_result.json", payload)
        return payload
    finally:
        session.stop()


def _discover_targets(session: DockerSession) -> list[str]:
    result = session.exec("find /out -maxdepth 1 -type f -perm -111 -printf '%f\\n' | sort")
    result.raise_for_status("failed to list /out executables")
    return [line.strip() for line in result.stdout.splitlines() if _looks_like_target(line.strip())]


def _looks_like_target(name: str) -> bool:
    if not name or name in _TOOL_NAMES:
        return False
    if any(name.startswith(prefix) for prefix in _TOOL_PREFIXES):
        return False
    if any(name.endswith(suffix) for suffix in _NON_TARGET_SUFFIXES):
        return False
    if name.endswith("-pass") or "pass.so" in name:
        return False
    return True


def _select_fuzzer(project: str, available_targets: list[str], *, explicit: str | None) -> str:
    if explicit:
        if explicit not in available_targets:
            raise RuntimeError(
                f"[{project}] requested fuzzer {explicit!r} is not available in /out. "
                f"Available targets: {available_targets}"
            )
        return explicit

    preferred = _preferred_targets_from_setup(project)
    for candidate in preferred:
        if candidate in available_targets:
            return candidate
    for candidate in available_targets:
        if "fuzz" in candidate.lower():
            return candidate
    if available_targets:
        return available_targets[0]
    raise RuntimeError(f"[{project}] no AFL-compatible target binaries found in /out")


def _preferred_targets_from_setup(project: str) -> list[str]:
    setup_dir = project_root(project) / "setup"
    names: set[str] = set()
    for path in setup_dir.glob("*.dict"):
        names.add(path.stem)
    for path in setup_dir.glob("*.options"):
        names.add(path.stem)
    for path in setup_dir.glob("*_seed_corpus.zip"):
        names.add(path.name.removesuffix("_seed_corpus.zip"))
    return sorted(names)


def _prepare_seed_inputs(session: DockerSession, *, project: str, selected_fuzzer: str) -> int:
    seed_script = f"""
python3 - <<'PY'
import pathlib
import zipfile

root = pathlib.Path("/workspace/run/input")
root.mkdir(parents=True, exist_ok=True)
for child in root.iterdir():
    if child.is_file():
        child.unlink()

archive = pathlib.Path("/out/{selected_fuzzer}_seed_corpus.zip")
count = 0
if archive.exists():
    with zipfile.ZipFile(archive) as zf:
        for idx, info in enumerate(zf.infolist()):
            if info.is_dir():
                continue
            name = pathlib.Path(info.filename).name or f"seed_{{idx:06d}}"
            if not name:
                name = f"seed_{{idx:06d}}"
            target = root / f"seed_{{idx:06d}}_{{name}}"
            target.write_bytes(zf.read(info))
            count += 1
            if count >= 8:
                break
if count == 0:
    (root / "seed_000000").write_bytes(b"0")
    count = 1
print(count)
PY
"""
    result = session.exec(seed_script)
    result.raise_for_status(f"[{project}] failed to prepare AFL seed corpus")
    return int(result.stdout.strip().splitlines()[-1])


def _summarize_output(output_dir: Path) -> dict[str, int | str]:
    default_dir = output_dir / "default"
    queue_dir = default_dir / "queue"
    crash_dir = default_dir / "crashes"
    hang_dir = default_dir / "hangs"
    stats = _read_fuzzer_stats(default_dir / "fuzzer_stats")
    return {
        "queue_entries": _count_data_files(queue_dir),
        "crash_entries": _count_data_files(crash_dir),
        "hang_entries": _count_data_files(hang_dir),
        "cycles_done": stats.get("cycles_done", ""),
        "execs_done": stats.get("execs_done", ""),
        "paths_total": stats.get("paths_total", ""),
        "bitmap_cvg": stats.get("bitmap_cvg", ""),
    }


def _materialize_output_dir(session: DockerSession, output_dir: Path, *, output_listing: list[str]) -> None:
    if not output_listing:
        return
    if output_dir.exists():
        shutil.rmtree(output_dir)
    session.copy_from("/workspace/run/output", output_dir)


def _list_output_files(session: DockerSession) -> list[str]:
    result = session.exec("find /workspace/run/output -maxdepth 4 -type f -printf '%P\\n' | sort")
    if result.returncode != 0:
        return []
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _classify_run(*, result, output: str, stats_path: Path, summary: dict[str, int | str]) -> str:
    if result.timed_out or result.returncode != 0:
        return "failure"
    if stats_path.exists():
        return "success"
    if any(marker in output for marker in _SUCCESS_MARKERS):
        return "success"
    if int(summary.get("queue_entries", 0) or 0) > 0:
        return "success"
    return "failure"


def _count_data_files(path: Path) -> int:
    if not path.exists():
        return 0
    count = 0
    for child in path.iterdir():
        if child.name == "README.txt":
            continue
        if child.is_file():
            count += 1
    return count


def _read_fuzzer_stats(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    stats: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        stats[key.strip()] = value.strip()
    return stats
