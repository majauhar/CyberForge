#!/usr/bin/env python3
"""Run patch-guided secure-vs-patched fuzz validation for one injection attempt."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"
DEFAULT_CACHE_DIR = REPO_ROOT / "runs" / "ossfuzz_metadata"
DEFAULT_OUTPUT_ROOT = REPO_ROOT / "runs" / "fuzz_validation"

sys.path.insert(0, str(REPO_ROOT / "src"))

from setup.container_runtime import DockerSession  # noqa: E402


def _load_mapper():
    mapper_path = REPO_ROOT / "scripts" / "fuzzing" / "map_injection_to_harness.py"
    spec = importlib.util.spec_from_file_location("map_injection_to_harness", mapper_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load mapper from {mapper_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAPPER = _load_mapper()


PROJECT_CLEANUP_COMMANDS: dict[str, list[str]] = {
    "harfbuzz": [
        "rm -rf /src/all-fonts",
    ],
}


@dataclass
class RunResult:
    kind: str
    returncode: int
    timed_out: bool
    log_path: str
    crash_detected: bool
    artifact_files: list[str]
    seed_used: str | None = None
    command: str | None = None


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def shell_join(parts: list[str]) -> str:
    return " ".join(shlex.quote(part) for part in parts)


def project_config(project: str) -> dict[str, Any]:
    project_json = PROJECTS_ROOT / project / "project.json"
    if not project_json.exists():
        raise FileNotFoundError(f"missing project config: {project_json}")
    return load_json(project_json)


def attempt_root_from_injection(injection_result: Path) -> Path:
    return injection_result.parent


def collect_seed_candidates(injection: dict[str, Any], attempt_root: Path) -> list[Path]:
    candidates: list[Path] = []
    seen: set[Path] = set()

    def add(path: Path) -> None:
        resolved = path.resolve()
        if resolved.exists() and resolved not in seen and resolved.is_file():
            seen.add(resolved)
            candidates.append(resolved)

    strategy = injection.get("strategy") or {}
    historical = strategy.get("historical_testcase") or {}
    for key in ("host_path", "staged_path", "starter_path"):
        value = historical.get(key)
        if value:
            add(Path(value))

    for rel_dir in ("reference", "exploit_seed", "artifacts/exploit_files"):
        path = attempt_root / rel_dir
        if path.exists():
            for item in sorted(path.rglob("*")):
                if item.is_file():
                    add(item)
    return candidates


def likely_replay_seeds(seed_candidates: list[Path]) -> list[Path]:
    ignore_suffixes = {".sh", ".out", ".txt", ".log", ".patch", ".json"}
    ignore_names = {"exploit.c", "hdr.h", "hdr_clean.h", "hdr_vuln.h", "run.out"}
    filtered = []
    for path in seed_candidates:
        if path.name in ignore_names:
            continue
        if path.suffix.lower() in ignore_suffixes:
            continue
        filtered.append(path)
    return filtered


def sanitize_name(name: str) -> str:
    return "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in name)


def detect_repo_dir(project: str, target_dir: str) -> str:
    return f"/src/{target_dir or project}"


def cleanup_commands_for_project(project: str) -> list[str]:
    return PROJECT_CLEANUP_COMMANDS.get(project, [])


def image_exists(tag: str) -> bool:
    result = subprocess.run(
        ["docker", "image", "inspect", tag],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.returncode == 0


def resolve_image_tag(project: str, dockerhub_image: str) -> str:
    ready_candidates = sorted(
        subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}", f"vuljector/{project}"],
            capture_output=True,
            text=True,
            timeout=30,
        ).stdout.splitlines()
    )
    ready_candidates = [tag for tag in ready_candidates if tag.endswith("-ready")]
    if ready_candidates:
        return ready_candidates[-1]
    return dockerhub_image


def start_session(project: str, image_tag: str, timeout: int) -> DockerSession:
    try:
        result = subprocess.run(
            ["docker", "run", "-d", "--rm", image_tag, "sleep", "infinity"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"docker run timed out after {timeout}s for image {image_tag}") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"docker run failed for image {image_tag}: {detail}")
    container_id = result.stdout.strip()
    subprocess.run(
        ["docker", "exec", container_id, "git", "config", "--global", "--add", "safe.directory", "*"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    return DockerSession(project=project, container_id=container_id)


def classify_rebuild_failure(log_text: str) -> str:
    low = log_text.lower()
    if "mkdir: cannot create directory" in low and "file exists" in low:
        return "rebuild_failed_environment_state"
    if "patch unexpectedly ends in middle of line" in low or "malformed patch" in low:
        return "patch_apply_failed"
    if "no such file or directory" in low or "command not found" in low:
        return "rebuild_failed_missing_dependency"
    return "rebuild_failed_project_logic"


def crash_detected(text: str) -> bool:
    needles = [
        "AddressSanitizer",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
        "heap-buffer-overflow",
        "stack-buffer-overflow",
        "use-after-free",
        "SEGV",
        "SIGSEGV",
        "SIGABRT",
        "ABRT",
        "artifact_prefix=",
        "Test unit written to ",
    ]
    low = text.lower()
    return any(needle.lower() in low for needle in needles)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def prepare_container_fuzzer_assets(
    session: DockerSession,
    *,
    fuzzer: str,
    seed_files: list[Path],
    artifact_root: str,
) -> dict[str, str]:
    corpus_dir = f"{artifact_root}/corpus"
    extra_dir = f"{artifact_root}/extra_seeds"
    findings_dir = f"{artifact_root}/findings"
    session.exec(f"mkdir -p {corpus_dir} {extra_dir} {findings_dir}").raise_for_status("failed to create work dirs")

    unzip_cmd = (
        f"if [ -f /out/{shlex.quote(fuzzer)}_seed_corpus.zip ]; then "
        f"python3 - <<'PY'\n"
        "import pathlib, zipfile\n"
        f"zf = zipfile.ZipFile('/out/{fuzzer}_seed_corpus.zip')\n"
        f"dest = pathlib.Path('{corpus_dir}')\n"
        "dest.mkdir(parents=True, exist_ok=True)\n"
        "zf.extractall(dest)\n"
        "print('extracted', len(zf.namelist()))\n"
        "PY\n"
        "fi"
    )
    session.exec(unzip_cmd).raise_for_status("failed to extract seed corpus")

    if seed_files:
        seeds_host_dir = Path("/tmp") / f"vuljector_seeds_{os.getpid()}_{abs(hash((session.container_id, fuzzer))) % 1000000}"
        seeds_host_dir.mkdir(parents=True, exist_ok=True)
        try:
            for seed in seed_files:
                dest = seeds_host_dir / sanitize_name(seed.name)
                if dest.exists():
                    stem = dest.stem
                    suffix = dest.suffix
                    index = 1
                    while dest.exists():
                        dest = seeds_host_dir / f"{stem}_{index}{suffix}"
                        index += 1
                dest.write_bytes(seed.read_bytes())
            session.copy_to(seeds_host_dir, extra_dir)
        finally:
            for child in seeds_host_dir.glob("*"):
                child.unlink()
            seeds_host_dir.rmdir()

    return {
        "corpus_dir": corpus_dir,
        "extra_dir": extra_dir,
        "findings_dir": findings_dir,
        "dict_path": f"/out/{fuzzer}.dict",
        "options_path": f"/out/{fuzzer}.options",
        "binary_path": f"/out/{fuzzer}",
    }


def run_replay(
    session: DockerSession,
    *,
    fuzzer: str,
    seed_path: str,
    log_path: str,
    timeout: int,
) -> tuple[str, Any]:
    cmd = (
        "set -o pipefail && "
        f"{shlex.quote('/out/' + fuzzer)} "
        f"{shlex.quote(seed_path)} "
        f"2>&1 | tee {shlex.quote(log_path)}"
    )
    result = session.exec(cmd, timeout=timeout)
    return cmd, result


def run_fuzz(
    session: DockerSession,
    *,
    fuzzer: str,
    corpus_dir: str,
    extra_dir: str,
    findings_dir: str,
    timeout: int,
    max_total_time: int,
    runs: int | None,
) -> tuple[str, Any]:
    args = [
        f"/out/{fuzzer}",
        f"-artifact_prefix={findings_dir}/",
        f"-max_total_time={max_total_time}",
        "-print_final_stats=1",
    ]
    if session.exec(f"test -f /out/{shlex.quote(fuzzer)}.dict").returncode == 0:
        args.append(f"-dict=/out/{fuzzer}.dict")
    if runs is not None:
        args.append(f"-runs={runs}")
    args.append(corpus_dir)
    if extra_dir:
        args.append(extra_dir)
    cmd = "set -o pipefail && " + shell_join(args) + " 2>&1 | tee " + shlex.quote(f"{findings_dir}/fuzz.log")
    result = session.exec(cmd, timeout=timeout)
    return cmd, result


def copy_out_tree(session: DockerSession, container_dir: str, host_dir: Path) -> None:
    host_dir.mkdir(parents=True, exist_ok=True)
    try:
        session.copy_from(container_dir, host_dir)
    except RuntimeError:
        return


def ensure_patch_applied(session: DockerSession, repo_dir: str, patch_diff: str) -> None:
    patch_text = patch_diff if patch_diff.endswith("\n") else patch_diff + "\n"
    session.write_file("/tmp/vuljector_apply.patch", patch_text)
    session.exec(
        "patch -p1 --fuzz=3 < /tmp/vuljector_apply.patch",
        workdir=repo_dir,
    ).raise_for_status("patch apply failed")


def cleanup_before_rebuild(session: DockerSession, *, project_cfg: dict[str, Any]) -> None:
    repo_dir = detect_repo_dir(project_cfg["project"], project_cfg.get("target_dir", project_cfg["project"]))
    session.exec("git clean -fdx", workdir=repo_dir).raise_for_status("git clean before rebuild failed")
    for cmd in cleanup_commands_for_project(project_cfg["project"]):
        session.exec(cmd).raise_for_status(f"project cleanup failed: {cmd}")


def rebuild_target(session: DockerSession, *, project_cfg: dict[str, Any], timeout: int) -> Any:
    cleanup_before_rebuild(session, project_cfg=project_cfg)
    return session.exec(
        "compile",
        env={"FUZZING_LANGUAGE": project_cfg.get("language", "c++")},
        timeout=timeout,
    )


def evaluate_mode(
    *,
    session: DockerSession,
    mode: str,
    repo_dir: str,
    fuzzer: str,
    seed_files: list[Path],
    host_output_dir: Path,
    replay_timeout: int,
    fuzz_timeout: int,
    max_total_time: int,
    fuzz_runs: int | None,
) -> dict[str, Any]:
    container_root = f"/tmp/vuljector_fuzz_validation/{mode}"
    assets = prepare_container_fuzzer_assets(
        session,
        fuzzer=fuzzer,
        seed_files=seed_files,
        artifact_root=container_root,
    )
    mode_dir = host_output_dir / mode
    mode_dir.mkdir(parents=True, exist_ok=True)

    replays: list[RunResult] = []
    for index, seed in enumerate(seed_files):
        container_seed = f"{assets['extra_dir']}/{sanitize_name(seed.name)}"
        log_path = f"{container_root}/replay_{index:02d}.log"
        cmd, replay_result = run_replay(
            session,
            fuzzer=fuzzer,
            seed_path=container_seed,
            log_path=log_path,
            timeout=replay_timeout,
        )
        host_log = mode_dir / f"replay_{index:02d}.log"
        write_text(host_log, (replay_result.stdout or "") + (replay_result.stderr or ""))
        replays.append(
            RunResult(
                kind="replay",
                returncode=replay_result.returncode,
                timed_out=bool(getattr(replay_result, "timed_out", False)),
                log_path=str(host_log),
                crash_detected=crash_detected((replay_result.stdout or "") + "\n" + (replay_result.stderr or "")),
                artifact_files=[],
                seed_used=str(seed),
                command=cmd,
            )
        )

    fuzz_cmd, fuzz_result = run_fuzz(
        session,
        fuzzer=fuzzer,
        corpus_dir=assets["corpus_dir"],
        extra_dir=assets["extra_dir"],
        findings_dir=assets["findings_dir"],
        timeout=fuzz_timeout,
        max_total_time=max_total_time,
        runs=fuzz_runs,
    )
    fuzz_host_log = mode_dir / "fuzz.log"
    fuzz_output = (fuzz_result.stdout or "") + (fuzz_result.stderr or "")
    write_text(fuzz_host_log, fuzz_output)

    findings_host_dir = mode_dir / "findings"
    copy_out_tree(session, assets["findings_dir"], findings_host_dir)
    artifact_files = sorted(
        str(path.relative_to(host_output_dir))
        for path in findings_host_dir.rglob("*")
        if path.is_file() and path.name != "fuzz.log"
    )

    fuzz_payload = RunResult(
        kind="fuzz",
        returncode=fuzz_result.returncode,
        timed_out=bool(getattr(fuzz_result, "timed_out", False)),
        log_path=str(fuzz_host_log),
        crash_detected=crash_detected(fuzz_output) or any(path.name.startswith("crash-") for path in findings_host_dir.rglob("*")),
        artifact_files=artifact_files,
        command=fuzz_cmd,
    )

    return {
        "mode": mode,
        "replays": [vars(item) for item in replays],
        "fuzz": vars(fuzz_payload),
    }


def classify_outcome(secure: dict[str, Any], patched: dict[str, Any]) -> str:
    secure_replay = any(item["crash_detected"] for item in secure["replays"])
    patched_replay = any(item["crash_detected"] for item in patched["replays"])
    secure_fuzz = bool(secure["fuzz"]["crash_detected"])
    patched_fuzz = bool(patched["fuzz"]["crash_detected"])

    if patched_replay and not secure_replay:
        return "patched_only_replay_crash"
    if patched_fuzz and not secure_fuzz:
        return "patched_only_fuzz_crash"
    if patched_replay or patched_fuzz:
        return "both_or_ambiguous_crash"
    return "no_crash_observed"


def run_validation(
    *,
    injection_result: Path,
    cache_dir: Path,
    output_root: Path,
    max_total_time: int,
    replay_timeout: int,
    fuzz_timeout: int,
    rebuild_timeout: int,
    start_timeout: int,
    max_replay_seeds: int,
    top_n: int,
    fuzz_runs: int | None,
    buggy_only: bool,
    force_fuzzer: str | None,
) -> dict[str, Any]:
    injection = load_json(injection_result)
    attempt_root = attempt_root_from_injection(injection_result)
    project = injection.get("project") or attempt_root.parts[attempt_root.parts.index("injection") + 1]
    project_cfg = project_config(project)
    mapping = MAPPER.map_attempt(injection_result, cache_dir)
    recommendations = mapping.get("recommendations", [])[:top_n]
    if not recommendations:
        raise RuntimeError(f"no recommended fuzzers for {injection_result}")

    if force_fuzzer:
        chosen = next((item for item in mapping.get("recommendations", []) if item["fuzzer"] == force_fuzzer), None)
        if chosen is None:
            raise RuntimeError(f"forced fuzzer {force_fuzzer!r} not present in recommendations for {injection_result}")
        top_choice = chosen
    else:
        top_choice = recommendations[0]
    fuzzer = top_choice["fuzzer"]
    patch_diff = ((injection.get("artifacts") or {}).get("patch_diff") or "")
    if not patch_diff.strip():
        raise RuntimeError(f"missing patch diff in {injection_result}")

    seed_candidates = likely_replay_seeds(collect_seed_candidates(injection, attempt_root))[:max_replay_seeds]
    repo_dir = detect_repo_dir(project, project_cfg.get("target_dir", project))
    output_dir = output_root / project / injection.get("run_id", attempt_root.parent.name) / attempt_root.name / fuzzer
    output_dir.mkdir(parents=True, exist_ok=True)
    image_tag = resolve_image_tag(project, project_cfg["dockerhub_image"])

    patched_session = start_session(project=project, image_tag=image_tag, timeout=start_timeout)
    secure_session = None if buggy_only else start_session(project=project, image_tag=image_tag, timeout=start_timeout)
    try:
        secure_summary = None
        if secure_session is not None:
            secure_summary = evaluate_mode(
                session=secure_session,
                mode="secure",
                repo_dir=repo_dir,
                fuzzer=fuzzer,
                seed_files=seed_candidates,
                host_output_dir=output_dir,
                replay_timeout=replay_timeout,
                fuzz_timeout=fuzz_timeout,
                max_total_time=max_total_time,
                fuzz_runs=fuzz_runs,
            )

        ensure_patch_applied(patched_session, repo_dir, patch_diff)
        rebuild_result = rebuild_target(
            patched_session,
            project_cfg=project_cfg,
            timeout=rebuild_timeout,
        )
        rebuild_log = output_dir / "patched_rebuild.log"
        write_text(rebuild_log, (rebuild_result.stdout or "") + (rebuild_result.stderr or ""))
        rebuild_summary = {
            "returncode": rebuild_result.returncode,
            "timed_out": bool(getattr(rebuild_result, "timed_out", False)),
            "log_path": str(rebuild_log),
        }
        rebuild_text = (rebuild_result.stdout or "") + (rebuild_result.stderr or "")
        if rebuild_result.returncode != 0:
            return {
                "project": project,
                "injection_result": str(injection_result),
                "selected_fuzzer": top_choice,
                "recommendations": recommendations,
                "matched_functions": mapping.get("matched_functions", []),
                "seed_candidates": [str(path) for path in seed_candidates],
                "output_dir": str(output_dir),
                "status": classify_rebuild_failure(rebuild_text),
                "patched_rebuild": rebuild_summary,
            }

        patched_summary = evaluate_mode(
            session=patched_session,
            mode="patched",
            repo_dir=repo_dir,
            fuzzer=fuzzer,
            seed_files=seed_candidates,
            host_output_dir=output_dir,
            replay_timeout=replay_timeout,
            fuzz_timeout=fuzz_timeout,
            max_total_time=max_total_time,
            fuzz_runs=fuzz_runs,
        )
        payload = {
            "project": project,
            "injection_result": str(injection_result),
            "selected_fuzzer": top_choice,
            "recommendations": recommendations,
            "matched_functions": mapping.get("matched_functions", []),
            "seed_candidates": [str(path) for path in seed_candidates],
            "output_dir": str(output_dir),
            "patched_rebuild": rebuild_summary,
            "patched": patched_summary,
            "status": "completed",
        }
        if secure_summary is not None:
            payload["secure"] = secure_summary
            payload["classification"] = classify_outcome(secure_summary, patched_summary)
        else:
            payload["classification"] = "buggy_only_completed"
        return payload
    finally:
        if secure_session is not None:
            secure_session.stop()
        patched_session.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--injection-result", type=Path, required=True)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--output-root", type=Path, default=DEFAULT_OUTPUT_ROOT)
    parser.add_argument("--max-total-time", type=int, default=120)
    parser.add_argument("--replay-timeout", type=int, default=120)
    parser.add_argument("--fuzz-timeout", type=int, default=300)
    parser.add_argument("--rebuild-timeout", type=int, default=1800)
    parser.add_argument("--start-timeout", type=int, default=120)
    parser.add_argument("--max-replay-seeds", type=int, default=3)
    parser.add_argument("--top-n", type=int, default=3)
    parser.add_argument("--fuzz-runs", type=int, default=None)
    parser.add_argument("--buggy-only", action="store_true")
    parser.add_argument("--force-fuzzer")
    args = parser.parse_args()

    try:
        payload = run_validation(
            injection_result=args.injection_result.resolve(),
            cache_dir=args.cache_dir.resolve(),
            output_root=args.output_root.resolve(),
            max_total_time=args.max_total_time,
            replay_timeout=args.replay_timeout,
            fuzz_timeout=args.fuzz_timeout,
            rebuild_timeout=args.rebuild_timeout,
            start_timeout=args.start_timeout,
            max_replay_seeds=args.max_replay_seeds,
            top_n=args.top_n,
            fuzz_runs=args.fuzz_runs,
            buggy_only=args.buggy_only,
            force_fuzzer=args.force_fuzzer,
        )
        output_dir = Path(payload["output_dir"])
        summary_path = output_dir / "summary.json"
        write_text(summary_path, json.dumps(payload, indent=2) + "\n")
        print(json.dumps(payload, indent=2))
        print(f"\nsummary written to {summary_path}")
    except Exception as exc:
        injection_result = args.injection_result.resolve()
        attempt_root = attempt_root_from_injection(injection_result)
        project = attempt_root.parts[attempt_root.parts.index("injection") + 1]
        fallback_dir = (
            args.output_root.resolve()
            / project
            / attempt_root.parent.name
            / attempt_root.name
            / "runner_error"
        )
        payload = {
            "project": project,
            "injection_result": str(injection_result),
            "output_dir": str(fallback_dir),
            "status": "runner_error",
            "error": str(exc),
            "error_type": exc.__class__.__name__,
        }
        summary_path = fallback_dir / "summary.json"
        write_text(summary_path, json.dumps(payload, indent=2) + "\n")
        print(json.dumps(payload, indent=2))
        print(f"\nsummary written to {summary_path}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
