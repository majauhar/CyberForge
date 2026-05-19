"""Forward-guided fuzz PoC generation that prefers selector metadata first."""

from __future__ import annotations

from pathlib import Path
import re
import shutil
from typing import Any

from agent_tasks.assets import ensure_task_assets, extract_sanitizer_report
from utils.cwe import resolve_cwe_group
from utils.json_io import read_json, write_json
from utils.paths import fuzz_guided_backfill_run_dir, new_run_id, project_root, runs_root
from vuljector.core import load_project_config, next_vulnerability_id
from vuljector.io_contracts import utc_now_iso
from vuljector.run_fuzz_poc import (
    DEFAULT_CACHE_DIR,
    _build_verification_rollup,
    _build_generated_attempt as _legacy_build_generated_attempt,
    _candidate_fuzz_metadata,
    _copy_curated_seeds,
    _generate_input_records,
    _infer_trigger_profile,
    _load_local_fuzz_assets,
    _pick_fuzzer as _legacy_pick_fuzzer,
    _preferred_extensions,
    _relative_paths_for_attempt,
    _render_exploit_sh,
    _render_fuzz_poc_py,
    _resolve_patch_diff,
    _retarget_profile_for_fuzzer,
    _sanitize_tag,
    _select_builtin_corpus_members,
    _synthesized_injection_result,
    _trigger_profile_from_fuzz_metadata,
    _write_fuzz_poc_request,
    verify_fuzz_poc_attempt,
)


FUZZ_GUIDED_POC_ROOT = runs_root() / "fuzz_poc_guided"

_GUIDED_REJECT_NAME_TOKENS = (
    "log",
    "out",
    "trace",
    "gdb",
    "asan",
    "ubsan",
    "build",
    "compile",
    "stderr",
    "stdout",
    "clean",
    "vuln",
)

_GUIDED_REJECT_PATH_PART_PATTERNS = (
    "clean",
    "vuln",
)

_GUIDED_BUILTIN_CORPUS_LIMITS = {
    "script_text": 64,
    "json_text": 64,
    "font_binary": 48,
    "zip_archive": 48,
    "image_png": 48,
}


def _guided_candidate_template_files(source_attempt_dir: Path, preferred_exts: set[str]) -> list[Path]:
    roots = [
        source_attempt_dir / "artifacts" / "exploit_files",
        source_attempt_dir / "exploit_seed",
        source_attempt_dir / "reference",
    ]
    files: list[Path] = []
    for root in roots:
        if not root.exists():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            lowered_parts = [part.lower() for part in path.parts]
            if any(
                part == token
                or part.startswith(f"{token}_")
                or part.endswith(f"_{token}")
                for part in lowered_parts
                for token in _GUIDED_REJECT_PATH_PART_PATTERNS
            ):
                continue
            low_name = path.name.lower()
            ext = path.suffix.lower()
            if low_name in {"exploit.sh", "attack.sh", "attack.py"}:
                continue
            if any(token in low_name for token in _GUIDED_REJECT_NAME_TOKENS):
                continue
            if ext in {".py", ".sh", ".c", ".cc", ".cpp", ".h", ".hpp", ".md", ".json"}:
                if ext == ".json" and any(tok in low_name for tok in ("seed", "sample", "input", "corpus")):
                    pass
                elif ext in preferred_exts:
                    pass
                else:
                    continue
            try:
                size = path.stat().st_size
            except OSError:
                continue
            if size <= 0 or size > 1_000_000:
                continue
            files.append(path)
    return files


def _collect_guided_source_templates(source_attempt_dir: Path, profile: dict[str, Any], fuzzer: str) -> list[Path]:
    preferred_exts = set(_preferred_extensions(profile.get("format_family"), fuzzer))
    ranked: list[tuple[int, Path]] = []
    for path in _guided_candidate_template_files(source_attempt_dir, preferred_exts):
        score = 0
        ext = path.suffix.lower()
        low_name = path.name.lower()
        if ext in preferred_exts:
            score += 6
        elif not ext and ".bin" in preferred_exts:
            score += 2
        if any(token in low_name for token in ("poc", "seed", "input", "sample", "corpus", "fixture", "case")):
            score += 3
        if path.parent.name in {"exploit_seed", "reference"}:
            score += 2
        if re.fullmatch(r"(empty|simple|nested|truncated|regexp)\.(js|mjs|txt|bin|json)", low_name):
            score += 2
        if score > 0:
            ranked.append((score, path))
    ranked.sort(key=lambda item: (-item[0], len(item[1].name), str(item[1])))
    return [path for _, path in ranked[:8]]


def _metadata_recommendations(fuzz: dict[str, Any]) -> list[dict[str, Any]]:
    recs = list(fuzz.get("recommendations") or [])
    if recs:
        return recs
    synthesized: list[dict[str, Any]] = []
    preferred = fuzz.get("preferred_fuzzer")
    if preferred:
        synthesized.append(
            {
                "fuzzer": preferred,
                "score": 100,
                "reasons": ["selector preferred fuzzer"],
                "has_blockers": bool(fuzz.get("has_blockers")),
                "has_dict": bool(fuzz.get("dict_available") or fuzz.get("dict_name")),
                "has_options": bool(fuzz.get("options_available") or fuzz.get("max_len") or fuzz.get("timeout_seconds")),
            }
        )
    for idx, alternate in enumerate(fuzz.get("alternate_fuzzers") or []):
        synthesized.append(
            {
                "fuzzer": alternate,
                "score": 90 - idx,
                "reasons": ["selector alternate fuzzer"],
                "has_blockers": bool(fuzz.get("has_blockers")),
                "has_dict": bool(fuzz.get("dict_available") or fuzz.get("dict_name")),
                "has_options": bool(fuzz.get("options_available") or fuzz.get("max_len") or fuzz.get("timeout_seconds")),
            }
        )
    return synthesized


def _guided_builtin_corpus_sample_limit(profile: dict[str, Any]) -> int:
    format_family = str(profile.get("format_family") or "").strip().lower()
    return _GUIDED_BUILTIN_CORPUS_LIMITS.get(format_family, 32)


def _guided_curated_seed_limit(profile: dict[str, Any]) -> int:
    return max(16, min(64, _guided_builtin_corpus_sample_limit(profile)))


def _guided_replay_timeout_seconds(profile: dict[str, Any]) -> int:
    format_family = str(profile.get("format_family") or "").strip().lower()
    if format_family in {"script_text", "json_text"}:
        return 5
    return 10


def _guided_libfuzzer_options(
    *,
    profile: dict[str, Any],
    candidate_fuzz: dict[str, Any],
    local_assets: dict[str, Any],
) -> dict[str, Any]:
    options = dict(local_assets.get("options") or {})
    format_family = str(profile.get("format_family") or "").strip().lower()
    if "use_value_profile" not in options:
        options["use_value_profile"] = 1
    if "max_len" not in options:
        if format_family in {"script_text", "json_text"}:
            options["max_len"] = 8192
        elif format_family in {"font_binary", "zip_archive", "image_png"}:
            options["max_len"] = 16384
    dict_name = candidate_fuzz.get("dict_name")
    if dict_name and "dict" not in options:
        options["dict"] = dict_name
    return options


def _pick_guided_fuzzer(
    injection_result: Path,
    cache_dir: Path,
    force_fuzzer: str | None,
    profile: dict[str, Any],
) -> dict[str, Any]:
    injection = read_json(injection_result)
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    if not candidate_fuzz:
        fallback = _legacy_pick_fuzzer(injection_result, cache_dir, force_fuzzer, profile)
        fallback["source"] = "patch_inference_fallback"
        return fallback

    recs = _metadata_recommendations(candidate_fuzz)
    recs_by_name = {item["fuzzer"]: item for item in recs if item.get("fuzzer")}
    preferred = candidate_fuzz.get("preferred_fuzzer")
    alternates = [item for item in candidate_fuzz.get("alternate_fuzzers") or [] if item]

    if force_fuzzer:
        forced = recs_by_name.get(force_fuzzer)
        if forced is None:
            forced = {
                "fuzzer": force_fuzzer,
                "score": 0,
                "reasons": ["forced override"],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available") or candidate_fuzz.get("dict_name")),
                "has_options": bool(candidate_fuzz.get("options_available") or candidate_fuzz.get("max_len") or candidate_fuzz.get("timeout_seconds")),
            }
        return {"mapping": {"recommendations": recs, "matched_functions": []}, "selected": forced, "source": "force_override"}

    if preferred:
        chosen = recs_by_name.get(preferred)
        if chosen is None:
            chosen = {
                "fuzzer": preferred,
                "score": 100,
                "reasons": ["selector preferred fuzzer"],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available") or candidate_fuzz.get("dict_name")),
                "has_options": bool(candidate_fuzz.get("options_available") or candidate_fuzz.get("max_len") or candidate_fuzz.get("timeout_seconds")),
            }
        return {"mapping": {"recommendations": recs, "matched_functions": []}, "selected": chosen, "source": "selection_metadata_preferred"}

    for alternate in alternates:
        chosen = recs_by_name.get(alternate)
        if chosen is not None:
            return {"mapping": {"recommendations": recs, "matched_functions": []}, "selected": chosen, "source": "selection_metadata_alternate"}

    if recs:
        return {"mapping": {"recommendations": recs, "matched_functions": []}, "selected": recs[0], "source": "selection_metadata_recommendation"}

    fallback = _legacy_pick_fuzzer(injection_result, cache_dir, force_fuzzer, profile)
    fallback["source"] = "patch_inference_fallback"
    return fallback


def _guided_pick_sequence(
    injection_result: Path,
    cache_dir: Path,
    force_fuzzer: str | None,
    profile: dict[str, Any],
    *,
    top_fuzzers: int = 1,
) -> list[dict[str, Any]]:
    first_pick = _pick_guided_fuzzer(injection_result, cache_dir, force_fuzzer, profile)
    if force_fuzzer or top_fuzzers <= 1:
        return [first_pick]
    injection = read_json(injection_result)
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    if not candidate_fuzz:
        return [first_pick]

    recs = _metadata_recommendations(candidate_fuzz)
    recs_by_name = {item["fuzzer"]: item for item in recs if item.get("fuzzer")}
    ordered_names: list[tuple[str, str]] = []
    preferred = candidate_fuzz.get("preferred_fuzzer")
    if preferred:
        ordered_names.append((preferred, "selection_metadata_preferred"))
    for alt in candidate_fuzz.get("alternate_fuzzers") or []:
        if alt:
            ordered_names.append((alt, "selection_metadata_alternate"))
    for rec in recs:
        name = rec.get("fuzzer")
        if name:
            ordered_names.append((name, "selection_metadata_recommendation"))

    picks: list[dict[str, Any]] = []
    seen: set[str] = set()
    for name, source in ordered_names:
        if not name or name in seen:
            continue
        selected = recs_by_name.get(name)
        if selected is None:
            selected = {
                "fuzzer": name,
                "score": 0,
                "reasons": [source.replace("_", " ")],
                "has_blockers": bool(candidate_fuzz.get("has_blockers")),
                "has_dict": bool(candidate_fuzz.get("dict_available") or candidate_fuzz.get("dict_name")),
                "has_options": bool(
                    candidate_fuzz.get("options_available")
                    or candidate_fuzz.get("max_len")
                    or candidate_fuzz.get("timeout_seconds")
                ),
            }
        picks.append(
            {
                "mapping": {"recommendations": recs, "matched_functions": []},
                "selected": selected,
                "source": source,
            }
        )
        seen.add(name)
        if len(picks) >= top_fuzzers:
            break
    if not picks:
        return [first_pick]
    return picks


def _build_guided_attempt(
    *,
    source_attempt_dir: Path,
    destination_attempt_dir: Path,
    run_id: str,
    cache_dir: Path,
    force_fuzzer: str | None,
    max_total_time: int,
    use_curated_corpus: bool = True,
    picked: dict[str, Any] | None = None,
) -> dict[str, Any]:
    injection_result_path = source_attempt_dir / "injection_result.json"
    if not injection_result_path.exists():
        raise FileNotFoundError(f"missing injection_result.json in {source_attempt_dir}")
    injection = read_json(injection_result_path)
    project = injection["project"]
    candidate_fuzz = _candidate_fuzz_metadata(injection)
    if not candidate_fuzz:
        return _legacy_build_generated_attempt(
            source_attempt_dir=source_attempt_dir,
            destination_attempt_dir=destination_attempt_dir,
            run_id=run_id,
            cache_dir=cache_dir,
            force_fuzzer=force_fuzzer,
            max_total_time=max_total_time,
        )

    profile = _trigger_profile_from_fuzz_metadata(injection, candidate_fuzz)
    picked = picked or _pick_guided_fuzzer(injection_result_path, cache_dir, force_fuzzer, profile)
    selected = picked["selected"]
    selection_source = picked.get("source", "selection_metadata_preferred")
    profile = _retarget_profile_for_fuzzer(profile, selected["fuzzer"])
    local_assets = _load_local_fuzz_assets(project, selected["fuzzer"])
    libfuzzer_options = _guided_libfuzzer_options(
        profile=profile,
        candidate_fuzz=candidate_fuzz,
        local_assets=local_assets,
    )
    builtin_corpus_sample_limit = _guided_builtin_corpus_sample_limit(profile)
    curated_seed_limit = _guided_curated_seed_limit(profile)
    replay_timeout_seconds = _guided_replay_timeout_seconds(profile)

    exploit_dir = destination_attempt_dir / "artifacts" / "exploit_files"
    generated_inputs_dir = exploit_dir / "generated_inputs"
    exploit_dir.mkdir(parents=True, exist_ok=True)
    (destination_attempt_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    source_templates = _collect_guided_source_templates(source_attempt_dir, profile, selected["fuzzer"])
    builtin_corpus_members = _select_builtin_corpus_members(
        project=project,
        fuzzer=selected["fuzzer"],
        profile=profile,
        source_templates=source_templates,
        candidate_fuzz=candidate_fuzz,
        limit=builtin_corpus_sample_limit,
        replay_limit=min(8, builtin_corpus_sample_limit),
    )
    input_records = _generate_input_records(
        profile,
        generated_inputs_dir,
        source_templates,
        builtin_corpus_members=builtin_corpus_members,
    )
    if use_curated_corpus:
        curated_names = _copy_curated_seeds(project, selected["fuzzer"], generated_inputs_dir, limit=curated_seed_limit)
        for curated_name in curated_names:
            input_records.append(
                {
                    "name": curated_name,
                    "relative_path": str(Path("artifacts/exploit_files/generated_inputs") / curated_name),
                    "provenance": "curated_carryover",
                    "generator": "curated_carryover",
                    "bug_conditioned": False,
                    "source_kind": "curated_corpus",
                    "source_name": curated_name,
                    "replay_target": True,
                    "corpus_target": True,
                    "replay_order": len(input_records),
                }
            )
    generated_names = [record["name"] for record in input_records]
    preferred_exts = _preferred_extensions(profile.get("format_family"), selected["fuzzer"])
    selected_builtin_manifest = [{key: value for key, value in item.items() if key != "data"} for item in builtin_corpus_members]

    manifest = {
        "project": project,
        "source_attempt_dir": str(source_attempt_dir),
        "source_injection_result": str(injection_result_path),
        "generated_at_utc": utc_now_iso(),
        "selected_fuzzer": selected,
        "selected_fuzzer_source": selection_source,
        "recommendations": _metadata_recommendations(candidate_fuzz),
        "matched_functions": [],
        "trigger_profile": profile,
        "candidate_fuzz": candidate_fuzz,
        "generated_inputs": [str(Path("artifacts/exploit_files/generated_inputs") / name) for name in generated_names],
        "generated_input_records": input_records,
        "selected_builtin_corpus_members": selected_builtin_manifest,
        "max_total_time": max_total_time,
        "replay_timeout_seconds": replay_timeout_seconds,
        "use_builtin_corpus": True,
        "use_curated_corpus": use_curated_corpus,
        "builtin_corpus_sample_limit": max(builtin_corpus_sample_limit, len(selected_builtin_manifest)),
        "builtin_corpus_extensions": preferred_exts,
        "libfuzzer_options": libfuzzer_options,
        "local_dict_path": local_assets["dict_path"],
        "local_options_path": local_assets["options_path"],
        "source_templates": [str(path) for path in source_templates],
        "cwe_id": injection.get("cwe_id"),
        "reference_kind": (injection.get("strategy") or {}).get("reference_kind"),
    }

    write_json(destination_attempt_dir / "source_injection_result.json", injection)
    patch_diff = _resolve_patch_diff(injection, attempt_dir=source_attempt_dir)
    (destination_attempt_dir / "artifacts" / "vuln.patch").write_text(patch_diff, encoding="utf-8")
    write_json(exploit_dir / "fuzz_poc_manifest.json", manifest)
    (exploit_dir / "fuzz_poc.py").write_text(
        _render_fuzz_poc_py("artifacts/exploit_files/fuzz_poc_manifest.json"),
        encoding="utf-8",
    )
    (exploit_dir / "exploit.sh").write_text(_render_exploit_sh(project), encoding="utf-8")
    write_json(
        destination_attempt_dir / "injection_result.json",
        _synthesized_injection_result(
            source_injection=injection,
            run_id=run_id,
            attempt_dir=destination_attempt_dir,
            exploit_dir=exploit_dir,
            selected=selected,
            selection_source=selection_source,
            generated_input_count=len(generated_names),
        ),
    )
    return {
        "project": project,
        "attempt_dir": str(destination_attempt_dir),
        "selected_fuzzer": selected["fuzzer"],
        "selected_fuzzer_source": selection_source,
        "generated_input_count": len(generated_names),
        "selected_builtin_corpus_count": len(selected_builtin_manifest),
        "manifest_path": str(exploit_dir / "fuzz_poc_manifest.json"),
        "source_attempt_dir": str(source_attempt_dir),
    }


def generate_guided_fuzz_poc(
    *,
    source_attempt_dir: Path,
    tag: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    force_fuzzer: str | None = None,
    max_total_time: int = 90,
    top_fuzzers: int = 1,
    use_curated_corpus: bool = True,
) -> dict[str, Any]:
    injection = read_json(source_attempt_dir / "injection_result.json")
    project = injection["project"]
    run_suffix = _sanitize_tag(tag or source_attempt_dir.name)
    run_id = new_run_id("fuzz_poc_guided", suffix=run_suffix)
    run_dir = FUZZ_GUIDED_POC_ROOT / project / run_id
    profile = _infer_trigger_profile(injection)
    picks = _guided_pick_sequence(
        source_attempt_dir / "injection_result.json",
        cache_dir,
        force_fuzzer,
        profile,
        top_fuzzers=max(1, top_fuzzers),
    )
    attempts: list[dict[str, Any]] = []
    for index, picked in enumerate(picks):
        attempt_dir = run_dir / f"attempt_{index:02d}"
        payload = _build_guided_attempt(
            source_attempt_dir=source_attempt_dir,
            destination_attempt_dir=attempt_dir,
            run_id=run_id,
            cache_dir=cache_dir,
            force_fuzzer=force_fuzzer,
            max_total_time=max_total_time,
            use_curated_corpus=use_curated_corpus,
            picked=picked,
        )
        attempts.append(payload)
    _write_fuzz_poc_request(
        run_dir=run_dir,
        project=project,
        run_id=run_id,
        source_run_dir=None,
        source_attempt_dir=str(source_attempt_dir),
        tag=tag,
        force_fuzzer=force_fuzzer,
        max_total_time=max_total_time,
        exploit_timeout=None,
    )
    summary = {
        "project": project,
        "run_id": run_id,
        "mode": "fuzz_poc_guided",
        "source_attempt_dir": str(source_attempt_dir),
        "generated_attempt_dir": str(run_dir / "attempt_00"),
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def batch_generate_guided_fuzz_poc(
    *,
    source_run_dir: Path,
    tag: str | None = None,
    cache_dir: Path = DEFAULT_CACHE_DIR,
    force_fuzzer: str | None = None,
    max_total_time: int = 90,
    limit: int | None = None,
    exploit_timeout: int | None = 600,
    top_fuzzers: int = 1,
    use_curated_corpus: bool = True,
    register_curated_results: bool = True,
) -> dict[str, Any]:
    raw_attempt_dirs = sorted(path for path in source_run_dir.glob("attempt_*") if path.is_dir())
    if limit is not None:
        raw_attempt_dirs = raw_attempt_dirs[:limit]
    if not raw_attempt_dirs:
        raise RuntimeError(f"no attempt directories found in {source_run_dir}")

    attempt_dirs: list[Path] = []
    skipped_attempts: list[dict[str, str]] = []
    for attempt_dir in raw_attempt_dirs:
        injection_path = attempt_dir / "injection_result.json"
        if not injection_path.exists():
            skipped_attempts.append({"attempt_dir": str(attempt_dir), "reason": "missing injection_result.json"})
            continue
        injection = read_json(injection_path)
        if injection.get("status") != "success":
            skipped_attempts.append(
                {"attempt_dir": str(attempt_dir), "reason": f"skipping injection status {injection.get('status')}"}
            )
            continue
        patch_diff = _resolve_patch_diff(injection, attempt_dir=attempt_dir).strip()
        if not patch_diff:
            skipped_attempts.append({"attempt_dir": str(attempt_dir), "reason": "missing patch_diff"})
            continue
        attempt_dirs.append(attempt_dir)
    if not attempt_dirs:
        raise RuntimeError(f"no successful injection attempts available in {source_run_dir}")

    first_injection = read_json(attempt_dirs[0] / "injection_result.json")
    project = first_injection["project"]
    run_suffix = _sanitize_tag(tag or source_run_dir.name)
    run_id = new_run_id("fuzz_poc_guided", suffix=run_suffix)
    run_dir = FUZZ_GUIDED_POC_ROOT / project / run_id
    _write_fuzz_poc_request(
        run_dir=run_dir,
        project=project,
        run_id=run_id,
        source_run_dir=str(source_run_dir),
        source_attempt_dir=None,
        tag=tag,
        force_fuzzer=force_fuzzer,
        max_total_time=max_total_time,
        exploit_timeout=exploit_timeout,
    )

    attempts: list[dict[str, Any]] = []
    verification_results: list[dict[str, Any]] = []
    summary = {
        "project": project,
        "run_id": run_id,
        "mode": "fuzz_poc_guided",
        "source_run_dir": str(source_run_dir),
        "generated_run_dir": str(run_dir),
        "skipped_source_attempts": skipped_attempts,
        "attempts": attempts,
    }
    write_json(run_dir / "run_summary.json", summary)

    created_count = 0
    for source_index, source_attempt in enumerate(attempt_dirs):
        injection = read_json(source_attempt / "injection_result.json")
        profile = _infer_trigger_profile(injection)
        picks = _guided_pick_sequence(
            source_attempt / "injection_result.json",
            cache_dir,
            force_fuzzer,
            profile,
            top_fuzzers=max(1, top_fuzzers),
        )
        print(
            f"[fuzz-poc guided] generating source attempt {source_index + 1}/{len(attempt_dirs)} "
            f"with {len(picks)} fuzzer variant(s) from {source_attempt}"
        )
        for picked in picks:
            try:
                payload = _build_guided_attempt(
                    source_attempt_dir=source_attempt,
                    destination_attempt_dir=run_dir / f"attempt_{created_count:02d}",
                    run_id=run_id,
                    cache_dir=cache_dir,
                    force_fuzzer=force_fuzzer,
                    max_total_time=max_total_time,
                    use_curated_corpus=use_curated_corpus,
                    picked=picked,
                )
                if exploit_timeout is not None:
                    verification = verify_fuzz_poc_attempt(
                        attempt_dir=Path(payload["attempt_dir"]),
                        exploit_timeout=exploit_timeout,
                        register_curated_results=register_curated_results,
                    )
                    if verification.get("status") == "success":
                        exported = _export_guided_success_bundle(Path(payload["attempt_dir"]), verification)
                        verification["exported_vulnerability_id"] = exported.get("vulnerability_id", "")
                    verification_results.append(
                        {
                            "attempt_dir": payload["attempt_dir"],
                            "verification_result": verification,
                        }
                    )
            except Exception as exc:
                payload = {
                    "source_attempt_dir": str(source_attempt),
                    "selected_fuzzer": (picked.get("selected") or {}).get("fuzzer"),
                    "generated": False,
                    "failure_message": str(exc),
                }
            attempts.append(payload)
            created_count += 1
            write_json(run_dir / "run_summary.json", summary)

    if exploit_timeout is not None:
        verification_summary = {
            "run_dir": str(run_dir),
            "attempts": verification_results,
            "summary": _build_verification_rollup(run_dir, verification_results),
        }
        write_json(run_dir / "verification_summary.json", verification_summary)
        summary["verification"] = {
            "completed": len(verification_results),
            "total": len([attempt for attempt in attempts if attempt.get("generated", True)]),
            "summary_path": str(run_dir / "verification_summary.json"),
            "rollup": verification_summary["summary"],
        }
    write_json(run_dir / "run_summary.json", summary)
    return summary


def backfill_guided_success_exports(
    *,
    guided_root: Path | None = None,
    project: str | None = None,
    limit: int | None = None,
) -> dict[str, Any]:
    """Export successful historical guided fuzz PoC attempts into vulnerability bundles."""
    root = guided_root or FUZZ_GUIDED_POC_ROOT
    if project:
        root = root / project
    run_project = project or "_all"
    run_id = new_run_id("fuzz_poc_guided_backfill")
    run_dir = fuzz_guided_backfill_run_dir(run_project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    summary_files = sorted(root.rglob("verification_summary.json"))
    exported: list[dict[str, Any]] = []
    skipped: list[dict[str, Any]] = []
    seen = 0

    for summary_path in summary_files:
        try:
            payload = read_json(summary_path)
        except Exception as exc:
            skipped.append({"summary_path": str(summary_path), "reason": f"parse_error: {exc}"})
            continue
        run_project = str(payload.get("project") or summary_path.parent.parent.name)
        if project and run_project != project:
            continue
        for item in payload.get("attempts", []):
            verification = item.get("verification_result") or {}
            if verification.get("status") != "success":
                continue
            attempt_dir = Path(str(item.get("attempt_dir") or "")).resolve()
            if not attempt_dir.exists():
                skipped.append({"attempt_dir": str(attempt_dir), "reason": "attempt_dir_missing"})
                continue
            manifest_path = attempt_dir / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json"
            if not manifest_path.exists():
                skipped.append({"attempt_dir": str(attempt_dir), "reason": "manifest_missing"})
                continue
            manifest = read_json(manifest_path)
            source_attempt_dir = Path(str(manifest.get("source_attempt_dir") or "")).resolve()
            selected_fuzzer = str((manifest.get("selected_fuzzer") or {}).get("fuzzer") or "")
            existing = _find_existing_guided_export(
                project=run_project,
                source_attempt_dir=source_attempt_dir,
                guided_run_id=attempt_dir.parent.name,
                guided_attempt_id=attempt_dir.name,
                selected_fuzzer=selected_fuzzer,
            )
            if existing:
                skipped.append(
                    {
                        "attempt_dir": str(attempt_dir),
                        "reason": "already_exported",
                        "vulnerability_id": existing,
                    }
                )
                continue
            exported.append(_export_guided_success_bundle(attempt_dir, verification))
            seen += 1
            if limit is not None and seen >= limit:
                payload = {
                    "status": "success",
                    "run_id": run_id,
                    "run_dir": str(run_dir),
                    "guided_root": str(root),
                    "project": project or "",
                    "exported_count": len(exported),
                    "skipped_count": len(skipped),
                    "exports": exported,
                    "skipped": skipped,
                    "limit_reached": True,
                }
                write_json(run_dir / "backfill_summary.json", payload)
                return payload

    payload = {
        "status": "success",
        "run_id": run_id,
        "run_dir": str(run_dir),
        "guided_root": str(root),
        "project": project or "",
        "exported_count": len(exported),
        "skipped_count": len(skipped),
        "exports": exported,
        "skipped": skipped,
        "limit_reached": False,
    }
    write_json(run_dir / "backfill_summary.json", payload)
    return payload


def _export_guided_success_bundle(attempt_dir: Path, verification: dict[str, Any]) -> dict[str, Any]:
    source_injection = read_json(attempt_dir / "source_injection_result.json")
    manifest = read_json(attempt_dir / "artifacts" / "exploit_files" / "fuzz_poc_manifest.json")
    project = source_injection["project"]
    vuln_parent = project_root(project) / "vulnerabilities"
    vulnerability_id = next_vulnerability_id(vuln_parent)
    vuln_dir = vuln_parent / vulnerability_id
    if vuln_dir.exists() and not (vuln_dir / "vulnerability_metadata.json").exists():
        shutil.rmtree(vuln_dir, ignore_errors=True)
    vuln_dir.mkdir(parents=True, exist_ok=True)

    exploit_src = attempt_dir / "artifacts" / "exploit_files"
    exploit_dst = vuln_dir / "exploit_files"
    if exploit_dst.exists():
        shutil.rmtree(exploit_dst, ignore_errors=True)
    shutil.copytree(exploit_src, exploit_dst)

    patch_diff = (
        (attempt_dir / "artifacts" / "vuln.patch").read_text(encoding="utf-8")
        if (attempt_dir / "artifacts" / "vuln.patch").exists()
        else (source_injection.get("artifacts") or {}).get("patch_diff", "")
    )
    (vuln_dir / "patch.diff").write_text(patch_diff, encoding="utf-8")
    write_json(vuln_dir / "verification_result.json", verification)
    write_json(vuln_dir / "fuzz_poc_manifest.json", manifest)
    write_json(vuln_dir / "source_injection_result.json", source_injection)

    metadata = _build_guided_vulnerability_metadata(
        vulnerability_id=vulnerability_id,
        attempt_dir=attempt_dir,
        source_injection=source_injection,
        manifest=manifest,
        verification=verification,
    )
    write_json(vuln_dir / "vulnerability_metadata.json", metadata)
    write_json(vuln_dir / "task_generation_context.json", _build_task_generation_context(attempt_dir, manifest, verification))
    ensure_task_assets(project, vulnerability_id, model_id=None)
    return {"vulnerability_id": vulnerability_id, "bundle_dir": str(vuln_dir)}


def _build_guided_vulnerability_metadata(
    *,
    vulnerability_id: str,
    attempt_dir: Path,
    source_injection: dict[str, Any],
    manifest: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    candidate_fuzz = manifest.get("candidate_fuzz") or {}
    selected_fuzzer = (manifest.get("selected_fuzzer") or {}).get("fuzzer", "")
    reports = ((verification.get("metadata") or {}).get("reports") or {})
    vulnerable_report = reports.get("vulnerable") or {}
    sanitizer_report = _load_best_effort_sanitizer_report(vulnerable_report)
    source_attempt_dir = Path(str(manifest.get("source_attempt_dir") or ""))
    source_run_id = source_attempt_dir.parent.name if source_attempt_dir.name else ""
    config = load_project_config(source_injection.get("project", ""))
    seed_provenance = vulnerable_report.get("seed_provenance") if isinstance(vulnerable_report, dict) else {}
    seed_name = str(
        vulnerable_report.get("seed")
        or vulnerable_report.get("seed_name")
        or (seed_provenance or {}).get("name")
        or ""
    ).strip()
    return {
        "id": vulnerability_id,
        "project": source_injection.get("project", ""),
        "producer": "fuzz_poc_guided",
        "cwe_group": resolve_cwe_group(
            source_injection.get("cwe_id", ""),
            fallback=source_injection.get("cwe_group", "Unknown"),
        ),
        "cwe_id": source_injection.get("cwe_id", ""),
        "selection_run_id": "",
        "injection_run_id": source_injection.get("run_id", ""),
        "source_injection_run_id": source_injection.get("run_id", ""),
        "guided_run_id": attempt_dir.parent.name,
        "guided_attempt_id": attempt_dir.name,
        "secure_base_commit": source_injection.get("secure_base_commit", "") or config.secure_base_commit,
        "selected_fuzzer": selected_fuzzer,
        "selected_fuzzer_source": manifest.get("selected_fuzzer_source", ""),
        "success_mode": vulnerable_report.get("mode", ""),
        "seed_name": seed_name,
        "seed_relative_path": vulnerable_report.get("seed_relative_path", ""),
        "seed_provenance": _stringify_seed_provenance(seed_provenance),
        "seed_source_kind": vulnerable_report.get("source_kind", ""),
        "seed_generator": vulnerable_report.get("generator", ""),
        "sanitizer_kind": vulnerable_report.get("sanitizer", "") or candidate_fuzz.get("sanitizer", ""),
        "has_sanitizer_report": bool(sanitizer_report),
        "exported_from_verification_status": verification.get("status", ""),
        "source_attempt_dir": str(source_attempt_dir),
        "source_run_id": source_run_id,
    }


def _build_task_generation_context(
    attempt_dir: Path,
    manifest: dict[str, Any],
    verification: dict[str, Any],
) -> dict[str, Any]:
    profile = manifest.get("trigger_profile") or {}
    candidate_fuzz = manifest.get("candidate_fuzz") or {}
    reports = ((verification.get("metadata") or {}).get("reports") or {})
    vulnerable_report = reports.get("vulnerable") or {}
    successful_seed = vulnerable_report.get("seed_provenance") if isinstance(vulnerable_report, dict) else {}
    seed_name = str(
        vulnerable_report.get("seed")
        or vulnerable_report.get("seed_name")
        or (successful_seed or {}).get("name")
        or ""
    ).strip()
    vulnerable_log_relative_path = _normalize_bundle_relative_log_path(
        vulnerable_report.get("log")
    ) or "exploit_files/fuzz_results/vulnerable/replay_00.log"
    return {
        "producer": "fuzz_poc_guided",
        "source_injection_result_path": manifest.get("source_injection_result", ""),
        "selected_fuzzer": (manifest.get("selected_fuzzer") or {}).get("fuzzer", ""),
        "selected_fuzzer_source": manifest.get("selected_fuzzer_source", ""),
        "success_mode": vulnerable_report.get("mode", ""),
        "seed_name": seed_name,
        "seed_relative_path": vulnerable_report.get("seed_relative_path", ""),
        "seed_provenance": _stringify_seed_provenance(successful_seed),
        "seed_source_kind": (successful_seed or {}).get("source_kind", "") if isinstance(successful_seed, dict) else "",
        "seed_generator": (successful_seed or {}).get("generator", "") if isinstance(successful_seed, dict) else "",
        "successful_log_relative_path": vulnerable_log_relative_path,
        "vulnerable_log_relative_path": vulnerable_log_relative_path,
        "target_file": candidate_fuzz.get("patch_path") or profile.get("patch_path") or "",
        "target_function": candidate_fuzz.get("function_name") or profile.get("function_name") or "",
        "target_line_range": profile.get("line_range") or candidate_fuzz.get("line_range") or [],
        "bug_shape": profile.get("bug_shape") or candidate_fuzz.get("bug_shape") or "",
        "format_family": profile.get("format_family") or candidate_fuzz.get("format_family") or "",
        "subsystem": profile.get("subsystem") or candidate_fuzz.get("subsystem") or "",
        "input_model": profile.get("input_model") or candidate_fuzz.get("input_model") or "",
        "mutation_goal": profile.get("mutation_goal") or candidate_fuzz.get("mutation_goal") or "",
        "harness_context": candidate_fuzz.get("harness_context") or "",
        "instruction_hints": candidate_fuzz.get("instruction_hints") or [],
        "slice_excerpt": candidate_fuzz.get("slice_excerpt") or "",
        "triggerability_rationale": candidate_fuzz.get("rationale") or "",
        "attempt_dir": str(attempt_dir),
    }


def _load_best_effort_sanitizer_report(vulnerable_report: dict[str, Any]) -> str:
    if not isinstance(vulnerable_report, dict):
        return ""
    for key in ("stderr", "stdout", "output", "report_text"):
        value = vulnerable_report.get(key)
        if isinstance(value, str) and value.strip():
            extracted = extract_sanitizer_report(value)
            if extracted:
                return extracted
    return ""


def _stringify_seed_provenance(value: Any) -> str:
    if isinstance(value, dict):
        return str(value.get("provenance") or value.get("source_kind") or "")
    if value is None:
        return ""
    return str(value)


def _normalize_bundle_relative_log_path(value: Any) -> str:
    if not value:
        return ""
    text = str(value).strip()
    if not text:
        return ""
    marker = "exploit_files/"
    marker_index = text.find(marker)
    if marker_index != -1:
        return text[marker_index:]
    return text


def _find_existing_guided_export(
    *,
    project: str,
    source_attempt_dir: Path,
    guided_run_id: str,
    guided_attempt_id: str,
    selected_fuzzer: str,
) -> str | None:
    vulnerabilities_dir = project_root(project) / "vulnerabilities"
    if not vulnerabilities_dir.exists():
        return None
    source_attempt_str = str(source_attempt_dir)
    for vuln_dir in sorted(vulnerabilities_dir.iterdir()):
        if not vuln_dir.is_dir():
            continue
        metadata_path = vuln_dir / "vulnerability_metadata.json"
        if not metadata_path.exists():
            continue
        try:
            metadata = read_json(metadata_path)
        except Exception:
            continue
        if metadata.get("producer") != "fuzz_poc_guided":
            continue
        if (
            str(metadata.get("source_attempt_dir") or "") == source_attempt_str
            and str(metadata.get("guided_run_id") or "") == guided_run_id
            and str(metadata.get("guided_attempt_id") or "") == guided_attempt_id
            and str(metadata.get("selected_fuzzer") or "") == selected_fuzzer
        ):
            return str(metadata.get("id") or vuln_dir.name)
    return None
