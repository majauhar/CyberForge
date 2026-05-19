"""Collect teacher trajectories with staged assistance regimes and diversity."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import traceback
from typing import Any

from agent_tasks.assets import ensure_task_assets
from agent_tasks.contract_analysis import ensure_task_contract, summarize_success_path
from agent_tasks.secb_contract import derive_testcase_filename
from utils.json_io import read_json, write_json
from utils.paths import agent_task_run_dir, new_run_id, project_root, teacher_collection_run_dir
from vuljector.run_agent_tasks import run_agent_task_pipeline
from vuljector.run_task_scout import scout_task_instances


def collect_teacher_trajectories(
    *,
    project: str,
    model_id: str,
    scout_summary_path: Path | None = None,
    task_modes: list[str] | None = None,
    limit: int = 10,
    regimes: list[str] | None = None,
    stop_on_success: bool = True,
    diversity: str = "standard",
    variant_policy: str = "deterministic_random",
    profile_policy: str = "first",
    regime_retry_limit: int = 3,
) -> dict[str, Any]:
    selected_task_modes = task_modes or ["poc-san", "patch"]
    selected_regimes = regimes or _default_regimes_for(selected_task_modes)
    run_id = new_run_id("teacher_collection")
    run_dir = teacher_collection_run_dir(project, run_id)
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "teacher_assistance").mkdir(parents=True, exist_ok=True)
    candidates: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    successful_attempts: list[dict[str, Any]] = []
    success_paths: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    fatal_error: dict[str, Any] | None = None

    write_json(run_dir / "collection_request.json", {
        "project": project,
        "model_id": model_id,
        "task_modes": selected_task_modes,
        "regimes": selected_regimes,
        "diversity": diversity,
        "variant_policy": variant_policy,
        "profile_policy": profile_policy,
        "regime_retry_limit": max(1, int(regime_retry_limit)),
        "stop_on_success": stop_on_success,
        "limit": limit,
        "scout_summary_path": str(scout_summary_path) if scout_summary_path else "",
        "run_id": run_id,
    })

    try:
        candidates = _select_candidates(
            project=project,
            scout_summary_path=scout_summary_path,
            task_modes=selected_task_modes,
            limit=limit,
        )
        write_json(run_dir / "candidates.json", {
            "project": project,
            "run_id": run_id,
            "candidate_count": len(candidates),
            "candidates": candidates,
        })
        _write_partial_summary(
            run_dir=run_dir,
            project=project,
            model_id=model_id,
            task_modes=selected_task_modes,
            regimes=selected_regimes,
            diversity=diversity,
            variant_policy=variant_policy,
            profile_policy=profile_policy,
            regime_retry_limit=max(1, int(regime_retry_limit)),
            stop_on_success=stop_on_success,
            candidates=candidates,
            attempts=attempts,
            successful_attempts=successful_attempts,
            success_paths=success_paths,
            errors=errors,
            status="running",
            fatal_error=None,
        )
        for candidate in candidates:
            task_mode = str(candidate["task_mode"])
            vulnerability_id = str(candidate["vulnerability_id"])
            assets = ensure_task_assets(project, vulnerability_id, model_id=model_id)
            task_contract = ensure_task_contract(
                project,
                vulnerability_id,
                assets=assets,
            )
            variant_ids = _select_variant_ids_for_candidate(
                project=project,
                vulnerability_id=vulnerability_id,
                task_mode=task_mode,
                assets=assets,
                variant_policy=variant_policy,
            )
            profiles = _select_profiles_for_candidate(
                task_mode=task_mode,
                diversity=diversity,
                profile_policy=profile_policy,
            )
            manifest_path = run_dir / "teacher_assistance" / f"{project}.{vulnerability_id}.{task_mode}.json"
            manifest: dict[str, Any] = {
                "project": project,
                "vulnerability_id": vulnerability_id,
                "task_mode": task_mode,
                "candidate_score": candidate.get("score"),
                "candidate_reasons": candidate.get("reasons", []),
                "task_contract_path": str(project_root(project) / "vulnerabilities" / vulnerability_id / "task_contract.json"),
                "task_contract": task_contract,
                "variant_policy": variant_policy,
                "variant_ids": variant_ids,
                "profile_policy": profile_policy,
                "profiles": profiles,
                "regimes": selected_regimes,
                "regime_retry_limit": max(1, int(regime_retry_limit)),
                "attempts": [],
            }
            write_json(manifest_path, manifest)
            success_for_candidate = _run_candidate_attempts(
                run_dir=run_dir,
                project=project,
                model_id=model_id,
                task_modes=selected_task_modes,
                regimes=selected_regimes,
                diversity=diversity,
                variant_policy=variant_policy,
                profile_policy=profile_policy,
                regime_retry_limit=max(1, int(regime_retry_limit)),
                stop_on_success=stop_on_success,
                candidates=candidates,
                candidate=candidate,
                vulnerability_id=vulnerability_id,
                task_mode=task_mode,
                assets=assets,
                task_contract=task_contract,
                variant_ids=variant_ids,
                profiles=profiles,
                manifest_path=manifest_path,
                manifest=manifest,
                attempts=attempts,
                successful_attempts=successful_attempts,
                success_paths=success_paths,
                errors=errors,
            )
    except Exception as exc:
        fatal_error = {
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }
        collector_error = {
            "project": project,
            "phase": "collector",
            "error": str(exc),
            "traceback": fatal_error["traceback"],
        }
        errors.append(collector_error)
        _append_jsonl(run_dir / "errors.jsonl", collector_error)

    payload = _summary_payload(
        run_dir=run_dir,
        project=project,
        model_id=model_id,
        task_modes=selected_task_modes,
        regimes=selected_regimes,
        diversity=diversity,
        variant_policy=variant_policy,
        profile_policy=profile_policy,
        regime_retry_limit=max(1, int(regime_retry_limit)),
        stop_on_success=stop_on_success,
        candidates=candidates,
        attempts=attempts,
        successful_attempts=successful_attempts,
        success_paths=success_paths,
        errors=errors,
        status=_final_status(errors=errors, fatal_error=fatal_error),
        fatal_error=fatal_error,
    )
    write_json(run_dir / "collection_summary.json", payload)
    write_json(run_dir / "success_paths.json", {
        "project": project,
        "run_id": run_id,
        "success_count": len(success_paths),
        "success_paths": success_paths,
    })
    return payload


def _default_regimes_for(task_modes: list[str]) -> list[str]:
    if task_modes and all(mode == "poc-san" for mode in task_modes):
        return ["faithful", "assisted"]
    return ["faithful", "assisted"]


def _profiles_for_task(task_mode: str, *, diversity: str) -> list[str]:
    if diversity == "minimal":
        return ["default"]
    if task_mode == "poc-san":
        return ["corpus_first", "slice_localized", "hybrid"]
    if task_mode == "patch":
        return ["default", "localized_fix"]
    return ["default"]


def _variant_ids_for_task(task_mode: str, assets: dict[str, Any]) -> list[str]:
    if task_mode not in {"poc-desc", "poc-san", "patch"}:
        return ["v0"]
    variants = (assets.get("bug_description_variants") or {}).get("variants") or []
    ids = [str(item.get("variant_id")) for item in variants if item.get("variant_id")]
    return ids or ["v1"]


def _select_variant_ids_for_candidate(
    *,
    project: str,
    vulnerability_id: str,
    task_mode: str,
    assets: dict[str, Any],
    variant_policy: str,
) -> list[str]:
    variant_ids = _variant_ids_for_task(task_mode, assets)
    if variant_policy == "all":
        return variant_ids
    if variant_policy == "first":
        return [variant_ids[0]]
    if variant_policy == "deterministic_random":
        material = f"{project}:{vulnerability_id}:{task_mode}".encode("utf-8")
        digest = hashlib.sha1(material).hexdigest()
        index = int(digest[:8], 16) % len(variant_ids)
        return [variant_ids[index]]
    raise ValueError(f"Unsupported variant_policy: {variant_policy}")


def _select_profiles_for_candidate(
    *,
    task_mode: str,
    diversity: str,
    profile_policy: str,
) -> list[str]:
    profiles = _profiles_for_task(task_mode, diversity=diversity)
    if profile_policy == "all":
        return profiles
    if profile_policy == "first":
        return [profiles[0]]
    raise ValueError(f"Unsupported profile_policy: {profile_policy}")


def _write_partial_summary(
    *,
    run_dir: Path,
    project: str,
    model_id: str,
    task_modes: list[str],
    regimes: list[str],
    diversity: str,
    variant_policy: str,
    profile_policy: str,
    regime_retry_limit: int,
    stop_on_success: bool,
    candidates: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    successful_attempts: list[dict[str, Any]],
    success_paths: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    status: str,
    fatal_error: dict[str, Any] | None,
) -> None:
    payload = _summary_payload(
        run_dir=run_dir,
        project=project,
        model_id=model_id,
        task_modes=task_modes,
        regimes=regimes,
        diversity=diversity,
        variant_policy=variant_policy,
        profile_policy=profile_policy,
        regime_retry_limit=regime_retry_limit,
        stop_on_success=stop_on_success,
        candidates=candidates,
        attempts=attempts,
        successful_attempts=successful_attempts,
        success_paths=success_paths,
        errors=errors,
        status=status,
        fatal_error=fatal_error,
    )
    write_json(run_dir / "collection_summary.partial.json", payload)


def _summary_payload(
    *,
    run_dir: Path,
    project: str,
    model_id: str,
    task_modes: list[str],
    regimes: list[str],
    diversity: str,
    variant_policy: str,
    profile_policy: str,
    regime_retry_limit: int,
    stop_on_success: bool,
    candidates: list[dict[str, Any]],
    attempts: list[dict[str, Any]],
    successful_attempts: list[dict[str, Any]],
    success_paths: list[dict[str, Any]],
    errors: list[dict[str, Any]],
    status: str,
    fatal_error: dict[str, Any] | None,
) -> dict[str, Any]:
    return {
        "status": status,
        "run_id": run_dir.name,
        "run_dir": str(run_dir),
        "project": project,
        "model_id": model_id,
        "task_modes": task_modes,
        "regimes": regimes,
        "diversity": diversity,
        "variant_policy": variant_policy,
        "profile_policy": profile_policy,
        "regime_retry_limit": regime_retry_limit,
        "stop_on_success": stop_on_success,
        "candidate_count": len(candidates),
        "attempt_count": len(attempts),
        "success_count": len(successful_attempts),
        "success_path_count": len(success_paths),
        "error_count": len(errors),
        "candidates": candidates,
        "attempts": attempts,
        "successful_attempts": successful_attempts,
        "success_paths": success_paths,
        "errors": errors,
        "fatal_error": fatal_error or {},
    }


def _final_status(*, errors: list[dict[str, Any]], fatal_error: dict[str, Any] | None) -> str:
    if fatal_error:
        return "failure"
    if errors:
        return "completed_with_errors"
    return "success"


def _append_jsonl(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, sort_keys=True) + "\n")


def _run_candidate_attempts(
    *,
    run_dir: Path,
    project: str,
    model_id: str,
    task_modes: list[str],
    regimes: list[str],
    diversity: str,
    variant_policy: str,
    profile_policy: str,
    regime_retry_limit: int,
    stop_on_success: bool,
    candidates: list[dict[str, Any]],
    candidate: dict[str, Any],
    vulnerability_id: str,
    task_mode: str,
    assets: dict[str, Any],
    task_contract: dict[str, Any],
    variant_ids: list[str],
    profiles: list[str],
    manifest_path: Path,
    manifest: dict[str, Any],
    attempts: list[dict[str, Any]],
    successful_attempts: list[dict[str, Any]],
    success_paths: list[dict[str, Any]],
    errors: list[dict[str, Any]],
) -> bool:
    success_for_candidate = False
    retry_limit = max(1, int(regime_retry_limit))
    for variant_id in variant_ids:
        for profile_name in profiles:
            for regime in regimes:
                include_hints = regime in {"assisted", "oracle"}
                for retry_index in range(1, retry_limit + 1):
                    teacher_assistance = _build_teacher_assistance(
                        regime=regime,
                        profile_name=profile_name,
                        vuln_dir=project_root(project) / "vulnerabilities" / vulnerability_id,
                        assets=assets,
                        task_contract=task_contract,
                        task_mode=task_mode,
                    )
                    manifest_entry = {
                        "variant_id": variant_id,
                        "teacher_regime": regime,
                        "profile_name": profile_name,
                        "include_hints": include_hints,
                        "retry_index": retry_index,
                        "retry_limit": retry_limit,
                        "teacher_assistance": teacher_assistance,
                    }
                    manifest["attempts"].append(manifest_entry)
                    try:
                        result = run_agent_task_pipeline(
                            project=project,
                            vulnerability_id=vulnerability_id,
                            task_type=task_mode,
                            model_id=model_id,
                            variant_id=variant_id,
                            include_hints=include_hints,
                            teacher_regime=regime,
                            teacher_assistance=teacher_assistance,
                        )
                        attempt = {
                            "project": project,
                            "vulnerability_id": vulnerability_id,
                            "task_mode": task_mode,
                            "bug_description_variant_id": variant_id,
                            "teacher_regime": regime,
                            "profile_name": profile_name,
                            "include_hints": include_hints,
                            "retry_index": retry_index,
                            "retry_limit": retry_limit,
                            "candidate_score": candidate.get("score"),
                            "teacher_assistance_manifest": str(manifest_path),
                            "result": result,
                        }
                        attempts.append(attempt)
                        _append_jsonl(run_dir / "attempts.jsonl", attempt)
                        if result.get("validation_status") == "success":
                            success_path = _summarize_attempt_success(
                                project=project,
                                vulnerability_id=vulnerability_id,
                                task_mode=task_mode,
                                variant_id=variant_id,
                                regime=regime,
                                profile_name=profile_name,
                                result=result,
                                task_contract=task_contract,
                            )
                            success_paths.append(success_path)
                            _append_jsonl(run_dir / "success_paths.jsonl", success_path)
                            successful_attempts.append(attempt)
                            success_for_candidate = True
                            if stop_on_success:
                                break
                    except Exception as exc:
                        error_payload = {
                            "project": project,
                            "vulnerability_id": vulnerability_id,
                            "task_mode": task_mode,
                            "bug_description_variant_id": variant_id,
                            "teacher_regime": regime,
                            "profile_name": profile_name,
                            "retry_index": retry_index,
                            "retry_limit": retry_limit,
                            "error": str(exc),
                            "traceback": traceback.format_exc(),
                        }
                        errors.append(error_payload)
                        _append_jsonl(run_dir / "errors.jsonl", error_payload)
                    finally:
                        write_json(manifest_path, manifest)
                        _write_partial_summary(
                            run_dir=run_dir,
                            project=project,
                            model_id=model_id,
                            task_modes=task_modes,
                            regimes=regimes,
                            diversity=diversity,
                            variant_policy=variant_policy,
                            profile_policy=profile_policy,
                            regime_retry_limit=retry_limit,
                            stop_on_success=stop_on_success,
                            candidates=candidates,
                            attempts=attempts,
                            successful_attempts=successful_attempts,
                            success_paths=success_paths,
                            errors=errors,
                            status="running",
                            fatal_error=None,
                        )
                    if success_for_candidate and stop_on_success:
                        break
                if success_for_candidate and stop_on_success:
                    break
            if success_for_candidate and stop_on_success:
                break
        if success_for_candidate and stop_on_success:
            break
    return success_for_candidate


def _select_candidates(
    *,
    project: str,
    scout_summary_path: Path | None,
    task_modes: list[str],
    limit: int,
) -> list[dict[str, Any]]:
    if scout_summary_path:
        payload = read_json(scout_summary_path)
        rankings = payload.get("rankings") or []
        selected = [
            row for row in rankings
            if row.get("project") == project
            and row.get("task_mode") in task_modes
            and row.get("recommendation") in {"run_first", "run_after_easy"}
        ]
        return selected[:limit]

    auto_summary = scout_task_instances(
        project=project,
        task_modes=task_modes,
        limit=max(limit * 4, limit),
    )
    rankings = auto_summary.get("rankings") or []
    selected = [
        row for row in rankings
        if row.get("project") == project
        and row.get("task_mode") in task_modes
        and row.get("recommendation") in {"run_first", "run_after_easy"}
    ]
    if selected:
        return selected[:limit]

    base = project_root(project) / "vulnerabilities"
    candidates: list[dict[str, Any]] = []
    for vuln_dir in sorted(path for path in base.iterdir() if path.is_dir()):
        for task_mode in task_modes:
            candidates.append(
                {
                    "project": project,
                    "vulnerability_id": vuln_dir.name,
                    "task_mode": task_mode,
                    "score": 0,
                    "recommendation": "manual",
                    "reasons": ["selected without scout ranking"],
                }
            )
    return candidates[:limit]


def _build_teacher_assistance(
    *,
    regime: str,
    profile_name: str,
    vuln_dir: Path,
    assets: dict[str, Any],
    task_contract: dict[str, Any],
    task_mode: str,
) -> dict[str, Any]:
    if regime == "faithful":
        return {}

    hints = dict(assets.get("hints") or {})
    context = dict(assets.get("context") or {})
    expected_testcase_filename = derive_testcase_filename(vuln_dir)
    assistance: dict[str, Any] = {
        "regime": regime,
        "profile_name": profile_name,
        "goal": "Produce a validated SEC-bench-style artifact while still checking success with secb repro.",
        "selected_fuzzer": hints.get("selected_fuzzer", ""),
        "target_file": hints.get("target_file", ""),
        "target_function": hints.get("target_function", ""),
        "sanitizer_summary": hints.get("sanitizer_summary", ""),
        "mutation_goal": hints.get("mutation_goal", ""),
        "expected_testcase_filename": expected_testcase_filename,
        "expected_testcase_path": f"/testcase/{expected_testcase_filename}",
        "input_format_family": task_contract.get("input_format_family", ""),
    }

    if task_mode == "poc-san":
        repo_example_dirs = _repo_example_dirs(task_contract, limit=5)
        repo_example_strategy = [
            f"Keep the final testcase at /testcase/{expected_testcase_filename}.",
            "Search repo-visible tests, models, samples, and examples that match the testcase format.",
            "Start from a small valid repo-visible sample before attempting larger mutations.",
            "Use secb repro after each candidate change and keep only inputs that preserve the same parser path.",
        ]
        if profile_name == "corpus_first":
            assistance["likely_repo_example_dirs"] = repo_example_dirs
            assistance["repo_example_strategy"] = repo_example_strategy
        elif profile_name == "slice_localized":
            assistance["slice_excerpt"] = context.get("slice_excerpt", "")
            assistance["instruction_hints"] = (context.get("instruction_hints") or [])[:4]
            assistance["localization_strategy"] = [
                f"The expected testcase file for this instance is /testcase/{expected_testcase_filename}.",
                "Stay close to the crash site and preserve the same parser path.",
                "Prefer small local mutations that keep the file structurally valid.",
            ]
            if repo_example_dirs:
                assistance["likely_repo_example_dirs"] = repo_example_dirs[:3]
        elif profile_name == "hybrid":
            assistance["likely_repo_example_dirs"] = repo_example_dirs
            assistance["slice_excerpt"] = context.get("slice_excerpt", "")
            assistance["instruction_hints"] = (context.get("instruction_hints") or [])[:3]
            assistance["repo_example_strategy"] = [
                f"Save all final repro attempts as /testcase/{expected_testcase_filename}.",
                "Start from the most promising repo-visible examples, then use the slice excerpt to guide local mutations.",
                "Keep rerunning secb repro until the sanitizer family matches.",
            ]

    if task_mode == "patch" and profile_name == "localized_fix":
        assistance["slice_excerpt"] = context.get("slice_excerpt", "")
        assistance["instruction_hints"] = (context.get("instruction_hints") or [])[:4]

    if regime == "oracle":
        assistance["replay_candidates"] = _replay_ordered_inputs(vuln_dir, limit=12)
        assistance["exact_success_seed_reference"] = _exact_success_seed_reference(vuln_dir)
        if task_mode == "poc-san":
            assistance["oracle_note"] = (
                "Use replay ordering and exact seed provenance to recover a working testcase faster, "
                "but still validate the final artifact with secb repro."
            )
    return {key: value for key, value in assistance.items() if value not in ("", [], {}, None)}


def _candidate_visible_inputs(vuln_dir: Path, limit: int) -> list[str]:
    inputs_dir = vuln_dir / "exploit_files" / "generated_inputs"
    if not inputs_dir.exists():
        return []
    preferred = sorted(path.name for path in inputs_dir.iterdir() if path.is_file())
    return preferred[:limit]


def _repo_example_dirs(task_contract: dict[str, Any], limit: int) -> list[str]:
    summary = dict(task_contract.get("repo_example_summary") or {})
    dirs = summary.get("matching_dirs") or []
    out: list[str] = []
    for item in dirs:
        if not isinstance(item, dict):
            continue
        path = str(item.get("path") or "").strip()
        if path:
            out.append(path)
        if len(out) >= limit:
            break
    return out


def _replay_ordered_inputs(vuln_dir: Path, limit: int) -> list[dict[str, Any]]:
    verification = _load_optional_json(vuln_dir / "verification_result.json")
    records = (((verification.get("metadata") or {}).get("generated_input_records")) or [])
    ordered = sorted(
        (record for record in records if record.get("replay_target")),
        key=lambda item: int(item.get("replay_order", 999999)),
    )
    return [
        {
            "name": record.get("name", ""),
            "source_name": record.get("source_name", ""),
            "provenance": record.get("provenance", ""),
            "replay_order": record.get("replay_order", None),
        }
        for record in ordered[:limit]
    ]


def _exact_success_seed_reference(vuln_dir: Path) -> dict[str, Any]:
    verification = _load_optional_json(vuln_dir / "verification_result.json")
    reports = (((verification.get("metadata") or {}).get("reports")) or {})
    vulnerable = reports.get("vulnerable") or {}
    seed_provenance = vulnerable.get("seed_provenance") or {}
    return {
        "seed": vulnerable.get("seed") or vulnerable.get("seed_name") or seed_provenance.get("name") or "",
        "seed_provenance": seed_provenance,
    }


def _load_optional_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return read_json(path)


def _summarize_attempt_success(
    *,
    project: str,
    vulnerability_id: str,
    task_mode: str,
    variant_id: str,
    regime: str,
    profile_name: str,
    result: dict[str, Any],
    task_contract: dict[str, Any],
) -> dict[str, Any]:
    run_dir = agent_task_run_dir(project, task_mode, str(result.get("run_id") or ""))
    paths = dict(result.get("paths") or {})
    artifact_rel = str(paths.get("artifact") or "")
    artifact_path = (run_dir / artifact_rel) if artifact_rel else run_dir / "artifacts" / "testcase"
    success_path = summarize_success_path(
        project=project,
        vulnerability_id=vulnerability_id,
        artifact_path=artifact_path,
        contract=task_contract,
    )
    return {
        "project": project,
        "vulnerability_id": vulnerability_id,
        "task_mode": task_mode,
        "bug_description_variant_id": variant_id,
        "teacher_regime": regime,
        "profile_name": profile_name,
        "run_id": result.get("run_id", ""),
        "artifact_path": str(artifact_path),
        "task_contract_path": str(project_root(project) / "vulnerabilities" / vulnerability_id / "task_contract.json"),
        **success_path,
    }
