"""Shared fuzz-guidance helpers for candidate and patch mapping."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from vuljector.io_contracts import SelectionCandidate


REPO_ROOT = Path(__file__).resolve().parents[3]
PROJECTS_ROOT = REPO_ROOT.parent / "vuljector-projects"
DEFAULT_CACHE_DIR = REPO_ROOT / "runs" / "ossfuzz_metadata"
PATCH_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.MULTILINE)

RUNTIME_FUNCTION_SCORE = 10
STATIC_FUNCTION_SCORE = 6
FILE_COVERAGE_SCORE = 3
DICT_BONUS = 1
OPTIONS_BONUS = 1
BLOCKER_PENALTY = 2

_PATH_TOKEN_WEIGHTS: dict[str, tuple[int, str]] = {
    "gsub": (2, "token match gsub"),
    "gpos": (2, "token match gpos"),
    "shape": (2, "token match shape"),
    "subset": (2, "token match subset"),
    "repack": (2, "token match repack"),
    "m3d": (2, "token match m3d"),
    "obj": (2, "token match obj"),
    "fbx": (2, "token match fbx"),
    "gltf": (2, "token match gltf"),
    "glb": (2, "token match glb"),
    "stl": (2, "token match stl"),
    "png": (2, "token match png"),
    "read": (1, "token match read"),
    "eval": (1, "token match eval"),
    "compile": (1, "token match compile"),
    "regexp": (1, "token match regexp"),
}

_MODALITY_PENALTIES: dict[str, tuple[int, str]] = {
    "export": (-4, "exporter-heavy path"),
    "exporter": (-4, "exporter-heavy path"),
    "destruct": (-5, "destructor-heavy path"),
    "destroy": (-5, "destructor-heavy path"),
    "finalize": (-4, "destructor-heavy path"),
    "postprocess": (-4, "postprocess-heavy path"),
    "post_process": (-4, "postprocess-heavy path"),
    "cleanup": (-2, "cleanup-heavy path"),
}

_SYNTHETIC_MIN_SCORE = 4


def _path_tokens(value: str) -> set[str]:
    normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", value)
    return {token for token in re.split(r"[^a-z0-9]+", normalized.lower()) if len(token) >= 2}


def _shared_path_tokens(a: str, b: str) -> set[str]:
    return _path_tokens(a) & _path_tokens(b)


def _synthetic_recommendations_from_context(
    *,
    project: str,
    targets: list[dict[str, Any]],
    cache: dict[str, Any],
    fuzz_assets: dict[str, dict[str, bool]],
    blockers_by_fuzzer: dict[str, list[Any]],
    all_fuzzer_names: list[str],
    modality_penalty_total: int,
    modality_reasons: list[str],
) -> list[dict[str, Any]]:
    coverage = cache.get("coverage", {}).get("fuzzer_stats", {})
    introspector = cache.get("introspector", {})
    all_files = {str(path) for path in introspector.get("all_files") or []}
    recommendations: list[dict[str, Any]] = []

    for fuzzer in all_fuzzer_names:
        score = 0
        reasons: list[str] = []
        covered_files = [str(item.get("filename") or "") for item in (coverage.get(fuzzer) or {}).get("files", []) if item.get("filename")]
        covered_dirs = {str(Path(path).parent) for path in covered_files}
        covered_tokens = set().union(*(_path_tokens(path) for path in covered_files)) if covered_files else set()

        for target in targets:
            target_path = str(target["path"])
            target_dir = str(Path(target_path).parent)
            target_name = Path(target_path).name

            if target_path in all_files:
                score += 1
                reasons.append("target file exists in introspector project file list")
            if target_dir in covered_dirs:
                score += 3
                reasons.append("covered file exists in same directory as target")
            shared = covered_tokens & _path_tokens(target_name)
            if shared:
                score += min(3, len(shared))
                reasons.append(f"covered files share target tokens: {', '.join(sorted(shared))}")

            target_low = target_path.lower()
            fuzzer_low = fuzzer.lower()
            if any(token in target_low for token in ("json", "yaml", "patch")) and any(token in fuzzer_low for token in ("json", "yaml", "read", "parse")):
                score += 2
                reasons.append("format and fuzzer names suggest structured text parsing")
            if any(token in target_low for token in ("client", "server", "securechannel", "ua_")) and any(token in fuzzer_low for token in ("client", "server", "opcua", "open62541")):
                score += 2
                reasons.append("path and fuzzer names suggest protocol-path affinity")

        heuristic_scores = _path_heuristics(" ".join(str(target["path"]) for target in targets), [fuzzer]).get(fuzzer)
        if heuristic_scores:
            score += heuristic_scores["score"]
            reasons.extend(heuristic_scores["reasons"])

        if len(all_fuzzer_names) == 1 and score > 0:
            score += 3
            reasons.append("single project fuzzer fallback")

        if fuzz_assets[fuzzer]["dict"]:
            score += DICT_BONUS
            reasons.append("local dictionary available")
        if fuzz_assets[fuzzer]["options"]:
            score += OPTIONS_BONUS
            reasons.append("local options available")
        if blockers_by_fuzzer.get(fuzzer):
            score -= BLOCKER_PENALTY
            reasons.append("introspector blockers present")
        if modality_penalty_total:
            score += modality_penalty_total
            reasons.extend(modality_reasons)

        if score >= _SYNTHETIC_MIN_SCORE:
            recommendations.append(
                {
                    "fuzzer": fuzzer,
                    "score": score,
                    "reasons": sorted(set(reasons + ["synthetic fallback recommendation"])),
                    "has_blockers": bool(blockers_by_fuzzer.get(fuzzer)),
                    "has_dict": fuzz_assets[fuzzer]["dict"],
                    "has_options": fuzz_assets[fuzzer]["options"],
                }
            )

    recommendations.sort(key=lambda item: (-item["score"], item["fuzzer"]))
    return recommendations


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def normalize_source_path(project: str, path: str) -> str:
    clean = path.strip().replace("\\", "/")
    clean = re.sub(r"^[A-Za-z]:", "", clean)
    clean = clean.lstrip("./")
    if clean.startswith("/src/"):
        return re.sub(r"/+", "/", clean)
    if clean.startswith(f"{project}/"):
        return f"/src/{clean}"
    return f"/src/{project}/{clean}".replace("//", "/")


def overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start <= b_end and b_start <= a_end


def patch_targets_and_hunks(project: str, patch_diff: str) -> list[dict[str, Any]]:
    lines = patch_diff.splitlines()
    results: list[dict[str, Any]] = []
    current_path: str | None = None
    for line in lines:
        if line.startswith("+++ b/"):
            current_path = normalize_source_path(project, line[6:])
            continue
        match = PATCH_HUNK_RE.match(line)
        if match and current_path:
            start = int(match.group(1))
            count = int(match.group(2) or "1")
            results.append(
                {
                    "path": current_path,
                    "line_start": start,
                    "line_end": max(start, start + max(count, 1) - 1),
                }
            )
    return results


def local_fuzz_assets(project: str) -> dict[str, dict[str, bool]]:
    setup_dir = PROJECTS_ROOT / project / "setup"
    assets: dict[str, dict[str, bool]] = defaultdict(
        lambda: {"dict": False, "options": False, "seed_corpus": False}
    )
    for path in setup_dir.glob("*.dict"):
        assets[path.stem]["dict"] = True
    for path in setup_dir.glob("*.options"):
        assets[path.stem]["options"] = True
    for path in setup_dir.glob("*_seed_corpus.zip"):
        stem = path.name.removesuffix("_seed_corpus.zip")
        assets[stem]["seed_corpus"] = True
    return assets


def load_local_fuzzer_options(project: str) -> dict[str, dict[str, str]]:
    setup_dir = PROJECTS_ROOT / project / "setup"
    parsed: dict[str, dict[str, str]] = {}
    for path in setup_dir.glob("*.options"):
        values: dict[str, str] = {}
        current_section = ""
        for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                current_section = line.strip("[]").strip().lower()
                continue
            if "=" not in line:
                continue
            key, value = [part.strip() for part in line.split("=", 1)]
            flat_key = f"{current_section}.{key}" if current_section else key
            values[flat_key] = value
        parsed[path.stem] = values
    return parsed


def load_cache(project: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> dict[str, Any]:
    path = cache_dir / f"{project}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"missing offline OSS-Fuzz metadata cache for project {project!r}: {path}"
        )
    payload = load_json(path)
    introspector = payload.get("introspector") or {}
    if not introspector.get("available"):
        raise RuntimeError(f"offline OSS-Fuzz introspector metadata unavailable for {project!r}")
    return payload


def _normalize_candidate_path(project: str, repo_root: Path, path: str) -> str:
    raw = Path(path)
    if raw.is_absolute():
        try:
            rel = raw.resolve().relative_to(repo_root.resolve())
            return normalize_source_path(project, str(rel))
        except Exception:
            return normalize_source_path(project, raw.name)
    return normalize_source_path(project, path)


def _make_targets_for_candidate(
    project: str,
    repo_root: Path,
    candidate: SelectionCandidate,
) -> list[dict[str, Any]]:
    line_start, line_end = candidate.line_range or (0, 0)
    return [
        {
            "path": _normalize_candidate_path(project, repo_root, candidate.repo_path),
            "line_start": max(1, int(line_start or 1)),
            "line_end": max(1, int(line_end or line_start or 1)),
            "symbol": candidate.symbol or "",
        }
    ]


def _path_heuristics(target_path: str, fuzzer_names: list[str]) -> dict[str, dict[str, Any]]:
    low_path = target_path.lower()
    scores: dict[str, dict[str, Any]] = defaultdict(lambda: {"score": 0, "reasons": []})
    for fuzzer in fuzzer_names:
        low_fuzzer = fuzzer.lower()
        if "m3d" in low_path and low_fuzzer == "assimp_fuzzer":
            scores[fuzzer]["score"] += 3
            scores[fuzzer]["reasons"].append("generic importer fallback for M3D path")
        for token, (weight, reason) in _PATH_TOKEN_WEIGHTS.items():
            if token in low_path and token in low_fuzzer:
                scores[fuzzer]["score"] += weight
                scores[fuzzer]["reasons"].append(reason)
    return scores


def _modality_penalty(path: str, symbol: str) -> tuple[int, list[str]]:
    low = f"{path} {symbol}".lower()
    total = 0
    reasons: list[str] = []
    for token, (penalty, reason) in _MODALITY_PENALTIES.items():
        if token in low:
            total += penalty
            reasons.append(reason)
    return total, sorted(set(reasons))


def _summarize_kind(
    *,
    runtime_reachable: bool,
    static_reachable: bool,
    file_covered: bool,
) -> str:
    if runtime_reachable:
        return "runtime_function"
    if static_reachable:
        return "static_function"
    if file_covered:
        return "file_coverage"
    return "no_harness_path"


def infer_format_family(path: str, symbol: str, preferred_fuzzer: str | None) -> str | None:
    low = f"{path} {symbol} {(preferred_fuzzer or '')}".lower()
    if any(token in low for token in ("gsub", "gpos", "font", "hb-")):
        return "font_binary"
    if any(token in low for token in ("obj", "fbx", "gltf", "glb", "stl", "m3d", "assimp")):
        return "model_asset"
    if "zip" in low:
        return "zip_archive"
    if "png" in low:
        return "image_png"
    if any(token in low for token in ("json", "cjson")):
        return "json_text"
    if any(token in low for token in ("regex", "regexp", "quickjs", "js")):
        return "script_text"
    return None


def infer_subsystem(path: str, symbol: str, preferred_fuzzer: str | None) -> str | None:
    low = f"{path} {symbol} {(preferred_fuzzer or '')}".lower()
    if "gsub" in low:
        return "gsub"
    if "gpos" in low:
        return "gpos"
    if "subset" in low:
        return "subset"
    if "zip" in low:
        return "zip"
    if "png" in low:
        return "png"
    if "utf" in low:
        return "text_encoding"
    if any(token in low for token in ("obj", "fbx", "gltf", "glb", "m3d")):
        return "importer"
    return None


def infer_input_model(format_family: str | None, subsystem: str | None) -> str | None:
    if format_family == "font_binary":
        if subsystem == "gsub":
            return "valid_font_with_gsub_tables"
        if subsystem == "gpos":
            return "valid_font_with_gpos_tables"
        return "valid_font_binary"
    if format_family == "model_asset":
        return "valid_model_asset"
    if format_family == "zip_archive":
        return "valid_zip_archive"
    if format_family == "image_png":
        return "valid_png_image"
    if format_family == "json_text":
        return "valid_json_text"
    if format_family == "script_text":
        return "valid_script_text"
    return None


def score_security(candidate: SelectionCandidate) -> float:
    extra = candidate.extra or {}
    confidence = max(0.0, min(1.0, float(candidate.confidence or 0.0)))
    checkpoint_bonus = 0.1 if extra.get("checkpoint") else 0.0
    operation_bonus = 0.1 if extra.get("operation") else 0.0
    cwe_bonus = min(0.1, 0.03 * len(extra.get("cwe_candidates") or []))
    hint_bonus = 0.05 if (candidate.location_hint or "").strip() else 0.0
    score = (confidence * 0.65) + checkpoint_bonus + operation_bonus + cwe_bonus + hint_bonus
    return round(min(1.0, score), 4)


def score_fuzzability(
    recommendations: list[dict[str, Any]],
    fuzz_payload: dict[str, Any],
    *,
    modality_penalty: int,
) -> float:
    best_score = max((int(item.get("score", 0)) for item in recommendations), default=0)
    base = min(1.0, best_score / 16.0)
    if fuzz_payload.get("runtime_reachable"):
        base += 0.2
    elif fuzz_payload.get("static_reachable"):
        base += 0.12
    elif fuzz_payload.get("reachability_kind") == "file_coverage":
        base += 0.05
    if fuzz_payload.get("dict_available"):
        base += 0.03
    if fuzz_payload.get("options_available"):
        base += 0.03
    if fuzz_payload.get("has_blockers"):
        base -= 0.08
    base += max(-0.25, modality_penalty / 20.0)
    return round(max(0.0, min(1.0, base)), 4)


def validation_likelihood_from_scores(security_score: float, fuzzability_score: float) -> str:
    combined = (security_score * 0.4) + (fuzzability_score * 0.6)
    if combined >= 0.75:
        return "high"
    if combined >= 0.45:
        return "medium"
    return "low"


def _analyze_targets(
    *,
    project: str,
    targets: list[dict[str, Any]],
    cache: dict[str, Any],
) -> dict[str, Any]:
    functions = cache.get("introspector", {}).get("functions", [])
    coverage = cache.get("coverage", {}).get("fuzzer_stats", {})
    fuzzers = cache.get("introspector", {}).get("fuzzers", [])
    blockers_by_fuzzer = {item["name"]: item.get("blockers", []) or [] for item in fuzzers}
    all_fuzzer_names = [item["name"] for item in fuzzers]
    fuzz_assets = local_fuzz_assets(project)

    matched_functions: list[dict[str, Any]] = []
    seen_matches: set[tuple[str, int, int, str]] = set()
    scorecard: dict[str, dict[str, Any]] = defaultdict(lambda: {"score": 0, "reasons": []})
    file_covered = False
    path_reasons: list[str] = []
    modality_penalty_total = 0
    modality_reasons: list[str] = []

    for target in targets:
        target_matches = []
        penalty, reasons = _modality_penalty(target["path"], str(target.get("symbol") or ""))
        modality_penalty_total += penalty
        modality_reasons.extend(reasons)

        for fn in functions:
            if fn.get("source_file") != target["path"]:
                continue
            line_begin = int(fn.get("source_line_begin") or 0)
            line_end = int(fn.get("source_line_end") or line_begin)
            if not overlaps(target["line_start"], target["line_end"], line_begin, line_end):
                continue
            target_matches.append(fn)
            match_key = (target["path"], line_begin, line_end, str(fn.get("name")))
            if match_key not in seen_matches:
                matched_functions.append(
                    {
                        "patch_path": target["path"],
                        "patch_line_start": target["line_start"],
                        "patch_line_end": target["line_end"],
                        "function_name": fn.get("name"),
                        "source_line_begin": line_begin,
                        "source_line_end": line_end,
                        "reached_by_fuzzers": fn.get("reached_by_fuzzers", []),
                        "runtime_reached_by_fuzzers": fn.get("runtime_reached_by_fuzzers", []),
                    }
                )
                seen_matches.add(match_key)
            for fuzzer in fn.get("runtime_reached_by_fuzzers", []):
                scorecard[fuzzer]["score"] += RUNTIME_FUNCTION_SCORE
                scorecard[fuzzer]["reasons"].append(f"runtime reaches function {fn.get('name')}")
            for fuzzer in fn.get("reached_by_fuzzers", []):
                scorecard[fuzzer]["score"] += STATIC_FUNCTION_SCORE
                scorecard[fuzzer]["reasons"].append(f"static reachability to function {fn.get('name')}")

        if not target_matches:
            for fuzzer, payload in coverage.items():
                for file_entry in payload.get("files", []):
                    if file_entry.get("filename") == target["path"]:
                        file_covered = True
                        scorecard[fuzzer]["score"] += FILE_COVERAGE_SCORE
                        scorecard[fuzzer]["reasons"].append(
                            f"coverage reaches target file {target['path']}"
                        )
                        break

        heuristic_scores = _path_heuristics(target["path"], all_fuzzer_names)
        for fuzzer, payload in heuristic_scores.items():
            scorecard[fuzzer]["score"] += payload["score"]
            scorecard[fuzzer]["reasons"].extend(payload["reasons"])
            path_reasons.extend(payload["reasons"])

    for fuzzer, payload in scorecard.items():
        if fuzz_assets[fuzzer]["dict"]:
            payload["score"] += DICT_BONUS
            payload["reasons"].append("local dictionary available")
        if fuzz_assets[fuzzer]["options"]:
            payload["score"] += OPTIONS_BONUS
            payload["reasons"].append("local options available")
        if blockers_by_fuzzer.get(fuzzer):
            payload["score"] -= BLOCKER_PENALTY
            payload["reasons"].append("introspector blockers present")
        if modality_penalty_total:
            payload["score"] += modality_penalty_total
            payload["reasons"].extend(modality_reasons)

    recommendations = [
        {
            "fuzzer": fuzzer,
            "score": payload["score"],
            "reasons": sorted(set(payload["reasons"])),
            "has_blockers": bool(blockers_by_fuzzer.get(fuzzer)),
            "has_dict": fuzz_assets[fuzzer]["dict"],
            "has_options": fuzz_assets[fuzzer]["options"],
        }
        for fuzzer, payload in scorecard.items()
        if payload["score"] > 0
    ]
    recommendations.sort(key=lambda item: (-item["score"], item["fuzzer"]))
    synthetic_recommendations = False
    if not recommendations:
        recommendations = _synthetic_recommendations_from_context(
            project=project,
            targets=targets,
            cache=cache,
            fuzz_assets=fuzz_assets,
            blockers_by_fuzzer=blockers_by_fuzzer,
            all_fuzzer_names=all_fuzzer_names,
            modality_penalty_total=modality_penalty_total,
            modality_reasons=modality_reasons,
        )
        synthetic_recommendations = bool(recommendations)

    return {
        "project": project,
        "matched_functions": matched_functions,
        "recommendations": recommendations,
        "synthetic_recommendations": synthetic_recommendations,
        "file_covered": file_covered,
        "path_reasons": sorted(set(path_reasons)),
        "modality_penalty": modality_penalty_total,
        "modality_reasons": sorted(set(modality_reasons)),
    }


def map_patch_to_harness(
    *,
    project: str,
    patch_diff: str,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> dict[str, Any]:
    cache = load_cache(project, cache_dir)
    targets = patch_targets_and_hunks(project, patch_diff)
    payload = _analyze_targets(project=project, targets=targets, cache=cache)
    payload["cache_file"] = str(cache_dir / f"{project}.json")
    payload["patch_hunks"] = targets
    return payload


def map_injection_result_to_harness(
    injection_result_path: Path,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> dict[str, Any]:
    injection = load_json(injection_result_path)
    project = str(injection.get("project") or "")
    if not project:
        raise ValueError(f"missing project in {injection_result_path}")
    patch_diff = ((injection.get("artifacts") or {}).get("patch_diff") or "")
    payload = map_patch_to_harness(project=project, patch_diff=patch_diff, cache_dir=cache_dir)
    payload["injection_result"] = str(injection_result_path)
    return payload


def build_candidate_fuzz_payload(
    *,
    project: str,
    candidate: SelectionCandidate,
    repo_root: Path,
    cache_dir: Path = DEFAULT_CACHE_DIR,
) -> tuple[dict[str, Any], dict[str, Any]]:
    cache = load_cache(project, cache_dir)
    targets = _make_targets_for_candidate(project, repo_root, candidate)
    mapping = _analyze_targets(project=project, targets=targets, cache=cache)

    recommendations = list(mapping.get("recommendations") or [])
    preferred = recommendations[0] if recommendations else None
    target_functions = [item.get("function_name") for item in mapping.get("matched_functions") or [] if item.get("function_name")]
    target_files = sorted({item["patch_path"] for item in mapping.get("matched_functions") or [] if item.get("patch_path")})
    if not target_files:
        target_files = sorted({item["path"] for item in targets})

    runtime_reachable = any(
        preferred and preferred["fuzzer"] in (item.get("runtime_reached_by_fuzzers") or [])
        for item in mapping.get("matched_functions") or []
    )
    static_reachable = any(
        preferred and preferred["fuzzer"] in (item.get("reached_by_fuzzers") or [])
        for item in mapping.get("matched_functions") or []
    )
    reachability_kind = _summarize_kind(
        runtime_reachable=runtime_reachable,
        static_reachable=static_reachable,
        file_covered=bool(mapping.get("file_covered")),
    )
    preferred_fuzzer = preferred["fuzzer"] if preferred else None
    format_family = infer_format_family(candidate.repo_path, candidate.symbol, preferred_fuzzer)
    subsystem = infer_subsystem(candidate.repo_path, candidate.symbol, preferred_fuzzer)
    input_model = infer_input_model(format_family, subsystem)
    security_score = score_security(candidate)
    fuzz_payload = {
        "preferred_fuzzer": preferred_fuzzer,
        "alternate_fuzzers": [item["fuzzer"] for item in recommendations[1:4]],
        "runtime_reachable": runtime_reachable,
        "static_reachable": static_reachable,
        "reachability_kind": reachability_kind,
        "target_functions": target_functions,
        "target_files": target_files,
        "format_family": format_family,
        "subsystem": subsystem,
        "input_model": input_model,
        "validation_likelihood": "low",
        "dict_available": bool(preferred and preferred.get("has_dict")),
        "options_available": bool(preferred and preferred.get("has_options")),
        "has_blockers": bool(preferred and preferred.get("has_blockers")),
        "recommendations": recommendations,
        "security_score": security_score,
        "fuzzability_score": 0.0,
        "combined_score": 0.0,
    }
    fuzzability_score = score_fuzzability(
        recommendations,
        fuzz_payload,
        modality_penalty=int(mapping.get("modality_penalty") or 0),
    )
    fuzz_payload["fuzzability_score"] = fuzzability_score
    fuzz_payload["combined_score"] = round((security_score * 0.4) + (fuzzability_score * 0.6), 4)
    fuzz_payload["validation_likelihood"] = validation_likelihood_from_scores(
        security_score,
        fuzzability_score,
    )
    mapping["cache_file"] = str(cache_dir / f"{project}.json")
    mapping["candidate_targets"] = targets
    return fuzz_payload, mapping
