"""Shared forward fuzz execution context for injection and fuzz-PoC stages."""

from __future__ import annotations

import re
from typing import Any


_GENERATOR_HINTS: dict[str, str] = {
    "utf16_be_obj_variants": "Prefer UTF-16 big-endian OBJ-like text with a BOM and short structured records.",
    "odd_length_variants": "Bias toward odd-length or truncated UTF-16 payloads near 2-byte boundaries.",
    "trailing_nul_variants": "Try extra trailing NULs or near-terminated tails without changing the overall format family.",
    "gsub_marker_mutations": "Mutate GSUB/font table markers and short table bodies while keeping the file recognizably font-like.",
    "binary_edge_byte_flips": "Use small binary seeds with edge-byte flips near offsets that parser code is likely to inspect.",
    "long_line_variants": "Keep the file mostly valid but stretch a single line or token to a boundary length.",
    "newline_boundary_variants": "Use short structured text with newline placement or truncation near record boundaries.",
    "zip_like_binary_variants": "Preserve ZIP-like headers and metadata structure while mutating filename and central-directory fields.",
    "long_filename_token_variants": "Bias toward oversized filename-style fields or long path-like tokens.",
    "generic_small_binary_variants": "Use very small binary seeds and perturb only a few bytes at key boundaries.",
    "length_boundary_variants": "Try exact boundary sizes, off-by-one lengths, and truncated tails.",
    "png_like_variants": "Keep PNG magic and chunk layout recognizable while mutating chunk lengths and short payloads.",
    "script_text_variants": "Use small parseable scripts, then add truncation, nesting, or token-boundary regressions.",
    "json_text_variants": "Use small valid or near-valid JSON objects and arrays with truncation or deep nesting around boundaries.",
}


def candidate_fuzz_metadata(injection: dict[str, Any]) -> dict[str, Any]:
    strategy = injection.get("strategy") or {}
    selected_candidate = strategy.get("selection_candidate") or {}
    extra = selected_candidate.get("extra") or {}
    fuzz_native = extra.get("fuzz_native") or {}
    if isinstance(fuzz_native, dict) and fuzz_native:
        return fuzz_native
    fuzz = extra.get("fuzz") or {}
    if not isinstance(fuzz, dict) or not fuzz:
        return {}
    return fuzz


def infer_trigger_profile(
    *,
    cwe_id: str = "",
    patch_diff: str = "",
    attack_script: str = "",
    patch_path: str = "",
) -> dict[str, Any]:
    low_patch = (patch_diff or "").lower()
    low_attack = (attack_script or "").lower()
    low_path = (patch_path or "").lower()

    bug_shape = "generic_memory_corruption"
    format_family = "binary"
    conditions = ["target harness must reach patched code path"]
    generators = ["generic_small_binary_variants"]

    if "utf-16" in low_attack or "converttoutf8" in low_patch or "feff" in low_attack:
        bug_shape = "utf16_boundary_overread"
        format_family = "text_obj_utf16"
        conditions = [
            "OBJ/text importer path",
            "UTF-16 BE data",
            "buffer length near a uint16 boundary",
        ]
        generators = ["utf16_be_obj_variants", "odd_length_variants", "trailing_nul_variants"]
    elif "gsub" in low_path or "ligaturesubstformat1" in low_path:
        bug_shape = "unchecked_index_gsub"
        format_family = "font_binary"
        conditions = [
            "font parse reaches GSUB ligature substitution",
            "coverage miss still flows into ligature set indexing",
        ]
        generators = ["gsub_marker_mutations", "binary_edge_byte_flips"]
    elif "m3d.h" in low_path or "_m3d_safestr" in low_patch:
        bug_shape = "string_copy_bound_removal"
        format_family = "m3d_text"
        conditions = [
            "M3D importer path",
            "overlong field or unterminated line copied through _m3d_safestr",
        ]
        generators = ["long_line_variants", "newline_boundary_variants"]
    elif "ziparchive" in low_path or "filename" in low_patch:
        bug_shape = "filename_length_guard_removal"
        format_family = "zip_archive"
        conditions = [
            "archive importer path",
            "oversized filename metadata",
        ]
        generators = ["zip_like_binary_variants", "long_filename_token_variants"]
    elif cwe_id in {"CWE-125", "CWE-787", "CWE-119"}:
        bug_shape = "bounds_regression"
        generators = ["generic_small_binary_variants", "length_boundary_variants"]

    return {
        "patch_path": patch_path,
        "bug_shape": bug_shape,
        "format_family": format_family,
        "required_conditions": conditions,
        "input_generators": generators,
    }


def trigger_profile_from_fuzz_metadata(
    fuzz: dict[str, Any],
    *,
    cwe_id: str = "",
    patch_diff: str = "",
    attack_script: str = "",
    patch_path: str = "",
) -> dict[str, Any]:
    inferred = infer_trigger_profile(
        cwe_id=cwe_id,
        patch_diff=patch_diff,
        attack_script=attack_script,
        patch_path=patch_path,
    )
    format_family = fuzz.get("format_family") or inferred.get("format_family")
    input_model = fuzz.get("input_model") or ""
    subsystem = fuzz.get("subsystem") or ""
    bug_shape = fuzz.get("bug_shape") or inferred.get("bug_shape") or "generic_memory_corruption"
    generators = list(inferred.get("input_generators") or [])

    if format_family == "font_binary":
        if "gsub" in subsystem and "gsub_marker_mutations" not in generators:
            generators.insert(0, "gsub_marker_mutations")
        elif "binary_edge_byte_flips" not in generators:
            generators.insert(0, "binary_edge_byte_flips")
    elif format_family == "zip_archive" and "zip_like_binary_variants" not in generators:
        generators.insert(0, "zip_like_binary_variants")
    elif format_family in {"json_text", "script_text"} and "long_line_variants" not in generators:
        generators.insert(0, "long_line_variants")
    elif format_family == "model_asset" and "generic_small_binary_variants" not in generators:
        generators.insert(0, "generic_small_binary_variants")
    if bug_shape == "off_by_one_iteration" and "length_boundary_variants" not in generators:
        generators.insert(0, "length_boundary_variants")
    if bug_shape == "removed_copy_size_constraint" and "long_line_variants" not in generators:
        generators.insert(0, "long_line_variants")

    conditions = list(inferred.get("required_conditions") or [])
    if fuzz.get("preferred_fuzzer"):
        conditions.insert(0, f"preferred harness {fuzz['preferred_fuzzer']} remains reachable")
    if input_model:
        conditions.insert(0, f"input model {input_model}")
    if bug_shape:
        conditions.insert(0, f"bug shape {bug_shape}")

    return {
        "patch_path": inferred.get("patch_path", ""),
        "bug_shape": bug_shape,
        "format_family": format_family,
        "required_conditions": conditions,
        "input_generators": generators,
        "subsystem": subsystem,
        "input_model": input_model or None,
    }


def retarget_profile_for_fuzzer(profile: dict[str, Any], fuzzer: str) -> dict[str, Any]:
    tuned = dict(profile)
    generators = list(tuned.get("input_generators") or [])
    low = fuzzer.lower()
    if "png" in low:
        tuned["format_family"] = "image_png"
        generators = ["png_like_variants"]
    elif any(token in low for token in ("quickjs", "fuzz_compile", "fuzz_eval", "fuzz_regexp")):
        tuned["format_family"] = "script_text"
        if "script_text_variants" not in generators:
            generators.insert(0, "script_text_variants")
    elif "json" in low:
        tuned["format_family"] = "json_text"
        if "json_text_variants" not in generators:
            generators.insert(0, "json_text_variants")
    tuned["input_generators"] = generators
    return tuned


def preferred_extensions(format_family: str | None, fuzzer: str) -> list[str]:
    low = (fuzzer or "").lower()
    if format_family == "image_png" or "png" in low:
        return [".png"]
    if format_family == "text_obj_utf16":
        return [".obj", ".txt"]
    if format_family == "json_text" or "json" in low:
        return [".json", ".txt"]
    if format_family == "script_text" or any(token in low for token in ("quickjs", "compile", "eval", "regexp")):
        return [".js", ".mjs", ".txt"]
    if format_family == "zip_archive" or "zip" in low:
        return [".zip"]
    if format_family == "font_binary" or low.startswith("hb-"):
        return [".ttf", ".otf", ".woff", ".woff2", ".bin"]
    if format_family == "model_asset" or any(token in low for token in ("assimp", "_obj", "_fbx", "_gltf", "_glb", "_stl")):
        return [".obj", ".fbx", ".gltf", ".glb", ".stl", ".m3d", ".ply", ".x", ".3ds", ".dae", ".bin", ".txt"]
    return [".bin", ".txt"]


def build_forward_fuzzing_context(
    fuzz: dict[str, Any],
    *,
    cwe_id: str = "",
    repo_path: str = "",
) -> dict[str, Any]:
    profile = trigger_profile_from_fuzz_metadata(
        fuzz,
        cwe_id=cwe_id,
        patch_path=repo_path,
    )
    preferred = fuzz.get("preferred_fuzzer") or ""
    if preferred:
        profile = retarget_profile_for_fuzzer(profile, preferred)
    exts = preferred_extensions(profile.get("format_family"), preferred)
    generators = list(profile.get("input_generators") or [])
    generator_hints = [_GENERATOR_HINTS.get(name, f"Favor inputs compatible with generator `{name}`.") for name in generators]

    exploit_hints: list[str] = []
    if fuzz.get("input_model"):
        exploit_hints.append(f"Keep the exploit input close to the advertised input model: {fuzz['input_model']}.")
    if exts:
        joined = ", ".join(exts)
        exploit_hints.append(f"If you materialize a file input, prefer a small seed-like sample with one of these extensions: {joined}.")
    if fuzz.get("existing_harness_viability"):
        exploit_hints.append(
            f"Existing harness viability is {fuzz['existing_harness_viability']}; avoid edits that make the current path harder to rediscover."
        )
    if fuzz.get("hot_path_bucket"):
        exploit_hints.append(
            f"Hot-path confidence is {fuzz['hot_path_bucket']}; keep the exploit focused on the same compact path slice."
        )
    if fuzz.get("helper_judgment"):
        exploit_hints.append(
            f"Helper judgment is {fuzz['helper_judgment']}; do not accidentally move the exploit onto a different endpoint than the selected slice."
        )
    if fuzz.get("blocker_hotspots"):
        hotspots = ", ".join(str(item) for item in (fuzz.get("blocker_hotspots") or [])[:3])
        exploit_hints.append(f"Be careful around blocker hotspots already constraining fuzzing depth: {hotspots}.")
    if fuzz.get("bug_shape"):
        exploit_hints.append(f"Make the exploit demonstrate the intended bug shape without broad semantic drift: {fuzz['bug_shape']}.")

    return {
        "format_family": profile.get("format_family"),
        "bug_shape": profile.get("bug_shape"),
        "required_conditions": profile.get("required_conditions") or [],
        "input_generators": generators,
        "generator_hints": generator_hints,
        "preferred_extensions": exts,
        "exploit_hints": exploit_hints,
    }


def derive_patch_path_from_diff(patch_diff: str) -> str:
    for line in (patch_diff or "").splitlines():
        if line.startswith("+++ b/"):
            return line[6:]
    return ""


def attack_script_fuzzer_hint(attack_script: str) -> str | None:
    match = re.search(r"/out/([A-Za-z0-9._-]+)", attack_script or "")
    if match:
        return match.group(1)
    return None
