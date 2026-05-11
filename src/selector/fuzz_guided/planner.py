"""Harness-first candidate planner for fuzz-guided selection."""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from selector.fuzz_guided.surface import HarnessRecord, ProjectFuzzSurface, ReachableFunction
from utils.cwe import resolve_cwe_group
from vuljector.io_contracts import SelectionCandidate


_INPUT_TOKENS = re.compile(
    r"(parse|read|decode|import|load|lex|token|compile|eval|shape|subset|inflate|stream|convert|utf|json|png|zip|lzma)",
    re.IGNORECASE,
)
_ENTRY_FILE_TOKENS = re.compile(r"(parse|read|decode|import|compile|eval|regexp|json|png|zip|lzma|xml|font|subset)", re.IGNORECASE)
_LOOP_TOKENS = re.compile(r"\b(for|while)\b", re.IGNORECASE)
_INDEX_TOKENS = re.compile(r"\b(idx|index|slot|offset|array|table|hash|property)\b", re.IGNORECASE)
_COPY_TOKENS = re.compile(r"\b(memcpy|memmove|strcpy|strncpy|copy|append|push)\b", re.IGNORECASE)
_CONVERSION_TOKENS = re.compile(r"\b(utf|unicode|decode|encode|convert|surrogate|bom|inflate|decompress)\b", re.IGNORECASE)
_STATE_TOKENS = re.compile(r"\b(state|token|kind|type|tag|mode|null|NULL)\b", re.IGNORECASE)
_WRITE_TOKENS = re.compile(r"\b(write|put|append|push|reserve|grow|expand)\b", re.IGNORECASE)
_UTILITY_TOKENS = re.compile(r"\b(alloc|realloc|ensure|reserve|buffer|grow)\b", re.IGNORECASE)
_EXPORT_TOKENS = re.compile(r"\b(export|destroy|destruct|finalize|cleanup|teardown|free)\b", re.IGNORECASE)
_LEN_TOKENS = re.compile(r"\b(len|length|size|count|limit|bound|capacity|end)\b", re.IGNORECASE)
_CONDITIONAL_TOKENS = re.compile(r"\b(if|else if|switch|case|return)\b", re.IGNORECASE)
_DANGEROUS_LINE = re.compile(r"(\[[^\]]+\]|->|memcpy|memmove|strcpy|strncpy|copy|read|write|decode|encode|parse|load|convert|append|push)", re.IGNORECASE)
_FUNC_DEF = re.compile(r"^\s*(?:static\s+)?(?:inline\s+)?[\w\*\s]+?\b([A-Za-z_]\w*)\s*\([^;]*\)\s*\{?\s*$")
_GENERIC_HELPER_PREFIXES = (
    "dbuf_",
    "pstr",
    "mpb_",
    "exchange_",
    "sort_",
    "rqsort",
    "cmp_",
    "hash_",
)
_PARSERISH_CALLEE_TOKENS = re.compile(
    r"\b(parse|decode|token|lex|scan|regexp|json|module|expr|state|unicode|utf|import|compile|eval)\b",
    re.IGNORECASE,
)
_STATE_TRANSITION_TOKENS = re.compile(
    r"\b(state|token|mode|phase|expr|node|module|class|scope|import|unicode|escape)\b",
    re.IGNORECASE,
)

_ROLE_PRIORITY = {
    "parser_entry": 0.22,
    "decoder_conversion": 0.2,
    "container_access": 0.18,
    "buffer_writer": 0.16,
    "copy_bridge": 0.15,
    "state_machine": 0.13,
    "allocator_helper": -0.06,
    "utility_helper": -0.08,
    "exporter_cleanup": -0.35,
}

_ROLE_TO_HINT = {
    "parser_entry": "preserve the parser entry path and weaken a local validation gate so malformed inputs continue deeper into the same parser state machine",
    "decoder_conversion": "preserve the decode or conversion path and relax a boundary assumption so malformed data reaches a sanitizer-visible fault",
    "container_access": "preserve the same reachable table or array lookup path and relax index validation immediately before the access",
    "buffer_writer": "preserve the write or append path and relax capacity or size accounting near the reachable write",
    "copy_bridge": "preserve the copy path and weaken size coupling so malformed input can overrun a copy boundary",
    "state_machine": "preserve the parser state transition path and weaken a state or nullability guard without changing the harness-visible flow",
    "allocator_helper": "stay on the same input path and make a minimal size-accounting regression rather than a broad semantic rewrite",
    "utility_helper": "keep this helper on the same harness path and weaken only a narrow input-facing guard",
    "exporter_cleanup": "avoid this unless no stronger parser-side target exists because cleanup-only paths are poor fuzz targets",
}

_BUG_CWE = {
    "unchecked_index": ["CWE-129", "CWE-125"],
    "removed_bounds_check": ["CWE-125", "CWE-787"],
    "removed_copy_size_constraint": ["CWE-120", "CWE-787"],
    "conversion_boundary_regression": ["CWE-125", "CWE-193"],
    "parser_state_misuse": ["CWE-476", "CWE-754"],
    "off_by_one_iteration": ["CWE-193", "CWE-125"],
    "removed_length_restriction": ["CWE-130", "CWE-125"],
}


@dataclass(frozen=True)
class TriggerabilityAssessment:
    score: float
    hot_path_bucket: str
    calltree_proximity: str
    blocker_proximity: str
    guard_to_sink_distance: int | None
    repeated_callsite_count: int
    path_signal_score: float
    parser_proximity_score: float
    helper_judgment: str
    rationale: str
    reasons: list[str]


@dataclass
class CandidatePlan:
    harness: HarnessRecord
    function: ReachableFunction
    reachability_kind: str
    function_role: str
    bug_shape: str
    expected_cwe: list[str]
    target_file: str
    target_line_range: tuple[int, int]
    function_line_range: tuple[int, int]
    checkpoint_line: int
    checkpoint_text: str
    checkpoint_type: str
    operation_line: int
    operation_text: str
    operation_type: str
    slice_excerpt: str
    score: float
    validation_likelihood: str
    rationale: str
    mutation_goal: str
    selection_rationale: str
    instruction_hints: list[str]
    harness_context: str
    triggerability: TriggerabilityAssessment


def _read_file_lines(repo_root: Path, source_file: str) -> list[str]:
    local_path = repo_root / source_file.removeprefix(f"/src/{repo_root.name}/")
    if not local_path.exists():
        parts = Path(source_file).parts
        project_rel = Path(*parts[3:]) if len(parts) >= 4 else Path(Path(source_file).name)
        local_path = repo_root / project_rel
    try:
        return local_path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []


def _language_for_path(path: str) -> str:
    return "javascript" if Path(path).suffix.lower() in {".js", ".mjs", ".ts"} else "c++"


def _reachability_kind(fn: ReachableFunction, harness_name: str) -> str:
    if harness_name in fn.runtime_fuzzers:
        return "runtime_function"
    if harness_name in fn.static_fuzzers or harness_name in fn.combined_fuzzers:
        return "static_function"
    return "file_coverage"


def _function_blob(fn: ReachableFunction, harness: HarnessRecord) -> str:
    raw = " ".join(
        [
            fn.name,
            fn.source_file,
            fn.function_signature,
            " ".join(fn.callsites.keys()),
            harness.name,
            harness.subsystem or "",
            harness.format_family or "",
        ]
    ).lower()
    return re.sub(r"[^a-z0-9]+", " ", raw)


def _semantic_blob(fn: ReachableFunction) -> str:
    raw = " ".join(
        [
            fn.name,
            fn.source_file,
            fn.function_signature,
            " ".join(fn.callsites.keys()),
        ]
    ).lower()
    return re.sub(r"[^a-z0-9]+", " ", raw)


def _classify_role(fn: ReachableFunction, harness: HarnessRecord) -> str:
    blob = _semantic_blob(fn)
    if _EXPORT_TOKENS.search(blob):
        return "exporter_cleanup"
    if _CONVERSION_TOKENS.search(blob):
        return "decoder_conversion"
    if _COPY_TOKENS.search(blob):
        return "copy_bridge"
    if _WRITE_TOKENS.search(blob):
        return "buffer_writer"
    if re.search(r"\b(parse|read|load|import|token|lex|scan)\b", blob):
        return "parser_entry"
    if _INDEX_TOKENS.search(blob) or re.search(r"\b(lookup|get|find|property|element)\b", blob):
        return "container_access"
    if _STATE_TOKENS.search(blob):
        return "state_machine"
    if _UTILITY_TOKENS.search(blob):
        return "allocator_helper"
    if _ENTRY_FILE_TOKENS.search(fn.source_file):
        return "parser_entry"
    return "utility_helper"


def _file_coverage_bonus(harness: HarnessRecord, source_file: str) -> float:
    percent = float(harness.file_coverage.get(source_file, 0.0))
    return min(percent / 100.0, 1.0) * 0.12


def _fanout_bonus(fn: ReachableFunction) -> float:
    reached = int(fn.functions_reached_count or 0)
    return min(reached, 50) / 50.0 * 0.12


def _depth_bonus(fn: ReachableFunction) -> float:
    depth = fn.call_depth
    if depth is None:
        return 0.03
    if depth <= 2:
        return 0.12
    if depth <= 4:
        return 0.09
    if depth <= 8:
        return 0.05
    return 0.02


def _function_score(fn: ReachableFunction, harness: HarnessRecord, role: str) -> float:
    reachability_kind = _reachability_kind(fn, harness.name)
    score = 0.0
    if reachability_kind == "runtime_function":
        score += 0.62
    elif reachability_kind == "static_function":
        score += 0.26
    else:
        score += 0.06
    score += _ROLE_PRIORITY.get(role, 0.0)
    score += _fanout_bonus(fn)
    score += _depth_bonus(fn)
    score += _file_coverage_bonus(harness, fn.source_file)
    if harness.has_dict:
        score += 0.03
    if harness.has_options:
        score += 0.03
    if harness.has_seed_corpus:
        score += 0.05
    if harness.blockers:
        score -= min(0.16, 0.01 * harness.blocker_count)
        hotspot = harness.blocker_hotspots[0] if harness.blocker_hotspots else None
        if hotspot and int(hotspot.get("max_unique_uncovered_complexity", 0)) > 500:
            score -= 0.04
    if harness.max_len is not None and harness.max_len <= 1024 and role in {"parser_entry", "decoder_conversion"}:
        score += 0.02
    if harness.timeout_seconds is not None and harness.timeout_seconds <= 5:
        score -= 0.02
    if fn.cyclomatic_complexity and fn.cyclomatic_complexity > 80:
        score -= 0.05
    elif fn.cyclomatic_complexity and fn.cyclomatic_complexity > 40:
        score -= 0.02
    if fn.undiscovered_complexity and fn.undiscovered_complexity > 400:
        score -= 0.04
    if _INPUT_TOKENS.search(_semantic_blob(fn)):
        score += 0.06
    if fn.callsite_occurrences >= 2:
        score += min(0.06, 0.02 * fn.callsite_occurrences)
    if role in {"utility_helper", "allocator_helper"} and fn.name.lower().startswith(_GENERIC_HELPER_PREFIXES):
        score -= 0.12
    if role == "buffer_writer" and not _ENTRY_FILE_TOKENS.search(fn.source_file):
        score -= 0.08
    return max(0.0, min(1.0, score))


def _choose_bug_shape(role: str, lines: list[str], fn: ReachableFunction, harness: HarnessRecord) -> str:
    blob = " ".join(lines).lower() + " " + _function_blob(fn, harness)
    if _LOOP_TOKENS.search(blob) and _LEN_TOKENS.search(blob):
        return "off_by_one_iteration"
    if _COPY_TOKENS.search(blob):
        return "removed_copy_size_constraint"
    if _CONVERSION_TOKENS.search(blob):
        return "conversion_boundary_regression"
    if role == "container_access" or _INDEX_TOKENS.search(blob):
        return "unchecked_index"
    if role == "state_machine" or _STATE_TOKENS.search(blob):
        return "parser_state_misuse"
    if role == "parser_entry" and _LEN_TOKENS.search(blob):
        return "removed_length_restriction"
    return "removed_bounds_check"


def _validation_likelihood(score: float) -> str:
    if score >= 0.85:
        return "high"
    if score >= 0.6:
        return "medium"
    return "low"


def _find_function_anchor(lines: list[str], start_line: int, end_line: int, fn: ReachableFunction) -> tuple[int, str]:
    if not lines:
        return max(1, start_line), fn.name
    line_start = min(max(1, start_line), len(lines))
    line_end = min(max(line_start, end_line), len(lines))
    for idx in range(line_start - 1, line_end):
        stripped = lines[idx].strip()
        if fn.name in stripped and _FUNC_DEF.search(stripped):
            return idx + 1, stripped
    return line_start, lines[line_start - 1].strip() if lines and line_start - 1 < len(lines) else fn.name


def _line_matches_objective(line: str, bug_shape: str, role: str) -> bool:
    low = line.lower()
    if not low:
        return False
    if bug_shape == "unchecked_index":
        return "if" in low and bool(_INDEX_TOKENS.search(low))
    if bug_shape in {"removed_bounds_check", "removed_length_restriction"}:
        return "if" in low and bool(_LEN_TOKENS.search(low))
    if bug_shape == "removed_copy_size_constraint":
        return ("if" in low and bool(_LEN_TOKENS.search(low))) or bool(_COPY_TOKENS.search(low))
    if bug_shape == "conversion_boundary_regression":
        return ("if" in low and bool(_CONVERSION_TOKENS.search(low))) or bool(_CONVERSION_TOKENS.search(low))
    if bug_shape == "parser_state_misuse":
        return "if" in low and bool(_STATE_TOKENS.search(low))
    if bug_shape == "off_by_one_iteration":
        return bool(_LOOP_TOKENS.search(low)) and bool(_LEN_TOKENS.search(low))
    return role in {"parser_entry", "buffer_writer"} and "if" in low


def _find_operation(lines: list[str], start_idx: int, end_idx: int, bug_shape: str) -> tuple[int, str]:
    window_end = min(len(lines), end_idx + 6)
    for pos in range(start_idx, window_end):
        stripped = lines[pos].strip()
        if not stripped:
            continue
        if bug_shape == "unchecked_index" and _INDEX_TOKENS.search(stripped) and _DANGEROUS_LINE.search(stripped):
            return pos + 1, stripped
        if bug_shape == "removed_copy_size_constraint" and _COPY_TOKENS.search(stripped):
            return pos + 1, stripped
        if bug_shape == "conversion_boundary_regression" and _CONVERSION_TOKENS.search(stripped):
            return pos + 1, stripped
        if _DANGEROUS_LINE.search(stripped):
            return pos + 1, stripped
    return start_idx + 1, lines[start_idx].strip() if 0 <= start_idx < len(lines) else ""


def _fallback_operation_from_callsites(fn: ReachableFunction) -> str:
    for callee, sites in fn.callsites.items():
        if callee:
            if sites:
                return f"{callee} via {sites[0]}"
            return callee
    return fn.function_signature or fn.name


def _compact_target_line_range(
    *,
    function_range: tuple[int, int],
    checkpoint_line: int,
    operation_line: int,
) -> tuple[int, int]:
    start, end = function_range
    lo = min(checkpoint_line, operation_line)
    hi = max(checkpoint_line, operation_line)
    if lo <= 0 or hi <= 0:
        return function_range
    compact_start = max(start, lo - 4)
    compact_end = min(end, hi + 6)
    if compact_end - compact_start < 10:
        midpoint = (compact_start + compact_end) // 2
        compact_start = max(start, midpoint - 5)
        compact_end = min(end, midpoint + 6)
    if compact_end - compact_start > 28:
        compact_end = min(end, compact_start + 28)
    return compact_start, max(compact_start, compact_end)


def _slice_excerpt(lines: list[str], line_range: tuple[int, int]) -> str:
    if not lines:
        return ""
    start, end = line_range
    excerpt_lines: list[str] = []
    for idx in range(max(1, start), min(len(lines), end) + 1):
        excerpt_lines.append(f"{idx}: {lines[idx - 1].rstrip()}")
    return "\n".join(excerpt_lines[:18])


def _blocker_proximity(harness: HarnessRecord, fn: ReachableFunction) -> str:
    for hotspot in harness.blocker_hotspots:
        if hotspot.get("function_name") == fn.name and hotspot.get("source_file") == fn.source_file:
            return "same_function"
        if hotspot.get("source_file") == fn.source_file:
            return "same_file"
    if harness.blocker_hotspots:
        return "other_hotspot"
    return "none"


def _calltree_proximity(fn: ReachableFunction) -> str:
    depth = fn.call_depth
    if depth is None:
        return "unknown"
    if depth <= 2:
        return "very_short"
    if depth <= 6:
        return "short"
    if depth <= 12:
        return "medium"
    return "long"


def _parser_proximity_signal(fn: ReachableFunction, harness: HarnessRecord, role: str) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    semantic = _semantic_blob(fn)
    callee_blob = " ".join(fn.callsites.keys())
    harness_blob = " ".join(filter(None, [harness.subsystem or "", harness.format_family or "", harness.input_model or ""]))

    if role in {"parser_entry", "decoder_conversion", "state_machine", "container_access"}:
        score += 0.34
        reasons.append("role is parser/state adjacent")
    if _ENTRY_FILE_TOKENS.search(fn.source_file):
        score += 0.18
        reasons.append("source file looks parser-facing")
    if _STATE_TRANSITION_TOKENS.search(semantic):
        score += 0.12
        reasons.append("function naming/signature suggests state transitions")
    parserish_callee_hits = len(_PARSERISH_CALLEE_TOKENS.findall(callee_blob))
    if parserish_callee_hits:
        score += min(0.18, 0.06 * parserish_callee_hits)
        reasons.append("callee set includes parser-ish operations")
    if harness.subsystem and harness.subsystem.lower() in semantic:
        score += 0.08
        reasons.append("function aligns with harness subsystem")
    if harness.input_model and _INPUT_TOKENS.search(harness_blob):
        if _INPUT_TOKENS.search(semantic) or _INPUT_TOKENS.search(callee_blob):
            score += 0.08
            reasons.append("function aligns with input model / parser flow")
    return min(1.0, score), reasons


def _path_signal_evidence(
    fn: ReachableFunction,
    harness: HarnessRecord,
    role: str,
    parser_proximity_score: float,
) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []
    calltree_proximity = _calltree_proximity(fn)

    if calltree_proximity == "very_short":
        score += 0.28
        reasons.append("very short harness path")
    elif calltree_proximity == "short":
        score += 0.2
        reasons.append("short harness path")
    elif calltree_proximity == "medium":
        score += 0.08
        reasons.append("medium harness path")
    elif calltree_proximity == "long":
        score -= 0.08
        reasons.append("long harness path")

    if fn.callsite_occurrences >= 2:
        score += min(0.2, 0.03 * fn.callsite_occurrences)
        reasons.append("repeated local callsite evidence")
    if fn.functions_reached_count and fn.functions_reached_count >= 8:
        score += min(0.14, fn.functions_reached_count / 100.0)
        reasons.append("fanout suggests repeated harness traversal")
    if parser_proximity_score >= 0.45:
        score += min(0.22, parser_proximity_score * 0.35)
        reasons.append("path stays close to parser/state frames")

    blocker_proximity = _blocker_proximity(harness, fn)
    if blocker_proximity == "same_function":
        score -= 0.12
        reasons.append("same function already appears in blocker hotspots")
    elif blocker_proximity == "same_file":
        score -= 0.06
        reasons.append("same file already contains blocker hotspots")

    if role in {"parser_entry", "decoder_conversion"} and fn.call_depth is not None and fn.call_depth <= 4:
        score += 0.08
        reasons.append("parser slice is close to harness entry")
    return max(0.0, min(1.0, score)), reasons


def _helper_judgment(
    fn: ReachableFunction,
    harness: HarnessRecord,
    role: str,
    parser_proximity_score: float,
    path_signal_score: float,
) -> tuple[str, list[str]]:
    reasons: list[str] = []
    generic_family = fn.name.lower().startswith(_GENERIC_HELPER_PREFIXES)
    helper_like_role = role in {"utility_helper", "allocator_helper"}
    non_parser_writer = role in {"buffer_writer", "copy_bridge"} and not _ENTRY_FILE_TOKENS.search(fn.source_file)

    if role in {"parser_entry", "decoder_conversion", "state_machine", "container_access"}:
        return "endpoint_or_stateful_slice", ["role is parser/stateful rather than generic helper"]

    if generic_family or helper_like_role or non_parser_writer:
        reasons.append("function belongs to a generic helper family or helper-like role")
        if parser_proximity_score >= 0.55 and path_signal_score >= 0.45 and (fn.call_depth or 999) <= 6:
            reasons.append("but parser/path evidence is strong enough to keep it as helper-on-hot-path")
            return "helper_on_hot_parser_path", reasons
        reasons.append("parser/path evidence is not strong enough for true hot-path confidence")
        return "generic_helper_family", reasons

    if path_signal_score >= 0.35 or parser_proximity_score >= 0.35:
        return "reachable_endpoint_slice", ["reachable slice has endpoint-like evidence"]
    return "reachable_helper_slice", ["reachable slice lacks strong parser/state evidence"]


def _triggerability_reasons_for_slice(
    *,
    reachability_kind: str,
    role: str,
    checkpoint: tuple[int, str, str],
    operation: tuple[int, str, str],
    slice_lines: list[str],
    fn: ReachableFunction,
    harness: HarnessRecord,
) -> TriggerabilityAssessment:
    score = 0.0
    reasons: list[str] = []
    parser_proximity_score, parser_proximity_reasons = _parser_proximity_signal(fn, harness, role)
    path_signal_score, path_signal_reasons = _path_signal_evidence(fn, harness, role, parser_proximity_score)

    if reachability_kind == "runtime_function":
        score += 0.34
        reasons.append("runtime-reachable under the preferred harness")
    elif reachability_kind == "static_function":
        score += 0.18
        reasons.append("statically reachable from the preferred harness")
    else:
        score += 0.02
        reasons.append("only coarse file-coverage evidence is available")

    if checkpoint[2] == "guard":
        score += 0.16
        reasons.append("localized on an explicit guard line")
    else:
        score -= 0.06
        reasons.append("no guard-localized checkpoint was found")

    if operation[2] == "reachable_operation":
        score += 0.14
        reasons.append("near a concrete downstream operation")

    distance = abs(operation[0] - checkpoint[0]) if checkpoint[0] and operation[0] else None
    if distance is not None:
        if distance <= 6:
            score += 0.12
            reasons.append("guard and sink sit inside a short local slice")
        elif distance <= 12:
            score += 0.07
            reasons.append("guard and sink stay within a compact local path")
        elif distance > 24:
            score -= 0.08
            reasons.append("guard and sink are far apart inside the function")

    checkpoint_text = checkpoint[1].lower()
    operation_text = operation[1].lower()
    slice_blob = " ".join(slice_lines).lower()

    if _LEN_TOKENS.search(checkpoint_text) or _INDEX_TOKENS.search(checkpoint_text) or _STATE_TOKENS.search(checkpoint_text):
        score += 0.08
        reasons.append("guard references parser-controlled length/index/state")
    if _DANGEROUS_LINE.search(operation_text):
        score += 0.08
        reasons.append("downstream operation is memory-sensitive or parser-critical")
    if _CONDITIONAL_TOKENS.search(slice_blob) and _DANGEROUS_LINE.search(slice_blob):
        score += 0.05
        reasons.append("slice contains both control gating and a sensitive operation")

    if role in {"parser_entry", "decoder_conversion", "container_access", "state_machine"}:
        score += 0.05
        reasons.append("function role aligns with input-triggerable parser state")

    repeated_callsite_count = fn.callsite_occurrences
    if repeated_callsite_count >= 2:
        score += min(0.08, 0.02 * repeated_callsite_count)
        reasons.append("callsite metadata suggests repeated path reuse")

    if fn.functions_reached_count and fn.functions_reached_count >= 8:
        score += 0.04
        reasons.append("fanout suggests the harness keeps traversing this region")

    calltree_proximity = _calltree_proximity(fn)
    if calltree_proximity in {"very_short", "short"}:
        score += 0.08
        reasons.append("call depth is short from harness entry")
    elif calltree_proximity == "long":
        score -= 0.05
        reasons.append("call depth is long from harness entry")

    blocker_proximity = _blocker_proximity(harness, fn)
    if blocker_proximity == "same_function":
        score -= 0.08
        reasons.append("same function already appears in blocker hotspots")
    elif blocker_proximity == "same_file":
        score -= 0.04
        reasons.append("same file already contains blocker hotspots")

    if fn.undiscovered_complexity and fn.undiscovered_complexity > 300:
        score -= 0.04
        reasons.append("high undiscovered complexity suggests a colder path tail")

    if path_signal_score:
        score += min(0.12, path_signal_score * 0.15)
        reasons.extend(path_signal_reasons)
    if parser_proximity_score:
        score += min(0.1, parser_proximity_score * 0.12)
        reasons.extend(parser_proximity_reasons)

    helper_judgment, helper_reasons = _helper_judgment(fn, harness, role, parser_proximity_score, path_signal_score)
    reasons.extend(helper_reasons)
    if helper_judgment == "generic_helper_family":
        score -= 0.18
    elif helper_judgment == "helper_on_hot_parser_path":
        score -= 0.05

    score = max(0.0, min(1.0, score))
    if reachability_kind == "file_coverage":
        hot_path_bucket = "weak_or_coarse_match"
    elif helper_judgment == "generic_helper_family":
        hot_path_bucket = "helper_reachable_slice"
    elif (
        score >= 0.78
        and checkpoint[2] == "guard"
        and operation[2] == "reachable_operation"
        and parser_proximity_score >= 0.25
        and path_signal_score >= 0.2
        and helper_judgment in {"endpoint_or_stateful_slice", "reachable_endpoint_slice"}
    ):
        hot_path_bucket = "high_confidence_hot_path"
    elif score >= 0.66 and helper_judgment == "helper_on_hot_parser_path":
        hot_path_bucket = "helper_reachable_slice"
    elif score >= 0.46:
        hot_path_bucket = "medium_confidence_hot_path"
    else:
        hot_path_bucket = "weak_or_coarse_match"

    return TriggerabilityAssessment(
        score=round(score, 4),
        hot_path_bucket=hot_path_bucket,
        calltree_proximity=calltree_proximity,
        blocker_proximity=blocker_proximity,
        guard_to_sink_distance=distance,
        repeated_callsite_count=repeated_callsite_count,
        path_signal_score=round(path_signal_score, 4),
        parser_proximity_score=round(parser_proximity_score, 4),
        helper_judgment=helper_judgment,
        rationale="; ".join(reasons[:4]),
        reasons=list(dict.fromkeys(reasons)),
    )


def _localize_candidate(
    repo_root: Path,
    fn: ReachableFunction,
    bug_shape: str,
    role: str,
) -> tuple[tuple[int, str, str], tuple[int, str, str], tuple[int, int], tuple[int, int], str, list[str]]:
    lines = _read_file_lines(repo_root, fn.source_file)
    if not lines:
        checkpoint_line = max(1, fn.line_start)
        checkpoint_text = fn.function_signature or fn.name
        return (
            (checkpoint_line, checkpoint_text, "function_region"),
            (checkpoint_line, checkpoint_text, "reachable_region"),
            (max(1, fn.line_start), max(checkpoint_line, fn.line_end)),
            (max(1, fn.line_start), max(checkpoint_line, fn.line_end)),
            "",
            [],
        )

    line_start = min(max(1, fn.line_start), len(lines))
    line_end = min(max(line_start, fn.line_end), len(lines))
    anchor_line, anchor_text = _find_function_anchor(lines, line_start, line_end, fn)
    checkpoint = (anchor_line, anchor_text, "function_region")
    operation = (anchor_line, _fallback_operation_from_callsites(fn), "reachable_region")

    for idx in range(line_start - 1, line_end):
        stripped = lines[idx].strip()
        if _line_matches_objective(stripped, bug_shape, role):
            checkpoint = (idx + 1, stripped, "guard")
            op_line, op_text = _find_operation(lines, idx, line_end, bug_shape)
            operation = (op_line, op_text or _fallback_operation_from_callsites(fn), "reachable_operation")
            break

    function_range = (line_start, line_end)
    compact_range = _compact_target_line_range(
        function_range=function_range,
        checkpoint_line=checkpoint[0],
        operation_line=operation[0],
    )
    slice_lines = lines[compact_range[0] - 1:compact_range[1]]
    return checkpoint, operation, compact_range, function_range, _slice_excerpt(lines, compact_range), slice_lines


def _harness_context(harness: HarnessRecord, fn: ReachableFunction, role: str) -> str:
    return (
        f"`{harness.name}` already reaches `{fn.name}` in subsystem "
        f"`{harness.subsystem or 'unknown'}` for `{harness.format_family or 'unknown'}` inputs"
        f"{f' using input model `{harness.input_model}`' if harness.input_model else ''}. "
        f"Treat this as a {role.replace('_', ' ')} target on the existing harness path."
    )


def _mutation_goal(harness: HarnessRecord, fn: ReachableFunction, role: str, bug_shape: str) -> str:
    role_hint = _ROLE_TO_HINT.get(role, "preserve the same harness path and make a minimal input-facing regression")
    return (
        f"Using `{harness.name}`, keep `{fn.name}` on the same reachable path and realize a "
        f"`{bug_shape}` style regression: {role_hint}."
    )


def _selection_rationale(
    harness: HarnessRecord,
    fn: ReachableFunction,
    reachability_kind: str,
    role: str,
    triggerability: TriggerabilityAssessment | None = None,
) -> str:
    parts = [
        f"{harness.name} reaches {fn.name} as a {reachability_kind.replace('_', ' ')} target",
        f"function role looks like {role.replace('_', ' ')}",
    ]
    if fn.call_depth is not None:
        parts.append(f"call depth {fn.call_depth}")
    if fn.functions_reached_count:
        parts.append(f"fanout {fn.functions_reached_count}")
    if harness.file_coverage.get(fn.source_file):
        parts.append(f"file coverage {harness.file_coverage[fn.source_file]:.1f}%")
    if triggerability is not None:
        parts.append(f"hot-path bucket {triggerability.hot_path_bucket}")
        parts.append(f"helper judgment {triggerability.helper_judgment.replace('_', ' ')}")
        if triggerability.guard_to_sink_distance is not None:
            parts.append(f"guard-to-sink distance {triggerability.guard_to_sink_distance}")
    return "; ".join(parts)


def _instruction_hints(
    harness: HarnessRecord,
    fn: ReachableFunction,
    role: str,
    bug_shape: str,
    triggerability: TriggerabilityAssessment | None = None,
) -> list[str]:
    hints = [
        f"Prefer edits that keep `{harness.name}` reaching `{fn.name}` through the same caller chain.",
        f"Target a `{bug_shape}` outcome inside this {role.replace('_', ' ')} function rather than rewriting signatures or types.",
        "Keep the mutation compile-clean and easy for sanitizers to observe.",
    ]
    if harness.subsystem:
        hints.append(f"Stay aligned with the `{harness.subsystem}` subsystem instead of drifting into unrelated helpers.")
    if harness.input_model:
        hints.append(f"Assume inputs should stay compatible with `{harness.input_model}`.")
    if harness.has_dict or harness.has_options:
        asset_names = []
        if harness.has_dict:
            asset_names.append("dictionary")
        if harness.has_options:
            asset_names.append("options")
        if harness.has_seed_corpus:
            asset_names.append("seed corpus")
        hints.append(f"Exploit existing fuzz assets ({', '.join(asset_names)}) by preserving the same input structure.")
    if harness.max_len is not None:
        hints.append(f"Respect the target's bounded input expectations (max_len around {harness.max_len}).")
    if harness.blocker_hotspots:
        hotspot = harness.blocker_hotspots[0]
        hints.append(
            f"Do not detach from the current path before blocker hotspot `{hotspot['function_name']}` in `{hotspot['source_file']}`."
        )
    if triggerability is not None and triggerability.guard_to_sink_distance is not None:
        hints.append(
            f"Stay inside the compact guard-to-sink slice (distance {triggerability.guard_to_sink_distance} lines) instead of drifting elsewhere in the function."
        )
    if triggerability is not None and triggerability.helper_judgment in {"generic_helper_family", "helper_on_hot_parser_path"}:
        hints.append(
            "Do not broaden this helper into a synthetic endpoint; preserve the surrounding parser/state path exactly as selected."
        )
    return hints


def _existing_harness_viability(harness: HarnessRecord, reachability_kind: str, score: float) -> str:
    if reachability_kind == "runtime_function" and harness.blocker_count <= 5 and score >= 0.8:
        return "high"
    if reachability_kind == "runtime_function" and harness.blocker_count <= 50:
        return "medium"
    if reachability_kind == "static_function" and harness.blocker_count > 20:
        return "low"
    if reachability_kind == "file_coverage":
        return "low"
    return "medium"


def _make_plan(repo_root: Path, harness: HarnessRecord, fn: ReachableFunction) -> CandidatePlan | None:
    role = _classify_role(fn, harness)
    if role == "exporter_cleanup":
        return None
    if role == "utility_helper" and _reachability_kind(fn, harness.name) != "runtime_function":
        return None
    lines = _read_file_lines(repo_root, fn.source_file)
    bug_shape = _choose_bug_shape(role, lines[max(0, fn.line_start - 1): max(0, fn.line_end)], fn, harness)
    reachability_kind = _reachability_kind(fn, harness.name)
    checkpoint, operation, line_range, function_range, slice_excerpt, slice_lines = _localize_candidate(
        repo_root,
        fn,
        bug_shape,
        role,
    )
    triggerability = _triggerability_reasons_for_slice(
        reachability_kind=reachability_kind,
        role=role,
        checkpoint=checkpoint,
        operation=operation,
        slice_lines=slice_lines,
        fn=fn,
        harness=harness,
    )
    base_score = _function_score(fn, harness, role)
    score = round(min(1.0, (base_score * 0.58) + (triggerability.score * 0.42)), 4)
    selection_rationale = _selection_rationale(harness, fn, reachability_kind, role, triggerability)
    return CandidatePlan(
        harness=harness,
        function=fn,
        reachability_kind=reachability_kind,
        function_role=role,
        bug_shape=bug_shape,
        expected_cwe=list(_BUG_CWE[bug_shape]),
        target_file=fn.source_file,
        target_line_range=line_range,
        function_line_range=function_range,
        checkpoint_line=checkpoint[0],
        checkpoint_text=checkpoint[1],
        checkpoint_type=checkpoint[2],
        operation_line=operation[0],
        operation_text=operation[1],
        operation_type=operation[2],
        slice_excerpt=slice_excerpt,
        score=score,
        validation_likelihood=_validation_likelihood(score),
        rationale=(
            f"fuzz_native: `{harness.name}` reaches `{fn.name}` and this {role.replace('_', ' ')} "
            f"path is a good fit for `{bug_shape}` while preserving fuzz rediscoverability; "
            f"{triggerability.rationale}"
        ),
        mutation_goal=_mutation_goal(harness, fn, role, bug_shape),
        selection_rationale=selection_rationale,
        instruction_hints=_instruction_hints(harness, fn, role, bug_shape, triggerability),
        harness_context=_harness_context(harness, fn, role),
        triggerability=triggerability,
    )


def _covered_files_without_functions(harness: HarnessRecord, functions: list[ReachableFunction]) -> list[str]:
    owned = {fn.source_file for fn in functions}
    return sorted(path for path in harness.reached_files if path not in owned)


def _allow_file_fallback(target_file: str, harness: HarnessRecord) -> bool:
    path = Path(target_file)
    suffix = path.suffix.lower()
    normalized = target_file.lower()
    if suffix in {".h", ".hh", ".hpp", ".hxx"}:
        return False
    if "/fuzz/" in normalized or "/fuzzing/" in normalized:
        return False
    if harness.file_coverage.get(target_file, 0.0) < 15.0:
        return False
    return suffix in {".c", ".cc", ".cpp", ".cxx", ".js", ".mjs", ".ts"}


def _synthesize_file_plan(repo_root: Path, harness: HarnessRecord, target_file: str) -> CandidatePlan | None:
    if not _allow_file_fallback(target_file, harness):
        return None
    lines = _read_file_lines(repo_root, target_file)
    if not lines:
        return None
    synthetic = ReachableFunction(
        name=Path(target_file).stem,
        source_file=target_file,
        line_start=1,
        line_end=len(lines),
        runtime_fuzzers=(harness.name,),
        static_fuzzers=(harness.name,),
        combined_fuzzers=(harness.name,),
        call_depth=2,
        cyclomatic_complexity=None,
        functions_reached_count=None,
        function_signature="",
        callsites={},
    )
    role = "parser_entry" if _ENTRY_FILE_TOKENS.search(target_file) else "utility_helper"
    bug_shape = "removed_length_restriction" if role == "parser_entry" else "removed_bounds_check"
    checkpoint = (1, lines[0].strip() if lines else target_file, "file_region")
    operation = (checkpoint[0], checkpoint[1], "reachable_region")
    triggerability = TriggerabilityAssessment(
        score=0.18,
        hot_path_bucket="weak_or_coarse_match",
        calltree_proximity="unknown",
        blocker_proximity="none",
        guard_to_sink_distance=None,
        repeated_callsite_count=0,
        path_signal_score=0.0,
        parser_proximity_score=0.0,
        helper_judgment="reachable_helper_slice",
        rationale="only file-coverage fallback evidence is available",
        reasons=["only coarse file-coverage evidence is available"],
    )
    return CandidatePlan(
        harness=harness,
        function=synthetic,
        reachability_kind="file_coverage",
        function_role=role,
        bug_shape=bug_shape,
        expected_cwe=list(_BUG_CWE[bug_shape]),
        target_file=target_file,
        target_line_range=(1, min(len(lines), 120)),
        function_line_range=(1, len(lines)),
        checkpoint_line=checkpoint[0],
        checkpoint_text=checkpoint[1],
        checkpoint_type=checkpoint[2],
        operation_line=operation[0],
        operation_text=operation[1],
        operation_type=operation[2],
        slice_excerpt=_slice_excerpt(lines, (1, min(len(lines), 24))),
        score=round(max(0.2, _file_coverage_bonus(harness, target_file) + _ROLE_PRIORITY.get(role, 0.0) + 0.08), 4),
        validation_likelihood="medium",
        rationale=f"fuzz_native: `{harness.name}` covers `{target_file}` and this file-level parser surface is still fuzzable",
        mutation_goal=f"Stay on `{harness.name}` and target an input-facing region in `{target_file}` with a narrow `{bug_shape}` regression.",
        selection_rationale=f"{harness.name} covers {target_file} even without function-level introspector detail",
        instruction_hints=[
            f"Use `{harness.name}` as the primary harness and stay inside `{target_file}`.",
            "Localize to a reachable parser or decoder region instead of inventing a new path.",
            "Prefer a small sanitizer-visible guard regression.",
        ],
        harness_context=f"`{harness.name}` covers `{target_file}` in subsystem `{harness.subsystem or 'unknown'}`.",
        triggerability=triggerability,
    )


def _dedupe_key(plan: CandidatePlan) -> tuple[str, str]:
    return (plan.target_file, plan.function.name)


def _diversify(plans: list[CandidatePlan]) -> list[CandidatePlan]:
    buckets: dict[tuple[str, str, str], list[CandidatePlan]] = defaultdict(list)
    for plan in sorted(plans, key=lambda item: (-item.score, item.target_file, item.function.name)):
        buckets[(plan.harness.name, plan.function_role, plan.bug_shape)].append(plan)
    ordered_keys = sorted(
        buckets,
        key=lambda key: (-buckets[key][0].score, key[0], key[1], key[2]),
    )
    diversified: list[CandidatePlan] = []
    file_counts: defaultdict[str, int] = defaultdict(int)
    while ordered_keys:
        next_round: list[tuple[str, str, str]] = []
        for key in ordered_keys:
            bucket = buckets[key]
            if not bucket:
                continue
            idx = 0
            while idx < len(bucket) and file_counts[bucket[idx].target_file] >= 25:
                idx += 1
            if idx >= len(bucket):
                continue
            plan = bucket.pop(idx)
            diversified.append(plan)
            file_counts[plan.target_file] += 1
            if bucket:
                next_round.append(key)
        ordered_keys = sorted(next_round, key=lambda key: (-buckets[key][0].score, key[0], key[1], key[2]))
    return diversified


def _location_hint(plan: CandidatePlan) -> str:
    if plan.triggerability.guard_to_sink_distance is not None:
        return (
            f"{plan.mutation_goal} Keep the edit inside the compact slice around lines "
            f"{plan.target_line_range[0]}-{plan.target_line_range[1]}."
        )
    return plan.mutation_goal


def _to_selection_candidate(plan: CandidatePlan, rank: int) -> SelectionCandidate:
    cwe_id = plan.expected_cwe[0]
    cwe_group = resolve_cwe_group(cwe_id, fallback="Input validation")
    alternate = [
        name for name in plan.function.runtime_fuzzers if name != plan.harness.name
    ] or [
        name for name in plan.function.static_fuzzers if name != plan.harness.name
    ]
    fuzz_native = {
        "preferred_fuzzer": plan.harness.name,
        "alternate_fuzzers": alternate[:4],
        "runtime_fuzzers": list(plan.function.runtime_fuzzers),
        "static_fuzzers": list(plan.function.static_fuzzers),
        "reachability_kind": plan.reachability_kind,
        "target_function": plan.function.name,
        "target_file": plan.target_file,
        "target_line_range": list(plan.target_line_range),
        "target_function_line_range": list(plan.function_line_range),
        "format_family": plan.harness.format_family,
        "subsystem": plan.harness.subsystem,
        "input_model": plan.harness.input_model,
        "bug_shape": plan.bug_shape,
        "expected_cwe": plan.expected_cwe,
        "validation_likelihood": plan.validation_likelihood,
        "existing_harness_viability": _existing_harness_viability(plan.harness, plan.reachability_kind, plan.score),
        "hot_path_bucket": plan.triggerability.hot_path_bucket,
        "triggerability_score": plan.triggerability.score,
        "triggerability_rationale": plan.triggerability.rationale,
        "triggerability_reasons": plan.triggerability.reasons,
        "path_signal_score": plan.triggerability.path_signal_score,
        "parser_proximity_score": plan.triggerability.parser_proximity_score,
        "helper_judgment": plan.triggerability.helper_judgment,
        "calltree_proximity": plan.triggerability.calltree_proximity,
        "blocker_proximity": plan.triggerability.blocker_proximity,
        "guard_to_sink_distance": plan.triggerability.guard_to_sink_distance,
        "repeated_callsite_count": plan.triggerability.repeated_callsite_count,
        "call_depth": plan.function.call_depth,
        "functions_reached_count": plan.function.functions_reached_count,
        "undiscovered_complexity": plan.function.undiscovered_complexity,
        "blocker_count": plan.harness.blocker_count,
        "blocker_hotspots": plan.harness.blocker_hotspots,
        "timeout_seconds": plan.harness.timeout_seconds,
        "max_len": plan.harness.max_len,
        "dict_name": plan.harness.dict_name,
        "preserve_reachability": True,
        "preserve_compile_viability": True,
        "preserve_input_path": True,
        "favor_sanitizer_visible_failure": True,
        "function_role": plan.function_role,
        "mutation_goal": plan.mutation_goal,
        "selection_rationale": plan.selection_rationale,
        "instruction_hints": plan.instruction_hints,
        "harness_context": plan.harness_context,
        "slice_excerpt": plan.slice_excerpt,
    }
    return SelectionCandidate(
        candidate_id=f"fg_{rank:04d}",
        rank=rank,
        cwe_group=cwe_group,
        cwe_id=cwe_id,
        repo_path=plan.target_file,
        symbol=plan.function.name,
        location_hint=_location_hint(plan),
        rationale=plan.rationale,
        confidence=plan.score,
        language=_language_for_path(plan.target_file),
        line_range=plan.target_line_range,
        extra={
            "strategy": "fuzz_native",
            "checkpoint": {
                "type": plan.checkpoint_type,
                "text": plan.checkpoint_text,
                "line": plan.checkpoint_line,
                "file": plan.target_file,
            },
            "operation": {
                "type": plan.operation_type,
                "text": plan.operation_text,
                "line": plan.operation_line,
                "file": plan.target_file,
            },
            "cwe_candidates": plan.expected_cwe,
            "evidence": {
                "harness": plan.harness.name,
                "format_family": plan.harness.format_family,
                "subsystem": plan.harness.subsystem,
                "runtime_fuzzers": list(plan.function.runtime_fuzzers),
                "static_fuzzers": list(plan.function.static_fuzzers),
                "call_depth": plan.function.call_depth,
                "functions_reached_count": plan.function.functions_reached_count,
                "undiscovered_complexity": plan.function.undiscovered_complexity,
                "hot_path_bucket": plan.triggerability.hot_path_bucket,
                "triggerability_score": plan.triggerability.score,
                "path_signal_score": plan.triggerability.path_signal_score,
                "parser_proximity_score": plan.triggerability.parser_proximity_score,
                "helper_judgment": plan.triggerability.helper_judgment,
            },
            "fuzz_native": fuzz_native,
        },
    )


def plan_fuzz_guided_candidates(
    *,
    project: str,
    repo_root: Path,
    surface: ProjectFuzzSurface,
    max_candidates: int | None = None,
) -> list[SelectionCandidate]:
    del project
    discovered: list[CandidatePlan] = []
    for harness in surface.harnesses.values():
        functions: list[ReachableFunction] = []
        seen: set[tuple[str, int, int, str]] = set()
        for fn in harness.runtime_functions + harness.static_functions:
            key = (fn.source_file, fn.line_start, fn.line_end, fn.name)
            if key in seen:
                continue
            seen.add(key)
            functions.append(fn)
        for fn in functions:
            plan = _make_plan(repo_root, harness, fn)
            if plan is not None:
                discovered.append(plan)
        for target_file in _covered_files_without_functions(harness, functions):
            plan = _synthesize_file_plan(repo_root, harness, target_file)
            if plan is not None:
                discovered.append(plan)

    deduped: dict[tuple[str, str], CandidatePlan] = {}
    for plan in discovered:
        key = _dedupe_key(plan)
        best = deduped.get(key)
        if best is None or plan.score > best.score:
            deduped[key] = plan

    ordered = _diversify(list(deduped.values()))
    if max_candidates is not None:
        ordered = ordered[:max_candidates]
    return [_to_selection_candidate(plan, rank) for rank, plan in enumerate(ordered, start=1)]
