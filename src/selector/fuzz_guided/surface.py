"""Harness-conditioned fuzz surface loader backed by offline OSS-Fuzz metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from selector.fuzz_guided.guidance import (
    DEFAULT_CACHE_DIR,
    load_cache,
    load_local_fuzzer_options,
    local_fuzz_assets,
)


_IGNORED_PATH_PARTS = (
    "/test/",
    "/tests/",
    "/testing/",
    "/fuzz/",
    "/fuzzing/",
    "/examples/",
    "/example/",
    "/contrib/",
    "/third_party/",
    "/vendor/",
)


@dataclass(frozen=True)
class ReachableFunction:
    name: str
    source_file: str
    line_start: int
    line_end: int
    runtime_fuzzers: tuple[str, ...]
    static_fuzzers: tuple[str, ...]
    combined_fuzzers: tuple[str, ...]
    call_depth: int | None = None
    cyclomatic_complexity: float | None = None
    functions_reached_count: int | None = None
    undiscovered_complexity: float | None = None
    function_signature: str = ""
    callsites: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def callsite_occurrences(self) -> int:
        return sum(len(sites) for sites in self.callsites.values())


@dataclass
class HarnessRecord:
    name: str
    blockers: list[str] = field(default_factory=list)
    has_dict: bool = False
    has_options: bool = False
    has_seed_corpus: bool = False
    options: dict[str, str] = field(default_factory=dict)
    format_family: str | None = None
    subsystem: str | None = None
    input_model: str | None = None
    timeout_seconds: int | None = None
    max_len: int | None = None
    dict_name: str | None = None
    blocker_count: int = 0
    blocker_hotspots: list[dict[str, int | str]] = field(default_factory=list)
    runtime_functions: list[ReachableFunction] = field(default_factory=list)
    static_functions: list[ReachableFunction] = field(default_factory=list)
    reached_files: list[str] = field(default_factory=list)
    file_coverage: dict[str, float] = field(default_factory=dict)


@dataclass
class ProjectFuzzSurface:
    project: str
    cache_file: str
    harnesses: dict[str, HarnessRecord]
    project_functions: list[ReachableFunction]
    reached_files: list[str]


def _is_project_local(project: str, source_file: str) -> bool:
    normalized = source_file.replace("\\", "/")
    return normalized.startswith(f"/src/{project}/")


def _is_candidate_source_file(source_file: str) -> bool:
    normalized = source_file.replace("\\", "/").lower()
    if any(part in normalized for part in _IGNORED_PATH_PARTS):
        return False
    return normalized.endswith((
        ".c",
        ".cc",
        ".cpp",
        ".cxx",
        ".h",
        ".hh",
        ".hpp",
        ".hxx",
        ".js",
        ".mjs",
        ".ts",
    ))


def _normalize_function(entry: dict) -> ReachableFunction:
    return ReachableFunction(
        name=str(entry.get("name") or entry.get("raw_name") or ""),
        source_file=str(entry.get("source_file") or ""),
        line_start=int(entry.get("source_line_begin") or 1),
        line_end=int(entry.get("source_line_end") or entry.get("source_line_begin") or 1),
        runtime_fuzzers=tuple(str(x) for x in (entry.get("runtime_reached_by_fuzzers") or [])),
        static_fuzzers=tuple(str(x) for x in (entry.get("reached_by_fuzzers") or [])),
        combined_fuzzers=tuple(str(x) for x in (entry.get("combined_reached_by_fuzzers") or [])),
        call_depth=int(entry["call_depth"]) if entry.get("call_depth") is not None else None,
        cyclomatic_complexity=(
            float(entry["cyclomatic_complexity"])
            if entry.get("cyclomatic_complexity") is not None
            else None
        ),
        functions_reached_count=(
            int(entry["functions_reached_count"])
            if entry.get("functions_reached_count") is not None
            else None
        ),
        undiscovered_complexity=(
            float(entry["undiscovered_complexity"])
            if entry.get("undiscovered_complexity") is not None
            else None
        ),
        function_signature=str(entry.get("function_signature") or ""),
        callsites={
            str(callee): tuple(str(site) for site in (sites or []))
            for callee, sites in (entry.get("callsites") or {}).items()
        },
    )


def infer_format_family(*, harness_name: str, reached_files: list[str]) -> str | None:
    low = f"{harness_name} {' '.join(reached_files)}".lower()
    if any(token in low for token in ("hb-", "font", "gsub", "gpos", "subset")):
        return "font_binary"
    if any(token in low for token in ("assimp", "obj", "fbx", "gltf", "glb", "stl", "m3d")):
        return "model_asset"
    if "png" in low:
        return "image_png"
    if "zip" in low:
        return "zip_archive"
    if any(token in low for token in ("json", "cjson", "jsoncpp")):
        return "json_text"
    if any(token in low for token in ("quickjs", "regexp", "compile", "eval", "parser", "tokenizer", "lexer")):
        return "script_text"
    if any(token in low for token in ("xz", "lzma")):
        return "compressed_stream"
    return "binary"


def infer_subsystem(*, harness_name: str, reached_files: list[str]) -> str | None:
    low = f"{harness_name} {' '.join(reached_files)}".lower()
    if "gsub" in low:
        return "gsub"
    if "gpos" in low:
        return "gpos"
    if "subset" in low:
        return "subset"
    if any(token in low for token in ("shape", "harfbuzz")):
        return "shape"
    if "regexp" in low:
        return "regexp"
    if "compile" in low:
        return "parser_compile"
    if "eval" in low:
        return "parser_eval"
    if any(token in low for token in ("json", "cjson", "jsoncpp")):
        return "json_parser"
    if "png" in low:
        return "png_parser"
    if "zip" in low:
        return "zip_reader"
    if any(token in low for token in ("obj", "fbx", "gltf", "glb", "stl", "m3d")):
        return "importer"
    if any(token in low for token in ("xz", "lzma")):
        return "codec"
    return "parser"


def infer_input_model(
    *,
    harness_name: str,
    format_family: str | None,
    subsystem: str | None,
    has_dict: bool,
    has_seed_corpus: bool,
) -> str | None:
    low = harness_name.lower()
    if format_family == "font_binary":
        if subsystem == "gsub":
            return "small_valid_font_with_gsub_tables"
        if subsystem == "gpos":
            return "small_valid_font_with_gpos_tables"
        return "small_valid_font_binary"
    if format_family == "model_asset":
        if "obj" in low:
            return "small_valid_obj_variants"
        if "gltf" in low or "glb" in low:
            return "small_valid_gltf_variants"
        return "small_valid_model_asset"
    if format_family == "zip_archive":
        return "small_valid_zip_archive"
    if format_family == "image_png":
        return "small_valid_png_images"
    if format_family == "json_text":
        return "small_valid_json_texts"
    if format_family == "script_text":
        if "regexp" in low:
            return "small_valid_regex_patterns"
        if "compile" in low:
            return "small_valid_script_compile_units"
        if "eval" in low:
            return "small_valid_script_eval_inputs"
        return "small_valid_script_texts"
    if format_family == "compressed_stream":
        return "small_valid_compressed_streams"
    if has_seed_corpus:
        return "seed_corpus_backed_inputs"
    if has_dict:
        return "dictionary_guided_inputs"
    return None


def _to_int(value: str | None) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _summarize_blockers(raw_blockers: list[dict]) -> list[dict[str, int | str]]:
    hotspot_map: dict[tuple[str, str], dict[str, int | str]] = {}
    for blocker in raw_blockers:
        if not isinstance(blocker, dict):
            continue
        fn = str(blocker.get("function_name") or "")
        source_file = str(blocker.get("source_file") or "")
        if not fn or not source_file:
            continue
        key = (fn, source_file)
        summary = hotspot_map.setdefault(
            key,
            {
                "function_name": fn,
                "source_file": source_file,
                "count": 0,
                "max_blocked_complexity": 0,
                "max_unique_uncovered_complexity": 0,
                "max_sides_hitcount_diff": 0,
            },
        )
        summary["count"] = int(summary["count"]) + 1
        summary["max_blocked_complexity"] = max(
            int(summary["max_blocked_complexity"]),
            int(blocker.get("blocked_reachable_complexity") or 0),
        )
        summary["max_unique_uncovered_complexity"] = max(
            int(summary["max_unique_uncovered_complexity"]),
            int(blocker.get("blocked_unique_not_covered_complexity") or 0),
        )
        summary["max_sides_hitcount_diff"] = max(
            int(summary["max_sides_hitcount_diff"]),
            int(blocker.get("sides_hitcount_diff") or 0),
        )
    return sorted(
        hotspot_map.values(),
        key=lambda item: (
            -int(item["max_unique_uncovered_complexity"]),
            -int(item["max_blocked_complexity"]),
            -int(item["count"]),
            str(item["function_name"]),
        ),
    )[:5]


def load_project_fuzz_surface(project: str, cache_dir: Path = DEFAULT_CACHE_DIR) -> ProjectFuzzSurface:
    cache = load_cache(project, cache_dir)
    assets = local_fuzz_assets(project)
    options_map = load_local_fuzzer_options(project)
    raw_functions = cache.get("introspector", {}).get("functions", [])
    normalized = [
        _normalize_function(entry)
        for entry in raw_functions
        if _is_project_local(project, str(entry.get("source_file") or ""))
        and _is_candidate_source_file(str(entry.get("source_file") or ""))
    ]

    coverage = cache.get("coverage", {}).get("fuzzer_stats", {})
    harnesses: dict[str, HarnessRecord] = {}
    all_reached_files: set[str] = set()

    for raw_harness in cache.get("introspector", {}).get("fuzzers", []):
        name = str(raw_harness.get("name") or "")
        runtime_functions = [fn for fn in normalized if name in fn.runtime_fuzzers]
        static_functions = [fn for fn in normalized if name in fn.static_fuzzers and name not in fn.runtime_fuzzers]
        reached_files = {fn.source_file for fn in runtime_functions + static_functions}
        file_coverage: dict[str, float] = {}
        for file_entry in (coverage.get(name, {}) or {}).get("files", []):
            filename = str(file_entry.get("filename") or "")
            if not (_is_project_local(project, filename) and _is_candidate_source_file(filename)):
                continue
            reached_files.add(filename)
            summary = file_entry.get("summary") or {}
            lines = summary.get("lines") or {}
            file_coverage[filename] = float(lines.get("percent") or 0.0)
        reached_files_list = sorted(reached_files)
        all_reached_files.update(reached_files)
        asset_flags = assets.get(name) or {"dict": False, "options": False, "seed_corpus": False}
        option_values = options_map.get(name, {})
        format_family = infer_format_family(harness_name=name, reached_files=reached_files_list)
        subsystem = infer_subsystem(harness_name=name, reached_files=reached_files_list)
        blockers = list(raw_harness.get("blockers") or [])
        harnesses[name] = HarnessRecord(
            name=name,
            blockers=blockers,
            has_dict=bool(asset_flags.get("dict")),
            has_options=bool(asset_flags.get("options")),
            has_seed_corpus=bool(asset_flags.get("seed_corpus")),
            options=option_values,
            format_family=format_family,
            subsystem=subsystem,
            input_model=infer_input_model(
                harness_name=name,
                format_family=format_family,
                subsystem=subsystem,
                has_dict=bool(asset_flags.get("dict")),
                has_seed_corpus=bool(asset_flags.get("seed_corpus")),
            ),
            timeout_seconds=_to_int(option_values.get("libfuzzer.timeout")),
            max_len=_to_int(option_values.get("libfuzzer.max_len")),
            dict_name=option_values.get("libfuzzer.dict"),
            blocker_count=len(blockers),
            blocker_hotspots=_summarize_blockers(blockers),
            runtime_functions=sorted(runtime_functions, key=lambda fn: (fn.call_depth or 999, -int(fn.functions_reached_count or 0), fn.source_file, fn.line_start, fn.name)),
            static_functions=sorted(static_functions, key=lambda fn: (fn.call_depth or 999, -int(fn.functions_reached_count or 0), fn.source_file, fn.line_start, fn.name)),
            reached_files=reached_files_list,
            file_coverage=file_coverage,
        )

    return ProjectFuzzSurface(
        project=project,
        cache_file=str(cache_dir / f"{project}.json"),
        harnesses=harnesses,
        project_functions=normalized,
        reached_files=sorted(all_reached_files),
    )
