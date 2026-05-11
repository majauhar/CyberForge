"""Schema-tolerant Introspector path-signal extraction helpers."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


def discover_calltree_sources(cache: dict[str, Any]) -> list[str]:
    introspector = cache.get("introspector") or {}
    discovered: list[str] = []
    for key, value in introspector.items():
        if "calltree" in key.lower() or "call_tree" in key.lower():
            if value not in (None, [], {}, ""):
                discovered.append(f"introspector.{key}")
    for fuzzer in introspector.get("fuzzers", []) or []:
        if not isinstance(fuzzer, dict):
            continue
        name = str(fuzzer.get("name") or "unknown")
        for key, value in fuzzer.items():
            if "calltree" in key.lower() or "call_tree" in key.lower():
                if value not in (None, [], {}, ""):
                    discovered.append(f"fuzzer:{name}.{key}")
    return sorted(discovered)


def _calltree_name_hits(calltree_blobs: list[Any], function_name: str) -> int:
    hits = 0
    needle = function_name.lower()
    for blob in calltree_blobs:
        serialized = str(blob).lower()
        hits += serialized.count(needle)
    return hits


def summarize_project_path_signals(cache: dict[str, Any], *, top_n: int = 12) -> dict[str, Any]:
    introspector = cache.get("introspector") or {}
    functions = list(introspector.get("functions") or [])
    fuzzers = [item for item in (introspector.get("fuzzers") or []) if isinstance(item, dict)]

    global_calltree_blobs = [
        value
        for key, value in introspector.items()
        if ("calltree" in key.lower() or "call_tree" in key.lower()) and value not in (None, [], {}, "")
    ]
    by_harness: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for raw in functions:
        if not isinstance(raw, dict):
            continue
        fn_name = str(raw.get("name") or raw.get("raw_name") or "")
        if not fn_name:
            continue
        runtime_fuzzers = [str(item) for item in (raw.get("runtime_reached_by_fuzzers") or [])]
        static_fuzzers = [str(item) for item in (raw.get("reached_by_fuzzers") or [])]
        call_depth = raw.get("call_depth")
        functions_reached = int(raw.get("functions_reached_count") or 0)
        undiscovered = float(raw.get("undiscovered_complexity") or 0.0)
        callsites = raw.get("callsites") or {}
        callsite_occurrences = sum(len(sites or []) for sites in callsites.values()) if isinstance(callsites, dict) else 0
        calltree_hits = _calltree_name_hits(global_calltree_blobs, fn_name)

        for harness_name in sorted(set(runtime_fuzzers + static_fuzzers)):
            score = 0.0
            reasons: list[str] = []
            if harness_name in runtime_fuzzers:
                score += 5.0
                reasons.append("runtime reached")
            else:
                score += 2.0
                reasons.append("statically reached")
            if call_depth is not None:
                if int(call_depth) <= 2:
                    score += 2.0
                    reasons.append("very short call depth")
                elif int(call_depth) <= 6:
                    score += 1.0
                    reasons.append("short call depth")
                elif int(call_depth) >= 15:
                    score -= 1.0
                    reasons.append("long call depth")
            if callsite_occurrences:
                score += min(2.0, 0.25 * callsite_occurrences)
                reasons.append("repeated callsite evidence")
            if functions_reached:
                score += min(2.0, functions_reached / 20.0)
                reasons.append("fanout evidence")
            if undiscovered >= 300.0:
                score -= 1.0
                reasons.append("high undiscovered complexity")
            if calltree_hits:
                score += min(3.0, calltree_hits / 2.0)
                reasons.append("calltree blob references function")

            by_harness[harness_name].append(
                {
                    "function": fn_name,
                    "source_file": raw.get("source_file"),
                    "line_start": raw.get("source_line_begin"),
                    "line_end": raw.get("source_line_end"),
                    "score": round(score, 3),
                    "call_depth": call_depth,
                    "callsite_occurrences": callsite_occurrences,
                    "functions_reached_count": functions_reached,
                    "undiscovered_complexity": undiscovered if undiscovered else None,
                    "calltree_hits": calltree_hits,
                    "reasons": reasons,
                }
            )

    harness_summaries = []
    for fuzzer in fuzzers:
        name = str(fuzzer.get("name") or "")
        ranked = sorted(
            by_harness.get(name, []),
            key=lambda item: (-float(item["score"]), int(item.get("call_depth") or 999), str(item.get("function") or "")),
        )[:top_n]
        harness_summaries.append(
            {
                "harness": name,
                "blocker_count": len(fuzzer.get("blockers") or []),
                "calltree_sources": [
                    key for key in discover_calltree_sources({"introspector": {"fuzzers": [fuzzer]}})
                    if key.startswith(f"fuzzer:{name}.")
                ],
                "top_functions": ranked,
            }
        )

    return {
        "calltree_sources": discover_calltree_sources(cache),
        "harnesses": harness_summaries,
    }
