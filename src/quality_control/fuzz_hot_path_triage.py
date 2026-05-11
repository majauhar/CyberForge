"""Cheap hot-path triage for fuzz-guided injection outputs."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from utils.json_io import read_json, write_json
from utils.paths import new_run_id, runs_root
from vuljector.fuzz_execution_context import candidate_fuzz_metadata
from vuljector.io_contracts import utc_now_iso


_BUCKET_ORDER = {
    "high_confidence_hot_path": 0,
    "medium_confidence_hot_path": 1,
    "helper_reachable_slice": 2,
    "weak_or_coarse_match": 3,
}


def triage_injection_result_payload(payload: dict[str, Any]) -> dict[str, Any]:
    fuzz = candidate_fuzz_metadata(payload)
    strategy = payload.get("strategy") or {}
    selected_candidate = strategy.get("selection_candidate") or {}

    reachability = str(fuzz.get("reachability_kind") or "unknown")
    viability = str(fuzz.get("existing_harness_viability") or "unknown")
    selector_bucket = str(fuzz.get("hot_path_bucket") or "")
    helper_judgment = str(fuzz.get("helper_judgment") or "")
    blocker_count = int(fuzz.get("blocker_count") or len(fuzz.get("blocker_hotspots") or []))
    triggerability_score = float(fuzz.get("triggerability_score") or 0.0)
    path_signal_score = float(fuzz.get("path_signal_score") or 0.0)
    parser_proximity_score = float(fuzz.get("parser_proximity_score") or 0.0)

    score = 0.0
    reasons: list[str] = []

    if reachability == "runtime_function":
        score += 5.0
        reasons.append("runtime reachability")
    elif reachability == "static_function":
        score += 2.5
        reasons.append("static reachability")
    elif reachability == "file_coverage":
        score -= 1.5
        reasons.append("file-only coverage fallback")
    else:
        reasons.append("missing reachability evidence")

    if viability == "high":
        score += 3.0
        reasons.append("high existing harness viability")
    elif viability == "medium":
        score += 1.5
        reasons.append("medium existing harness viability")
    elif viability == "low":
        score -= 1.0
        reasons.append("low existing harness viability")

    if fuzz.get("preferred_fuzzer"):
        score += 1.0
        reasons.append("preferred harness recorded")
    if fuzz.get("alternate_fuzzers"):
        score += 0.5
        reasons.append("alternate harness fallback recorded")
    if fuzz.get("format_family") and fuzz.get("subsystem"):
        score += 0.75
        reasons.append("format/subsystem context recorded")
    if fuzz.get("bug_shape"):
        score += 0.75
        reasons.append("bug shape recorded")
    if fuzz.get("target_function") and fuzz.get("target_line_range"):
        score += 0.75
        reasons.append("compact target slice recorded")
    if path_signal_score:
        score += min(1.5, path_signal_score * 1.5)
        reasons.append("selector path-signal score available")
    if parser_proximity_score:
        score += min(1.25, parser_proximity_score * 1.25)
        reasons.append("selector parser-proximity score available")

    if triggerability_score:
        score += min(2.0, triggerability_score * 2.0)
        reasons.append("selector triggerability score available")
    if selector_bucket == "high_confidence_hot_path":
        score += 2.0
        reasons.append("selector already marked this as high-confidence hot path")
    elif selector_bucket == "medium_confidence_hot_path":
        score += 1.0
        reasons.append("selector already marked this as medium-confidence hot path")
    elif selector_bucket == "weak_or_coarse_match":
        score -= 0.5
        reasons.append("selector only had coarse hot-path confidence")

    if helper_judgment == "generic_helper_family":
        score -= 2.5
        reasons.append("selector marked this as a generic helper family")
    elif helper_judgment == "helper_on_hot_parser_path":
        score -= 1.0
        reasons.append("selector marked this as helper-on-hot-parser-path rather than endpoint slice")
    elif helper_judgment in {"endpoint_or_stateful_slice", "reachable_endpoint_slice"}:
        score += 0.75
        reasons.append("selector marked this as endpoint/stateful slice")

    if blocker_count == 0:
        score += 1.0
        reasons.append("no blocker hotspots recorded")
    elif blocker_count <= 5:
        score += 0.5
        reasons.append("only a few blocker hotspots recorded")
    elif blocker_count >= 25:
        score -= 1.5
        reasons.append("many blocker hotspots recorded")

    selector_confirms_hot_path = (
        selector_bucket == "high_confidence_hot_path"
        or triggerability_score >= 0.72
    )
    endpoint_like = helper_judgment in {"endpoint_or_stateful_slice", "reachable_endpoint_slice", ""}
    if reachability == "file_coverage" or viability == "low":
        bucket = "weak_or_coarse_match"
    elif (
        reachability == "runtime_function"
        and viability == "high"
        and blocker_count <= 5
        and selector_confirms_hot_path
        and endpoint_like
        and parser_proximity_score >= 0.3
    ):
        bucket = "high_confidence_hot_path"
    elif helper_judgment in {"generic_helper_family", "helper_on_hot_parser_path"} and reachability == "runtime_function":
        bucket = "helper_reachable_slice"
    elif score >= 6.0 and reachability in {"runtime_function", "static_function"}:
        bucket = "medium_confidence_hot_path"
    else:
        bucket = "weak_or_coarse_match"

    return {
        "project": payload.get("project"),
        "selected_candidate_id": payload.get("selected_candidate_id") or selected_candidate.get("candidate_id"),
        "preferred_fuzzer": fuzz.get("preferred_fuzzer"),
        "reachability_kind": reachability,
        "existing_harness_viability": viability,
        "hot_path_bucket": bucket,
        "helper_judgment": helper_judgment or None,
        "score": round(score, 3),
        "reasons": reasons,
        "target_file": fuzz.get("target_file") or selected_candidate.get("repo_path"),
        "target_function": fuzz.get("target_function") or selected_candidate.get("symbol"),
        "target_line_range": fuzz.get("target_line_range") or selected_candidate.get("line_range"),
    }


def run_fuzz_hot_path_triage(
    *,
    source_dir: Path,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    injection_results = sorted(source_dir.rglob("injection_result.json"))
    decisions: list[dict[str, Any]] = []

    for path in injection_results:
        decision = triage_injection_result_payload(read_json(path))
        decision["injection_result"] = str(path)
        decisions.append(decision)

    decisions.sort(
        key=lambda item: (
            _BUCKET_ORDER.get(str(item.get("hot_path_bucket") or ""), 99),
            -float(item.get("score") or 0.0),
            str(item.get("injection_result") or ""),
        )
    )

    out_dir = output_dir or (
        runs_root() / "quality_control" / "fuzz_hot_path_triage" / source_dir.name / new_run_id("fuzz_hot_path_triage")
    )
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "source_dir": str(source_dir),
        "attempt_count": len(decisions),
        "bucket_counts": dict(Counter(item["hot_path_bucket"] for item in decisions)),
        "preferred_fuzzer_counts": dict(Counter(item.get("preferred_fuzzer") or "unknown" for item in decisions)),
    }
    report = {
        "schema_version": "fuzz_hot_path_triage_v1",
        "timestamp_utc": utc_now_iso(),
        "output_dir": str(out_dir),
        "summary": summary,
        "decisions": decisions,
    }
    write_json(out_dir / "fuzz_hot_path_triage_report.json", report)
    return report
