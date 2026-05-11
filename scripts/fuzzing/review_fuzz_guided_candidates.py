#!/usr/bin/env python3
"""Render a compact review table for fuzz_guided candidates."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def _helper_vs_endpoint(fuzz: dict) -> str:
    judgment = str(fuzz.get("helper_judgment") or "")
    if not judgment:
        role = str(fuzz.get("function_role") or "")
        if role in {"parser_entry", "decoder_conversion", "state_machine", "container_access"}:
            judgment = "endpoint_or_stateful_slice"
        elif role in {"buffer_writer", "copy_bridge"}:
            judgment = "helper_on_hot_parser_path"
        elif role:
            judgment = "reachable_helper_slice"
    mapping = {
        "endpoint_or_stateful_slice": "endpoint/stateful",
        "reachable_endpoint_slice": "endpoint-like",
        "helper_on_hot_parser_path": "helper on hot path",
        "generic_helper_family": "generic helper",
        "reachable_helper_slice": "reachable helper",
    }
    return mapping.get(judgment, judgment or "unknown")


def _send_to_injection(fuzz: dict) -> str:
    bucket = str(fuzz.get("hot_path_bucket") or "")
    judgment = str(fuzz.get("helper_judgment") or "")
    if not judgment:
        role = str(fuzz.get("function_role") or "")
        if role in {"parser_entry", "decoder_conversion", "state_machine", "container_access"}:
            judgment = "endpoint_or_stateful_slice"
        elif role in {"buffer_writer", "copy_bridge"}:
            judgment = "helper_on_hot_parser_path"
    if bucket == "high_confidence_hot_path" and judgment in {"endpoint_or_stateful_slice", "reachable_endpoint_slice"}:
        return "yes"
    if bucket == "medium_confidence_hot_path":
        return "maybe"
    if judgment in {"helper_on_hot_parser_path", "generic_helper_family"}:
        return "probably not"
    return "no"


def render_review_table(candidates_file: Path, *, limit: int) -> str:
    payload = json.loads(candidates_file.read_text(encoding="utf-8"))
    rows = [
        "| rank | symbol | file | harness | role | helper vs endpoint | send to injection |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for candidate in payload.get("candidates", [])[:limit]:
        fuzz = ((candidate.get("extra") or {}).get("fuzz_native") or {})
        rows.append(
            "| {rank} | `{symbol}` | `{file}` | `{harness}` | `{role}` | {judgment} | {send} |".format(
                rank=candidate.get("rank", "?"),
                symbol=candidate.get("symbol", ""),
                file=Path(candidate.get("repo_path", "")).name,
                harness=fuzz.get("preferred_fuzzer", "unknown"),
                role=fuzz.get("function_role", "unknown"),
                judgment=_helper_vs_endpoint(fuzz),
                send=_send_to_injection(fuzz),
            )
        )
    return "\n".join(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates_file", help="Path to fuzz_guided candidates.json")
    parser.add_argument("--limit", type=int, default=10, help="Maximum candidates to render.")
    args = parser.parse_args()
    print(render_review_table(Path(args.candidates_file).resolve(), limit=args.limit))


if __name__ == "__main__":
    main()
