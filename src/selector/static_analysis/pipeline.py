"""Pipeline orchestrator — connects all 7 stages.

Usage:
    from selector.static_analysis.pipeline import run
    output = run("/path/to/repo")
    print(output.stats)
"""

from __future__ import annotations
from collections import Counter
from pathlib import Path

from selector.static_analysis.models import VulnCandidate, PipelineOutput
from selector.static_analysis.classifier import classify_repo, RepoProfile
from selector.static_analysis.api_extractor import extract_api
from selector.static_analysis.call_graph import build_call_graph
from selector.static_analysis.call_graph_c import build_call_graph_c
from selector.static_analysis.call_graph_js import build_call_graph_js
from selector.static_analysis.enumerator import enumerate_pairs
from selector.static_analysis.scorer import score_complexity, get_difficulty
from selector.static_analysis.cwe import assign_cwes, injection_hint
from selector.static_analysis.gap_fill import run_gap_fill


DIFFICULTY_ORDER = {"easy": 0, "medium": 1, "hard": 2, "expert": 3}


def _build_candidate_from_pair(pair, nodes) -> VulnCandidate:
    """Convert a CheckpointOperationPair into a fully-labelled VulnCandidate."""
    score = score_complexity(pair, nodes)
    difficulty = get_difficulty(score)
    cwe_ids, cwe_groups = assign_cwes(pair)
    hint = injection_hint(pair)

    op_node = nodes.get(pair.operation_function)
    line_range = (pair.operation.line, pair.operation.line + 1)
    if op_node:
        line_range = (op_node.line_start, op_node.line_end)

    op_language = nodes[pair.operation_function].language if pair.operation_function in nodes else "python"
    return VulnCandidate(
        file=pair.operation.file,
        function=pair.operation_function.split("::")[-1],
        line_range=line_range,
        language=op_language,
        strategy="checkpoint_op_pair",
        checkpoint=pair.checkpoint,
        operation=pair.operation,
        call_path=pair.call_path,
        cwe_candidates=cwe_ids,
        cwe_groups=cwe_groups,
        complexity_score=score,
        difficulty=difficulty,
        evidence={
            "checkpoint_scope": pair.checkpoint_scope,
            "module_crossings": pair.module_crossings,
            "language_boundary": pair.language_boundary,
            "call_hops": len(pair.call_path) - 1,
        },
        injection_hint=hint,
    )


def _compute_stats(candidates: list[VulnCandidate]) -> dict:
    """Aggregate statistics over the candidate list."""
    by_difficulty: Counter = Counter()
    by_cwe: Counter = Counter()
    by_cwe_group: Counter = Counter()
    by_strategy: Counter = Counter()

    for c in candidates:
        by_difficulty[c.difficulty] += 1
        by_strategy[c.strategy] += 1
        for cwe in c.cwe_candidates:
            by_cwe[cwe] += 1
        for grp in c.cwe_groups:
            by_cwe_group[grp] += 1

    return {
        "total": len(candidates),
        "by_difficulty": dict(by_difficulty),
        "by_cwe": dict(by_cwe.most_common(20)),
        "by_cwe_group": dict(by_cwe_group.most_common()),
        "by_strategy": dict(by_strategy),
    }


def run(
    repo_path: str | Path,
    top_n: int | None = None,
    min_difficulty: str | None = None,
    strategy_filter: str | None = None,
    verbose: bool = False,
) -> PipelineOutput:
    """
    Run the full VulInjector pipeline on a repository.

    Args:
        repo_path:       Path to the repository root.
        top_n:           Return only the top N candidates (by complexity score).
        min_difficulty:  Only include candidates at or above this difficulty.
        strategy_filter: Only include candidates from this strategy.
        verbose:         Print progress messages.

    Returns:
        PipelineOutput with all candidates, call graph, and stats.
    """
    repo_root = Path(repo_path).resolve()
    if not repo_root.is_dir():
        raise ValueError(f"Not a directory: {repo_root}")

    def _log(msg: str) -> None:
        if verbose:
            print(f"  [vuljector] {msg}", flush=True)

    # ── Stage 0: Classify repo ────────────────────────────────────────────────
    _log("Stage 0: classifying repo…")
    profile: RepoProfile = classify_repo(repo_root)
    _log(f"  languages={profile.languages}, models={profile.security_models}")

    # ── Stage 1: Extract API surface ──────────────────────────────────────────
    _log("Stage 1: extracting API surface…")
    api_entries = extract_api(repo_root, profile)
    _log(f"  {len(api_entries)} public API entry points found")

    if not api_entries:
        _log("  WARNING: no API entries found. Returning empty output.")
        return PipelineOutput(
            repo=str(repo_root),
            candidates=[],
            call_graph={},
            stats=_compute_stats([]),
        )

    # ── Stage 2: Build call graph ─────────────────────────────────────────────
    _log("Stage 2: building call graph…")
    graph, nodes = build_call_graph(repo_root, api_entries, profile)

    if any(lang in profile.languages for lang in ("c", "cpp", "c++")):
        _log("Stage 2 (C/C++): building C/C++ call graph…")
        graph_c, nodes_c = build_call_graph_c(repo_root, api_entries, profile)
        graph.update(graph_c)
        nodes.update(nodes_c)

    if any(lang in profile.languages for lang in ("js", "ts")):
        _log("Stage 2 (JS/TS): building JS/TS call graph…")
        graph_js, nodes_js = build_call_graph_js(repo_root, api_entries, profile)
        graph.update(graph_js)
        nodes.update(nodes_js)

    _log(f"  {len(nodes)} functions, {sum(len(v) for v in graph.values())} edges")

    # ── Stage 3: Enumerate checkpoint × operation pairs ───────────────────────
    _log("Stage 3: enumerating checkpoint × operation pairs…")
    pairs = enumerate_pairs(api_entries, graph, nodes)
    _log(f"  {len(pairs)} unique pairs (after dedup)")

    # ── Stages 4 + 5: Score + assign CWEs ────────────────────────────────────
    _log("Stages 4+5: scoring complexity and assigning CWEs…")
    candidates: list[VulnCandidate] = []
    for pair in pairs:
        try:
            c = _build_candidate_from_pair(pair, nodes)
            candidates.append(c)
        except Exception:
            continue

    # ── Stage 6: Gap-fill detectors ───────────────────────────────────────────
    _log("Stage 6: running gap-fill detectors…")
    gap_candidates = run_gap_fill(repo_root, nodes, profile)
    _log(f"  {len(gap_candidates)} gap-fill candidates")
    candidates.extend(gap_candidates)

    # ── Filter and rank ───────────────────────────────────────────────────────
    if min_difficulty:
        min_level = DIFFICULTY_ORDER.get(min_difficulty, 0)
        candidates = [
            c for c in candidates
            if DIFFICULTY_ORDER.get(c.difficulty, 0) >= min_level
        ]

    if strategy_filter:
        candidates = [c for c in candidates if c.strategy == strategy_filter]

    # Sort by complexity score descending (hardest to see = most interesting)
    candidates.sort(key=lambda c: -c.complexity_score)

    if top_n is not None:
        candidates = candidates[:top_n]

    stats = _compute_stats(candidates)

    return PipelineOutput(
        repo=str(repo_root),
        candidates=candidates,
        call_graph={k: v for k, v in graph.items()},
        stats=stats,
    )
