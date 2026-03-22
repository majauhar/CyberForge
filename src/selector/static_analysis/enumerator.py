"""Stage 3 — Checkpoint × Operation Enumerator.

For each API entry node, BFS through the call graph and collect all reachable
(checkpoint, operation) pairs. Each pair represents a structurally plausible
vulnerability injection location.

Deduplication strategy:
  Keep one pair per (checkpoint.type, operation.type, operation_function),
  retaining the instance with the lowest complexity (fewest hops).

The caller/scope distinction:
  - 'dominates': checkpoint is in the same function as the operation and
    appears before it (line-based approximation of CFG dominance)
  - 'caller': checkpoint is in an ancestor function on the call path
"""

from __future__ import annotations
from selector.static_analysis.models import (
    APIEntry, CheckpointOperationPair, GraphNode, Checkpoint, Operation
)
from selector.static_analysis.call_graph import bfs_paths, count_module_crossings


def _checkpoint_scope(
    cp: Checkpoint,
    op: Operation,
    cp_fn_id: str,
    op_fn_id: str,
) -> str:
    """Classify how a checkpoint guards an operation."""
    if cp_fn_id == op_fn_id:
        # Same function — use line number as proxy for dominance
        if cp.line <= op.line:
            return "dominates"
        else:
            return "conditional"   # op appears before cp (cp may be in an else/except)
    else:
        return "caller"


def enumerate_pairs(
    entries: list[APIEntry],
    graph: dict[str, list[str]],
    nodes: dict[str, GraphNode],
    max_hops: int = 8,
    max_pairs_per_entry: int = 500,
) -> list[CheckpointOperationPair]:
    """
    For each API entry, BFS and collect all reachable (checkpoint, operation) pairs.

    Returns a deduplicated list of CheckpointOperationPair instances,
    sorted by call path length ascending (simpler pairs first).
    """
    # Dedup key → best (lowest hop count) pair seen
    best_pairs: dict[tuple[str, str, str], CheckpointOperationPair] = {}

    for entry in entries:
        start_id = entry.function_id
        if start_id not in nodes:
            # Try to find matching node by function name
            matches = [nid for nid in nodes if nid.endswith(f"::{entry.function}")]
            if not matches:
                continue
            start_id = matches[0]

        reachable = bfs_paths(graph, start_id, max_hops=max_hops)
        entry_pairs_count = 0

        for node_id, path in reachable.items():
            if entry_pairs_count >= max_pairs_per_entry:
                break

            op_node = nodes.get(node_id)
            if not op_node or not op_node.operations:
                continue

            for op in op_node.operations:
                # ── Checkpoints in the same function ─────────────────────────
                if op_node.checkpoints:
                    for cp in op_node.checkpoints:
                        scope = _checkpoint_scope(cp, op, node_id, node_id)
                        mod_crossings = count_module_crossings(path, nodes)
                        lang_boundary = any(
                            nodes[n].is_ffi_boundary for n in path if n in nodes
                        )
                        pair = CheckpointOperationPair(
                            checkpoint=cp,
                            checkpoint_function=node_id,
                            operation=op,
                            operation_function=node_id,
                            call_path=path,
                            module_crossings=mod_crossings,
                            language_boundary=lang_boundary,
                            checkpoint_scope=scope,
                        )
                        dedup_key = (cp.type, op.type, node_id)
                        _update_best(best_pairs, dedup_key, pair)
                        entry_pairs_count += 1

                # ── Checkpoints in ancestor functions on the path ─────────────
                for ancestor_id in path[:-1]:
                    ancestor = nodes.get(ancestor_id)
                    if not ancestor or not ancestor.checkpoints:
                        continue

                    for cp in ancestor.checkpoints:
                        mod_crossings = count_module_crossings(path, nodes)
                        lang_boundary = any(
                            nodes[n].is_ffi_boundary for n in path if n in nodes
                        )
                        pair = CheckpointOperationPair(
                            checkpoint=cp,
                            checkpoint_function=ancestor_id,
                            operation=op,
                            operation_function=node_id,
                            call_path=path,
                            module_crossings=mod_crossings,
                            language_boundary=lang_boundary,
                            checkpoint_scope="caller",
                        )
                        dedup_key = (cp.type, op.type, node_id)
                        _update_best(best_pairs, dedup_key, pair)
                        entry_pairs_count += 1

    return sorted(best_pairs.values(), key=lambda p: len(p.call_path))


def _update_best(
    best: dict[tuple, CheckpointOperationPair],
    key: tuple,
    candidate: CheckpointOperationPair,
) -> None:
    """Keep the pair with the fewest call hops (simplest to demonstrate)."""
    existing = best.get(key)
    if existing is None or len(candidate.call_path) < len(existing.call_path):
        best[key] = candidate
