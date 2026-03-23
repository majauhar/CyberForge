"""Stage 4 — Complexity Scorer.

Assigns a continuous complexity score to each checkpoint × operation pair.
The score reflects how hard it is for a human or LLM to understand the
vulnerability, not how hard it is to exploit.

Score components:
  call_hops         × 2.0   — path length between entry and operation
  module_crossings  × 3.0   — cross-module calls require understanding imports
  language_boundary × 6.0   — FFI boundary (Python→C) is hardest to reason about
  requires_domain   × 8.0   — operation is in a function whose name doesn't
                               signal the operation type (hidden danger)
  conditional_guard × 2.0   — checkpoint is conditional (not always active)
  requires_alias    × 5.0   — path involves shared state (harder to trace)

Difficulty buckets:
  easy   [0,  5)   — same function, obvious guard
  medium [5,  10)  — cross-function, same module
  hard   [10, 18)  — cross-module or hidden operation
  expert [18, ∞)   — multi-hop + domain knowledge + aliasing
"""

from __future__ import annotations
from selector.static_analysis.models import CheckpointOperationPair, GraphNode


# Operation type keywords — if none appear in the function name, it's "hidden"
_OP_TYPE_KEYWORDS: dict[str, list[str]] = {
    "eval_exec":       ["eval", "exec", "run", "execute", "interpret", "compile"],
    "deser":           ["load", "deserializ", "unpickle", "decode", "parse", "unmarshal"],
    "file_op":         ["file", "read", "write", "open", "save", "load", "path", "dir"],
    "subprocess":      ["run", "exec", "shell", "command", "proc", "spawn", "system"],
    "data_return":     ["get", "return", "fetch", "retrieve", "export", "send", "view"],
    "state_mutation":  ["set", "update", "write", "store", "save", "mutate", "assign"],
    "memory_view":     ["view", "reshape", "cast", "reinterpret", "convert", "buffer"],
    "array_index":     ["index", "get", "access", "slice", "item", "at", "fetch"],
    "alloc":           ["alloc", "create", "new", "make", "init", "buffer"],
    "sql_exec":        ["query", "execute", "sql", "db", "fetch", "select", "insert"],
    "template_render": ["render", "template", "view", "page", "html", "format"],
    "http_request":    ["request", "fetch", "get", "post", "call", "http", "api"],
    "xml_parse":       ["parse", "xml", "load", "read", "decode"],
    "log_op":          ["log", "print", "debug", "warn", "error", "info"],
    "crypto_op":       ["hash", "crypto", "encrypt", "decrypt", "sign", "verify", "hmac"],
}

DIFFICULTY_BUCKETS = [
    (0,   5,   "easy"),
    (5,   10,  "medium"),
    (10,  18,  "hard"),
    (18,  9999, "expert"),
]


def _requires_domain_knowledge(
    pair: CheckpointOperationPair,
    nodes: dict[str, GraphNode],
) -> bool:
    """
    Return True if the operation is in a function whose name gives no hint
    about what security-critical thing it does. This is the "hidden danger"
    signal — requires domain knowledge to understand the risk.
    """
    op_fn = nodes.get(pair.operation_function)
    if not op_fn:
        return False

    fn_name = op_fn.id.split("::")[-1].lower()
    op_type = pair.operation.type
    keywords = _OP_TYPE_KEYWORDS.get(op_type, [])

    # If any keyword appears in the function name → operation is obvious
    if any(kw in fn_name for kw in keywords):
        return False

    # Function name gives no hint about the operation → requires domain knowledge
    return True


def _requires_aliasing(
    pair: CheckpointOperationPair,
    nodes: dict[str, GraphNode],
) -> bool:
    """Return True if any node on the call path has shared mutable state."""
    return any(
        nodes[nid].has_shared_state
        for nid in pair.call_path
        if nid in nodes
    )


def score_complexity(
    pair: CheckpointOperationPair,
    nodes: dict[str, GraphNode],
) -> float:
    """Compute a continuous complexity score for a pair."""
    call_hops         = max(0, len(pair.call_path) - 1)
    module_crossings  = pair.module_crossings
    language_boundary = 1 if pair.language_boundary else 0
    requires_domain   = 1 if _requires_domain_knowledge(pair, nodes) else 0
    conditional_guard = 1 if pair.checkpoint_scope in ("conditional", "caller") else 0
    requires_alias    = 1 if _requires_aliasing(pair, nodes) else 0

    score = (
        call_hops         * 2.0
        + module_crossings  * 3.0
        + language_boundary * 6.0
        + requires_domain   * 8.0
        + conditional_guard * 2.0
        + requires_alias    * 5.0
    )
    return round(score, 2)


def get_difficulty(score: float) -> str:
    """Map a complexity score to a difficulty bucket label."""
    for low, high, label in DIFFICULTY_BUCKETS:
        if low <= score < high:
            return label
    return "expert"
