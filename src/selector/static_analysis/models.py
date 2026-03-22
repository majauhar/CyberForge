"""Core dataclasses shared across all pipeline stages and language plugins."""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


# ── Pattern descriptors ───────────────────────────────────────────────────────

@dataclass
class CheckpointPattern:
    """A regex pattern that identifies a security checkpoint in source text."""
    type: str       # null_check | type_check | bounds_check | auth_guard | ...
    pattern: str    # raw regex string


@dataclass
class OperationPattern:
    """A regex pattern that identifies a security-critical operation in source text."""
    type: str       # eval_exec | deser | file_op | subprocess | ...
    pattern: str    # raw regex string
    cwe_class: str  # broad CWE class label from cwe_groups.json


# ── Found instances ───────────────────────────────────────────────────────────

@dataclass
class Checkpoint:
    """A security checkpoint found at a specific location in source code."""
    type: str           # matches CheckpointPattern.type
    text: str           # the actual source line(s)
    line: int           # 1-based line number
    function: str       # qualified function id  "module::function"
    file: str           # absolute or relative path


@dataclass
class Operation:
    """A security-critical operation found at a specific location in source code."""
    type: str
    text: str
    line: int
    function: str
    file: str
    cwe_class: str      # from OperationPattern.cwe_class


@dataclass
class CallSite:
    """A function call found inside a function body."""
    callee_name: str        # raw name as written (e.g. "foo", "mod.bar")
    line: int
    caller_id: str          # qualified id of the containing function


# ── Call graph nodes ──────────────────────────────────────────────────────────

@dataclass
class GraphNode:
    """Annotated node in the call graph — one node per function."""
    id: str                             # "module::function"
    file: str
    line_start: int
    line_end: int
    module: str                         # dotted module path e.g. "flask.app"
    language: str
    checkpoints: list[Checkpoint] = field(default_factory=list)
    operations: list[Operation]   = field(default_factory=list)
    is_api_entry: bool            = False
    is_ffi_boundary: bool         = False
    imports: dict[str, str]       = field(default_factory=dict)
    # alias → qualified name, e.g. {"os": "os", "path": "os.path"}
    has_shared_state: bool        = False
    # True if function accesses self.x or module-level globals


# ── API surface ───────────────────────────────────────────────────────────────

@dataclass
class APIEntry:
    """A public API function — its parameters are taint entry points."""
    file: str
    function: str           # short name
    function_id: str        # qualified "module::function"
    line: int
    params: list[str]       # parameter names
    evidence: str           # why this is considered public
    language: str


# ── Checkpoint × Operation pair ───────────────────────────────────────────────

@dataclass
class CheckpointOperationPair:
    """A structurally plausible injection location: one checkpoint guarding one operation."""
    checkpoint: Checkpoint
    checkpoint_function: str        # qualified id of the function containing the checkpoint
    operation: Operation
    operation_function: str         # qualified id of the function containing the operation
    call_path: list[str]            # [api_entry_id, ..., operation_function_id]
    module_crossings: int           # how many module boundaries the path crosses
    language_boundary: bool         # path crosses an FFI boundary
    checkpoint_scope: str           # 'dominates' | 'conditional' | 'caller'


# ── Vulnerability candidate ───────────────────────────────────────────────────

@dataclass
class VulnCandidate:
    """A fully-labelled vulnerability injection candidate ready for output."""
    # Location
    file: str
    function: str
    line_range: tuple[int, int]
    language: str

    # What was found
    strategy: str               # 'checkpoint_op_pair' | 'crypto_misuse' | 'toctou' | 'missing_check'
    checkpoint: Checkpoint | None
    operation: Operation | None
    call_path: list[str]

    # Labeling
    cwe_candidates: list[str]   # e.g. ['CWE-476', 'CWE-787']
    cwe_groups: list[str]       # mapped group names from cwe_groups.json
    complexity_score: float
    difficulty: str             # 'easy' | 'medium' | 'hard' | 'expert'

    # Evidence for downstream LLM stage
    evidence: dict[str, Any]    # free-form metadata
    injection_hint: str         # 'weaken checkpoint' | 'remove guard' | 'wrong api' | ...

    def to_dict(self) -> dict:
        return {
            "file": self.file,
            "function": self.function,
            "line_range": list(self.line_range),
            "language": self.language,
            "strategy": self.strategy,
            "checkpoint": {
                "type": self.checkpoint.type,
                "text": self.checkpoint.text,
                "line": self.checkpoint.line,
            } if self.checkpoint else None,
            "operation": {
                "type": self.operation.type,
                "text": self.operation.text,
                "line": self.operation.line,
                "cwe_class": self.operation.cwe_class,
            } if self.operation else None,
            "call_path": self.call_path,
            "cwe_candidates": self.cwe_candidates,
            "cwe_groups": self.cwe_groups,
            "complexity_score": self.complexity_score,
            "difficulty": self.difficulty,
            "evidence": self.evidence,
            "injection_hint": self.injection_hint,
        }


# ── Pipeline output ───────────────────────────────────────────────────────────

@dataclass
class PipelineOutput:
    repo: str
    candidates: list[VulnCandidate]
    call_graph: dict[str, list[str]]    # plain adjacency dict, JSON-serializable
    stats: dict[str, Any]

    def to_dict(self) -> dict:
        return {
            "repo": self.repo,
            "stats": self.stats,
            "candidates": [c.to_dict() for c in self.candidates],
            "call_graph_node_count": len(self.call_graph),
        }
