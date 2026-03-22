"""Stage 2 — Call Graph Builder + BFS.

Builds a plain dict adjacency call graph from Python source files.
Each node is annotated with:
  - checkpoints found in the function body
  - security-critical operations found in the function body
  - import map (alias → qualified name)
  - FFI boundary flag
  - shared state flag (accesses self.x or module globals)

BFS is implemented from scratch — no networkx needed for MVP.
"""

from __future__ import annotations
import ast
import re
from collections import defaultdict, deque
from pathlib import Path

from selector.static_analysis.models import (
    GraphNode, Checkpoint, Operation, CallSite, APIEntry
)
from selector.static_analysis.plugins.python_plugin import PythonPlugin, FFI_PATTERNS
from selector.static_analysis.classifier import RepoProfile


# Module-level plugin singleton used for pattern matching
_python_plugin = PythonPlugin()

# Pre-compile FFI detection patterns
_FFI_REGEXES = [re.compile(p) for p in FFI_PATTERNS]


def _get_module_name(file: Path, repo_root: Path) -> str:
    try:
        rel = file.relative_to(repo_root)
    except ValueError:
        rel = file
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else str(rel)


def _should_skip(path: Path, repo_root: Path | None = None) -> bool:
    """Skip noise directories. Only checks the RELATIVE path from repo_root
    so that running on a path inside site-packages still works correctly."""
    skip_dirs = {".git", ".svn", "__pycache__", ".venv", "venv", "env",
                 "node_modules", ".tox", "dist", "build", "site-packages"}
    # Use relative path if we have a repo_root, so we don't skip based on
    # parent directories outside the analysis scope
    try:
        rel = path.relative_to(repo_root) if repo_root else path
    except ValueError:
        rel = path
    for part in rel.parts:
        if part in skip_dirs or part.endswith(".egg-info"):
            return True
    return False


def _extract_imports(tree: ast.Module) -> dict[str, str]:
    """Parse all import statements → alias: qualified_name map."""
    imports: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                key = alias.asname if alias.asname else alias.name.split(".")[0]
                imports[key] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                key = alias.asname if alias.asname else alias.name
                qualified = f"{module}.{alias.name}" if module else alias.name
                imports[key] = qualified
    return imports


def _resolve_call_name(call_node: ast.Call, imports: dict[str, str]) -> str | None:
    """
    Try to resolve an ast.Call to a qualified callee name.
    Handles:
      - Direct calls:   foo()  → 'foo'
      - Attribute:      obj.method()  → try to qualify obj via imports
      - Chained attr:   a.b.c()
    """
    func = call_node.func

    if isinstance(func, ast.Name):
        # Simple call: foo()
        name = func.id
        return imports.get(name, name)

    if isinstance(func, ast.Attribute):
        # Attribute call: x.y() or x.y.z()
        parts = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
            parts.reverse()
            base = parts[0]
            qualified_base = imports.get(base, base)
            rest = ".".join(parts[1:])
            return f"{qualified_base}.{rest}" if rest else qualified_base

    return None


def _detect_checkpoints(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    fn_id: str,
    file_str: str,
) -> list[Checkpoint]:
    """Detect checkpoint patterns in a function's source lines."""
    start = fn_node.lineno
    end = fn_node.end_lineno or (start + 50)
    checkpoints = []
    seen: set[tuple[str, int]] = set()

    for lineno in range(start + 1, end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        line = source_lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith(("def ", "async def ", "class ", "@", "#")):
            continue

        for cp_type, cp_text in _python_plugin.match_checkpoints(stripped):
            key = (cp_type, lineno)
            if key not in seen:
                seen.add(key)
                checkpoints.append(Checkpoint(
                    type=cp_type,
                    text=stripped[:200],
                    line=lineno,
                    function=fn_id,
                    file=file_str,
                ))

    return checkpoints


def _detect_operations(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    fn_id: str,
    file_str: str,
) -> list[Operation]:
    """Detect operation patterns in a function's source lines."""
    start = fn_node.lineno
    end = fn_node.end_lineno or (start + 50)
    operations = []
    seen: set[tuple[str, int]] = set()

    # Skip the function's own def line (lineno) to avoid matching type annotations
    for lineno in range(start + 1, end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        line = source_lines[idx]
        stripped = line.strip()
        if not stripped:
            continue
        # Skip def/class/decorator lines — patterns here match type annotations, not ops
        if stripped.startswith(("def ", "async def ", "class ", "@")):
            continue
        # Skip pure comment lines
        if stripped.startswith("#"):
            continue

        for op_type, op_text, cwe_class in _python_plugin.match_operations(stripped):
            key = (op_type, lineno)
            if key not in seen:
                seen.add(key)
                operations.append(Operation(
                    type=op_type,
                    text=stripped[:200],
                    line=lineno,
                    function=fn_id,
                    file=file_str,
                    cwe_class=cwe_class,
                ))

    return operations


def _has_shared_state(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> bool:
    """Return True if function accesses self.x or module-level globals."""
    for node in ast.walk(fn_node):
        # self.attr access
        if isinstance(node, ast.Attribute):
            if isinstance(node.value, ast.Name) and node.value.id == "self":
                return True
        # globals() or os.environ mutations
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "globals":
                return True
    return False


def _is_ffi_boundary(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
) -> bool:
    """Return True if this function contains FFI calls."""
    start = fn_node.lineno - 1
    end = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    chunk = "\n".join(source_lines[start:end + 1])
    return any(regex.search(chunk) for regex in _FFI_REGEXES)


def _extract_calls_from_function(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    imports: dict[str, str],
    fn_id: str,
) -> list[CallSite]:
    """Extract all call sites from a function body."""
    calls: list[CallSite] = []
    for node in ast.walk(fn_node):
        if isinstance(node, ast.Call):
            name = _resolve_call_name(node, imports)
            if name:
                calls.append(CallSite(
                    callee_name=name,
                    line=getattr(node, "lineno", 0),
                    caller_id=fn_id,
                ))
    return calls


def _all_fn_nodes(tree: ast.Module):
    """Yield all FunctionDef / AsyncFunctionDef nodes in a module."""
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            yield node


def build_call_graph(
    repo_root: Path,
    api_entries: list[APIEntry],
    profile: RepoProfile,
) -> tuple[dict[str, list[str]], dict[str, GraphNode]]:
    """
    Two-pass call graph construction:
      Pass 1: Parse all .py files → build GraphNode registry
      Pass 2: Resolve call sites → populate adjacency dict

    Returns:
      graph:  dict[node_id → list of callee node_ids]
      nodes:  dict[node_id → GraphNode]
    """
    graph: dict[str, list[str]] = defaultdict(list)
    nodes: dict[str, GraphNode] = {}

    # Index: short function name → list of qualified ids (for call resolution)
    name_index: dict[str, list[str]] = defaultdict(list)

    # Qualified module prefix → set of node_ids (for attribute resolution)
    module_index: dict[str, list[str]] = defaultdict(list)

    api_entry_ids = {e.function_id for e in api_entries}

    # ── Pass 1: build nodes ───────────────────────────────────────────────────
    all_calls: list[tuple[CallSite, str]] = []   # (callsite, caller module)

    py_files = [
        f for f in repo_root.rglob("*.py")
        if not _should_skip(f, repo_root)
    ]

    for py_file in py_files:
        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, OSError):
            continue

        source_lines = source.splitlines()
        module_name = _get_module_name(py_file, repo_root)
        imports = _extract_imports(tree)
        file_str = str(py_file.relative_to(repo_root))

        for fn_node in _all_fn_nodes(tree):
            fn_id = f"{module_name}::{fn_node.name}"

            # Avoid duplicate node ids by appending line number if needed
            if fn_id in nodes:
                fn_id = f"{fn_id}@{fn_node.lineno}"

            checkpoints = _detect_checkpoints(fn_node, source_lines, fn_id, file_str)
            operations = _detect_operations(fn_node, source_lines, fn_id, file_str)
            shared_state = _has_shared_state(fn_node)
            ffi = _is_ffi_boundary(fn_node, source_lines)

            node = GraphNode(
                id=fn_id,
                file=file_str,
                line_start=fn_node.lineno,
                line_end=fn_node.end_lineno or fn_node.lineno,
                module=module_name,
                language="python",
                checkpoints=checkpoints,
                operations=operations,
                is_api_entry=fn_id in api_entry_ids,
                is_ffi_boundary=ffi,
                imports=imports,
                has_shared_state=shared_state,
            )
            nodes[fn_id] = node
            graph[fn_id]  # ensure key exists

            # Build indices for call resolution
            name_index[fn_node.name].append(fn_id)
            module_index[module_name].append(fn_id)

            # Collect call sites for pass 2
            calls = _extract_calls_from_function(fn_node, imports, fn_id)
            for cs in calls:
                all_calls.append((cs, module_name))

    # ── Pass 2: resolve call sites → edges ───────────────────────────────────
    for cs, caller_module in all_calls:
        callee_name = cs.callee_name
        caller_id = cs.caller_id

        resolved = _resolve_to_node_id(callee_name, caller_module, name_index, module_index, nodes)
        if resolved and resolved != caller_id and resolved not in graph[caller_id]:
            graph[caller_id].append(resolved)

    return dict(graph), nodes


def _resolve_to_node_id(
    callee_name: str,
    caller_module: str,
    name_index: dict[str, list[str]],
    module_index: dict[str, list[str]],
    nodes: dict[str, GraphNode],
) -> str | None:
    """
    Resolve a callee name string to a graph node id.
    Priority:
      1. Direct fully-qualified id  "module::name"
      2. Short name in same module
      3. Short name in any module
      4. Attribute call: last part matched by short name
    """
    # 1. Direct id
    if callee_name in nodes:
        return callee_name

    # 2. Qualified module::name style
    if "::" in callee_name:
        if callee_name in nodes:
            return callee_name
        return None

    # 3. Short name (foo) — prefer same module
    short = callee_name.split(".")[-1]
    same_module_candidates = [
        nid for nid in name_index.get(short, [])
        if nodes[nid].module == caller_module
    ]
    if same_module_candidates:
        return same_module_candidates[0]

    # 4. Any module
    all_candidates = name_index.get(short, [])
    if all_candidates:
        return all_candidates[0]

    # 5. Try "module.sub.function" by splitting on dots
    parts = callee_name.split(".")
    if len(parts) >= 2:
        fn_part = parts[-1]
        mod_part = ".".join(parts[:-1])
        # Look for node_id matching module containing fn_part
        for nid in name_index.get(fn_part, []):
            node = nodes[nid]
            if node.module.endswith(mod_part) or node.module == mod_part:
                return nid

    return None


# ── BFS ──────────────────────────────────────────────────────────────────────

def bfs_paths(
    graph: dict[str, list[str]],
    start: str,
    max_hops: int = 8,
) -> dict[str, list[str]]:
    """
    BFS from `start` node. Returns {node_id: shortest path from start}.
    Path length is limited to max_hops to avoid explosion.
    """
    if start not in graph:
        return {start: [start]}

    visited: dict[str, list[str]] = {start: [start]}
    queue: deque[str] = deque([start])

    while queue:
        current = queue.popleft()
        current_path = visited[current]

        if len(current_path) > max_hops:
            continue

        for neighbor in graph.get(current, []):
            if neighbor not in visited:
                visited[neighbor] = current_path + [neighbor]
                queue.append(neighbor)

    return visited


def count_module_crossings(path: list[str], nodes: dict[str, GraphNode]) -> int:
    """Count how many times the call path crosses a module boundary."""
    crossings = 0
    prev_module = None
    for node_id in path:
        node = nodes.get(node_id)
        if node:
            if prev_module is not None and node.module != prev_module:
                crossings += 1
            prev_module = node.module
    return crossings
