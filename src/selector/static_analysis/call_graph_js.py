"""Stage 2 (JS/TS) — Call Graph Builder using tree-sitter.

Mirrors the structure of call_graph_c.py exactly, but parses JavaScript and
TypeScript source files instead of C/C++.

tree-sitter is a HARD dependency — no fallback. If the packages are missing,
the ImportError surfaces immediately at module load time.

Requires:
    tree-sitter>=0.24
    tree-sitter-javascript>=0.24
    tree-sitter-typescript>=0.23
"""

from __future__ import annotations
import re
from collections import defaultdict
from pathlib import Path

from selector.static_analysis.models import (
    GraphNode, Checkpoint, Operation, CallSite, APIEntry
)
from selector.static_analysis.plugins.js_plugin import JsPlugin, FFI_PATTERNS
from selector.static_analysis.classifier import RepoProfile

# ── tree-sitter bootstrap ─────────────────────────────────────────────────────
# Hard dependency — intentionally no try/except.
# A missing package raises ImportError at module load time, which is the
# correct failure mode (surfaces in pipeline.py's import, not silently later).

import tree_sitter_javascript as _tsjs
import tree_sitter_typescript as _tsts
from tree_sitter import Language, Parser, Query, QueryCursor

_JS_LANGUAGE  = Language(_tsjs.language())
_TS_LANGUAGE  = Language(_tsts.language_typescript())
_TSX_LANGUAGE = Language(_tsts.language_tsx())

# Module-level plugin singleton
_js_plugin = JsPlugin()

# Pre-compile FFI detection regexes
_FFI_REGEXES = [re.compile(p) for p in FFI_PATTERNS]

# Shared-state detection regex
_SHARED_STATE_RE = re.compile(
    r"\b(?:global\.\w+\s*=|process\.env\.\w+\s*=|"
    r"module\.exports\s*=|exports\.\w+\s*=|"
    r"globalThis\.\w+\s*=|self\.\w+\s*=)"
)

# Route-handler assignment patterns (marks functions as public API entries)
_ROUTE_HANDLER_RE = re.compile(
    r"(?:app|router)\s*\.\s*(?:get|post|put|delete|patch|use|all|head|options)\s*\("
)


# ─────────────────────────────────────────────────────────────────────────────
# tree-sitter query strings
# ─────────────────────────────────────────────────────────────────────────────

# Named function declarations and class methods — these always have a @fn_name.
_NAMED_FN_QUERY_SRC = """
(function_declaration
  name: (identifier) @fn_name) @fn_def

(generator_function_declaration
  name: (identifier) @fn_name) @fn_def

(method_definition
  name: (property_identifier) @fn_name) @fn_def
"""

# Variable-assigned functions: const foo = () => {}  /  const foo = function() {}
# The variable name is the fn_name; the function node is fn_def.
_VAR_FN_QUERY_SRC = """
(variable_declarator
  name: (identifier) @fn_name
  value: (arrow_function) @fn_def)

(variable_declarator
  name: (identifier) @fn_name
  value: (function_expression) @fn_def)

(assignment_expression
  left: (identifier) @fn_name
  right: (arrow_function) @fn_def)

(assignment_expression
  left: (identifier) @fn_name
  right: (function_expression) @fn_def)

(assignment_expression
  left: (member_expression) @fn_name
  right: (arrow_function) @fn_def)

(assignment_expression
  left: (member_expression) @fn_name
  right: (function_expression) @fn_def)
"""

# Call expressions — covers identifier calls and member expression calls.
_CALL_QUERY_SRC = """
(call_expression
  function: [
    (identifier) @callee
    (member_expression) @callee
    (subscript_expression) @callee
  ]) @call
"""

# Export detection — used to mark functions as public API entries.
_EXPORT_QUERY_SRC = """
(export_statement
  declaration: (function_declaration
    name: (identifier) @exported_fn))

(export_statement
  declaration: (generator_function_declaration
    name: (identifier) @exported_fn))

(export_statement
  declaration: (lexical_declaration
    (variable_declarator name: (identifier) @exported_fn)))

(export_statement
  declaration: (class_declaration
    name: (identifier) @exported_fn))
"""


# ─────────────────────────────────────────────────────────────────────────────
# Query cache
# ─────────────────────────────────────────────────────────────────────────────

_QUERIES_CACHE: dict[Language, tuple] = {}


def _get_queries(language: Language) -> tuple:
    """Compile and cache tree-sitter queries for a given language."""
    if language in _QUERIES_CACHE:
        return _QUERIES_CACHE[language]

    def _try(src: str):
        try:
            return Query(language, src)
        except Exception:
            return None

    result = (
        _try(_NAMED_FN_QUERY_SRC),
        _try(_VAR_FN_QUERY_SRC),
        _try(_CALL_QUERY_SRC),
        _try(_EXPORT_QUERY_SRC),
    )
    _QUERIES_CACHE[language] = result
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _should_skip(path: Path, repo_root: Path | None = None) -> bool:
    skip_dirs = {
        ".git", ".svn", "__pycache__", ".venv", "venv", "env",
        "node_modules", ".tox", "dist", "build", "site-packages",
        "third_party", "third-party", "vendor", "external",
        ".next", ".nuxt", ".cache", "coverage", "__tests__",
    }
    try:
        rel = path.relative_to(repo_root) if repo_root else path
    except ValueError:
        rel = path
    for part in rel.parts:
        if part in skip_dirs or part.endswith(".min.js"):
            return True
    return False


def _get_module_name(file: Path, repo_root: Path) -> str:
    try:
        rel = file.relative_to(repo_root)
    except ValueError:
        rel = file
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts) if parts else str(rel)


def _lang_for_file(path: Path) -> Language:
    ext = path.suffix.lower()
    if ext == ".ts":
        return _TS_LANGUAGE
    if ext == ".tsx":
        return _TSX_LANGUAGE
    return _JS_LANGUAGE   # .js, .jsx, .mjs, .cjs


def _lang_str_for_file(path: Path) -> str:
    ext = path.suffix.lower()
    if ext in (".ts", ".tsx"):
        return "ts"
    return "js"


def _byte_offset_to_line(source_bytes: bytes, byte_offset: int) -> int:
    return source_bytes[:byte_offset].count(b"\n") + 1


def _get_node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


# ─────────────────────────────────────────────────────────────────────────────
# Node annotation helpers
# ─────────────────────────────────────────────────────────────────────────────

def _detect_checkpoints(
    source_lines: list[str],
    line_start: int,
    line_end: int,
    fn_id: str,
    file_str: str,
) -> list[Checkpoint]:
    checkpoints = []
    seen: set[tuple[str, int]] = set()
    for lineno in range(line_start + 1, line_end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        stripped = source_lines[idx].strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        for cp_type, cp_text in _js_plugin.match_checkpoints(stripped):
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
    source_lines: list[str],
    line_start: int,
    line_end: int,
    fn_id: str,
    file_str: str,
) -> list[Operation]:
    operations = []
    seen: set[tuple[str, int]] = set()
    for lineno in range(line_start + 1, line_end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        stripped = source_lines[idx].strip()
        if not stripped or stripped.startswith(("//", "/*", "*")):
            continue
        for op_type, op_text, cwe_class in _js_plugin.match_operations(stripped):
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


def _has_shared_state(source_lines: list[str], line_start: int, line_end: int) -> bool:
    for lineno in range(line_start, line_end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        if _SHARED_STATE_RE.search(source_lines[idx]):
            return True
    return False


def _is_ffi_boundary(source_lines: list[str], line_start: int, line_end: int) -> bool:
    chunk = "\n".join(source_lines[max(0, line_start - 1):line_end])
    return any(r.search(chunk) for r in _FFI_REGEXES)


def _is_route_handler_context(source_lines: list[str], line_start: int) -> bool:
    """True if this function is passed directly to an Express route handler."""
    # Look at the lines around the function start for route registration patterns
    look_start = max(0, line_start - 2)
    look_end = min(len(source_lines), line_start + 1)
    chunk = "\n".join(source_lines[look_start:look_end])
    return bool(_ROUTE_HANDLER_RE.search(chunk))


# ─────────────────────────────────────────────────────────────────────────────
# Exported function detection
# ─────────────────────────────────────────────────────────────────────────────

def _extract_exported_names(
    tree,
    source_bytes: bytes,
    export_q: Query | None,
    source: str,
) -> set[str]:
    """Return the set of function names that are exported from this file."""
    exported: set[str] = set()

    # tree-sitter query for ES6 exports
    if export_q is not None:
        try:
            cur = QueryCursor(export_q)
            for _idx, cap_dict in cur.matches(tree.root_node):
                for nodes in cap_dict.values():
                    for node in nodes:
                        exported.add(_get_node_text(node, source_bytes))
        except Exception:
            pass

    # CommonJS: module.exports.foo = ... / exports.foo = ...
    for m in re.finditer(r"(?:module\.exports|exports)\.(\w+)\s*=", source):
        exported.add(m.group(1))

    # module.exports = { foo, bar } object shorthand
    for m in re.finditer(
        r"module\.exports\s*=\s*\{([^}]+)\}", source, re.DOTALL
    ):
        for item in m.group(1).split(","):
            item = item.strip()
            if re.match(r"^\w+$", item):
                exported.add(item)

    return exported


# ─────────────────────────────────────────────────────────────────────────────
# Function extraction via tree-sitter
# ─────────────────────────────────────────────────────────────────────────────

def _extract_functions(
    tree,
    source_bytes: bytes,
    named_fn_q: Query | None,
    var_fn_q: Query | None,
) -> list[tuple[str, int, int]]:
    """Extract (fn_name, line_start_1based, line_end_1based) tuples."""
    functions: list[tuple[str, int, int]] = []
    seen_spans: set[tuple[int, int]] = set()

    def _add(name: str, fn_node) -> None:
        ls = fn_node.start_point[0] + 1
        le = fn_node.end_point[0] + 1
        span = (ls, le)
        if span not in seen_spans:
            seen_spans.add(span)
            functions.append((name, ls, le))

    # Named function declarations / methods
    if named_fn_q is not None:
        try:
            cur = QueryCursor(named_fn_q)
            for _idx, cap_dict in cur.matches(tree.root_node):
                fn_defs  = cap_dict.get("fn_def", [])
                fn_names = cap_dict.get("fn_name", [])
                if not fn_defs or not fn_names:
                    continue
                name = _get_node_text(fn_names[0], source_bytes)
                _add(name, fn_defs[0])
        except Exception:
            pass

    # Variable-assigned functions: const foo = () => {} / const foo = function() {}
    if var_fn_q is not None:
        try:
            cur = QueryCursor(var_fn_q)
            for _idx, cap_dict in cur.matches(tree.root_node):
                fn_defs  = cap_dict.get("fn_def", [])
                fn_names = cap_dict.get("fn_name", [])
                if not fn_defs or not fn_names:
                    # Anonymous arrow / function expression — synthesize a name
                    if fn_defs:
                        ls = fn_defs[0].start_point[0] + 1
                        _add(f"<anon>@{ls}", fn_defs[0])
                    continue
                name_text = _get_node_text(fn_names[0], source_bytes)
                # member_expression gives e.g. "module.exports.foo" — use last segment
                name = name_text.rsplit(".", 1)[-1]
                _add(name, fn_defs[0])
        except Exception:
            pass

    # Catch any remaining arrow/function_expression nodes not captured above
    # (e.g. callbacks, IIFEs) — walk the tree once
    _collect_anonymous_fns(tree.root_node, source_bytes, seen_spans, functions)

    return functions


def _collect_anonymous_fns(
    node,
    source_bytes: bytes,
    seen_spans: set[tuple[int, int]],
    functions: list[tuple[str, int, int]],
) -> None:
    """Walk tree, collect any function/arrow nodes not yet recorded."""
    ANON_TYPES = {"arrow_function", "function_expression", "generator_function"}
    if node.type in ANON_TYPES:
        ls = node.start_point[0] + 1
        le = node.end_point[0] + 1
        span = (ls, le)
        if span not in seen_spans:
            seen_spans.add(span)
            functions.append((f"<anon>@{ls}", ls, le))
    for child in node.children:
        _collect_anonymous_fns(child, source_bytes, seen_spans, functions)


# ─────────────────────────────────────────────────────────────────────────────
# Call site extraction
# ─────────────────────────────────────────────────────────────────────────────

def _extract_call_sites(
    tree,
    source_bytes: bytes,
    call_q: Query | None,
    fn_list: list[tuple[str, int, int]],
    module_name: str,
) -> list[tuple[CallSite, str]]:
    """Return (CallSite, caller_module) pairs for all call expressions."""
    all_calls: list[tuple[CallSite, str]] = []
    if call_q is None:
        return all_calls

    try:
        cur = QueryCursor(call_q)
        for _idx, cap_dict in cur.matches(tree.root_node):
            callee_nodes = cap_dict.get("callee", [])
            for node in callee_nodes:
                call_line = node.start_point[0] + 1
                callee = _get_node_text(node, source_bytes)
                # Strip member expression to last component for resolution
                callee_short = callee.rsplit(".", 1)[-1]

                # Attribute call to the enclosing function
                for fn_name, ls, le in fn_list:
                    if ls <= call_line <= le:
                        fn_id = f"{module_name}::{fn_name}"
                        all_calls.append((
                            CallSite(
                                callee_name=callee_short,
                                line=call_line,
                                caller_id=fn_id,
                            ),
                            module_name,
                        ))
                        break
    except Exception:
        pass

    return all_calls


# ─────────────────────────────────────────────────────────────────────────────
# Import extraction (regex — structure is simple enough)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_imports(source: str) -> dict[str, str]:
    """Parse import/require statements → alias: qualified_name map."""
    return _js_plugin.extract_imports(source)


# ─────────────────────────────────────────────────────────────────────────────
# Call resolution (same logic as call_graph_c.py)
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_to_node_id(
    callee_name: str,
    caller_module: str,
    name_index: dict[str, list[str]],
    module_index: dict[str, list[str]],
    nodes: dict[str, GraphNode],
) -> str | None:
    if callee_name in nodes:
        return callee_name

    short = callee_name.split(".")[-1].split("::")[-1]

    # Prefer same module
    same = [nid for nid in name_index.get(short, []) if nodes[nid].module == caller_module]
    if same:
        return same[0]

    # Any module
    all_cands = name_index.get(short, [])
    if all_cands:
        return all_cands[0]

    return None


# ─────────────────────────────────────────────────────────────────────────────
# Main call graph builder
# ─────────────────────────────────────────────────────────────────────────────

def build_call_graph_js(
    repo_root: Path,
    api_entries: list[APIEntry],
    profile: RepoProfile,
) -> tuple[dict[str, list[str]], dict[str, GraphNode]]:
    """Build a call graph from JS/TS source files using tree-sitter.

    Returns:
        graph:  dict[node_id → list of callee node_ids]
        nodes:  dict[node_id → GraphNode]
    """
    graph:  dict[str, list[str]] = defaultdict(list)
    nodes:  dict[str, GraphNode] = {}
    name_index:   dict[str, list[str]] = defaultdict(list)
    module_index: dict[str, list[str]] = defaultdict(list)

    api_entry_ids = {e.function_id for e in api_entries}

    js_exts = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
    js_files = [
        f for f in repo_root.rglob("*")
        if f.suffix.lower() in js_exts and not _should_skip(f, repo_root)
    ]

    all_calls: list[tuple[CallSite, str]] = []

    for js_file in js_files:
        try:
            source = js_file.read_text(errors="ignore")
        except OSError:
            continue

        source_lines = source.splitlines()
        module_name  = _get_module_name(js_file, repo_root)
        file_str     = str(js_file.relative_to(repo_root))
        lang         = _lang_for_file(js_file)
        lang_str     = _lang_str_for_file(js_file)
        imports      = _extract_imports(source)

        try:
            parser = Parser(lang)
            source_bytes = source.encode("utf-8", errors="replace")
            tree = parser.parse(source_bytes)
        except Exception:
            continue

        named_fn_q, var_fn_q, call_q, export_q = _get_queries(lang)

        exported_names = _extract_exported_names(tree, source_bytes, export_q, source)

        fn_list = _extract_functions(tree, source_bytes, named_fn_q, var_fn_q)

        # Collect call sites for pass 2
        file_calls = _extract_call_sites(tree, source_bytes, call_q, fn_list, module_name)
        all_calls.extend(file_calls)

        # Build graph nodes
        for fn_name, line_start, line_end in fn_list:
            fn_id = f"{module_name}::{fn_name}"
            if fn_id in nodes:
                fn_id = f"{fn_id}@{line_start}"

            is_exported      = fn_name in exported_names
            module_exports   = bool(re.search(
                rf"(?:module\.exports|exports)\.{re.escape(fn_name)}\s*=", source
            ))
            is_route_handler = _is_route_handler_context(source_lines, line_start)

            context = {
                "is_exported":      is_exported,
                "module_exports":   module_exports,
                "is_route_handler": is_route_handler,
            }

            checkpoints = _detect_checkpoints(source_lines, line_start, line_end, fn_id, file_str)
            operations  = _detect_operations(source_lines, line_start, line_end, fn_id, file_str)
            shared      = _has_shared_state(source_lines, line_start, line_end)
            ffi         = _is_ffi_boundary(source_lines, line_start, line_end)

            node = GraphNode(
                id=fn_id,
                file=file_str,
                line_start=line_start,
                line_end=line_end,
                module=module_name,
                language=lang_str,
                checkpoints=checkpoints,
                operations=operations,
                is_api_entry=(fn_id in api_entry_ids
                              or _js_plugin.is_public_function(fn_name, context)),
                is_ffi_boundary=ffi,
                imports=imports,
                has_shared_state=shared,
            )
            nodes[fn_id] = node
            graph[fn_id]  # ensure key exists

            name_index[fn_name].append(fn_id)
            module_index[module_name].append(fn_id)

    # ── Pass 2: resolve call sites → edges ───────────────────────────────────
    for cs, caller_module in all_calls:
        if cs.caller_id not in nodes:
            continue
        resolved = _resolve_to_node_id(
            cs.callee_name, caller_module, name_index, module_index, nodes
        )
        if (resolved
                and resolved != cs.caller_id
                and resolved not in graph[cs.caller_id]):
            graph[cs.caller_id].append(resolved)

    return dict(graph), nodes
