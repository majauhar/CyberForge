"""Stage 2 (C/C++) — Call Graph Builder using tree-sitter.

Mirrors the structure of call_graph.py exactly, but uses tree-sitter to parse
C and C++ source files instead of Python's built-in ast module.

Requires (Python 3.13 compatible):
    tree-sitter>=0.24
    tree-sitter-c>=0.24
    tree-sitter-cpp>=0.23
"""

from __future__ import annotations
import re
from collections import defaultdict
from pathlib import Path

from selector.static_analysis.models import (
    GraphNode, Checkpoint, Operation, CallSite, APIEntry
)
from selector.static_analysis.plugins.c_plugin import (
    CPlugin, FFI_PATTERNS, LOCK_SIGNALS
)
from selector.static_analysis.classifier import RepoProfile


# ── tree-sitter bootstrap ──────────────────────────────────────────────────────

try:
    import tree_sitter_c as _tsc
    import tree_sitter_cpp as _tscpp
    from tree_sitter import Language, Parser, Query, QueryCursor

    _C_LANGUAGE   = Language(_tsc.language())
    _CPP_LANGUAGE = Language(_tscpp.language())
    _TREESITTER_AVAILABLE = True
except Exception:
    _TREESITTER_AVAILABLE = False
    _C_LANGUAGE = _CPP_LANGUAGE = None

# Module-level plugin singleton
_c_plugin = CPlugin()

# Pre-compile FFI and lock regex patterns
_FFI_REGEXES  = [re.compile(p) for p in FFI_PATTERNS]
_LOCK_SIGNALS = LOCK_SIGNALS


# ─────────────────────────────────────────────────────────────────────────────
# tree-sitter query strings
# ─────────────────────────────────────────────────────────────────────────────

# Matches top-level and nested function definitions in C.
# Captures the declarator identifier and the full function_definition node.
_C_FN_QUERY_SRC = """
(function_definition
  declarator: (function_declarator
    declarator: (identifier) @fn_name)
) @fn_def
"""

# C++ also needs to handle qualified names (Foo::bar) and pointer declarators.
_CPP_FN_QUERY_SRC = """
(function_definition
  declarator: [
    (function_declarator
      declarator: (identifier) @fn_name)
    (function_declarator
      declarator: (qualified_identifier) @fn_name)
    (pointer_declarator
      declarator: (function_declarator
        declarator: (identifier) @fn_name))
  ]
) @fn_def
"""

# Call expressions — C only (no qualified_identifier in C grammar)
_C_CALL_QUERY_SRC = """
(call_expression
  function: [
    (identifier) @callee
    (field_expression field: (field_identifier) @callee)
  ]
) @call
"""

# Call expressions — C++ (adds qualified names like Foo::bar)
_CPP_CALL_QUERY_SRC = """
(call_expression
  function: [
    (identifier) @callee
    (field_expression field: (field_identifier) @callee)
    (qualified_identifier) @callee
  ]
) @call
"""

# Keep old name as alias for external callers that may import it
_CALL_QUERY_SRC = _CPP_CALL_QUERY_SRC

# #include statements
_INCLUDE_QUERY_SRC = """
(preproc_include path: (_) @include_path)
"""


def _make_queries(language):
    """Compile tree-sitter queries for a given language object."""
    if language is None:
        return None, None, None
    is_cpp  = (language == _CPP_LANGUAGE)
    fn_src  = _CPP_FN_QUERY_SRC if is_cpp else _C_FN_QUERY_SRC
    call_src = _CPP_CALL_QUERY_SRC if is_cpp else _C_CALL_QUERY_SRC

    def _try_query(src):
        try:
            return Query(language, src)
        except Exception:
            return None

    return _try_query(fn_src), _try_query(call_src), _try_query(_INCLUDE_QUERY_SRC)


# Cache compiled queries
_C_QUERIES   = None
_CPP_QUERIES = None


def _get_queries(language):
    global _C_QUERIES, _CPP_QUERIES
    if language == _C_LANGUAGE:
        if _C_QUERIES is None:
            _C_QUERIES = _make_queries(language)
        return _C_QUERIES
    else:
        if _CPP_QUERIES is None:
            _CPP_QUERIES = _make_queries(language)
        return _CPP_QUERIES


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _should_skip(path: Path, repo_root: Path | None = None) -> bool:
    skip_dirs = {".git", ".svn", "__pycache__", ".venv", "venv", "env",
                 "node_modules", ".tox", "dist", "build", "site-packages",
                 "third_party", "third-party", "vendor", "external"}
    try:
        rel = path.relative_to(repo_root) if repo_root else path
    except ValueError:
        rel = path
    for part in rel.parts:
        if part in skip_dirs:
            return True
    return False


def _byte_offset_to_line(source_bytes: bytes, byte_offset: int) -> int:
    """Convert a byte offset in source_bytes to a 1-based line number."""
    return source_bytes[:byte_offset].count(b"\n") + 1


def _get_module_name(file: Path, repo_root: Path) -> str:
    try:
        rel = file.relative_to(repo_root)
    except ValueError:
        rel = file
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts) if parts else str(rel)


def _language_for_file(path: Path):
    """Return the appropriate tree-sitter language for a file extension."""
    if path.suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp", ".hh"):
        return _CPP_LANGUAGE
    return _C_LANGUAGE  # .c and .h default to C


def _get_parser(language):
    if not _TREESITTER_AVAILABLE or language is None:
        return None
    try:
        return Parser(language)
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Node annotation helpers (same contract as call_graph.py counterparts)
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
        for cp_type, cp_text in _c_plugin.match_checkpoints(stripped):
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
        if not stripped or stripped.startswith(("//", "/*", "*", "#")):
            continue
        for op_type, op_text, cwe_class in _c_plugin.match_operations(stripped):
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
    """Heuristic: check for global/shared variable patterns in the function body."""
    shared_re = re.compile(
        r"\b(?:g_|global_|shared_|static\s+\w+\s*=|__thread\b|thread_local\b)"
    )
    for lineno in range(line_start, line_end + 1):
        idx = lineno - 1
        if idx >= len(source_lines):
            break
        if shared_re.search(source_lines[idx]):
            return True
    return False


def _is_ffi_boundary(source_lines: list[str], line_start: int, line_end: int) -> bool:
    chunk = "\n".join(source_lines[max(0, line_start - 1):line_end])
    return any(r.search(chunk) for r in _FFI_REGEXES)


def _extract_includes(inc_q, tree, source_bytes: bytes) -> dict[str, str]:
    """Run the include query and return stem → header mapping."""
    imports: dict[str, str] = {}
    if inc_q is None:
        return imports
    try:
        cur = QueryCursor(inc_q)
        for _idx, cap_dict in cur.matches(tree.root_node):
            for nodes in cap_dict.values():
                for node in nodes:
                    raw = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")
                    header = raw.strip().strip('<>"')
                    stem = header.rsplit("/", 1)[-1]
                    for suffix in (".h", ".hpp", ".hh"):
                        stem = stem.replace(suffix, "")
                    imports[stem] = header
    except Exception:
        pass
    return imports


# ─────────────────────────────────────────────────────────────────────────────
# Fallback: regex-based function detection (when tree-sitter unavailable)
# ─────────────────────────────────────────────────────────────────────────────

# Matches C/C++ function definitions: return_type name(params) {
_FN_DEF_RE = re.compile(
    r"^(?:(?:static|inline|extern|virtual|explicit|constexpr|__attribute__\s*\(\([^)]*\)\))\s+)*"
    r"(?:[\w:*&<>, ]+\s+)"       # return type
    r"(\w+)\s*"                   # function name (group 1)
    r"\([^;]*\)\s*"               # parameter list (no semicolon = definition not declaration)
    r"(?:const\s*)?(?:noexcept\s*)?"
    r"\{"
)

_BRACE_OPEN  = re.compile(r"\{")
_BRACE_CLOSE = re.compile(r"\}")


def _find_functions_regex(source_lines: list[str]) -> list[tuple[str, int, int, str]]:
    """
    Fallback function finder using brace matching.
    Returns list of (fn_name, line_start, line_end, declaration_line).
    """
    functions = []
    i = 0
    n = len(source_lines)
    while i < n:
        line = source_lines[i]
        m = _FN_DEF_RE.match(line.strip())
        if m:
            fn_name = m.group(1)
            decl_line = line
            # Count braces to find function end
            depth = line.count("{") - line.count("}")
            start = i + 1  # 1-based
            j = i + 1
            while j < n and depth > 0:
                depth += source_lines[j].count("{") - source_lines[j].count("}")
                j += 1
            end = j  # 1-based
            functions.append((fn_name, start, end, decl_line))
            i = j
        else:
            i += 1
    return functions


# ─────────────────────────────────────────────────────────────────────────────
# Main call graph builder
# ─────────────────────────────────────────────────────────────────────────────

def build_call_graph_c(
    repo_root: Path,
    api_entries: list[APIEntry],
    profile: RepoProfile,
) -> tuple[dict[str, list[str]], dict[str, GraphNode]]:
    """
    Build a call graph from C/C++ source files.

    Uses tree-sitter when available; falls back to regex-based function
    detection otherwise.

    Returns:
        graph:  dict[node_id → list of callee node_ids]
        nodes:  dict[node_id → GraphNode]
    """
    graph:  dict[str, list[str]] = defaultdict(list)
    nodes:  dict[str, GraphNode] = {}

    name_index:   dict[str, list[str]] = defaultdict(list)
    module_index: dict[str, list[str]] = defaultdict(list)

    api_entry_ids = {e.function_id for e in api_entries}

    c_exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    c_files = [
        f for f in repo_root.rglob("*")
        if f.suffix.lower() in c_exts and not _should_skip(f, repo_root)
    ]

    all_calls: list[tuple[CallSite, str]] = []

    for c_file in c_files:
        try:
            source = c_file.read_text(errors="ignore")
        except OSError:
            continue

        source_lines = source.splitlines()
        module_name  = _get_module_name(c_file, repo_root)
        file_str     = str(c_file.relative_to(repo_root))
        language     = _language_for_file(c_file)

        imports: dict[str, str] = {}
        fn_list: list[tuple[str, int, int, str]] = []  # (name, start, end, decl_line)

        if _TREESITTER_AVAILABLE:
            parser = _get_parser(language)
            if parser is not None:
                try:
                    source_bytes = source.encode("utf-8", errors="replace")
                    tree = parser.parse(source_bytes)
                    fn_q, call_q, inc_q = _get_queries(language)

                    # Extract includes
                    imports = _extract_includes(inc_q, tree, source_bytes)

                    # Extract function definitions
                    if fn_q is not None:
                        fn_cur = QueryCursor(fn_q)
                        for _idx, cap_dict in fn_cur.matches(tree.root_node):
                            fn_def_nodes  = cap_dict.get("fn_def",  [])
                            fn_name_nodes = cap_dict.get("fn_name", [])
                            if not fn_def_nodes or not fn_name_nodes:
                                continue
                            fn_def_node  = fn_def_nodes[0]
                            fn_name_node = fn_name_nodes[0]
                            fn_name = source_bytes[
                                fn_name_node.start_byte:fn_name_node.end_byte
                            ].decode("utf-8", errors="ignore")
                            line_start = fn_def_node.start_point[0] + 1
                            line_end   = fn_def_node.end_point[0] + 1
                            decl_line  = source_lines[line_start - 1] if line_start <= len(source_lines) else ""
                            fn_list.append((fn_name, line_start, line_end, decl_line))

                        # Extract call sites from each function using call_q
                        if call_q is not None:
                            call_cur = QueryCursor(call_q)
                            for _idx, cap_dict in call_cur.matches(tree.root_node):
                                callee_nodes = cap_dict.get("callee", [])
                                for node in callee_nodes:
                                    call_line = node.start_point[0] + 1
                                    callee = source_bytes[
                                        node.start_byte:node.end_byte
                                    ].decode("utf-8", errors="ignore")
                                    # Attribute call to the function containing this line
                                    for fn_name, line_start, line_end, _ in fn_list:
                                        if line_start <= call_line <= line_end:
                                            fn_id = f"{module_name}::{fn_name}"
                                            all_calls.append((
                                                CallSite(callee_name=callee, line=call_line, caller_id=fn_id),
                                                module_name,
                                            ))
                                            break
                except Exception:
                    fn_list = []  # fall through to regex

        # Fallback: regex-based function detection
        if not fn_list:
            imports = _c_plugin.extract_imports(source)
            fn_list = _find_functions_regex(source_lines)

        # Build graph nodes
        for fn_name, line_start, line_end, decl_line in fn_list:
            fn_id = f"{module_name}::{fn_name}"
            if fn_id in nodes:
                fn_id = f"{fn_id}@{line_start}"

            checkpoints = _detect_checkpoints(source_lines, line_start, line_end, fn_id, file_str)
            operations  = _detect_operations(source_lines, line_start, line_end, fn_id, file_str)
            shared      = _has_shared_state(source_lines, line_start, line_end)
            ffi         = _is_ffi_boundary(source_lines, line_start, line_end)
            lang_str    = "cpp" if c_file.suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp", ".hh") else "c"

            node = GraphNode(
                id=fn_id,
                file=file_str,
                line_start=line_start,
                line_end=line_end,
                module=module_name,
                language=lang_str,
                checkpoints=checkpoints,
                operations=operations,
                is_api_entry=fn_id in api_entry_ids,
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
        resolved = _resolve_to_node_id(cs.callee_name, caller_module, name_index, module_index, nodes)
        if resolved and resolved != cs.caller_id and resolved not in graph[cs.caller_id]:
            graph[cs.caller_id].append(resolved)

    return dict(graph), nodes


# ─────────────────────────────────────────────────────────────────────────────
# Call resolution (same logic as call_graph.py)
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

    short = callee_name.split("::")[-1].split(".")[-1]

    # Prefer same module
    same = [nid for nid in name_index.get(short, []) if nodes[nid].module == caller_module]
    if same:
        return same[0]

    # Any module
    all_cands = name_index.get(short, [])
    if all_cands:
        return all_cands[0]

    return None
