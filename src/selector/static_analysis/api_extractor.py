"""Stage 1 — API Surface Extractor.

Identifies public API entry points in the codebase. Every parameter of every
public function is a potential taint entry point.

For Python:
- Functions listed in __all__
- Functions whose name does not start with _
- Functions with a docstring (documented = intended for external use)
- Functions called from test files

For C/C++:
- Functions that are NOT declared static (no internal linkage)
- Functions whose name does not start with _
- Uses tree-sitter when available; falls back to regex heuristic
"""

from __future__ import annotations
import ast
import re
from pathlib import Path

from selector.static_analysis.models import APIEntry
from selector.static_analysis.classifier import RepoProfile


def _get_module_name(file: Path, repo_root: Path) -> str:
    """Convert a file path to a dotted module name."""
    try:
        rel = file.relative_to(repo_root)
    except ValueError:
        rel = file
    parts = list(rel.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts) if parts else str(rel)


def _extract_dunder_all(tree: ast.Module) -> list[str]:
    """Extract names listed in module-level __all__ = [...]."""
    names = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "__all__":
                    if isinstance(node.value, (ast.List, ast.Tuple)):
                        for elt in node.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                names.append(elt.value)
    return names


def _has_docstring(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function has a docstring."""
    return (
        len(fn_node.body) > 0
        and isinstance(fn_node.body[0], ast.Expr)
        and isinstance(fn_node.body[0].value, ast.Constant)
        and isinstance(fn_node.body[0].value.value, str)
    )


def _extract_param_names(fn_node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    """Extract parameter names from a function definition."""
    params = []
    args = fn_node.args
    for arg in args.posonlyargs + args.args + args.kwonlyargs:
        if arg.arg not in ("self", "cls"):
            params.append(arg.arg)
    if args.vararg:
        params.append(f"*{args.vararg.arg}")
    if args.kwarg:
        params.append(f"**{args.kwarg.arg}")
    return params


def _find_class_methods(tree: ast.Module) -> dict[str, bool]:
    """Return mapping of function_name → is_in_class for all functions."""
    in_class = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in ast.walk(node):
                if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    in_class[item.name] = True
    return in_class


def _is_public_python(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    module_all: list[str],
    in_class: dict[str, bool],
) -> tuple[bool, str]:
    """Determine if a Python function is public API. Returns (is_public, evidence)."""
    name = fn_node.name

    # Skip private/protected
    if name.startswith("__") and name.endswith("__"):
        # Allow constructors and protocol methods
        if name not in ("__init__", "__new__", "__call__", "__enter__", "__exit__",
                        "__get__", "__set__", "__delete__", "__iter__", "__next__"):
            return False, ""

    if name in module_all:
        return True, "listed_in___all__"

    if name.startswith("_"):
        return False, ""

    if _has_docstring(fn_node):
        return True, "has_docstring"

    # Default: public if not underscore-prefixed
    return True, "no_underscore_prefix"


def _find_test_references(repo_root: Path) -> set[str]:
    """Find all function names called in test files."""
    test_refs: set[str] = set()
    for test_file in repo_root.rglob("test_*.py"):
        try:
            source = test_file.read_text(errors="ignore")
            tree = ast.parse(source)
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        test_refs.add(node.func.id)
                    elif isinstance(node.func, ast.Attribute):
                        test_refs.add(node.func.attr)
        except (SyntaxError, OSError):
            continue
    return test_refs


def extract_python_api(
    repo_root: Path,
    profile: RepoProfile,
) -> list[APIEntry]:
    """Walk all Python files and extract public API entry points."""
    entries: list[APIEntry] = []
    test_refs = _find_test_references(repo_root)

    _skip = {".venv", "venv", "__pycache__", ".git", "node_modules", ".tox"}
    python_files = [
        f for f in repo_root.rglob("*.py")
        if not any(part in _skip for part in f.relative_to(repo_root).parts)
    ]

    for py_file in python_files:
        try:
            source = py_file.read_text(errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, OSError):
            continue

        module_name = _get_module_name(py_file, repo_root)
        module_all = _extract_dunder_all(tree)
        in_class = _find_class_methods(tree)

        # Walk top-level functions and methods in classes
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            is_public, evidence = _is_public_python(node, module_all, in_class)

            # Check if called from tests
            if not is_public and node.name in test_refs:
                is_public = True
                evidence = "called_in_tests"

            if not is_public:
                continue

            params = _extract_param_names(node)
            fn_id = f"{module_name}::{node.name}"

            entries.append(APIEntry(
                file=str(py_file.relative_to(repo_root)),
                function=node.name,
                function_id=fn_id,
                line=node.lineno,
                params=params,
                evidence=evidence,
                language="python",
            ))

    return entries


def extract_api(repo_root: Path, profile: RepoProfile) -> list[APIEntry]:
    """Dispatch to language-specific extractors based on the repo profile."""
    entries: list[APIEntry] = []

    if "python" in profile.languages:
        entries.extend(extract_python_api(repo_root, profile))

    if any(lang in profile.languages for lang in ("c", "cpp", "c++")):
        entries.extend(extract_c_api(repo_root, profile))

    # Future: if 'go' in profile.languages: entries.extend(extract_go_api(...))

    return entries


# ─────────────────────────────────────────────────────────────────────────────
# C / C++ API extraction
# ─────────────────────────────────────────────────────────────────────────────

# Regex for C/C++ function signatures (declaration or definition line).
# Captures the function name as group 1.
_C_FN_SIG_RE = re.compile(
    r"^(?:(?:static|inline|extern|virtual|explicit|constexpr|__attribute__\s*\(\([^)]*\)\))\s+)*"
    r"(?:[\w:*&<>, ]+?\s+)"       # return type (non-greedy)
    r"(\w+)\s*"                    # function name — group 1
    r"\([^;{]*\)"                  # parameter list
    r"\s*(?:const\s*)?(?:noexcept\s*)?"
    r"(?:\{|;)",                   # opening brace (definition) or semicolon (declaration)
)

# Regex to extract parameter names from a C/C++ parameter list.
_C_PARAM_RE = re.compile(r"\b(\w+)\s*(?:,|\))")


def _is_public_c(fn_name: str, decl_line: str) -> bool:
    """Return True if the C/C++ function should be considered a public entry point."""
    if re.search(r"\bstatic\b", decl_line):
        return False
    if fn_name.startswith("_"):
        return False
    return True


def _extract_c_params(param_str: str) -> list[str]:
    """Extract parameter names from a C/C++ parameter list string."""
    # Remove pointer/reference symbols, type qualifiers etc. and grab last word per param
    params = []
    for part in param_str.split(","):
        part = part.strip()
        if not part or part in ("void", "..."):
            continue
        # last word is usually the parameter name
        tokens = re.findall(r"\b\w+\b", part)
        if tokens:
            params.append(tokens[-1])
    return params


def _get_c_module_name(file: Path, repo_root: Path) -> str:
    try:
        rel = file.relative_to(repo_root)
    except ValueError:
        rel = file
    parts = list(rel.with_suffix("").parts)
    return ".".join(parts) if parts else str(rel)


def extract_c_api(
    repo_root: Path,
    profile: RepoProfile,
) -> list[APIEntry]:
    """Walk C/C++ files and extract public (non-static) function entry points."""
    entries: list[APIEntry] = []
    c_exts = {".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"}
    skip_dirs = {".git", ".venv", "venv", "__pycache__", "node_modules",
                 ".tox", "third_party", "third-party", "vendor", "external"}

    # Try tree-sitter first
    ts_available = False
    try:
        import tree_sitter_c as _tsc
        import tree_sitter_cpp as _tscpp
        from tree_sitter import Language as _TSLang, Parser as _TSParser, Query as _TSQuery, QueryCursor as _TSQueryCursor
        from selector.static_analysis.call_graph_c import (
            _C_FN_QUERY_SRC, _CPP_FN_QUERY_SRC,
        )
        _ts_c_lang   = _TSLang(_tsc.language())
        _ts_cpp_lang = _TSLang(_tscpp.language())
        ts_available = True
    except Exception:
        pass

    c_files = [
        f for f in repo_root.rglob("*")
        if f.suffix.lower() in c_exts
        and not any(p in skip_dirs for p in f.relative_to(repo_root).parts)
    ]

    for c_file in c_files:
        try:
            source = c_file.read_text(errors="ignore")
        except OSError:
            continue

        source_lines = source.splitlines()
        module_name  = _get_c_module_name(c_file, repo_root)
        file_str     = str(c_file.relative_to(repo_root))
        is_cpp       = c_file.suffix.lower() in (".cpp", ".cc", ".cxx", ".hpp", ".hh")
        lang_str     = "cpp" if is_cpp else "c"

        fn_found = False

        if ts_available:
            try:
                language     = _ts_cpp_lang if is_cpp else _ts_c_lang
                parser       = _TSParser(language)
                source_bytes = source.encode("utf-8", errors="replace")
                tree         = parser.parse(source_bytes)
                fn_src       = _CPP_FN_QUERY_SRC if is_cpp else _C_FN_QUERY_SRC
                fn_q         = _TSQuery(language, fn_src)
                fn_cur       = _TSQueryCursor(fn_q)

                for _idx, cap_dict in fn_cur.matches(tree.root_node):
                    fn_def_nodes  = cap_dict.get("fn_def",  [])
                    fn_name_nodes = cap_dict.get("fn_name", [])
                    if not fn_def_nodes or not fn_name_nodes:
                        continue
                    fn_def_node  = fn_def_nodes[0]
                    fn_name_node = fn_name_nodes[0]
                    fn_name  = source_bytes[
                        fn_name_node.start_byte:fn_name_node.end_byte
                    ].decode("utf-8", errors="ignore")
                    line_start = fn_def_node.start_point[0] + 1
                    decl_line  = source_lines[line_start - 1] if line_start <= len(source_lines) else ""

                    if not _is_public_c(fn_name, decl_line):
                        continue

                    decl_text = source_bytes[
                        fn_def_node.start_byte:fn_def_node.end_byte
                    ].decode("utf-8", errors="ignore")[:300]
                    param_match = re.search(r"\(([^)]*)\)", decl_text)
                    params = _extract_c_params(param_match.group(1)) if param_match else []

                    fn_id = f"{module_name}::{fn_name}"
                    entries.append(APIEntry(
                        file=file_str,
                        function=fn_name,
                        function_id=fn_id,
                        line=line_start,
                        params=params,
                        evidence="non_static_function",
                        language=lang_str,
                    ))
                fn_found = True
            except Exception:
                fn_found = False

        if not fn_found:
            # Fallback: line-by-line regex scan
            for lineno, line in enumerate(source_lines, start=1):
                m = _C_FN_SIG_RE.match(line.strip())
                if not m:
                    continue
                fn_name = m.group(1)
                if not _is_public_c(fn_name, line):
                    continue
                param_match = re.search(r"\(([^)]*)\)", line)
                params = _extract_c_params(param_match.group(1)) if param_match else []
                fn_id = f"{module_name}::{fn_name}"
                entries.append(APIEntry(
                    file=file_str,
                    function=fn_name,
                    function_id=fn_id,
                    line=lineno,
                    params=params,
                    evidence="non_static_function",
                    language=lang_str,
                ))

    return entries
