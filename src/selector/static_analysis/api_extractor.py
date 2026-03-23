"""Stage 1 — API Surface Extractor.

Identifies public API entry points in the codebase. Every parameter of every
public function is a potential taint entry point.

For Python:
- Functions listed in __all__
- Functions whose name does not start with _
- Functions with a docstring (documented = intended for external use)
- Functions called from test files
"""

from __future__ import annotations
import ast
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

    # Future: if 'c' in profile.languages: entries.extend(extract_c_api(...))
    # Future: if 'go' in profile.languages: entries.extend(extract_go_api(...))

    return entries
