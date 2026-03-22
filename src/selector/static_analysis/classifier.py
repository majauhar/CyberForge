"""Stage 0 — Repo Classifier.

Determines the languages present, security models active, and FFI boundaries
so downstream stages can configure themselves correctly.
"""

from __future__ import annotations
import re
from collections import Counter
from pathlib import Path
from dataclasses import dataclass, field

from selector.static_analysis.plugins import PLUGIN_REGISTRY, get_plugin


@dataclass
class RepoProfile:
    repo_root: Path
    languages: list[str]            # ordered by prevalence
    primary_language: str
    security_models: list[str]      # deserialization | eval | privilege_boundary | memory_management | ...
    has_ffi_boundary: bool
    plugins: list                   # list of LanguagePlugin instances
    file_counts: dict[str, int]     # extension → count


# Extension → language mapping
_EXT_TO_LANG: dict[str, str] = {
    ".py":   "python",
    ".pyx":  "python",  # Cython
    ".pxd":  "python",
    ".c":    "c",
    ".h":    "c",
    ".cc":   "cpp",
    ".cpp":  "cpp",
    ".cxx":  "cpp",
    ".hpp":  "cpp",
    ".go":   "go",
    ".java": "java",
    ".js":   "js",
    ".ts":   "js",
    ".jsx":  "js",
    ".tsx":  "js",
    ".rb":   "ruby",
    ".rs":   "rust",
    ".php":  "php",
}

# Security model detection — grep these regex patterns across the repo
_SECURITY_MODEL_SIGNALS: dict[str, list[str]] = {
    "deserialization": [
        r"pickle\.loads?", r"yaml\.load", r"marshal\.loads?",
        r"shelve\.open", r"dill\.loads?", r"jsonpickle\.decode",
        r"joblib\.load", r"cattrs\.structure",
    ],
    "eval": [
        r"\beval\s*\(", r"\bexec\s*\(", r"importlib\.import_module",
        r"jinja2\.Template\s*\(", r"\.from_string\s*\(",
    ],
    "privilege_boundary": [
        r"setuid|setgid|CAP_SYS|prctl",
        r"os\.setuid|os\.setgid",
        r"sudo|privilege|escalat",
    ],
    "web_input": [
        r"request\.(?:args|form|json|data|files)",
        r"flask|django|fastapi|bottle|tornado|aiohttp",
        r"@app\.route|@router\.",
    ],
    "cryptography": [
        r"hashlib\.|cryptography\.|nacl\.",
        r"hmac\.|ssl\.|tls\.",
        r"RSA|AES|DES|SHA|MD5",
    ],
    "database": [
        r"sqlite3|psycopg2|pymysql|pymongo",
        r"sqlalchemy|django\.db|peewee",
        r"\.execute\s*\(|cursor\.",
    ],
    "file_operations": [
        r"send_file|send_from_directory",
        r"os\.path\.join\(|pathlib\.Path",
        r"tarfile\.|zipfile\.",
    ],
}

# FFI boundary detection
_FFI_SIGNALS: list[str] = [
    r"PyArg_ParseTuple|Py_BuildValue",
    r"ctypes\.CDLL|ctypes\.cdll",
    r"\bcffi\b|\bcython\b|\bpybind11\b",
    r"ffi\.cdef\s*\(",
    r"cgo|CGO_ENABLED",
    r"JNI_OnLoad|native\s+\w",
]

# Files/dirs to skip
_SKIP_DIRS = {
    ".git", ".svn", "__pycache__", ".venv", "venv", "env",
    "node_modules", ".tox", "dist", "build", "site-packages",
    ".eggs", "*.egg-info",
}


def _should_skip(path: Path) -> bool:
    for part in path.parts:
        if part in _SKIP_DIRS or part.endswith(".egg-info"):
            return True
    return False


def _iter_source_files(repo_root: Path, extensions: set[str]) -> list[Path]:
    """Iterate all source files in repo, skipping noise directories."""
    files = []
    for path in repo_root.rglob("*"):
        if path.is_file() and path.suffix in extensions and not _should_skip(path):
            files.append(path)
    return files


def _grep_repo(pattern: str, files: list[Path]) -> bool:
    """Return True if any file in files contains a match for pattern."""
    regex = re.compile(pattern)
    for f in files:
        try:
            text = f.read_text(errors="ignore")
            if regex.search(text):
                return True
        except (OSError, PermissionError):
            continue
    return False


def detect_languages(repo_root: Path) -> tuple[list[str], dict[str, int]]:
    """Count source files per language, return sorted list and counts."""
    lang_counter: Counter = Counter()
    ext_counts: Counter = Counter()

    for path in repo_root.rglob("*"):
        if not path.is_file() or _should_skip(path):
            continue
        ext = path.suffix.lower()
        lang = _EXT_TO_LANG.get(ext)
        if lang:
            lang_counter[lang] += 1
            ext_counts[ext] += 1

    # Sort by count descending
    languages = [lang for lang, _ in lang_counter.most_common()]
    return languages, dict(ext_counts)


def detect_security_models(repo_root: Path, source_files: list[Path]) -> list[str]:
    """Detect which security models are present in the repo."""
    models = []
    # Always check memory management if C/C++ present
    for f in source_files:
        if f.suffix in (".c", ".cpp", ".cc", ".cxx", ".h", ".hpp"):
            if "memory_management" not in models:
                models.append("memory_management")
            break

    for model_name, patterns in _SECURITY_MODEL_SIGNALS.items():
        for pattern in patterns:
            if _grep_repo(pattern, source_files):
                if model_name not in models:
                    models.append(model_name)
                break

    return models


def detect_ffi(repo_root: Path, source_files: list[Path]) -> bool:
    """Detect FFI boundaries (Python→C, Cython, cffi, pybind11)."""
    # .pyx files = Cython = FFI
    if list(repo_root.rglob("*.pyx")):
        return True
    for pattern in _FFI_SIGNALS:
        if _grep_repo(pattern, source_files):
            return True
    return False


def classify_repo(repo_root: Path) -> RepoProfile:
    """Entry point: classify a repository and return its profile."""
    repo_root = repo_root.resolve()

    # Detect languages
    languages, file_counts = detect_languages(repo_root)

    if not languages:
        # Fallback: maybe it's a Python-only repo with no extension census hits
        languages = ["python"]

    primary_language = languages[0]

    # Collect all source files for grep-based detection
    all_extensions = set(_EXT_TO_LANG.keys())
    source_files = _iter_source_files(repo_root, all_extensions)

    # Security models
    security_models = detect_security_models(repo_root, source_files)

    # FFI
    has_ffi = detect_ffi(repo_root, source_files)

    # Select plugins for detected languages that we have plugins for
    plugins = []
    for lang in languages:
        plugin = get_plugin(lang)
        if plugin:
            plugins.append(plugin)

    if not plugins:
        # Fallback to Python plugin
        from selector.static_analysis.plugins.python_plugin import PythonPlugin
        plugins = [PythonPlugin()]

    return RepoProfile(
        repo_root=repo_root,
        languages=languages,
        primary_language=primary_language,
        security_models=security_models,
        has_ffi_boundary=has_ffi,
        plugins=plugins,
        file_counts=file_counts,
    )
