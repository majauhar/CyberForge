"""LanguagePlugin Protocol — the single extension point for adding new languages.

To add a new language:
1. Create vuljector/plugins/{lang}_plugin.py implementing this protocol
2. Register it in vuljector/plugins/__init__.py
3. Zero changes to pipeline code required.
"""

from __future__ import annotations
from typing import Protocol, runtime_checkable
from selector.static_analysis.models import CheckpointPattern, OperationPattern, CallSite


@runtime_checkable
class LanguagePlugin(Protocol):
    """Protocol that every language plugin must satisfy."""

    language: str           # 'python' | 'c' | 'go' | 'java' | 'js'
    file_extensions: list[str]   # e.g. ['.py'] or ['.c', '.h']

    # ── Pattern catalogs ──────────────────────────────────────────────────────

    def get_checkpoint_patterns(self) -> list[CheckpointPattern]:
        """Return all checkpoint patterns for this language."""
        ...

    def get_operation_patterns(self) -> list[OperationPattern]:
        """Return all operation patterns for this language."""
        ...

    def get_ffi_patterns(self) -> list[str]:
        """Regex patterns that indicate an FFI boundary call in this language."""
        ...

    def get_sanitizer_names(self) -> list[str]:
        """Known sanitizer / escaping function names (used for noise reduction)."""
        ...

    # ── AST / source helpers ──────────────────────────────────────────────────

    def is_public_function(self, fn_name: str, context: dict) -> bool:
        """Determine whether a function should be considered a public API entry.

        context is a plugin-specific dict (e.g. for Python: module __all__,
        whether a docstring exists, whether name starts with _).
        """
        ...

    def extract_imports(self, source: str) -> dict[str, str]:
        """Parse import statements and return alias → qualified_name mapping.

        Example Python output: {'os': 'os', 'path': 'os.path', 'pd': 'pandas'}
        """
        ...

    def preferred_backend(self) -> str:
        """Preferred parsing backend: 'ast' | 'treesitter' | 'joern'"""
        ...
