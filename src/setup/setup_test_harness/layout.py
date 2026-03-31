"""File I/O helpers for unit_tests/ directory management."""

from __future__ import annotations

import shutil
from pathlib import Path

PARSER_PATH = "/workspace/run/unit_tests/parse_results.py"


def _templates_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "test_templates"


def copy_default_parser_template(unit_tests_dir: Path, overwrite: bool = False) -> None:
    """Copy the default parse_results.py template into unit_tests/."""
    src = _templates_dir() / "parse_results.py"
    if not src.exists():
        raise RuntimeError(f"Missing parser template: {src}")
    dst = unit_tests_dir / "parse_results.py"
    unit_tests_dir.mkdir(parents=True, exist_ok=True)
    if overwrite or not dst.exists():
        shutil.copy2(src, dst)
        dst.chmod(0o755)


def validate_unit_tests_dir(unit_tests_dir: Path) -> tuple[bool, str]:
    """Return (True, 'ok') if test.sh and parse_results.py exist and test.sh pipes to PARSER_PATH."""
    test_sh = unit_tests_dir / "test.sh"
    parser_py = unit_tests_dir / "parse_results.py"
    if not test_sh.exists():
        return False, f"missing {test_sh}"
    if not parser_py.exists():
        return False, f"missing {parser_py}"
    try:
        text = test_sh.read_text(encoding="utf-8")
    except OSError as exc:
        return False, f"could not read {test_sh}: {exc}"
    if PARSER_PATH not in text:
        return False, f"{test_sh} missing parser pipeline ({PARSER_PATH})"
    return True, "ok"


def write_test_harness(unit_tests_dir: Path, script_content: str) -> None:
    """Write unit_tests/test.sh with executable permissions."""
    script_host = unit_tests_dir / "test.sh"
    script_host.parent.mkdir(parents=True, exist_ok=True)
    script_host.write_text(script_content, encoding="utf-8")
    script_host.chmod(0o755)
