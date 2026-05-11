"""Unit-test harness setup helpers."""

from __future__ import annotations

from .harness_heuristics import try_heuristic_harness
from .layout import (
    PARSER_PATH,
    copy_default_parser_template,
    validate_unit_tests_dir,
    write_test_harness,
)

__all__ = [
    "PARSER_PATH",
    "copy_default_parser_template",
    "run_baseline_unit_tests",
    "try_agent_harness",
    "try_heuristic_harness",
    "validate_unit_tests_dir",
    "write_test_harness",
]


def __getattr__(name: str):
    if name in {"run_baseline_unit_tests", "try_agent_harness"}:
        from .harness_agent import run_baseline_unit_tests, try_agent_harness

        return {
            "run_baseline_unit_tests": run_baseline_unit_tests,
            "try_agent_harness": try_agent_harness,
        }[name]
    raise AttributeError(name)
