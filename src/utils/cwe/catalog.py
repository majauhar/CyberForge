"""Approved CWE catalog helpers."""

from __future__ import annotations

import csv
from functools import lru_cache

from utils.paths import cwe_categories_csv


def _normalize_cwe_id(cwe_id: str) -> str:
    value = cwe_id.strip()
    if not value:
        return ""
    upper = value.upper()
    if upper.startswith("CWE-"):
        suffix = upper[4:]
    else:
        suffix = upper
    return f"CWE-{suffix}"


@lru_cache(maxsize=1)
def load_cwe_map() -> dict[str, tuple[str, str]]:
    """Return {CWE-N: (description, group)} from the approved CSV."""
    result: dict[str, tuple[str, str]] = {}
    with cwe_categories_csv().open(newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            cwe_id = _normalize_cwe_id(row["CWE#"])
            if not cwe_id:
                continue
            result[cwe_id] = (
                row["Description"].strip(),
                row["CWE Group"].strip(),
            )
    return result


def get_cwe_entry(cwe_id: str) -> tuple[str, str] | None:
    """Return (description, group) for a CWE id, or None if unknown."""
    return load_cwe_map().get(_normalize_cwe_id(cwe_id))


def resolve_cwe_group(cwe_id: str, *, fallback: str = "") -> str:
    """Return the approved CWE group for ``cwe_id`` or ``fallback``."""
    entry = get_cwe_entry(cwe_id)
    if entry:
        return entry[1]
    return fallback
