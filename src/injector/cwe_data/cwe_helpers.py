"""CWE data helpers: load groups, categories, and parse agent responses."""

import csv
import json
import re
from pathlib import Path
from typing import List, Optional, Tuple

CWE_DATA_DIR = Path(__file__).resolve().parent


def load_cwe_groups_text() -> str:
    with open(CWE_DATA_DIR / "cwe_groups.json", encoding="utf-8") as f:
        data = json.load(f)
    return "\n".join(f'  "{k}": {v}' for k, v in data.items())


def load_cwes_by_group(group: str) -> List[Tuple[str, str]]:
    rows = []
    with open(CWE_DATA_DIR / "cwe_categories.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["CWE Group"].strip() == group:
                rows.append((row["CWE#"].strip(), row["Description"].strip()))
    return rows


def format_cwes(rows: List[Tuple[str, str]]) -> str:
    return "\n".join(f"  CWE-{cwe}: {desc}" for cwe, desc in rows)


def valid_cwe_groups() -> set:
    with open(CWE_DATA_DIR / "cwe_groups.json", encoding="utf-8") as f:
        return set(json.load(f))


def parse_group_from_response(stdout: str, valid: set) -> Optional[str]:
    """Extract CWE group from agent JSON response. Returns None if missing or invalid."""
    m = re.search(r'"group"\s*:\s*"([^"]+)"', stdout)
    if m:
        g = m.group(1).strip()
        if g in valid:
            return g
    for g in valid:
        if g in stdout:
            return g
    return None
