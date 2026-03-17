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


def load_cwes_by_group(
    group: str, csv_path: Path = CWE_DATA_DIR / "cwe_categories.csv"
) -> List[Tuple[str, str]]:
    """Load all CWE rows belonging to a given group.

    If csv_path is provided, read from that file instead of the default
    CWE_DATA_DIR / "cwe_categories.csv".
    """
    rows: List[Tuple[str, str]] = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["CWE Group"].strip() == group:
                rows.append((row["CWE#"].strip(), row["Description"].strip()))
    return rows


def format_cwes(rows: List[Tuple[str, str]]) -> str:
    return "\n".join(f"  CWE-{cwe}: {desc}" for cwe, desc in rows)


def valid_cwe_groups(json_path: Path = CWE_DATA_DIR / "cwe_groups.json") -> set:
    """Return the set of valid CWE group names.

    If json_path is provided, read groups from that file instead of the default
    CWE_DATA_DIR / "cwe_groups.json".
    """
    with open(json_path, encoding="utf-8") as f:
        return set(json.load(f))


def all_valid_cwe_ids(
    csv_path: Path = CWE_DATA_DIR / "cwe_categories.csv",
) -> set[str]:
    """Return the set of valid bare CWE ids (e.g. {'79','89'}).

    If csv_path is provided, read IDs from that file instead of the default
    CWE_DATA_DIR / "cwe_categories.csv".
    """
    ids: set[str] = set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ids.add(row["CWE#"].strip())
    return ids


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


def parse_cwe_from_response(stdout: str, cwe_list: List[Tuple[str, str]]) -> Optional[str]:
    """Extract a CWE number from the agent JSON response and validate against cwe_list.

    Returns the bare CWE identifier (e.g. "79") if valid, otherwise None.
    Accepts values like "79" or "CWE-79" in the JSON payload.
    """
    # Look for a "cwe": "<value>" field in the JSON
    m = re.search(r'"cwe"\s*:\s*"([^"]+)"', stdout)
    if not m:
        return None

    raw = m.group(1).strip()
    # Normalize forms like "CWE-79" or "cwe-79" down to "79"
    normalized = re.sub(r"(?i)^cwe-?", "", raw).strip()

    valid_ids = {cwe_id for cwe_id, _ in cwe_list}
    if normalized in valid_ids:
        return normalized
    return None
