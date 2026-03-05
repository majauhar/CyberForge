"""LangGraph workflow for vulnerability injection: init session → select CWE group → select CWE & plan → execute."""

import csv
import json
import re
import uuid
from pathlib import Path
from typing import List, Optional, Tuple, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import RetryPolicy

from .prompts import (
    STEP1_ANALYZE,
    STEP2_SELECT_GROUP,
    STEP3_SELECT_CWE_AND_PLAN,
    STEP4_EXECUTE,
)
from utils import (
    DEFAULT_MODEL,
    continue_opencode_session,
    get_session_id_by_name,
    initiate_opencode_session,
)

INJECTOR_DIR = Path(__file__).resolve().parent


# --- State ---

class VulnInjectState(TypedDict, total=False):
    session_title: str
    session_id: str
    directory: str
    model: str
    cwe_group: str
    cwe_list: List[Tuple[str, str]]
    error: str


# --- CWE helpers (minimal, no import from inject to keep deps simple) ---

def _load_cwe_groups_text() -> str:
    with open(INJECTOR_DIR / "cwe_groups.json", encoding="utf-8") as f:
        data = json.load(f)
    return "\n".join(f'  "{k}": {v}' for k, v in data.items())


def _load_cwes_by_group(group: str) -> List[Tuple[str, str]]:
    rows = []
    with open(INJECTOR_DIR / "cwe_categories.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["CWE Group"].strip() == group:
                rows.append((row["CWE#"].strip(), row["Description"].strip()))
    return rows


def _format_cwes(rows: List[Tuple[str, str]]) -> str:
    return "\n".join(f"  CWE-{cwe}: {desc}" for cwe, desc in rows)


def _valid_cwe_groups() -> set:
    with open(INJECTOR_DIR / "cwe_groups.json", encoding="utf-8") as f:
        return set(json.load(f))


def _parse_group_from_response(stdout: str, valid: set) -> Optional[str]:
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


# --- Nodes ---

# Step 1: Analyze the codebase
def analyze_codebase(state: VulnInjectState) -> VulnInjectState:
    directory = state["directory"]
    model = state.get("model") or DEFAULT_MODEL
    title = f"vul-inject-{uuid.uuid4().hex[:12]}"

    initiate_opencode_session(
        STEP1_ANALYZE,
        title=title,
        model=model,
        directory=directory,
    )
    session_id = get_session_id_by_name(title, directory=directory)
    if not session_id:
        raise RuntimeError(f"No session found for title {title!r}")
    return {
        **state,
        "session_title": title,
        "session_id": session_id,
        "model": model,
    }


# Step 2: Select the CWE group (RetryPolicy retries on ValueError, max 3 attempts)
def select_cwe_group(state: VulnInjectState) -> VulnInjectState:
    # If user provided cwe_group, use it and skip agent
    group = state.get("cwe_group")
    if group:
        valid = _valid_cwe_groups()
        if group not in valid:
            return {**state, "error": f"Invalid cwe_group {group!r}. Must be one of: {sorted(valid)}"}
        cwe_list = _load_cwes_by_group(group)
        if not cwe_list:
            return {**state, "error": f"No CWEs found for group {group!r}"}
        return {**state, "cwe_list": cwe_list}

    stdout = continue_opencode_session(
        STEP2_SELECT_GROUP.format(cwe_groups=_load_cwe_groups_text()),
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    valid = _valid_cwe_groups()
    group = _parse_group_from_response(stdout or "", valid) if stdout else None
    if not group:
        raise ValueError("Could not parse valid CWE group from agent response.")
    cwe_list = _load_cwes_by_group(group)
    return {**state, "cwe_group": group, "cwe_list": cwe_list}


# Step 3: Select the CWE and plan the injection
def select_cwe_and_plan(state: VulnInjectState) -> VulnInjectState:
    if state.get("error"):
        return state
    continue_opencode_session(
        STEP3_SELECT_CWE_AND_PLAN.format(cwes=_format_cwes(state["cwe_list"])),
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
    )
    return state


# Step 4: Execute the injection
def execute_injection(state: VulnInjectState) -> VulnInjectState:
    if state.get("error"):
        return state
    continue_opencode_session(
        STEP4_EXECUTE,
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
    )
    return state


# --- Graph ---

def build_graph():
    g = StateGraph(VulnInjectState)
    g.add_node("analyze_codebase", analyze_codebase)
    g.add_node(
        "select_cwe_group",
        select_cwe_group,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ValueError),
    )
    g.add_node("select_cwe_and_plan", select_cwe_and_plan)
    g.add_node("execute_injection", execute_injection)
    
    g.add_edge(START, "analyze_codebase")
    g.add_edge("analyze_codebase", "select_cwe_group")
    g.add_edge("select_cwe_group", "select_cwe_and_plan")
    g.add_edge("select_cwe_and_plan", "execute_injection")
    g.add_edge("execute_injection", END)
    return g.compile()

def run(
    directory: str,
    model: Optional[str] = None,
    cwe_group: Optional[str] = None,
) -> VulnInjectState:
    """Run the vulnerability injection workflow on the given codebase directory.
    If cwe_group is not provided, the agent selects one (with RetryPolicy: up to 3 attempts on parse failure).
    """
    app = build_graph()
    initial: VulnInjectState = {"directory": str(Path(directory).resolve())}
    if model:
        initial["model"] = model
    if cwe_group:
        initial["cwe_group"] = cwe_group
    return app.invoke(initial)


