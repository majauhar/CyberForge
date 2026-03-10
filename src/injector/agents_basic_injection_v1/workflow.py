"""LangGraph workflow for vulnerability injection and exploit validation."""

import logging
import uuid
from pathlib import Path
from typing import List, Literal, Optional, Tuple, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import RetryPolicy

from injector.exploit_runner import (
    run_exploit_once,
    revert_codebase_changes,
    restore_modifications_from_snapshot,
    save_modifications_snapshot,
)
from injector.cwe_data.cwe_helpers import (
    format_cwes as _format_cwes,
    load_cwe_groups_text as _load_cwe_groups_text,
    load_cwes_by_group as _load_cwes_by_group,
    parse_group_from_response as _parse_group_from_response,
    valid_cwe_groups as _valid_cwe_groups,
)
from .prompts import (
    STEP1_ANALYZE,
    STEP2_THREAT_MODEL,
    STEP3_SELECT_GROUP,
    STEP4_SELECT_CWE_AND_PLAN,
    STEP5_EXECUTE,
    STEP6_GENERATE_EXPLOIT,
    STEP6_FIX_EXPLOIT,
    STEP6_EXPLOIT_NOT_REAL,
)
from utils import (
    DEFAULT_MODEL,
    build_codebase_snapshot,
    continue_opencode_session,
    get_session_id_by_name,
    initiate_opencode_session,
)

logger = logging.getLogger(__name__)

# Max retries when exploit run fails (fix script → run again loop)
MAX_EXPLOIT_RETRIES = 5


# --- State ---

class VulnInjectState(TypedDict, total=False):
    session_title: str
    session_id: str
    directory: str
    model: str
    cwe_group: str
    cwe_list: List[Tuple[str, str]]
    exploit_attempts: int
    exploit_feedback: str
    exploit_succeeded: bool
    snapshot_path: str
    exploit_not_real: bool
    real_exploit_attempts: int
    error: str


# --- Nodes ---

_REFUSAL_MARKERS = ("I can't assist", "I can’t assist")


def _raise_if_refusal(stdout: Optional[str]) -> None:
    text = (stdout or "").strip()
    for marker in _REFUSAL_MARKERS:
        if marker in text:
            logger.warning("Model response contained refusal marker %r; triggering retry.", marker)
            raise ValueError("Model refused to assist; retrying node.")


# Step 1: Analyze the codebase
def analyze_codebase(state: VulnInjectState) -> VulnInjectState:
    logger.info("1️⃣ Analyzing codebase")
    
    directory = state["directory"]
    model = state.get("model") or DEFAULT_MODEL
    title = f"vul-inject-{uuid.uuid4().hex[:12]}"
    codebase = build_codebase_snapshot(directory)

    initiate_opencode_session(
        STEP1_ANALYZE.format(codebase=codebase),
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


# Step 2: Generate project-specific threat model (what it does, what it trusts, where exposed)
def threat_model(state: VulnInjectState) -> VulnInjectState:
    logger.info("2️⃣ Generating threat model")
    continue_opencode_session(
        STEP2_THREAT_MODEL,
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
    )
    return state


# Step 3: Select the CWE group (RetryPolicy retries on ValueError, max 3 attempts)
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

    logger.info("3️⃣ Selecting CWE group")
    stdout = continue_opencode_session(
        STEP3_SELECT_GROUP.format(cwe_groups=_load_cwe_groups_text()),
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


# Step 4: Select the CWE and plan the injection
def select_cwe_and_plan(state: VulnInjectState) -> VulnInjectState:
    logger.info("4️⃣ Selecting CWE and planning injection")
    continue_opencode_session(
        STEP4_SELECT_CWE_AND_PLAN.format(cwes=_format_cwes(state["cwe_list"])),
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
    )
    return state


# Step 5: Execute the injection
def execute_injection(state: VulnInjectState) -> VulnInjectState:
    logger.info("5️⃣ Executing injection")
    stdout = continue_opencode_session(
        STEP5_EXECUTE,
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    _raise_if_refusal(stdout)
    return state


# Step 6: Generate exploit script
def generate_exploit_script(state: VulnInjectState) -> VulnInjectState:
    logger.info("6️⃣🅰️ Generating exploit script")
    next_attempt = state.get("exploit_attempts", 0) + 1
    feedback = state.get("exploit_feedback") or "None."
    if state.get("exploit_not_real"):
        logger.info("Using not-real-exploit prompt (exploit passed on original codebase)")
        prompt = STEP6_EXPLOIT_NOT_REAL.format(attempt=next_attempt, feedback=feedback)
    else:
        prompt = STEP6_GENERATE_EXPLOIT.format(attempt=next_attempt, feedback=feedback)
    stdout = continue_opencode_session(
        prompt,
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    _raise_if_refusal(stdout)
    return {**state, "exploit_not_real": False}


# Step 6 bis: Fix exploit script (retry path — use feedback to fix and run locally)
def fix_exploit_script(state: VulnInjectState) -> VulnInjectState:
    attempts = state.get("exploit_attempts", 0)
    feedback = state.get("exploit_feedback") or "None."
    logger.info("6️⃣🅱️ bis Fixing exploit script (attempt %s)", attempts + 1)
    stdout = continue_opencode_session(
        STEP6_FIX_EXPLOIT.format(attempt=attempts + 1, feedback=feedback),
        session_id=state["session_id"],
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    _raise_if_refusal(stdout)
    return state


# Step 7: Programmatically run exploit_files/exploit.sh
def run_exploit_script(state: VulnInjectState) -> VulnInjectState:
    logger.info("7️⃣ Running exploit script")
    attempts = state.get("exploit_attempts", 0) + 1
    result = run_exploit_once(directory=state["directory"], attempts=attempts)
    return {
        **state,
        "exploit_attempts": attempts,
        "exploit_succeeded": result["exploit_succeeded"],
        "exploit_feedback": result["exploit_feedback"],
        "error": f"Exploit validation failed after {MAX_EXPLOIT_RETRIES} attempts."
        if (not result["exploit_succeeded"] and attempts >= MAX_EXPLOIT_RETRIES)
        else state.get("error", ""),
    }


def _route_after_exploit_run(state: VulnInjectState) -> Literal["fix", "verify", "done"]:
    if state.get("exploit_succeeded"):
        return "verify"
    if state.get("exploit_attempts", 0) >= MAX_EXPLOIT_RETRIES:
        return "done"
    return "fix"


# --- Step 8 helpers (called inside verify_exploit_real node) ---

def _save_snapshot_and_revert(state: VulnInjectState) -> str:
    """Save a snapshot of all modifications then revert the codebase to HEAD.

    exploit_files/ is untracked so git restore leaves it intact — exploit.sh
    remains available for the follow-up run on the original code.
    Returns the snapshot directory path.
    """
    logger.info("8️⃣🅰️ Saving modifications snapshot")
    snapshot_path = save_modifications_snapshot(state["directory"])
    logger.info("8️⃣🅱️ Reverting codebase to original")
    revert_codebase_changes(state["directory"])
    return snapshot_path


def _run_exploit_on_original(state: VulnInjectState) -> dict:
    """Run exploit.sh against the now-reverted (original) codebase.

    A real exploit must exit non-zero here (bug not present).
    Returns the raw ExploitRunResult dict.
    """
    real_exploit_attempts = state.get("real_exploit_attempts", 0) + 1
    logger.info("8️⃣🅲️ Running exploit on original codebase (real-exploit check #%s)", real_exploit_attempts)
    return run_exploit_once(directory=state["directory"], attempts=real_exploit_attempts)


# Step 8: Verify exploit is real (fails on original codebase)
def verify_exploit_real(state: VulnInjectState) -> VulnInjectState:
    logger.info("8️⃣ Verifying exploit is real on original codebase")
    snapshot_path = _save_snapshot_and_revert(state)
    result = _run_exploit_on_original(state)
    real_exploit_attempts = state.get("real_exploit_attempts", 0) + 1

    if not result["exploit_succeeded"]:
        # Exploit correctly fails on original code — real exploit confirmed.
        logger.info("Exploit correctly fails on original codebase. Real exploit verified.")
        return {
            **state,
            "snapshot_path": snapshot_path,
            "real_exploit_attempts": real_exploit_attempts,
        }

    # Exploit unexpectedly passes on original — it is not a real exploit.
    logger.warning(
        "Exploit ALSO succeeded on the original codebase (real-exploit attempt %s). "
        "Restoring modifications and looping back to exploit generation.",
        real_exploit_attempts,
    )
    restore_modifications_from_snapshot(state["directory"], snapshot_path)
    feedback = (
        "The exploit script also succeeded on the ORIGINAL, unmodified codebase.\n"
        f"Output from that run:\n{result['exploit_feedback']}"
    )
    return {
        **state,
        "snapshot_path": snapshot_path,
        "real_exploit_attempts": real_exploit_attempts,
        "exploit_not_real": True,
        "exploit_feedback": feedback,
    }


def _route_after_verify(state: VulnInjectState) -> Literal["retry", "done"]:
    if state.get("exploit_not_real"):
        return "retry"
    return "done"


# --- Graph ---

def build_graph():
    g = StateGraph(VulnInjectState)
    g.add_node("analyze_codebase", analyze_codebase)
    g.add_node("threat_model", threat_model)
    g.add_node(
        "select_cwe_group",
        select_cwe_group,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ValueError),
    )
    g.add_node("select_cwe_and_plan", select_cwe_and_plan)
    g.add_node(
        "execute_injection",
        execute_injection,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ValueError),
    )
    g.add_node(
        "generate_exploit_script",
        generate_exploit_script,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ValueError),
    )
    g.add_node(
        "fix_exploit_script",
        fix_exploit_script,
        retry_policy=RetryPolicy(max_attempts=3, retry_on=ValueError),
    )
    g.add_node("run_exploit_script", run_exploit_script)
    g.add_node("verify_exploit_real", verify_exploit_real)

    g.add_edge(START, "analyze_codebase")
    g.add_edge("analyze_codebase", "threat_model")
    g.add_edge("threat_model", "select_cwe_group")
    g.add_edge("select_cwe_group", "select_cwe_and_plan")
    g.add_edge("select_cwe_and_plan", "execute_injection")
    g.add_edge("execute_injection", "generate_exploit_script")
    g.add_edge("generate_exploit_script", "run_exploit_script")
    g.add_conditional_edges(
        "run_exploit_script",
        _route_after_exploit_run,
        {"fix": "fix_exploit_script", "verify": "verify_exploit_real", "done": END},
    )
    g.add_edge("fix_exploit_script", "run_exploit_script")
    g.add_conditional_edges(
        "verify_exploit_real",
        _route_after_verify,
        {"retry": "generate_exploit_script", "done": END},
    )
    return g.compile()

def run(
    directory: str,
    model: Optional[str] = None,
    cwe_group: Optional[str] = None,
) -> VulnInjectState:
    """Run the vulnerability injection workflow on the given codebase directory.
    If cwe_group is not provided, the agent selects one (with RetryPolicy:
    up to 3 attempts on parse failure). After injecting the vulnerability, the
    workflow generates an exploit script and executes it programmatically.
    Failed exploit runs loop back to regeneration with feedback (up to 5 runs).
    """
    app = build_graph()
    initial: VulnInjectState = {"directory": str(Path(directory).resolve())}
    if model:
        initial["model"] = model
    if cwe_group:
        initial["cwe_group"] = cwe_group
    return app.invoke(initial)


