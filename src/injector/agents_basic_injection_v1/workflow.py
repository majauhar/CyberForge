"""LangGraph workflow for vulnerability injection and exploit validation."""

import logging
from pathlib import Path
from typing import List, Literal, Optional, Set, Tuple, TypedDict

from langgraph.graph import StateGraph, START, END
from langgraph.types import RetryPolicy

from injector.exploit_runner import (
    run_exploit_once,
    revert_codebase_changes,
    restore_modifications_from_snapshot,
    save_modifications_snapshot,
)
from injector.cwe_data.cwe_helpers import (
    format_cwes,
    load_cwe_groups_text,
    load_cwes_by_group,
    parse_cwe_from_response,
    parse_group_from_response,
    valid_cwe_groups,
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
from utils import AgentRunner, OpencodeRunner, build_codebase_snapshot, is_valid_id, raise_if_LLM_refusal

logger = logging.getLogger(__name__)

# Default model when none is provided (e.g. via CLI --model)
DEFAULT_MODEL = "rchat/gpt-oss-120b"

# Default maximums (can be overridden per run via function arguments)
CRASH_MAX_RETRY = 3
MAX_EXPLOIT_RETRIES = 3


# --- State ---

class VulnInjectState(TypedDict, total=False):
    runner: AgentRunner
    session_id: str
    directory: str
    model: str
    cwe_categories_path: str
    selected_cwe_group_to_inject: str
    cwe_id: str
    exploit_attempts: int
    exploit_feedback: str
    exploit_succeeded: bool
    snapshot_path: str
    exploit_not_real: bool
    real_exploit_attempts: int
    error: str


# --- Nodes ---


# Step 1: Analyze the codebase
def analyze_codebase(state: VulnInjectState) -> VulnInjectState:
    logger.info("1️⃣ Analyzing codebase")
    directory = state["directory"]
    model = state.get("model") or DEFAULT_MODEL
    runner = state["runner"]
    codebase = build_codebase_snapshot(directory)
    start = runner.create_session(
        first_message=STEP1_ANALYZE.format(codebase=codebase),
        model=model,
        directory=directory,
    )
    return {
        **state,
        "session_id": start.session_id,
        "model": model,
    }


# Step 2: Generate project-specific threat model (what it does, what it trusts, where exposed)
def threat_model(state: VulnInjectState) -> VulnInjectState:
    logger.info("2️⃣ Generating threat model")
    state["runner"].continue_session(
        session_id=state["session_id"],
        message=STEP2_THREAT_MODEL,
        model=state["model"],
        directory=state["directory"],
    )
    return state


# Step 3: Select the CWE group to inject (RetryPolicy retries on ValueError, max 3 attempts)
def select_cwe_group(state: VulnInjectState) -> VulnInjectState:
    logger.info("3️⃣ Selecting CWE group to inject")
    stdout = state["runner"].continue_session(
        session_id=state["session_id"],
        message=STEP3_SELECT_GROUP.format(cwe_groups=load_cwe_groups_text()),
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    # Derive the set of valid groups from the configured groups file (or default)
    groups_source = Path(state["cwe_groups_path"]) if "cwe_groups_path" in state else None
    valid_groups = valid_cwe_groups(groups_source)
    selected_cwe_group_to_inject = parse_group_from_response(stdout or "", valid_groups) if stdout else None
    if not is_valid_id(valid_groups, selected_cwe_group_to_inject):
        raise ValueError("Could not parse valid CWE group to inject from agent response.")
    return {**state, "selected_cwe_group_to_inject": selected_cwe_group_to_inject}


# Step 4: Select the CWE and plan the injection
def select_cwe_and_plan(state: VulnInjectState) -> VulnInjectState:
    logger.info("4️⃣ Selecting CWE and planning injection")
    # Load the CWE list for the selected group on demand (do not persist on state)
    csv_path = Path(state["cwe_categories_path"]) if "cwe_categories_path" in state else None
    cwe_list = load_cwes_by_group(state["selected_cwe_group_to_inject"], csv_path=csv_path)
    stdout = state["runner"].continue_session(
        session_id=state["session_id"],
        message=STEP4_SELECT_CWE_AND_PLAN.format(cwes=format_cwes(cwe_list)),
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    raise_if_LLM_refusal(stdout)
    # Build the valid ID set once and reuse it for parsing and validation
    valid_cwe_ids = {cwe for cwe, _ in cwe_list}
    cwe_id = parse_cwe_from_response(stdout or "", cwe_list)
    if not is_valid_id(valid_cwe_ids, cwe_id):
        raise ValueError("Could not parse valid CWE from agent response.")
    return {**state, "cwe_id": cwe_id}


# Step 5: Execute the injection
def execute_injection(state: VulnInjectState) -> VulnInjectState:
    logger.info("5️⃣ Executing injection")
    stdout = state["runner"].continue_session(
        session_id=state["session_id"],
        message=STEP5_EXECUTE,
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    raise_if_LLM_refusal(stdout)
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
    stdout = state["runner"].continue_session(
        session_id=state["session_id"],
        message=prompt,
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    raise_if_LLM_refusal(stdout)
    return {**state, "exploit_not_real": False}


# Step 6 bis: Fix exploit script (retry path — use feedback to fix and run locally)
def fix_exploit_script(state: VulnInjectState) -> VulnInjectState:
    attempts = state.get("exploit_attempts", 0)
    feedback = state.get("exploit_feedback") or "None."
    logger.info("6️⃣🅱️ bis Fixing exploit script (attempt %s)", attempts + 1)
    stdout = state["runner"].continue_session(
        session_id=state["session_id"],
        message=STEP6_FIX_EXPLOIT.format(attempt=attempts + 1, feedback=feedback),
        model=state["model"],
        directory=state["directory"],
        capture_output=True,
    )
    raise_if_LLM_refusal(stdout)
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


# Step 9: Restore snapshot so the codebase ends in the injected (modified) state
def restore_snapshot(state: VulnInjectState) -> VulnInjectState:
    snapshot_path = state["snapshot_path"]
    logger.info("9️⃣ Restoring codebase from snapshot at %s", snapshot_path)
    restore_modifications_from_snapshot(state["directory"], snapshot_path)
    return state


# --- Graph ---

def build_graph():
    g = StateGraph(VulnInjectState)
    g.add_node("analyze_codebase", analyze_codebase)
    g.add_node("threat_model", threat_model)
    g.add_node(
        "select_cwe_group",
        select_cwe_group,
        retry_policy=RetryPolicy(max_attempts=CRASH_MAX_RETRY, retry_on=ValueError),
    )
    g.add_node(
        "select_cwe_and_plan",
        select_cwe_and_plan,
        retry_policy=RetryPolicy(max_attempts=CRASH_MAX_RETRY, retry_on=ValueError),
    )
    g.add_node(
        "execute_injection",
        execute_injection,
        retry_policy=RetryPolicy(max_attempts=CRASH_MAX_RETRY, retry_on=ValueError),
    )
    g.add_node(
        "generate_exploit_script",
        generate_exploit_script,
        retry_policy=RetryPolicy(max_attempts=CRASH_MAX_RETRY, retry_on=ValueError),
    )
    g.add_node(
        "fix_exploit_script",
        fix_exploit_script,
        retry_policy=RetryPolicy(max_attempts=CRASH_MAX_RETRY, retry_on=ValueError),
    )
    g.add_node("run_exploit_script", run_exploit_script)
    g.add_node("verify_exploit_real", verify_exploit_real)
    g.add_node("restore_snapshot", restore_snapshot)

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
        {"retry": "generate_exploit_script", "done": "restore_snapshot"},
    )
    g.add_edge("restore_snapshot", END)
    return g.compile()

def run(
    directory: str,
    model: Optional[str] = None,
    runner: Optional[AgentRunner] = None,
    cwe_groups_path: Optional[str] = None,
    cwe_categories_path: Optional[str] = None,
    crash_max_retry: int = CRASH_MAX_RETRY,
    task_failure_max_loop_back: int = MAX_EXPLOIT_RETRIES,
) -> VulnInjectState:
    """Run the vulnerability injection workflow on the given codebase directory.

    The agent:
    - Analyzes the codebase and produces a threat model.
    - Selects a CWE group (using cwe_groups_path if provided, otherwise the default groups file).
    - Selects a specific CWE within that group and injects a bug.
    - Generates and validates an exploit script.

    crash_max_retry controls how many times individual reasoning steps (e.g. selecting
    a CWE group or ID, executing the injection) may be retried on parse/refusal errors.
    task_failure_max_loop_back controls how many times we loop back after exploit
    execution failures before giving up.
    """
    # Override module-level defaults for this run without putting them in state.
    global CRASH_MAX_RETRY, MAX_EXPLOIT_RETRIES
    CRASH_MAX_RETRY = crash_max_retry
    MAX_EXPLOIT_RETRIES = task_failure_max_loop_back

    app = build_graph()
    initial: VulnInjectState = {
        "directory": str(Path(directory).resolve()),
        "runner": runner if runner is not None else OpencodeRunner(),
    }
    if model:
        initial["model"] = model
    if cwe_groups_path:
        initial["cwe_groups_path"] = cwe_groups_path
    if cwe_categories_path:
        initial["cwe_categories_path"] = cwe_categories_path
    return app.invoke(initial)


