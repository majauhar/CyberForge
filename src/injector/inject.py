#!/usr/bin/env python3
"""Orchestrate opencode to inject a single realistic vulnerability into a target codebase."""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Tuple

from prompts import (
    STEP1_ANALYZE,
    STEP4_EXECUTE,
    step2_prompt,
    step3_prompt,
)

INJECTOR_DIR = Path(__file__).resolve().parent
DEFAULT_MODEL = "zen/big-pickle"  # OpenCode Zen; override with --model if needed


def run_opencode(
    prompt: str,
    cwd: Path,
    model: str,
    session_id: Optional[str] = None,
    verbose: bool = False,
) -> Tuple[str, int]:
    """Run opencode, streaming output live. Returns (stdout, returncode).

    stderr goes directly to the terminal.
    With verbose=True, adds --print-logs --log-level DEBUG to opencode.
    """
    cmd = ["opencode"]
    if verbose:
        cmd += ["--print-logs", "--log-level", "DEBUG"]
    cmd += ["run", "-m", model]
    if session_id:
        cmd.extend(["-s", session_id])
    else:
        cmd.append("-c")  # continue last session (steps 2–4)
    cmd.append(prompt)

    proc = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1)
    stdout_parts: List[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="", flush=True)
        stdout_parts.append(line)
    proc.wait()
    return "".join(stdout_parts), proc.returncode


def get_latest_session_id() -> Optional[str]:
    """Return the most recent session ID from opencode session list, or None."""
    result = subprocess.run(
        ["opencode", "session", "list", "--format", "json"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        data = json.loads(result.stdout)
        # Assume list of sessions; take first (most recent)
        if isinstance(data, list) and len(data) > 0:
            first = data[0]
            if isinstance(first, dict) and "id" in first:
                return first["id"]
            if isinstance(first, dict) and "sessionId" in first:
                return first["sessionId"]
        if isinstance(data, dict) and "sessions" in data and data["sessions"]:
            s = data["sessions"][0]
            return s.get("id") or s.get("sessionId")
    except (json.JSONDecodeError, KeyError, IndexError):
        pass
    return None


def parse_selected_group(stdout: str, valid_groups: set) -> Optional[str]:
    """Extract the selected CWE group from step 2 output."""
    for line in stdout.splitlines():
        line = line.strip().strip('"\'')
        if line in valid_groups:
            return line
    # Try to find a quoted group name
    for g in valid_groups:
        if g in stdout:
            return g
    return None


def load_cwe_groups_text() -> str:
    """Load cwe_groups.json and format as 'name → description' lines."""
    path = INJECTOR_DIR / "cwe_groups.json"
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return "\n".join(f'  "{k}": {v}' for k, v in data.items())


def load_cwes_by_group(group: str) -> List[Tuple[str, str]]:
    """Load (CWE#, Description) for the given group from cwe_categories.csv."""
    path = INJECTOR_DIR / "cwe_categories.csv"
    rows = []
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            if row["CWE Group"].strip() == group:
                rows.append((row["CWE#"].strip(), row["Description"].strip()))
    return rows


def format_cwes_for_prompt(rows: List[Tuple[str, str]]) -> str:
    """Format CWE rows as lines for the step 3 prompt."""
    return "\n".join(f"  CWE-{cwe}: {desc}" for cwe, desc in rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject a vulnerability into a codebase via opencode.")
    parser.add_argument("target", type=Path, help="Path to the target codebase")
    parser.add_argument("--cwe-group", type=str, help="Skip group selection; use this CWE group")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help=f"opencode model (default: {DEFAULT_MODEL})")
    parser.add_argument("--verbose", action="store_true", help="Pass --print-logs --log-level DEBUG to opencode")
    args = parser.parse_args()

    target = args.target.resolve()
    if not target.is_dir():
        print(f"Error: target is not a directory: {target}", file=sys.stderr)
        sys.exit(1)

    model = args.model
    verbose = args.verbose

    def oc(prompt: str, session_id: Optional[str] = None) -> Tuple[str, int]:
        return run_opencode(prompt, target, model, session_id, verbose)

    # Step 1 — Analyze (new session; opencode creates it automatically)
    print("--- Step 1: Analyze codebase ---", flush=True)
    cmd = ["opencode"]
    if verbose:
        cmd += ["--print-logs", "--log-level", "DEBUG"]
    cmd += ["run", "-m", model, STEP1_ANALYZE]
    proc = subprocess.Popen(cmd, cwd=target, stdout=subprocess.PIPE, stderr=None, text=True, bufsize=1)
    stdout1_parts: List[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="", flush=True)
        stdout1_parts.append(line)
    proc.wait()
    if proc.returncode != 0:
        print("Step 1 failed.", file=sys.stderr)
        sys.exit(1)

    session_id = get_latest_session_id()

    # Step 2 — Select group (or use --cwe-group)
    if args.cwe_group:
        selected_group = args.cwe_group.strip()
        cwe_groups_data = json.loads((INJECTOR_DIR / "cwe_groups.json").read_text(encoding="utf-8"))
        if selected_group not in cwe_groups_data:
            print(f"Error: unknown CWE group {selected_group!r}", file=sys.stderr)
            sys.exit(1)
        print(f"--- Using CWE group: {selected_group} ---", flush=True)
    else:
        print("--- Step 2: Select CWE group ---", flush=True)
        cwe_groups_text = load_cwe_groups_text()
        stdout2, rc2 = oc(step2_prompt(cwe_groups_text), session_id)
        if rc2 != 0:
            print("Step 2 failed.", file=sys.stderr)
            sys.exit(1)
        valid_groups = set(json.loads((INJECTOR_DIR / "cwe_groups.json").read_text(encoding="utf-8")))
        selected_group = parse_selected_group(stdout2, valid_groups)
        if not selected_group:
            print(
                "Could not parse selected CWE group from agent output. "
                'You can bypass automatic selection by rerunning with --cwe-group "<group name>".',
                file=sys.stderr,
            )
            sys.exit(1)
        print(f"Selected group: {selected_group}", flush=True)

    # Step 3 — Select CWE and plan
    cwe_rows = load_cwes_by_group(selected_group)
    if not cwe_rows:
        print(f"No CWEs found for group {selected_group!r}", file=sys.stderr)
        sys.exit(1)
    print("--- Step 3: Select CWE and plan injection ---", flush=True)
    _, rc3 = oc(step3_prompt(format_cwes_for_prompt(cwe_rows)), session_id)
    if rc3 != 0:
        print("Step 3 failed.", file=sys.stderr)
        sys.exit(1)

    # Step 4 — Execute
    print("--- Step 4: Execute injection ---", flush=True)
    _, rc4 = oc(STEP4_EXECUTE, session_id)
    if rc4 != 0:
        print("Step 4 failed.", file=sys.stderr)
        sys.exit(1)

    print("--- Done ---")


if __name__ == "__main__":
    main()
