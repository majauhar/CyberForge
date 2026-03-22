"""Data classes for VulInjector agent results.

Five-layer structure:

  AgentRun        — who, what, when, success/fail
  TestHarness     — discovered artifact: a bash script + baseline (test_discovery)
  VulnPatch       — injected vulnerability patch (vuln_patch)
  AttackScript    — proof-of-concept exploit (attack_script)
  AgentTelemetry  — how the agent performed: steps, tokens, cost, wall time
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any


# ─────────────────────────────────────────────────────────────────────────────
# TestHarness — the portable, replayable artifact
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TestHarness:
    """
    The main deliverable of the test_discovery task.

    `test_script` is a self-contained bash script that, when executed inside
    the project's OSS-Fuzz Docker container, installs any missing test deps
    and runs the project's test suite, exiting with the test suite's exit code.

    Usage in later stages:
        docker run gcr.io/oss-fuzz/<project> bash /tmp/test_harness.sh
    """

    project: str

    # ── Core executable ───────────────────────────────────────────────────────
    test_script: str          # Complete bash script (write to /tmp/test_harness.sh)
    test_cwd: str             # Working directory to cd to before running
    test_command: str         # The core test command, extracted for display/docs

    # ── Discovery metadata ────────────────────────────────────────────────────
    framework: str            # "pytest" | "unittest" | "tox" | "make" | "none"
    test_dirs: list[str] = field(default_factory=list)  # e.g. ["/src/flask/tests/"]
    passed: bool = False      # True = harness ran and exited 0
    notes: str = ""           # caveats: flakiness, network deps, etc.

    # ── Baseline capture (from the agent's actual run) ────────────────────────
    baseline_exit_code: int = -1       # 0 = all pass
    baseline_counts: str = "unknown"   # "47 passed, 0 failed"
    baseline_stdout: str = ""          # first ~3000 chars of test output
    baseline_duration_s: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_script(self, path: Path) -> None:
        """Write test_script to a standalone .sh file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.test_script)
        path.chmod(0o755)

    @classmethod
    def empty(cls, project: str) -> "TestHarness":
        return cls(
            project=project,
            test_script="#!/usr/bin/env bash\necho 'No test suite discovered'\nexit 1\n",
            test_cwd=f"/src/{project}",
            test_command="none",
            framework="none",
            passed=False,
        )


# ─────────────────────────────────────────────────────────────────────────────
# VulnPatch — the vulnerability injection artifact
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class VulnPatch:
    """
    The main deliverable of the vuln_patch task.

    `patch_diff` is a unified diff that, when applied inside the project's
    OSS-Fuzz Docker container, introduces a minimal realistic vulnerability
    by weakening or removing the security checkpoint.

    Usage in later stages:
        # Apply patch then run attack script
        patch -p0 < /tmp/vuln.patch && python /tmp/attack.py
    """

    project: str
    candidate_id: int           # index into the candidates array used as input

    # ── Location ──────────────────────────────────────────────────────────────
    file_path: str              # absolute container path of the patched file
    function: str
    cwe_candidates: list[str]   # e.g. ['CWE-476', 'CWE-787']
    injection_hint: str         # the strategy hint from VulInjector

    # ── The patch ─────────────────────────────────────────────────────────────
    patch_diff: str             # unified diff output (empty string if failed)
    patch_summary: str          # plain-English description of what changed

    # ── Validation ────────────────────────────────────────────────────────────
    tests_passed: bool = False      # harness exit 0 after patch (from post_commands)
    tests_output: str = ""          # first ~3000 chars of post-patch test run
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_patch(self, path: Path) -> None:
        """Write patch_diff to a standalone .patch file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.patch_diff)

    @classmethod
    def empty(cls, project: str, candidate_id: int = -1) -> "VulnPatch":
        return cls(
            project=project,
            candidate_id=candidate_id,
            file_path="",
            function="",
            cwe_candidates=[],
            injection_hint="",
            patch_diff="",
            patch_summary="",
            notes="No patch was produced.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# AttackScript — the proof-of-concept exploit artifact
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AttackScript:
    """
    The main deliverable of the attack_script task.

    `script_content` is a Python or bash PoC that, when run against a container
    where `patch_diff` has been applied, triggers the injected vulnerability.

    Usage:
        # In container with patch already applied:
        python /tmp/attack.py
    """

    project: str
    candidate_id: int

    # ── Location ──────────────────────────────────────────────────────────────
    file_path: str              # container path of the vulnerable file
    function: str
    cwe_candidates: list[str]

    # ── The script ────────────────────────────────────────────────────────────
    script_content: str         # full script text (write to /tmp/attack.py)
    script_type: str = "python" # "python" | "bash"
    attack_type: str = ""       # e.g. "type_confusion" | "auth_bypass" | "cmd_injection"
    trigger_command: str = ""   # exact command to run the exploit
    expected_behavior: str = "" # what the attacker observes on success

    # ── Validation ────────────────────────────────────────────────────────────
    attack_triggered: bool = False  # exploit ran and produced output (post_commands)
    attack_output: str = ""         # first ~3000 chars of exploit output
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_script(self, path: Path) -> None:
        """Write script_content to a standalone file."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.script_content)
        path.chmod(0o755)

    @classmethod
    def empty(cls, project: str, candidate_id: int = -1) -> "AttackScript":
        return cls(
            project=project,
            candidate_id=candidate_id,
            file_path="",
            function="",
            cwe_candidates=[],
            script_content="#!/usr/bin/env python3\n# No exploit produced\n",
            notes="No exploit produced.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# ExplorationResult — autonomous repo exploration artifact
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ExplorationResult:
    """
    The main deliverable of the repo_explore task.

    The agent autonomously explores the source tree and writes
    `/tmp/candidates.json` — a pipeline-compatible JSON with vulnerability
    injection candidates identified through LLM reasoning rather than regex
    pattern matching.

    The `candidates` list is in the same format as `PipelineOutput.candidates`
    so it can be consumed directly by downstream tasks (vuln_patch, vuln_inject).
    """

    project: str

    # ── Raw container output ──────────────────────────────────────────────────
    candidates_json: str        # Raw text of /tmp/candidates.json from container

    # ── Parsed fields ─────────────────────────────────────────────────────────
    candidates: list[dict]      # Parsed candidate dicts (pipeline-compatible)
    n_candidates: int           # len(candidates) for quick access
    project_path: str           # e.g. "/src/flask"
    exploration_notes: str      # Agent's free-form summary of what it found

    # ── Validation ────────────────────────────────────────────────────────────
    valid_json: bool = False    # True if candidates_json parsed without error
    notes: str = ""             # Caveats or error messages

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def save_candidates(self, path: Path) -> None:
        """
        Write candidates in pipeline-compatible PipelineOutput format so that
        load_candidates() in run_agent.py can consume them for vuln_patch etc.
        """
        path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "repo":                  self.project_path or f"/src/{self.project}",
            "stats": {
                "total":          self.n_candidates,
                "by_difficulty":  {},
                "by_cwe":         {},
                "by_cwe_group":   {},
                "by_strategy":    {},
            },
            "candidates":            self.candidates,
            "call_graph_node_count": 0,
            "exploration_notes":     self.exploration_notes,
        }
        with path.open("w") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def empty(cls, project: str) -> "ExplorationResult":
        return cls(
            project=project,
            candidates_json="",
            candidates=[],
            n_candidates=0,
            project_path=f"/src/{project}",
            exploration_notes="",
            valid_json=False,
            notes="No exploration performed.",
        )


# ─────────────────────────────────────────────────────────────────────────────
# AgentTelemetry — performance + cost metrics
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentTelemetry:
    """Captures how the agent performed: steps taken, tokens used, cost, time."""

    model: str
    exit_status: str           # "submitted" | "LimitsExceeded" | exception name
    wall_time_s: float = 0.0
    total_steps: int = 0

    # Token usage (−1 = not available)
    total_input_tokens: int = -1
    total_output_tokens: int = -1
    estimated_cost_usd: float = -1.0

    # Where the full step-by-step trajectory was saved
    trajectory_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_agent(
        cls,
        model: str,
        exit_status: str,
        wall_time_s: float,
        messages: list[dict],
        trajectory_path: str = "",
    ) -> "AgentTelemetry":
        """
        Build telemetry from the agent's messages list (available after run()).
        Tries to extract token usage from message extra fields and the saved
        trajectory JSON; falls back to -1 if unavailable.
        """
        t = cls(
            model=model,
            exit_status=exit_status,
            wall_time_s=wall_time_s,
            total_steps=sum(1 for m in messages if m.get("role") == "assistant"),
            trajectory_path=trajectory_path,
        )
        t._parse_tokens_from_messages(messages)
        if trajectory_path and Path(trajectory_path).exists():
            t._parse_tokens_from_trajectory(Path(trajectory_path))
        return t

    def _parse_tokens_from_messages(self, messages: list[dict]) -> None:
        """Try to pull token counts from message `extra` / `usage` fields.

        mini-swe-agent v2 stores usage at msg["extra"]["response"]["usage"]
        and per-step cost at msg["extra"]["cost"].  Fall back to the flat
        msg["extra"]["usage"] and msg["usage"] paths for other adapters.
        """
        total_in = total_out = 0
        total_cost = 0.0
        found = False
        for msg in messages:
            extra = msg.get("extra") or {}
            # Primary path: extra.response.usage  (mini-swe-agent v2 / litellm)
            usage = (
                extra.get("response", {}).get("usage")
                or extra.get("usage")
                or msg.get("usage")
            )
            if isinstance(usage, dict):
                total_in  += usage.get("prompt_tokens", 0) or usage.get("input_tokens", 0)
                total_out += usage.get("completion_tokens", 0) or usage.get("output_tokens", 0)
                found = True
            # Per-step cost stored directly on extra.cost
            step_cost = extra.get("cost")
            if isinstance(step_cost, (int, float)):
                total_cost += step_cost

        if found and (total_in + total_out) > 0:
            self.total_input_tokens  = total_in
            self.total_output_tokens = total_out
        if total_cost > 0:
            self.estimated_cost_usd = round(total_cost, 6)

    def _parse_tokens_from_trajectory(self, path: Path) -> None:
        """
        Parse token usage from the mini-swe-agent trajectory JSON.
        Only overwrites if we couldn't get tokens from messages.
        """
        if self.total_input_tokens != -1:
            return  # already have data
        try:
            data = json.loads(path.read_text())
            if isinstance(data, list):
                messages = data
            elif isinstance(data, dict):
                messages = data.get("messages", [])
            else:
                return
            self._parse_tokens_from_messages(messages)
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# AgentRun — top-level run record
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class AgentRun:
    """Top-level record for one agent task run on one project."""

    project: str
    slug: str
    task: str                   # "test_discovery" | "vuln_patch" | "attack_script"

    started_at: str = ""
    finished_at: str = ""
    success: bool = False
    error: str = ""

    # Nested results — only one will be set per task type
    harness: TestHarness | None = None              # set by test_discovery
    vuln_patch: VulnPatch | None = None             # set by vuln_patch
    attack_script: AttackScript | None = None       # set by attack_script
    exploration: ExplorationResult | None = None    # set by repo_explore
    telemetry: AgentTelemetry | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "project":       self.project,
            "slug":          self.slug,
            "task":          self.task,
            "started_at":    self.started_at,
            "finished_at":   self.finished_at,
            "success":       self.success,
            "error":         self.error,
            "harness":       self.harness.to_dict() if self.harness else None,
            "vuln_patch":    self.vuln_patch.to_dict() if self.vuln_patch else None,
            "attack_script": self.attack_script.to_dict() if self.attack_script else None,
            "exploration":   self.exploration.to_dict() if self.exploration else None,
            "telemetry":     self.telemetry.to_dict() if self.telemetry else None,
        }

    @classmethod
    def start(cls, project: str, slug: str, task: str) -> "AgentRun":
        r = cls(project=project, slug=slug, task=task)
        r.started_at = datetime.utcnow().isoformat()
        return r

    def finish(self, success: bool, error: str = "") -> None:
        self.finished_at = datetime.utcnow().isoformat()
        self.success = success
        self.error = error

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w") as f:
            json.dump(self.to_dict(), f, indent=2)
