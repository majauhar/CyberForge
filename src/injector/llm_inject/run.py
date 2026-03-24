"""
LLMInjectStrategy — vulnerability injection + exploit generation via mini-swe-agent.

Two sequential agent calls in the same container session (mirrors run_agent.py::run_vuln_inject):
  1. VULN_INJECT_TASK  — agent injects the vulnerability AND writes /tmp/attack.py in one shot.
     Extracts: /tmp/vuln.patch, /tmp/attack.py
     Post-commands: re-run test harness (if present), run exploit.

The combined single-prompt approach (VULN_INJECT_TASK) is preferred over two separate calls
because it guarantees the exploit targets the exact patch written in the same session.

Candidate fields pulled from SelectionCandidate.extra (set by static_analysis strategy):
  extra["checkpoint"]    — {"type": ..., "text": ..., "line": ...}
  extra["operation"]     — {"type": ..., "text": ..., "line": ...}
  extra["cwe_candidates"]  — list[str]
  extra["injection_hint"]  — str (== location_hint on the candidate)
  extra["strategy"]        — str

For candidates from llm_explore, these extra fields may be absent; graceful fallbacks used.
"""

from __future__ import annotations

import base64
import logging
import re
from pathlib import Path

from injector.base import InjectionRequest, InjectionStrategy
from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, run_agent_task
from utils.paths import project_root
from utils.agent.prompts import (
    SYSTEM_TEMPLATE,
    VULN_INJECT_TASK,
    build_harness_note,
)
from utils.agent.result import AgentTelemetry
from vuljector.io_contracts import InjectionResult, SelectionCandidate, utc_now_iso

logger = logging.getLogger(__name__)


# ─── Language context ─────────────────────────────────────────────────────────

def _get_language_context(language: str, *, project: str, cwes: str, injection_hint: str) -> dict:
    """
    Return language-specific prompt sections and exploit metadata.

    Keys returned:
      syntax_check_section   — A4 step block (syntax/build verification)
      exploit_template_section — C2 step block (exploit file template)
      run_exploit_cmd        — C3 step block (command to run exploit)
      exploit_file_rule      — Rules section bullet(s) for the exploit file
      exploit_filename       — basename of the exploit file (e.g. "attack.py")
      exploit_path           — container path to the exploit file
      exploit_run_cmd        — command run by exploit.sh (using /workspace paths)
    """
    lang = (language or "python").lower()

    if lang in ("python", "python3"):
        return {
            "syntax_check_section": (
                "**A4. Verify Python syntax:**\n"
                "```mswea_bash_command\n"
                'python3 -m py_compile "<path>" && echo "SYNTAX_OK" || echo "SYNTAX_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.py`:**\n"
                "```mswea_bash_command\n"
                "cat <<'ATTACK_EOF' > /tmp/attack.py\n"
                "#!/usr/bin/env python3\n"
                f"# PoC exploit — {project} — {cwes}\n"
                f"# Triggers: {injection_hint}\n"
                "import sys\n"
                f'sys.path.insert(0, "/src/{project}")\n'
                "\n"
                "# Import the target module/function\n"
                "# from <module> import <function>\n"
                "\n"
                "triggered = False\n"
                "try:\n"
                "    # Craft the malicious input that bypasses the removed checkpoint\n"
                "    # and reaches the sensitive operation\n"
                "    result = None  # replace with actual call\n"
                '    print("Result:", result)\n'
                "    triggered = True  # set True when exploitation is confirmed\n"
                "except Exception as e:\n"
                '    print(f"Exception raised: {e}")\n'
                "    triggered = True  # unexpected exception also counts as triggered\n"
                "\n"
                'print("TRIGGERED" if triggered else "NOT_TRIGGERED")\n'
                "sys.exit(1 if triggered else 0)\n"
                "ATTACK_EOF\n"
                "```"
            ),
            "run_exploit_cmd": (
                "**C3. Run the exploit:**\n"
                "```mswea_bash_command\n"
                f'cd /src/{project} && python3 /tmp/attack.py 2>&1; echo "ATTACK_EXIT:$?"\n'
                "```"
            ),
            "exploit_file_rule": (
                "- `/tmp/attack.py` MUST exist and be a complete, runnable Python script.\n"
                "- `/tmp/attack.py` MUST exit with code **1** when the vulnerability is triggered, **0** if not triggered."
            ),
            "exploit_filename": "attack.py",
            "exploit_path": "/tmp/attack.py",
            "post_run_cmd": f"cd /src/{project} && python3 /tmp/attack.py",
            "exploit_run_cmd": "python3 /tmp/attack.py",
        }

    elif lang in ("c", "c++", "cpp"):
        return {
            "syntax_check_section": (
                "**A4. Verify build is not broken:**\n"
                "```mswea_bash_command\n"
                'bash /src/build.sh 2>&1 | tail -10 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.sh`:**\n"
                "```mswea_bash_command\n"
                "cat <<'ATTACK_EOF' > /tmp/attack.sh\n"
                "#!/usr/bin/env bash\n"
                f"# PoC exploit — {project} — {cwes}\n"
                f"# Triggers: {injection_hint}\n"
                "set -e\n"
                "\n"
                "# Find the built binary (adjust as needed)\n"
                f"BINARY=$(find /out -name '{project}*' -type f 2>/dev/null | head -1)\n"
                '"${BINARY:-/out/' + project + '}" 2>&1\n'
                "EXIT=$?\n"
                '[ $EXIT -ne 0 ] && echo "TRIGGERED" || echo "NOT_TRIGGERED"\n'
                "exit $EXIT\n"
                "ATTACK_EOF\n"
                "chmod +x /tmp/attack.sh\n"
                "```"
            ),
            "run_exploit_cmd": (
                "**C3. Run the exploit:**\n"
                "```mswea_bash_command\n"
                'bash /tmp/attack.sh 2>&1; echo "ATTACK_EXIT:$?"\n'
                "```"
            ),
            "exploit_file_rule": (
                "- `/tmp/attack.sh` MUST exist and be a complete, runnable bash script.\n"
                "- `/tmp/attack.sh` MUST exit non-zero when the vulnerability is triggered, **0** if not triggered."
            ),
            "exploit_filename": "attack.sh",
            "exploit_path": "/tmp/attack.sh",
            "post_run_cmd": "bash /tmp/attack.sh",
            "exploit_run_cmd": "bash /tmp/attack.sh",
        }

    else:
        # Generic fallback — bash wrapper exploit
        return {
            "syntax_check_section": (
                "**A4. Verify the change parses/builds correctly:**\n"
                "```mswea_bash_command\n"
                'bash /src/build.sh 2>&1 | tail -10 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.sh`:**\n"
                "```mswea_bash_command\n"
                "cat <<'ATTACK_EOF' > /tmp/attack.sh\n"
                "#!/usr/bin/env bash\n"
                f"# PoC exploit — {project} — {cwes}\n"
                f"# Triggers: {injection_hint}\n"
                "set -e\n"
                "\n"
                "# Trigger the vulnerability and exit non-zero when confirmed\n"
                "echo 'Implement exploit here'\n"
                "exit 1\n"
                "ATTACK_EOF\n"
                "chmod +x /tmp/attack.sh\n"
                "```"
            ),
            "run_exploit_cmd": (
                "**C3. Run the exploit:**\n"
                "```mswea_bash_command\n"
                'bash /tmp/attack.sh 2>&1; echo "ATTACK_EXIT:$?"\n'
                "```"
            ),
            "exploit_file_rule": (
                "- `/tmp/attack.sh` MUST exist and be a complete, runnable bash script.\n"
                "- `/tmp/attack.sh` MUST exit non-zero when the vulnerability is triggered, **0** if not triggered."
            ),
            "exploit_filename": "attack.sh",
            "exploit_path": "/tmp/attack.sh",
            "post_run_cmd": "bash /tmp/attack.sh",
            "exploit_run_cmd": "bash /tmp/attack.sh",
        }


class LLMInjectStrategy(InjectionStrategy):
    """
    Injection via mini-swe-agent running VULN_INJECT_TASK.

    A single agent call injects the vulnerability (writes /tmp/vuln.patch) and
    writes the PoC exploit (/tmp/attack.py) in the same container session.
    Both files are extracted and returned in InjectionResult.
    """

    @property
    def id(self) -> str:
        return "llm_inject"

    def run(
        self,
        runtime: ContainerRuntime,
        request: InjectionRequest,
        candidate: SelectionCandidate,
    ) -> InjectionResult:
        extra = candidate.extra or {}
        cp = extra.get("checkpoint") or {}
        op = extra.get("operation") or {}

        file_path = candidate.repo_path or ""
        file_basename = Path(file_path).name if file_path else request.project
        line_range = candidate.line_range or (0, 0)
        line_start, line_end = line_range
        cwe_candidates = extra.get("cwe_candidates") or ([candidate.cwe_id] if candidate.cwe_id else [])
        injection_hint = candidate.location_hint or extra.get("injection_hint", "")

        # ── Setup commands ────────────────────────────────────────────────────
        setup_commands: list[str] = ["bash /src/build.sh 2>&1 | tail -30 || true"]
        # Read harness from disk (written by setup phase) — not from candidate.extra.
        _harness_path = project_root(request.project) / "unit_tests" / "test.sh"
        harness_script = _harness_path.read_text(encoding="utf-8") if _harness_path.exists() else ""
        if harness_script:
            encoded = base64.b64encode(harness_script.encode()).decode()
            setup_commands.append(
                f"echo '{encoded}' | base64 -d > /tmp/test_harness.sh"
                f" && chmod +x /tmp/test_harness.sh"
                f" && echo 'Harness installed OK'"
            )

        harness_available = bool(harness_script)

        # ── Language context (syntax check + exploit template) ────────────────
        cwes_str = ", ".join(cwe_candidates) or "unknown"
        lang_ctx = _get_language_context(
            candidate.language or "python",
            project=request.project,
            cwes=cwes_str,
            injection_hint=injection_hint,
        )
        exploit_path = lang_ctx["exploit_path"]
        exploit_filename = lang_ctx["exploit_filename"]

        # ── Build prompt ──────────────────────────────────────────────────────
        checkpoint_snippet = (cp.get("text", "") or "").strip()
        checkpoint_snippet = checkpoint_snippet.split("\n")[0][:60].replace('"', "'")

        task_prompt = VULN_INJECT_TASK.format(
            project=request.project,
            file_path=file_path,
            file_basename=file_basename,
            function=candidate.symbol or "",
            line_start=line_start,
            line_end=line_end,
            cwes=cwes_str,
            strategy=extra.get("strategy", ""),
            injection_hint=injection_hint,
            checkpoint_type=cp.get("type", ""),
            checkpoint_text=cp.get("text", "").strip(),
            checkpoint_line=cp.get("line", "?"),
            operation_type=op.get("type", ""),
            operation_text=op.get("text", "").strip(),
            operation_line=op.get("line", "?"),
            harness_note=build_harness_note(harness_available),
            **{k: lang_ctx[k] for k in (
                "syntax_check_section", "exploit_template_section",
                "run_exploit_cmd", "exploit_file_rule",
            )},
        )

        # ── Post commands: verify harness + run exploit ───────────────────────
        # First: overwrite the agent's diff-u patch with a proper git diff.
        # The agent edits source files directly; `git diff HEAD` in the same
        # container gives a clean git-format unified diff for `git apply` later.
        post_commands: list[str] = [
            f"cd {runtime.repo_dir_in_container} && git diff HEAD > /tmp/vuln.patch || true"
        ]
        if harness_available:
            post_commands.append(
                "bash /tmp/test_harness.sh > /tmp/harness_out.txt 2>&1"
                "; echo HARNESS_EXIT:$?; tail -20 /tmp/harness_out.txt"
            )
        post_commands.append(
            f"{lang_ctx['post_run_cmd']} > /tmp/attack_out.txt 2>&1"
            "; echo ATTACK_EXIT:$?; tail -30 /tmp/attack_out.txt"
        )

        # ── Trajectory path (inside the run mount on host) ────────────────────
        traj_name = f"{request.attempt_dir}_trajectory.json" if request.attempt_dir else "vuln_inject_trajectory.json"
        trajectory_path = str(
            runtime.run_mount_dir / "logs" / traj_name
        ) if runtime.run_mount_dir is not None else ""

        agent_req = AgentRequest(
            model_id=request.model_id,
            prompt=task_prompt,
            workdir=runtime.repo_dir_in_container,
            system_template=SYSTEM_TEMPLATE,
            step_limit=20,
            cost_limit=2.0,
            setup_commands=setup_commands,
            extract_paths=["/tmp/vuln.patch", exploit_path],
            post_commands=post_commands,
            trajectory_path=trajectory_path,
        )

        logger.info(
            "[%s] llm_inject: candidate=%s cwe=%s fn=%s",
            request.project, candidate.candidate_id,
            cwe_candidates[0] if cwe_candidates else "?",
            candidate.symbol or "?",
        )

        resp = run_agent_task(runtime, agent_req)

        # ── Parse outputs ─────────────────────────────────────────────────────
        # Do NOT strip patch_diff — git diff patches end with a blank context line
        # (` \n`) and stripping it removes it, making the hunk count off by 1,
        # which causes `git apply` to fail with "corrupt patch".
        patch_diff = resp.extracted_files.get("/tmp/vuln.patch", "")
        exploit_script = resp.extracted_files.get(exploit_path, "").strip()

        harness_passed, attack_triggered = _parse_post_results(resp.post_results)

        # ── Write artifacts to run mount (host-side run_mount_dir maps to /workspace/run/) ──
        # Artifacts go into the per-attempt subdirectory when attempt_dir is set.
        attempt_prefix = request.attempt_dir + "/" if request.attempt_dir else ""
        artifacts_rel = f"{attempt_prefix}artifacts"
        exploit_rel = f"{artifacts_rel}/exploit_files"
        snapshot_rel = f"{artifacts_rel}/snapshot"

        if runtime.run_mount_dir is not None:
            exploit_dir = runtime.run_mount_dir / exploit_rel
            exploit_dir.mkdir(parents=True, exist_ok=True)
            if exploit_script:
                (exploit_dir / exploit_filename).write_text(exploit_script, encoding="utf-8")
                # exploit.sh is a thin wrapper — passes through the exploit's exit code.
                # Convention: exploit exits non-zero when triggered.
                # verifier treats non-zero as triggered=True — consistent.
                exploit_sh = (
                    "#!/bin/bash\n"
                    f"cd /src/{request.project}\n"
                    f"{lang_ctx['exploit_run_cmd']}\n"
                )
                (exploit_dir / "exploit.sh").write_text(exploit_sh, encoding="utf-8")
            if patch_diff:
                (runtime.run_mount_dir / artifacts_rel / "vuln.patch").write_text(
                    patch_diff, encoding="utf-8"
                )

        # ── Build InjectionResult ─────────────────────────────────────────────
        telemetry = AgentTelemetry.from_agent(
            model=request.model_id,
            exit_status=resp.exit_status,
            wall_time_s=0.0,
            messages=resp.messages,
            trajectory_path=trajectory_path,
        )

        # Success = agent produced a patch (returncode may be non-zero even on agent success).
        succeeded = bool(patch_diff)

        if not succeeded:
            failure_msg = resp.stderr or resp.stdout or f"exit_status={resp.exit_status}"
            if not patch_diff:
                failure_msg = "Agent did not produce /tmp/vuln.patch"
            logger.warning("[%s] llm_inject FAILED: %s", request.project, failure_msg)
            return InjectionResult(
                project=request.project,
                run_id=request.run_id,
                timestamp_utc=utc_now_iso(),
                status="failure",
                selected_candidate_id=candidate.candidate_id,
                cwe_group=candidate.cwe_group,
                cwe_id=candidate.cwe_id,
                strategy={
                    "id": self.id,
                    "model_id": request.model_id,
                    "retries": 0,
                },
                usage={
                    "total_steps": telemetry.total_steps,
                    "total_input_tokens": telemetry.total_input_tokens,
                    "total_output_tokens": telemetry.total_output_tokens,
                    "estimated_cost_usd": telemetry.estimated_cost_usd,
                    "models_used": [request.model_id],
                },
                paths={
                    "exploit_dir": exploit_rel,
                    "snapshot_manifest": f"{snapshot_rel}/manifest.json",
                },
                failure={"cause": "agent_failed", "message": failure_msg},
            )

        logger.info(
            "[%s] llm_inject OK: patch=%d chars exploit=%d chars harness_passed=%s attack_triggered=%s",
            request.project, len(patch_diff), len(exploit_script),
            harness_passed, attack_triggered,
        )
        return InjectionResult(
            project=request.project,
            run_id=request.run_id,
            timestamp_utc=utc_now_iso(),
            status="success",
            selected_candidate_id=candidate.candidate_id,
            cwe_group=candidate.cwe_group,
            cwe_id=candidate.cwe_id,
            strategy={
                "id": self.id,
                "model_id": request.model_id,
                "retries": 0,
            },
            usage={
                "total_steps": telemetry.total_steps,
                "total_input_tokens": telemetry.total_input_tokens,
                "total_output_tokens": telemetry.total_output_tokens,
                "estimated_cost_usd": telemetry.estimated_cost_usd,
                "models_used": [request.model_id],
            },
            paths={
                "exploit_dir": exploit_rel,
                "snapshot_manifest": f"{snapshot_rel}/manifest.json",
            },
            artifacts={
                "patch_diff": patch_diff,
                "attack_script": exploit_script,
                "exploit_filename": exploit_filename,
                "harness_passed": str(harness_passed),
                "attack_triggered": str(attack_triggered),
            },
            failure=None,
        )


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parse_exit_marker(output: str, marker: str) -> int | None:
    """Extract integer exit code from a ``MARKER:N`` sentinel in command output."""
    m = re.search(rf"{re.escape(marker)}:(\d+)", output)
    return int(m.group(1)) if m else None


def _parse_post_results(post_results: list[dict]) -> tuple[bool, bool]:
    """
    Parse post-command outputs to determine:
      - harness_passed: HARNESS_EXIT:0 found in harness output
      - attack_triggered: ATTACK_EXIT non-zero (and marker present) in attack output
    """
    harness_passed = False
    attack_triggered = False

    for pr in post_results:
        cmd = pr.get("command", "")
        output = pr.get("output", "")[:3000]
        if "test_harness.sh" in cmd:
            code = _parse_exit_marker(output, "HARNESS_EXIT")
            harness_passed = (code == 0) if code is not None else False
        elif "ATTACK_EXIT" in output:
            code = _parse_exit_marker(output, "ATTACK_EXIT")
            attack_triggered = (code is not None and code != 0)

    return harness_passed, attack_triggered
