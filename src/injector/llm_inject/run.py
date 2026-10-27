"""
LLMInjectStrategy — vulnerability injection + exploit generation via mini-swe-agent.

The agent writes a git-format patch and an exploit in the same container
session so the exploit targets the exact injected bug. Modern C/C++ flows use a
self-contained `/tmp/exploit/` directory with `/tmp/exploit/exploit.sh` as the
entrypoint. Python and older flows may still emit a single attack file.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import shlex
import shutil
import tarfile
from pathlib import Path

from injector.base import InjectionRequest, InjectionStrategy
from setup.container_runtime import ContainerRuntime
from utils.agent import AgentRequest, run_agent_task
from utils.paths import project_root
from utils.agent.prompts import (
    SYSTEM_TEMPLATE,
    VULN_INJECT_TASK,
    VULN_ONLY_INJECT_TASK,
    build_harness_note,
    build_fuzz_guidance_section,
)
from utils.agent.result import AgentTelemetry
from vuljector.io_contracts import InjectionResult, SelectionCandidate, utc_now_iso

logger = logging.getLogger(__name__)


def _injection_mode() -> str:
    return (os.environ.get("VULJECTOR_INJECTION_MODE") or "").strip().lower()


def _vuln_only_mode() -> bool:
    return _injection_mode() == "vuln_only"


def _step_limit() -> int:
    raw = (os.environ.get("VULJECTOR_INJECTION_STEP_LIMIT") or "").strip()
    if not raw:
        return 30
    try:
        value = int(raw)
    except ValueError:
        return 30
    return max(1, value)


def _repo_relative_path(repo_dir: str, path: str) -> str:
    if not path:
        return ""
    repo_prefix = repo_dir.rstrip("/") + "/"
    if path.startswith(repo_prefix):
        return path[len(repo_prefix):]
    return path.lstrip("/")

# ─── Language context ─────────────────────────────────────────────────────────

def _get_generic_language_context(language: str, *, project: str, cwes: str, injection_hint: str) -> dict:
    """
    Original generic llm_inject language context.
    """
    lang = (language or "python").lower()

    if lang in ("python", "python3"):
        return {
            "syntax_check_section": (
                "**A4. Verify Python syntax:**\n"
                "```bash\n"
                'python3 -m py_compile "<path>" && echo "SYNTAX_OK" || echo "SYNTAX_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.py`:**\n  A suggested template is given below:"
                "```bash\n"
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
                "```bash\n"
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

    if lang in ("c", "c++", "cpp"):
        return {
            "syntax_check_section": (
                "**A4. Verify build is not broken:**\n"
                "```bash\n"
                'bash /src/build.sh 2>&1 | tail -10 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.sh`:**\n"
                "```bash\n"
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
                "```bash\n"
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

    return {
        "syntax_check_section": (
            "**A4. Verify the change parses/builds correctly:**\n"
            "```bash\n"
            'bash /src/build.sh 2>&1 | tail -10 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
            "```"
        ),
        "exploit_template_section": (
            "**C2. Write the exploit to `/tmp/attack.sh`:**\n"
            "```bash\n"
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
            "```bash\n"
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
                "```bash\n"
                'python3 -m py_compile "<path>" && echo "SYNTAX_OK" || echo "SYNTAX_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.py`:**\n  A suggested template is given below:"
                "```bash\n"
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
                "```bash\n"
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
                "**A4. Verify the source still builds or at least the edited translation unit is sane:**\n"
                "```bash\n"
                'bash /src/build.sh 2>&1 | tail -30 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Create a self-contained exploit directory at `/tmp/exploit`:**\n"
                "Everything needed to run the exploit must live inside `/tmp/exploit`, with one entrypoint: `/tmp/exploit/exploit.sh`.\n"
                "Clean the directory before writing files so stale attempts are not extracted.\n"
                "Choose the most controllable real entrypoint into the edited code path. Prefer options in this order:\n"
                "1. an existing project CLI/tool/helper that already accepts the relevant input type;\n"
                "2. a small C/C++ driver under `/tmp/exploit` that calls public project APIs or normal parser/entrypoint code;\n"
                "3. an existing fuzzer binary in `/out` with a testcase file written under `/tmp/exploit`;\n"
                "4. a project test/helper command when that is the cleanest external path.\n\n"
                "Do not choose a fuzzer by default just because it exists. Use a fuzzer only when it is the clearest way to exercise the edited path.\n"
                "If you use a CLI/tool/helper or API driver, explain to yourself which function or parser path it reaches and why that is more controllable than a fuzzer here.\n"
                "If you use a fuzzer, first discover the available binaries under `/out`, then identify what input type the chosen fuzzer expects, then write a plausibly valid testcase under `/tmp/exploit`, run the fuzzer with that testcase, and check sanitizer/crash output. "
                "If you write a C/C++ driver, do not directly mutate private/internal structs just to manufacture an impossible state.\n"
                "Your exploit must exercise the actual project code path that your patch weakens. "
                "Do not write a standalone toy program that merely reproduces the same bug shape in isolation.\n"
                "Do not inspect source text, `/tmp/vuln.patch`, or `git diff` and declare success just because a guard line is absent.\n"
                "Do not treat compiler errors, missing binaries, usage failures, shell errors, or arbitrary non-zero exits as proof of trigger.\n"
                "Prefer a shipped project binary or API-level driver over blind fuzzing when you need tighter control of the path. "
                "Only write a custom driver when it links against project headers/libraries or compiles project sources needed to reach the edited function.\n"
                "Discovery commands:\n"
                "```bash\n"
                "find /out -maxdepth 1 -type f -perm -111 -printf '%f\\n' 2>/dev/null | sort | head -50\n"
                f"find /src/{project} -maxdepth 3 -type f \\( -name '*test*' -o -name '*fuzz*' -o -name '*.cc' -o -name '*.c' \\) 2>/dev/null | head -80\n"
                "```\n"
                "Before writing the exploit, decide and document mentally:\n"
                "- which exact entrypoint you are using;\n"
                "- what input format it expects;\n"
                "- which existing sample, fixture, corpus file, or test input in the repo is closest;\n"
                "- what minimal change to that valid input should reach the edited path.\n"
                "If the target expects a structured file format, start from a valid sample/fixture whenever possible instead of inventing a tiny arbitrary blob.\n"
                "`exploit.sh` must be deterministic and must exit **1** only when the intended vulnerability signal is observed. "
                "Good trigger signals include AddressSanitizer/UBSan output, SIGSEGV/SIGABRT from the targeted path, or a precise checked error caused by the weakened guard. "
                "Do not treat a missing binary, bad command-line usage, or unrelated parser rejection as success.\n"
                "Do not rebuild both a 'clean' and a 'vulnerable' private copy inside `/tmp/exploit` unless there is no existing project or `/out` entrypoint that can show the behavioral difference.\n"
                "Before you submit, perform a quick differential sanity check inside the exploit itself when feasible: "
                "the vulnerable build should trigger, and a clean run condition should print `NOT_TRIGGERED`.\n"
                "Before submitting, remove large temporary copies, binaries, logs, and stale outputs from `/tmp/exploit`; keep only `exploit.sh` and the minimal inputs/sources it needs.\n"
                "```bash\n"
                "rm -rf /tmp/exploit && mkdir -p /tmp/exploit\n"
                "cat <<'ATTACK_EOF' > /tmp/exploit/exploit.sh\n"
                "#!/usr/bin/env bash\n"
                "set -u\n"
                "EXPLOIT_DIR=\"$(cd \"$(dirname \"${BASH_SOURCE[0]}\")\" && pwd)\"\n"
                f"REPO=/src/{project}\n"
                "cd \"$REPO\"\n"
                "\n"
                "# Replace this skeleton with the concrete trigger you tested.\n"
                "# Keep generated testcase/helper files in \"$EXPLOIT_DIR\".\n"
                "# This script must call into project code via the most controllable real entrypoint you found.\n"
                "OUT=\"$EXPLOIT_DIR/run.out\"\n"
                "set +e\n"
                "# Example shape:\n"
                "#   cp <existing_valid_sample> \"$EXPLOIT_DIR/poc.input\"\n"
                "#   <mutate sample minimally>\n"
                "#   /out/<binary> \"$EXPLOIT_DIR/poc.input\" >\"$OUT\" 2>&1\n"
                "#   STATUS=$?\n"
                "STATUS=0\n"
                "set -e\n"
                "cat \"$OUT\" 2>/dev/null || true\n"
                "if grep -Eiq 'No such file|not found|usage:|invalid option|unrecognized option|fatal error:' \"$OUT\" 2>/dev/null; then\n"
                "  echo NOT_TRIGGERED\n"
                "  exit 0\n"
                "fi\n"
                "if grep -Eiq 'AddressSanitizer|UndefinedBehaviorSanitizer|heap-buffer-overflow|stack-buffer-overflow|SEGV|SIGSEGV|SIGABRT' \"$OUT\" 2>/dev/null; then\n"
                "  echo TRIGGERED\n"
                "  exit 1\n"
                "fi\n"
                "if [ \"${STATUS:-0}\" -eq 134 ] || [ \"${STATUS:-0}\" -eq 139 ]; then\n"
                "  echo TRIGGERED\n"
                "  exit 1\n"
                "fi\n"
                "echo NOT_TRIGGERED\n"
                "exit 0\n"
                "ATTACK_EOF\n"
                "chmod +x /tmp/exploit/exploit.sh\n"
                "```"
            ),
            "run_exploit_cmd": (
                "**C3. Run the exploit:**\n"
                "```bash\n"
                'bash /tmp/exploit/exploit.sh 2>&1; echo "ATTACK_EXIT:$?"\n'
                "```"
            ),
            "exploit_file_rule": (
                "- `/tmp/exploit/exploit.sh` MUST exist and be a complete, runnable bash script.\n"
                "- Put every related testcase/helper/source/build artifact needed by the exploit under `/tmp/exploit/`.\n"
                "- The exploit MUST invoke project code, not a toy standalone reproduction of the same bug pattern.\n"
                "- Prefer a real project CLI/helper or API-level driver over a fuzzer when that gives tighter control of the target path.\n"
                "- A source grep, diff check, or compile failure does NOT count as a trigger.\n"
                "- The exploit must not read `/tmp/vuln.patch`, run `git diff`, or inspect source files to decide success.\n"
                "- `/tmp/exploit/exploit.sh` MUST exit non-zero when the intended vulnerability is triggered, **0** if not triggered."
            ),
            "exploit_filename": "exploit.sh",
            "exploit_path": "/tmp/exploit/exploit.sh",
            "extract_path": "/tmp/exploit",
            "post_run_cmd": "bash /tmp/exploit/exploit.sh",
            "exploit_run_cmd": "bash /tmp/exploit/exploit.sh",
        }

    else:
        # Generic fallback — bash wrapper exploit
        return {
            "syntax_check_section": (
                "**A4. Verify the change parses/builds correctly:**\n"
                "```bash\n"
                'bash /src/build.sh 2>&1 | tail -10 && echo "BUILD_OK" || echo "BUILD_ERROR"\n'
                "```"
            ),
            "exploit_template_section": (
                "**C2. Write the exploit to `/tmp/attack.sh`:**\n"
                "```bash\n"
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
                "```bash\n"
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

    def build_prompt_sections(
        self,
        request: InjectionRequest,
        candidate: SelectionCandidate,
        fuzz_guidance: dict,
    ) -> dict[str, str]:
        return {"fuzz_guidance_section": "", "execution_context_section": ""}

    def build_prompt_template(self) -> str:
        return VULN_ONLY_INJECT_TASK if _vuln_only_mode() else VULN_INJECT_TASK

    def build_language_context(self, candidate: SelectionCandidate, *, project: str, cwes_str: str, injection_hint: str) -> dict:
        # Use the self-contained exploit profile (/tmp/exploit dir with a
        # relocatable exploit.sh) rather than the legacy /tmp/attack.sh wrapper.
        # The old generic context produced an exploit.sh calling an absolute
        # /tmp/attack.sh path that doesn't exist in the fresh verification
        # containers, so every injection failed verification with
        # oracle_invalid_on_secure (infra_or_sanitizer_internal_error).
        return _get_language_context(
            candidate.language or "python",
            project=project,
            cwes=cwes_str,
            injection_hint=injection_hint,
        )

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
        fuzz_guidance = extra.get("fuzz_native") or extra.get("fuzz") or {}
        relevant_files = sorted(
            {
                _repo_relative_path(runtime.repo_dir_in_container, path)
                for path in (
                    candidate.repo_path or "",
                    cp.get("file", "") or "",
                    op.get("file", "") or "",
                )
                if path
            }
        )

        # ── Setup commands ────────────────────────────────────────────────────
        setup_commands: list[str] = [
            f"cd {runtime.repo_dir_in_container} && git diff --name-only HEAD | sed '/^$/d' | sort -u > /tmp/vuljector_preexisting_modified.txt || true",
        ]
        harness_available = (project_root(request.project) / "unit_tests" / "test.sh").exists()

        # ── Language context (syntax check + exploit template) ────────────────
        cwes_str = ", ".join(cwe_candidates) or "unknown"
        lang_ctx = self.build_language_context(
            candidate,
            project=request.project,
            cwes_str=cwes_str,
            injection_hint=injection_hint,
        )
        exploit_path = lang_ctx["exploit_path"]
        exploit_filename = lang_ctx["exploit_filename"]
        extract_path = lang_ctx.get("extract_path", exploit_path)

        # ── Build prompt ──────────────────────────────────────────────────────
        checkpoint_snippet = (cp.get("text", "") or "").strip()
        checkpoint_snippet = checkpoint_snippet.split("\n")[0][:60].replace('"', "'")

        prompt_sections = self.build_prompt_sections(request, candidate, fuzz_guidance)

        prompt_template = self.build_prompt_template()
        task_prompt = prompt_template.format(
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
            checkpoint_file=cp.get("file", file_path),
            operation_file=op.get("file", file_path),
            fuzz_guidance_section=prompt_sections["fuzz_guidance_section"],
            execution_context_section=prompt_sections["execution_context_section"],
            **{k: lang_ctx[k] for k in (
                "syntax_check_section", "exploit_template_section",
                "run_exploit_cmd", "exploit_file_rule",
            )},
        )

        # ── Post commands: verify harness + run exploit ───────────────────────
        # First: overwrite the agent's diff-u patch with a proper git diff.
        # The agent edits source files directly; `git diff HEAD` in the same
        # container gives a clean git-format unified diff for `git apply` later.
        patch_capture = f"""python3 - <<'PY'
import json
import pathlib
import subprocess

repo = pathlib.Path({runtime.repo_dir_in_container!r})
baseline_path = pathlib.Path('/tmp/vuljector_preexisting_modified.txt')
baseline = set()
if baseline_path.exists():
    baseline = {{line.strip() for line in baseline_path.read_text(encoding='utf-8', errors='ignore').splitlines() if line.strip()}}

current_proc = subprocess.run(
    ['git', 'diff', '--name-only', 'HEAD'],
    cwd=repo,
    capture_output=True,
    text=True,
)
current = {{line.strip() for line in current_proc.stdout.splitlines() if line.strip()}}
relevant = set(json.loads({json.dumps(json.dumps(relevant_files))}))
include = sorted((current - baseline) | relevant)

patch = ''
if include:
    diff_proc = subprocess.run(
        ['git', 'diff', 'HEAD', '--', *include],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    patch = diff_proc.stdout

pathlib.Path('/tmp/vuln.patch').write_text(patch, encoding='utf-8')
PY"""
        post_commands: list[str] = [
            f"cd {shlex.quote(runtime.repo_dir_in_container)} && {patch_capture}",
        ]


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
            step_limit=_step_limit(),
            cost_limit=2.0,
            setup_commands=setup_commands,
            extract_paths=["/tmp/vuln.patch"] if _vuln_only_mode() else ["/tmp/vuln.patch", extract_path],
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
        exploit_script = ""

        harness_passed, attack_triggered = False, False

        # ── Write artifacts to the host run directory (mounted at /workspace/run/attempt) ──
        # Artifacts go into the per-attempt subdirectory when attempt_dir is set.
        attempt_prefix = request.attempt_dir + "/" if request.attempt_dir else ""
        artifacts_rel = f"{attempt_prefix}artifacts"
        exploit_rel = f"{artifacts_rel}/exploit_files"

        if runtime.run_mount_dir is not None and not _vuln_only_mode():
            exploit_dir = runtime.run_mount_dir / exploit_rel
            exploit_script = _write_exploit_artifacts(
                resp,
                lang_ctx=lang_ctx,
                exploit_dir=exploit_dir,
                project=request.project,
            )
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

        succeeded = bool(patch_diff) if _vuln_only_mode() else bool(patch_diff and exploit_script)

        if not succeeded:
            failure_msg = resp.stderr or resp.stdout or f"exit_status={resp.exit_status}"
            if not patch_diff:
                failure_msg = "Agent did not produce /tmp/vuln.patch"
            elif not _vuln_only_mode() and not exploit_script:
                failure_msg = "Agent did not produce /tmp/exploit/exploit.sh"
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
                    "selection_candidate": candidate.to_dict(),
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
                "selection_candidate": candidate.to_dict(),
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


def _write_exploit_artifacts(resp, *, lang_ctx: dict, exploit_dir: Path, project: str) -> str:
    """Materialize extracted exploit artifacts into the run mount.

    C/C++ agents produce a whole `/tmp/exploit` directory. Older/Python flows may
    still produce a single attack file; keep that fallback so existing strategies
    do not break.
    """
    if exploit_dir.exists():
        shutil.rmtree(exploit_dir)
    exploit_dir.mkdir(parents=True, exist_ok=True)

    extract_path = lang_ctx.get("extract_path")
    if extract_path and extract_path in getattr(resp, "extracted_dirs", {}):
        _extract_tarball_to_dir(resp.extracted_dirs[extract_path], exploit_dir)
        entrypoint = exploit_dir / "exploit.sh"
        if entrypoint.exists():
            entrypoint.chmod(entrypoint.stat().st_mode | 0o111)
            return entrypoint.read_text(encoding="utf-8", errors="replace").strip()
        return ""

    exploit_path = lang_ctx["exploit_path"]
    exploit_filename = lang_ctx["exploit_filename"]
    exploit_script = resp.extracted_files.get(exploit_path, "").strip()
    if not exploit_script:
        return ""

    (exploit_dir / exploit_filename).write_text(exploit_script, encoding="utf-8")
    exploit_sh = (
        "#!/bin/bash\n"
        f"cd /src/{project}\n"
        f"{lang_ctx['exploit_run_cmd']}\n"
    )
    (exploit_dir / "exploit.sh").write_text(exploit_sh, encoding="utf-8")
    (exploit_dir / "exploit.sh").chmod((exploit_dir / "exploit.sh").stat().st_mode | 0o111)
    return exploit_script


def _extract_tarball_to_dir(payload_b64: str, dest: Path) -> None:
    data = base64.b64decode(payload_b64.encode())
    dest_resolved = dest.resolve()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = tar.getmembers()
        for member in members:
            target = (dest / member.name).resolve()
            if target != dest_resolved and dest_resolved not in target.parents:
                raise RuntimeError(f"Unsafe exploit artifact path: {member.name}")
        tar.extractall(dest, members=members)
