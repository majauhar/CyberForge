"""Agent prompt templates for VulInjector tasks (mini-swe-agent v2).

v2 formatting rules:
  - system_template   → Jinja2, supports {{system}} {{release}} {{machine}}
  - instance_template → Jinja2, {{task}} filled by agent.run(task=...)
  - Commands wrapped in ```mswea_bash_command blocks
  - Task ends with: echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
"""

from __future__ import annotations


# ─────────────────────────────────────────────────────────────────────────────
# System template (shared across all tasks)
# ─────────────────────────────────────────────────────────────────────────────

SYSTEM_TEMPLATE = """\
You are a software engineering assistant with full bash terminal access inside a \
Docker container.

## Action format
Every response must contain exactly ONE bash code block with ONE command \
(commands may be chained with && or ||):

```mswea_bash_command
your_command_here
```

Include a THOUGHT before your command explaining your reasoning.

## Rules
- Every response: exactly one action in triple backticks.
- Directory/env changes are NOT persistent. Prefix commands: `cd /path && ...`
- When finished: output your final structured answer in your THOUGHT, then:

```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

Do NOT combine the final echo with anything else.

System: {{system}} {{release}} {{machine}}
"""


# ─────────────────────────────────────────────────────────────────────────────
# Security-aligned system template (used for repo_explore task)
# ─────────────────────────────────────────────────────────────────────────────

SECURITY_SYSTEM_TEMPLATE = """\
You are a security researcher with full bash terminal access inside a Docker container. \
Your goal is to identify exploitable vulnerability patterns in source code.

## Action format
Every response must contain exactly ONE bash code block with ONE command \
(commands may be chained with && or ||):

```mswea_bash_command
your_command_here
```

Include a THOUGHT before your command explaining your security reasoning.

## Rules
- Every response: exactly one action in triple backticks.
- Directory/env changes are NOT persistent. Prefix commands: `cd /path && ...`
- Focus on security-critical code paths: authentication, authorization, input validation, \
  deserialization, file I/O, subprocess execution, SQL/template rendering.
- Think adversarially: which guards, if removed, would allow an attacker to reach a \
  dangerous operation with attacker-controlled input?
- When finished: output your final structured answer in your THOUGHT, then:

```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

Do NOT combine the final echo with anything else.

System: {{system}} {{release}} {{machine}}
"""

# Instance template — {{task}} filled by agent.run(task=...)
INSTANCE_TEMPLATE = "{{ task }}"


# ─────────────────────────────────────────────────────────────────────────────
# Task: Test Discovery
# ─────────────────────────────────────────────────────────────────────────────

TEST_DISCOVERY_TASK = """\
You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — the project's packages are installed.

## Goal
1. Find the project's internal unit/integration tests (NOT the OSS-Fuzz fuzz targets).
2. Write a self-contained bash harness to `/tmp/test_harness.sh` that runs them.
3. Run it and save the output to `/tmp/baseline_output.txt`.
4. Submit.

## Steps

1. **Verify pytest is available** (install if missing):
```mswea_bash_command
python -m pytest --version 2>/dev/null || pip install pytest --quiet 2>&1 | tail -3
```

2. **Find the test directory:**
```mswea_bash_command
ls /src/{src_dir}/ && (ls /src/{src_dir}/tests/ 2>/dev/null || \
  find /src/{src_dir} -name "test_*.py" -maxdepth 4 | head -15)
```

3. **Confirm at least 1 test is collected** (adjust path as needed):
```mswea_bash_command
cd /src/{src_dir} && python -m pytest tests/ --collect-only -q 2>&1 | head -20
```
   If 0 tests: try `test/` or `.` with `--ignore=docs --ignore=fuzz`.
   If ImportError: the package isn't installed — run `pip install /src/{src_dir} --quiet`.

4. **Write `/tmp/test_harness.sh`** using the working invocation from step 3:
```mswea_bash_command
cat <<'SCRIPT_EOF' > /tmp/test_harness.sh
#!/usr/bin/env bash
set -euo pipefail
python3 -m pytest --version 2>/dev/null || pip3 install pytest --quiet >&2
cd /src/{src_dir}
exec python3 -m pytest tests/ -x -q --tb=short --no-header
SCRIPT_EOF
chmod +x /tmp/test_harness.sh
```
   Adjust the pytest path/flags to whatever actually collected tests in step 3.

5. **Run the harness and save output:**
```mswea_bash_command
bash /tmp/test_harness.sh 2>&1 | tee /tmp/baseline_output.txt | tail -20; echo "HARNESS_EXIT:$?"
```
   If 0 tests ran, fix the harness and retry. Otherwise submit.

6. **Submit:**
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- Never accept "0 tests collected" as success — go back and fix the harness.
- The harness must exit with the test suite's real exit code (use `exec`).
- `/tmp/test_harness.sh` must exist and be executable when you submit.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Task: Vulnerability Patch Injection (standalone — writes /tmp/vuln.patch)
# ─────────────────────────────────────────────────────────────────────────────

VULN_PATCH_TASK = """\
You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — packages are installed.

## Vulnerability Target

File     : `{file_path}`
Function : `{function}`
Lines    : {line_start}–{line_end}
CWEs     : {cwes}
Strategy : {strategy}
Hint     : **{injection_hint}**

### Checkpoint to weaken or remove
- Type : `{checkpoint_type}`
- Code : `{checkpoint_text}`
- Line : {checkpoint_line}

### Sensitive operation (keep intact — it must still execute)
- Type : `{operation_type}`
- Code : `{operation_text}`
- Line : {operation_line}

## Test Harness
{harness_note}

---

## Steps

1. **Locate the file:**
```mswea_bash_command
find /src -type f -name "{file_basename}" 2>/dev/null | head -10
```

2. **Read the file** (replace TFILE with the path found above):
```mswea_bash_command
TFILE="<path>"; cat -n "$TFILE" | head -120
```

3. **Understand the checkpoint** — read the context around line {checkpoint_line}.
   Identify the exact guard expression that prevents the operation at line
   {operation_line} from executing unsafely.

4. **Backup and inject** — make ONE minimal, realistic change:
```mswea_bash_command
TFILE="<path>"; cp "$TFILE" "$TFILE.orig" && python3 - <<'PYEOF'
path = "<path>"
src = open(path).read()
patched = src.replace(
    "<exact original checkpoint code>",
    "<weakened version>"
)
assert patched != src, "No change made — check your replacement strings"
open(path, "w").write(patched)
print("Patch applied successfully")
PYEOF
```
   Alternative: `sed -i 's/old/new/' <path>`

5. **Verify Python syntax:**
```mswea_bash_command
python3 -m py_compile "<path>" && echo "SYNTAX_OK" || echo "SYNTAX_ERROR"
```

6. **Run the test harness** (if available):
```mswea_bash_command
bash /tmp/test_harness.sh 2>&1 | tail -30; echo "HARNESS_EXIT:$?"
```

7. **Save the unified diff to `/tmp/vuln.patch`:**
```mswea_bash_command
diff -u "<path>.orig" "<path>" > /tmp/vuln.patch || true
cat /tmp/vuln.patch
```

8. **Submit:**
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/vuln.patch` MUST exist and contain a non-empty unified diff when you submit.
- Make ONE minimal change — the goal is a plausible developer mistake.
- Do NOT combine the submit echo with any other command.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Task: Attack Script Generation (standalone — writes /tmp/attack.py)
# ─────────────────────────────────────────────────────────────────────────────

ATTACK_SCRIPT_TASK = """\
You are inside the OSS-Fuzz Docker container for **{project}**.
The vulnerability below has already been injected into the source code.

Your task: write a **Proof-of-Concept exploit script** that demonstrates the
vulnerability can be triggered by an external caller.

## Vulnerable Location

File     : `{file_path}`
Function : `{function}`
CWEs     : {cwes}
Hint     : **{injection_hint}**

## The Injected Patch

```diff
{patch_diff}
```

## Test Harness
{harness_note}

---

## Steps

1. **Verify the patch is applied:**
```mswea_bash_command
grep -n "{checkpoint_snippet}" "{file_path}" 2>/dev/null \
  && echo "CHECKPOINT_PRESENT" || echo "CHECKPOINT_REMOVED"
```
   If not applied, apply it now:
```mswea_bash_command
patch -p0 <<'PEOF'
{patch_diff}
PEOF
```

2. **Study the vulnerable function:**
```mswea_bash_command
grep -n "" "{file_path}" | sed -n '{line_start},{line_end}p'
```

3. **Write the exploit to `/tmp/attack.py`:**
```mswea_bash_command
cat <<'ATTACK_EOF' > /tmp/attack.py
#!/usr/bin/env python3
# PoC exploit — {project} — {cwes}
# Triggers: {injection_hint}
import sys
sys.path.insert(0, "/src/{project}")

# Import the target module/function
# from <module> import <function>

triggered = False
try:
    # Craft the malicious input that bypasses the removed checkpoint
    # and reaches the sensitive operation
    result = None  # replace with actual call
    # Check if the result/behavior indicates the vulnerability fired
    # e.g. unexpected return value, wrong type, sensitive data exposed
    print("Result:", result)
    triggered = True  # set True when exploitation is confirmed
except Exception as e:
    print(f"Exception raised: {{e}}")
    triggered = True  # unexpected exception also counts as triggered

print("TRIGGERED" if triggered else "NOT_TRIGGERED")
sys.exit(1 if triggered else 0)
ATTACK_EOF
```

4. **Run the exploit:**
```mswea_bash_command
cd /src/{project} && python3 /tmp/attack.py 2>&1; echo "ATTACK_EXIT:$?"
```

5. **Iterate** if the exploit didn't trigger — refine input and retry.

6. **Submit:**
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/attack.py` MUST exist and be a complete, runnable Python script.
- `/tmp/attack.py` MUST exit with code **1** when the vulnerability is triggered, **0** if not triggered.
- Do NOT combine the submit echo with any other command.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Task: Combined Vulnerability Injection + Exploit (single container session)
# ─────────────────────────────────────────────────────────────────────────────

VULN_INJECT_TASK = """\
You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — packages are installed.

## Goal
Inject a minimal vulnerability, then immediately write a PoC exploit for it —
all in this single container session so the exploit targets exactly the patch you apply.

---

# Part A — Inject the Vulnerability

## Target

File     : `{file_path}`
Function : `{function}`
Lines    : {line_start}–{line_end}
CWEs     : {cwes}
Strategy : {strategy}
Hint     : **{injection_hint}**

### Checkpoint to weaken or remove
- Type : `{checkpoint_type}`
- Code : `{checkpoint_text}`
- Line : {checkpoint_line}

### Sensitive operation (keep intact — it must still execute)
- Type : `{operation_type}`
- Code : `{operation_text}`
- Line : {operation_line}

**A1. Locate the file:**
```mswea_bash_command
find /src -type f -name "{file_basename}" 2>/dev/null | head -10
```

**A2. Read the file** (replace TFILE with the path found above):
```mswea_bash_command
TFILE="<path>"; cat -n "$TFILE" | head -120
```

**A3. Backup and inject** — ONE minimal, realistic change:
```mswea_bash_command
TFILE="<path>"; cp "$TFILE" "$TFILE.orig" && python3 - <<'PYEOF'
path = "<path>"
src = open(path).read()
patched = src.replace(
    "<exact original checkpoint code>",
    "<weakened version>"
)
assert patched != src, "No change made — check your replacement strings"
open(path, "w").write(patched)
print("Patch applied successfully")
PYEOF
```
   Alternative: `sed -i 's/old/new/' <path>`

{syntax_check_section}

**A5. Save the unified diff to `/tmp/vuln.patch`:**
```mswea_bash_command
diff -u "<path>.orig" "<path>" > /tmp/vuln.patch || true
cat /tmp/vuln.patch
```

---

# Part B — Verify with Test Harness

{harness_note}

```mswea_bash_command
bash /tmp/test_harness.sh 2>&1 | tail -30; echo "HARNESS_EXIT:$?"
```

---

# Part C — Write the Exploit

**C1. Study the vulnerable function** to understand what inputs reach the operation:
```mswea_bash_command
cat -n "<path>" | head -80
```

{exploit_template_section}

{run_exploit_cmd}

Iterate and refine if the exploit did not trigger the vulnerability.

---

# Submit

When both `/tmp/vuln.patch` and the exploit script are ready:
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/vuln.patch` MUST exist and contain a non-empty unified diff.
{exploit_file_rule}
- Make ONE minimal patch change — a plausible developer mistake.
- Do NOT combine the submit echo with any other command.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Task: Autonomous Repository Exploration (writes /tmp/candidates.json)
# ─────────────────────────────────────────────────────────────────────────────

REPO_EXPLORE_TASK = """\
You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — the project's packages are installed.

## Goal
Explore the source code and identify **{top_n} vulnerability injection candidates**:
locations where removing or weakening a security checkpoint would let a sensitive
operation execute unsafely.

Write your findings to `/tmp/candidates.json`.
Every candidate must reference code you actually read — do NOT invent paths or lines.

---

## Output Schema — keep it minimal, post-processing fills the rest

```json
{{
  "repo": "/src/{project}",
  "exploration_notes": "<one paragraph: what the project does, which files you read>",
  "candidates": [
    {{
      "file": "/absolute/path/to/file.py",
      "function": "function_name",
      "line_range": [start_line, end_line],
      "checkpoint": {{
        "type": "<checkpoint_type>",
        "text": "<exact source line>",
        "line": <line_number>
      }},
      "operation": {{
        "type": "<operation_type>",
        "text": "<exact source line>",
        "line": <line_number>
      }},
      "cwe_candidates": ["CWE-XXX", "CWE-YYY"],
      "cwe_groups": ["<group name>"],
      "injection_hint": "<one sentence: how to weaken or remove the checkpoint>",
      "reasoning": "<one sentence: why removing this checkpoint is dangerous>"
    }}
  ]
}}
```

## Checkpoint types (use exactly these labels)
null_check, bounds_check, type_check, auth_guard, ownership_check, assert,
error_check, shape_check, format_check, overflow_check, signature_check,
lock_acquire, rate_limit, csrf_check, sanitize, path_traversal_check,
content_type_check, size_check, redirect_check

## Operation types (use exactly these labels)
eval_exec, deser, file_op, subprocess, data_return, state_mutation,
memory_view, array_index, alloc, sql_exec, template_render, http_request,
xml_parse, log_op, crypto_op, redirect_op, header_inject, cookie_op,
regex_exec, env_write, priv_op, socket_op, reflection_op

---

## Exploration Steps

**1. Orient — find the source tree:**
```mswea_bash_command
ls /src/ && find /src/{project} -name "*.py" -not -path "*/test*" -not -path "*/__pycache__/*" -not -path "*/.git/*" 2>/dev/null | sort | head -60
```

**2. Find files that touch dangerous operations:**
```mswea_bash_command
grep -rln "eval\\|exec\\|subprocess\\|pickle\\|yaml.load\\|open(\\|os.path\\|.query\\|render\\|getattr" /src/{project} --include="*.py" 2>/dev/null | grep -v "test" | head -20
```

**3. Read a promising file** (repeat this for multiple files):
```mswea_bash_command
cat -n /src/{project}/<chosen_file>.py | head -200
```

Look for functions that:
- Accept external/user-controlled input
- Have a guard (if / assert / raise) **before** a dangerous call
- Handle file paths, shell args, SQL, deserialization, auth, or template rendering

**4. Grep for exact line numbers** of dangerous calls:
```mswea_bash_command
grep -n "eval\\|exec\\|subprocess\\|open(\\|pickle\\|yaml\\|query\\|render" /src/{project}/<file>.py
```

**5. Write `/tmp/candidates.json`** via python3:
```mswea_bash_command
python3 - << 'PYEOF'
import json
candidates = [
    # fill in your candidate dicts here
]
data = {{"repo": "/src/{project}", "exploration_notes": "TODO", "candidates": candidates}}
with open("/tmp/candidates.json", "w") as f:
    json.dump(data, f, indent=2)
print(f"Written {{len(candidates)}} candidates")
PYEOF
```

**6. Verify:**
```mswea_bash_command
python3 -c "import json; d=json.load(open('/tmp/candidates.json')); print('OK:', len(d['candidates']), 'candidates')"
```

**7. Submit:**
```mswea_bash_command
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/candidates.json` MUST exist and contain valid JSON with a `candidates` array.
- Every candidate MUST use real file paths, real function names, real lines you saw.
- Find at least **{top_n}** candidates. Keep reading files if early ones look clean.
- Prefer candidates with a clearly meaningful checkpoint guarding a genuinely dangerous op.
- Do NOT combine the submit echo with any other command.
"""


# ─────────────────────────────────────────────────────────────────────────────
# Harness helper — build the harness_note injected into task prompts
# ─────────────────────────────────────────────────────────────────────────────

def build_harness_note(harness_available: bool) -> str:
    """
    Return a one-line note about harness availability for injection into prompts.
    The harness is pre-installed at /tmp/test_harness.sh via setup_commands.
    """
    if harness_available:
        return (
            "A test harness is pre-installed at `/tmp/test_harness.sh`. "
            "Run it to verify the patch doesn't break existing tests."
        )
    return (
        "No test harness is available for this project — "
        "skip the harness step and proceed to the next step."
    )


# ─────────────────────────────────────────────────────────────────────────────
# Utility
# ─────────────────────────────────────────────────────────────────────────────

def extract_all_text_from_messages(messages: list[dict]) -> str:
    """
    Concatenate text from assistant and tool messages only.
    Skips user/system messages to avoid false-positive marker matches
    when the prompt template itself contains placeholder text.
    """
    parts: list[str] = []
    for msg in messages:
        role = msg.get("role", "")
        if role in ("user", "system"):
            continue
        content = msg.get("content", "")
        if isinstance(content, str):
            if content.strip():
                parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("text", "") or block.get("output", "")
                    if text and text.strip():
                        parts.append(text)
    return "\n\n".join(parts)
