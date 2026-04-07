"""Prompt builder for language-aware repository exploration."""

from __future__ import annotations

# Default per-specialist pool size; overridden at runtime by the budget planner.
_DEFAULT_POOL_SIZE = 50

# Ordered list of specialist roles.  Each agent runs sequentially and receives
# the locations already claimed by earlier agents so it focuses on fresh ground.
SPECIALIST_ROLES: list[dict] = [
    {
        "name": "injection_input",
        "label": "Injection & Input Handling",
        "cwe_groups": [
            "Input validation", "Web", "Dynamic code", "Path-related", "Meta",
        ],
        "focus": (
            "SQL injection, OS command injection, code injection (eval/exec), "
            "cross-site scripting (XSS), path traversal, template injection, "
            "deserialization of untrusted data, and missing input validation or sanitization."
        ),
        "py_keywords":  r"eval|exec|subprocess|pickle|yaml\.load|os\.path|\.query\b|render|sanitize|escape|lxml|template",
        "js_keywords":  r"eval|Function\(|child_process|exec|spawn|fs\.|vm\.|yaml|deserialize|innerHTML|document\.write|dangerouslySet",
        "c_keywords":   r"system\(|popen|execv|sprintf|snprintf|gets\b|scanf|sscanf|strcpy|strncpy",
    },
    {
        "name": "memory_numeric",
        "label": "Memory & Numeric Safety",
        "cwe_groups": [
            "Ante buffer operation", "Post buffer operation", "Memory allocation",
            "Memory release", "Memory leak", "Expired memory", "Invalid pointer",
            "Numeric errors", "Calculation", "Strings", "Undefined behavior",
            "Free of stack memory",
        ],
        "focus": (
            "Buffer overflows, use-after-free, double-free, null pointer dereference, "
            "integer overflow/underflow, incorrect size calculations, off-by-one errors, "
            "uninitialized memory, and missing bounds checks on array or buffer access."
        ),
        "py_keywords":  r"ctypes|struct\.pack|array\.|memoryview|bytearray|c_char|POINTER\b|cast\b",
        "js_keywords":  r"Buffer\b|ArrayBuffer|DataView|TypedArray|SharedArrayBuffer|Uint8Array|byteLength|\.offset\b",
        "c_keywords":   r"malloc|calloc|realloc\b|free\(|strcpy|strncpy|memcpy|memmove|memset|strlen\b|sizeof\b",
    },
    {
        "name": "access_control",
        "label": "Access Control & Confidentiality",
        "cwe_groups": [
            "Access control", "Authentication", "Privileges", "Credentials management",
            "Confidentiality", "Encapsulation",
        ],
        "focus": (
            "Missing or bypassable authentication checks, broken access control, privilege escalation, "
            "insecure direct object references (IDOR), hardcoded credentials, sensitive data exposure, "
            "weak session management, and missing authorization guards."
        ),
        "py_keywords":  r"auth|permission|role\b|token|password|secret|session|credential|admin|privilege|login|verify|is_admin|has_perm",
        "js_keywords":  r"auth|permission|role\b|token|password|secret|session|credential|admin|privilege|login|verify|isAdmin|jwt\b|bcrypt",
        "c_keywords":   r"auth|password|token|secret|session|credential|admin|privilege|uid\b|gid\b|setuid|getuid",
    },
    {
        "name": "concurrency_api",
        "label": "Concurrency, API Misuse & Resource Management",
        "cwe_groups": [
            "Concurrency", "API", "Resource management", "Control flow",
            "Error condition", "Unhandled errors", "Return value",
            "Denial of Service", "Cleanup", "Loop and recursion",
        ],
        "focus": (
            "Race conditions (TOCTOU), improper locking, unsafe shared state, "
            "unchecked return values of security-relevant functions, resource leaks "
            "(file handles, sockets, memory), missing error handling, and "
            "algorithmic complexity attacks."
        ),
        "py_keywords":  r"thread|Lock\b|RLock\b|async\b|await\b|open\(|socket|finally\b|contextmanager|timeout|Semaphore",
        "js_keywords":  r"Promise\b|async\b|await\b|setTimeout|setInterval|EventEmitter|stream\b|socket|fs\.open|\.lock\b",
        "c_keywords":   r"pthread|mutex|lock\b|unlock\b|sem_|fopen|fclose\b|open\(|close\(|socket\(|signal\b|errno\b",
    },
]


_REPO_EXPLORE_TASK_TEMPLATE = """\
You are working in the project workspace for **{project}**.
The source checkout is available under `/src/{project}`.

## Goal
Explore the source code and identify **{top_n} vulnerability injection candidates**:
locations where removing or weakening a security checkpoint would let a sensitive
operation execute unsafely.

Target language: **{language_label}**

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
      "file": "/absolute/path/to/file",
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
```bash
ls /src/ && {orient_cmd}
```

**2. Find files that touch dangerous operations:**
```bash
{search_cmd}
```

**3. Read a promising file** (repeat this for multiple files):
```bash
{read_cmd}
```

Look for functions that:
- Accept external/user-controlled input
- Have a guard (if / assert / raise) **before** a dangerous call
- Handle file paths, shell args, SQL, deserialization, auth, or template rendering
- Live in real runtime/library code, not tests, fixtures, examples, docs, or vendored code

**4. Grep for exact line numbers** of dangerous calls:
```bash
{detail_cmd}
```

**5. Write `/tmp/candidates.json`** via python3:
```bash
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
```bash
python3 -c "import json; d=json.load(open('/tmp/candidates.json')); print('OK:', len(d['candidates']), 'candidates')"
```

**7. Submit:**
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/candidates.json` MUST exist and contain valid JSON with a `candidates` array.
- Every candidate MUST use real file paths, real function names, real lines you saw.
- Find at least **{top_n}** candidates. Keep reading files if early ones look clean.
- Prefer candidates with a clearly meaningful checkpoint guarding a genuinely dangerous op.
- Only select candidates from real application or library runtime code.
- Reject paths under tests, specs, examples, docs, benchmarks, fixtures, mocks, generated code, vendored code, and dependency directories.
- Treat these path fragments as out of scope unless the project's main runtime truly lives there:
  `/test/`, `/tests/`, `/testing/`, `/spec/`, `/specs/`, `/example/`, `/examples/`, `/doc/`, `/docs/`,
  `/bench/`, `/benchmark/`, `/fixtures/`, `/mocks/`, `/node_modules/`, `/vendor/`, `/third_party/`,
  `/third-party/`, `/external/`, `/dist/`, `/build/`, `/coverage/`, `/site-packages/`.
- Prefer code under `src/`, `lib/`, package directories, or the project's main runtime modules.
- Do not use assertions in tests as security checkpoints.
- Before writing `/tmp/candidates.json`, remove any candidate from a non-production path.
- Do NOT combine the submit echo with any other command.
"""


def build_repo_explore_task(*, project: str, top_n: int, language: str) -> str:
    lang = (language or "python").lower()

    if lang in {"javascript", "js", "node", "nodejs", "typescript", "ts"}:
        return _REPO_EXPLORE_TASK_TEMPLATE.format(
            project=project,
            top_n=top_n,
            language_label="JavaScript / TypeScript",
            orient_cmd=(
                f'find /src/{project} \\( -name "*.js" -o -name "*.cjs" -o -name "*.mjs" '
                f'-o -name "*.ts" \\) -not -path "*/test/*" -not -path "*/tests/*" '
                f'-not -path "*/spec/*" -not -path "*/specs/*" -not -path "*/example/*" '
                f'-not -path "*/examples/*" -not -path "*/doc/*" -not -path "*/docs/*" '
                f'-not -path "*/bench/*" -not -path "*/benchmark/*" -not -path "*/fixture/*" '
                f'-not -path "*/fixtures/*" -not -path "*/mock/*" -not -path "*/mocks/*" '
                f'-not -path "*/node_modules/*" -not -path "*/vendor/*" -not -path "*/third_party/*" '
                f'-not -path "*/third-party/*" -not -path "*/external/*" -not -path "*/dist/*" '
                f'-not -path "*/build/*" -not -path "*/coverage/*" -not -path "*/.git/*" '
                f'2>/dev/null | sort | head -60'
            ),
            search_cmd=(
                f'grep -rln "eval\\|Function(\\|child_process\\|exec\\|spawn\\|fs\\.\\|http\\.\\|https\\.\\|'
                f'vm\\.\\|yaml\\|parse\\|deserialize\\|innerHTML\\|setHeader\\|cookie" /src/{project} '
                f'--include="*.js" --include="*.cjs" --include="*.mjs" --include="*.ts" 2>/dev/null | '
                f'grep -Ev "/(test|tests|testing|spec|specs|example|examples|doc|docs|bench|benchmark|fixture|fixtures|mock|mocks|node_modules|vendor|third_party|third-party|external|dist|build|coverage)/" | '
                f'head -20'
            ),
            read_cmd=f'cat -n /src/{project}/<chosen_file>.js | head -220',
            detail_cmd=(
                f'grep -n "eval\\|Function(\\|child_process\\|exec\\|spawn\\|fs\\.\\|http\\.\\|https\\.\\|'
                f'vm\\.\\|yaml\\|parse\\|deserialize\\|innerHTML\\|setHeader\\|cookie" /src/{project}/<file>.js'
            ),
        )

    if lang in {"c", "cpp", "c++"}:
        return _REPO_EXPLORE_TASK_TEMPLATE.format(
            project=project,
            top_n=top_n,
            language_label="C / C++",
            orient_cmd=(
                f'find /src/{project} \\( -name "*.c" -o -name "*.cc" -o -name "*.cpp" -o -name "*.cxx" '
                f'-o -name "*.h" -o -name "*.hpp" \\) -not -path "*/test/*" -not -path "*/tests/*" '
                f'-not -path "*/spec/*" -not -path "*/specs/*" -not -path "*/example/*" '
                f'-not -path "*/examples/*" -not -path "*/doc/*" -not -path "*/docs/*" '
                f'-not -path "*/bench/*" -not -path "*/benchmark/*" -not -path "*/fixture/*" '
                f'-not -path "*/fixtures/*" -not -path "*/mock/*" -not -path "*/mocks/*" '
                f'-not -path "*/vendor/*" -not -path "*/third_party/*" -not -path "*/third-party/*" '
                f'-not -path "*/external/*" -not -path "*/build/*" -not -path "*/.git/*" '
                f'2>/dev/null | sort | head -60'
            ),
            search_cmd=(
                f'grep -rln "strcpy\\|strncpy\\|memcpy\\|memmove\\|sprintf\\|snprintf\\|system(\\|popen\\|execv\\|'
                f'open(\\|fopen\\|read(\\|write(\\|malloc\\|calloc\\|realloc\\|free\\|assert\\|atoi\\|strtol" '
                f'/src/{project} --include="*.c" --include="*.cc" --include="*.cpp" --include="*.cxx" '
                f'--include="*.h" --include="*.hpp" 2>/dev/null | '
                f'grep -Ev "/(test|tests|testing|spec|specs|example|examples|doc|docs|bench|benchmark|fixture|fixtures|mock|mocks|vendor|third_party|third-party|external|build)/" | '
                f'head -20'
            ),
            read_cmd=f'cat -n /src/{project}/<chosen_file>.c | head -220',
            detail_cmd=(
                f'grep -n "strcpy\\|strncpy\\|memcpy\\|memmove\\|sprintf\\|snprintf\\|system(\\|popen\\|execv\\|'
                f'open(\\|fopen\\|read(\\|write(\\|malloc\\|calloc\\|realloc\\|free\\|assert\\|atoi\\|strtol" '
                f'/src/{project}/<file>.c'
            ),
        )

    return _REPO_EXPLORE_TASK_TEMPLATE.format(
        project=project,
        top_n=top_n,
        language_label="Python",
        orient_cmd=(
            f'find /src/{project} -name "*.py" -not -path "*/test*" -not -path "*/spec*" '
            f'-not -path "*/example/*" -not -path "*/examples/*" -not -path "*/doc/*" '
            f'-not -path "*/docs/*" -not -path "*/bench/*" -not -path "*/benchmark/*" '
            f'-not -path "*/fixture/*" -not -path "*/fixtures/*" -not -path "*/mock/*" '
            f'-not -path "*/mocks/*" -not -path "*/vendor/*" -not -path "*/third_party/*" '
            f'-not -path "*/third-party/*" -not -path "*/external/*" -not -path "*/site-packages/*" '
            f'-not -path "*/build/*" -not -path "*/dist/*" -not -path "*/__pycache__/*" '
            f'-not -path "*/.git/*" 2>/dev/null | sort | head -60'
        ),
        search_cmd=(
            f'grep -rln "eval\\|exec\\|subprocess\\|pickle\\|yaml.load\\|open(\\|os.path\\|.query\\|render\\|getattr" '
            f'/src/{project} --include="*.py" 2>/dev/null | '
            f'grep -Ev "/(test|tests|testing|spec|specs|example|examples|doc|docs|bench|benchmark|fixture|fixtures|mock|mocks|vendor|third_party|third-party|external|site-packages|build|dist)/" | '
            f'head -20'
        ),
        read_cmd=f'cat -n /src/{project}/<chosen_file>.py | head -200',
        detail_cmd=(
            f'grep -n "eval\\|exec\\|subprocess\\|open(\\|pickle\\|yaml\\|query\\|render" '
            f'/src/{project}/<file>.py'
        ),
    )


# ---------------------------------------------------------------------------
# Specialist agent prompt (multi-agent mode)
# ---------------------------------------------------------------------------

_SPECIALIST_EXPLORE_TASK_TEMPLATE = """\
You are working in the project workspace for **{project}**.
The source checkout is available under `/src/{project}`.

## Your Role: {role_label} Specialist
You are a specialist focused **exclusively** on **{role_label}** vulnerabilities.

**CWE groups in scope:** {cwe_groups_str}

**What to look for:**
{focus}

Do NOT report candidates outside your specialty — another agent covers those.

## Goal
Identify **at least {min_target} and up to {top_n} vulnerability injection candidates** within your specialty:
locations where removing or weakening a security checkpoint would let a sensitive
operation execute unsafely.  Target language: **{language_label}**.

Write your findings to `/tmp/candidates.json`.
Every candidate must reference code you actually read — do NOT invent paths or lines.
Write early and update incrementally: as soon as you have a batch of candidates,
write the file; then extend it after each additional batch.

{codebase_tree_block}{runtime_files_block}{already_found_section}
---

## Output schema

```json
{{
  "repo": "/src/{project}",
  "role": "{role_name}",
  "exploration_notes": "<one paragraph: which files you read, what patterns you found>",
  "candidates": [
    {{
      "file": "/absolute/path/to/file",
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
      "cwe_candidates": ["CWE-XXX"],
      "cwe_groups": ["<group name>"],
      "injection_hint": "<one sentence: how to weaken or remove the checkpoint>",
      "reasoning": "<one sentence: why this is dangerous>",
      "confidence": <0.0–1.0>
    }}
  ]
}}
```

### Checkpoint types
null_check, bounds_check, type_check, auth_guard, ownership_check, assert,
error_check, shape_check, format_check, overflow_check, signature_check,
lock_acquire, rate_limit, csrf_check, sanitize, path_traversal_check,
content_type_check, size_check, redirect_check

### Operation types
eval_exec, deser, file_op, subprocess, data_return, state_mutation,
memory_view, array_index, alloc, sql_exec, template_render, http_request,
xml_parse, log_op, crypto_op, redirect_op, header_inject, cookie_op,
regex_exec, env_write, priv_op, socket_op, reflection_op

---

## Exploration steps

**1. Create `/tmp/candidates.json` immediately (checkpoint file):**
```bash
cat > /tmp/candidates.json << 'JSONEOF'
{{
  "repo": "/src/{project}",
  "role": "{role_name}",
  "exploration_notes": "initial checkpoint",
  "candidates": []
}}
JSONEOF
```

**2. Read your CWE reference** — do this next:
```bash
cat /tmp/cwe_reference.json
```
Lists every CWE ID in scope for your specialty with its description.
Use **only** these IDs in `cwe_candidates`. Do not invent CWE IDs.

**3. Find files relevant to your specialty** from the in-scope list above:

```bash
{search_cmd}
```

**4. Read and analyse promising files** — repeat for as many files as needed:
```bash
{read_cmd}
```

Look for functions that:
- Accept external or user-controlled input
- Have a guard (`if` / `assert` / `raise`) **before** a dangerous call in your specialty
- Are real runtime or library code (not tests, fixtures, or examples)

**5. Grep for exact line numbers** of dangerous calls:
```bash
{detail_cmd}
```

**6. Update `/tmp/candidates.json` continuously:**
- As soon as you have the first valid candidate, immediately write a non-empty `/tmp/candidates.json`.
- After every **2-3 additional validated candidates**, rewrite `/tmp/candidates.json`.
- Do not keep candidate lists only in memory.
- Ensure `exploration_notes` reflects what you actually inspected.

**7. Verify before submit:**
```bash
jq '.candidates | length' /tmp/candidates.json
jq empty /tmp/candidates.json
```

**8. Submit:**
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

---

## Rules
- `/tmp/candidates.json` MUST exist and contain valid JSON before you submit.
- Every candidate MUST reference a real file from the in-scope list above, a real function name, and real line numbers you observed.
- `cwe_candidates` MUST only contain IDs from `/tmp/cwe_reference.json`.
- Only report candidates that genuinely fit your specialty CWE groups.
- Prefer breadth: cover as many different files and functions as possible. Avoid near-overlapping ranges from the same function.
- Perform no more than 8 file reads before your first non-empty `/tmp/candidates.json` update.
- Aim to reach at least **{min_target}** candidates before submitting; keep searching additional files if below target.
- If you cannot reach **{min_target}** after thorough exploration, submit the best valid set you found.
- If a command fails (for example regex/grep syntax), fix the command and continue; do not submit immediately after failed commands.
- Never exit without a valid `/tmp/candidates.json` file, even if it is partial.
- Do NOT combine the submit echo with any other command.
"""

_ALREADY_FOUND_SECTION_TEMPLATE = """\
## Already identified — DO NOT RE-PROPOSE
The following `(file, function)` pairs were found by a previous specialist.
Skip them and focus on fresh locations only.

{entries}
"""


_MAX_FILES_IN_PROMPT = 150  # cap to avoid bloating the context window


_PLANNER_PROMPT_TEMPLATE = """\
You are allocating a vulnerability analysis budget for project "{project}" ({language}).
Your goal is to weight each specialist by how relevant its category is to THIS specific codebase.
Do NOT default to an equal split — skew heavily toward the most relevant categories.

Examples of strong skews:
- Web framework / HTTP server -> inject injection_input with 50-60% of budget
- C/C++ memory-heavy library -> give memory_numeric 50-60%
- Auth / IAM service -> give access_control 50-60%
- Async / event-driven runtime -> give concurrency_api 40-50%

In-scope source files ({file_count} total):
{file_sample}

README:
{readme_section}

Specialists - allocate exactly {total_pool} total, minimum {min_each} each:
{specialist_lines}

Respond with JSON only:
{{"injection_input": N, "memory_numeric": N, "access_control": N, "concurrency_api": N}}"""


def build_budget_planner_prompt(
    *,
    project: str,
    language: str,
    file_count: int,
    file_sample: str,
    readme_section: str,
    total_pool: int,
    min_each: int,
    specialist_lines: str,
) -> str:
    """Build the budget-allocation prompt for llm_explore planner call."""
    return _PLANNER_PROMPT_TEMPLATE.format(
        project=project,
        language=language,
        file_count=file_count,
        file_sample=file_sample,
        readme_section=readme_section,
        total_pool=total_pool,
        min_each=min_each,
        specialist_lines=specialist_lines,
    )


def build_specialist_explore_task(
    *,
    project: str,
    language: str,
    role: dict,
    runtime_files: list[str],
    already_found: list[tuple[str, str]],
    codebase_tree: str = "",
    pool_size: int = _DEFAULT_POOL_SIZE,
) -> str:
    """Build a focused exploration prompt for a single specialist agent."""
    lang = (language or "python").lower()

    role_name: str = role["name"]
    role_label: str = role["label"]
    cwe_groups: list[str] = role["cwe_groups"]
    focus: str = role["focus"]
    min_target = max(5, min(pool_size, 15))

    if lang in {"javascript", "js", "node", "nodejs", "typescript", "ts"}:
        language_label = "JavaScript / TypeScript"
        kw = role["js_keywords"]
        read_cmd = "cat -n <chosen_file> | head -220"
    elif lang in {"c", "cpp", "c++"}:
        language_label = "C / C++"
        kw = role["c_keywords"]
        read_cmd = "cat -n <chosen_file> | head -220"
    else:
        language_label = "Python"
        kw = role["py_keywords"]
        read_cmd = "cat -n <chosen_file> | head -200"

    # /tmp/runtime_files.txt is written by a setup command before the agent starts.
    search_cmd = f'xargs grep -El "{kw}" < /tmp/runtime_files.txt 2>/dev/null | head -20'
    detail_cmd = f'grep -n "{kw}" <file>'

    # Codebase tree block for quick structural orientation.
    if codebase_tree:
        codebase_tree_block = (
            "## Repository structure\n\n"
            f"```\n{codebase_tree}\n```\n\n"
        )
    else:
        codebase_tree_block = ""

    # Build the runtime files block embedded directly in the prompt.
    if runtime_files:
        shown = runtime_files[:_MAX_FILES_IN_PROMPT]
        tail = (
            f"\n... and {len(runtime_files) - _MAX_FILES_IN_PROMPT} more"
            if len(runtime_files) > _MAX_FILES_IN_PROMPT
            else ""
        )
        file_list = "\n".join(shown) + tail
        runtime_files_block = (
            f"## In-scope runtime files ({len(runtime_files)} total)\n"
            "Pre-filtered to exclude tests, docs, vendor, build artefacts, fixtures, and generated code.\n"
            "**Work exclusively within these files.**\n\n"
            f"```\n{file_list}\n```\n\n"
        )
    else:
        runtime_files_block = ""

    if already_found:
        entries = "\n".join(f"- {path} :: {symbol}" for path, symbol in already_found)
        already_found_section = _ALREADY_FOUND_SECTION_TEMPLATE.format(entries=entries)
    else:
        already_found_section = ""

    return _SPECIALIST_EXPLORE_TASK_TEMPLATE.format(
        project=project,
        role_name=role_name,
        role_label=role_label,
        cwe_groups_str=", ".join(cwe_groups),
        focus=focus,
        top_n=pool_size,
        min_target=min_target,
        language_label=language_label,
        codebase_tree_block=codebase_tree_block,
        runtime_files_block=runtime_files_block,
        search_cmd=search_cmd,
        read_cmd=read_cmd,
        detail_cmd=detail_cmd,
        already_found_section=already_found_section,
    )
