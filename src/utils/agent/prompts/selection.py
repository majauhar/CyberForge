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
            "Comparison", "Expression",
        ],
        "focus": (
            "Vulnerabilities arising from untrusted data reaching dangerous sinks without proper validation, "
            "encoding, or contextual sanitization. Covered CWE groups:\n"
            "- Input validation: Missing or improper validation or sanitization of user/external input — "
            "look for raw request parameters used directly in queries, shell commands, or rendering.\n"
            "- Web: XSS, open redirect, XXE, tainted input, or other web-specific vulnerabilities — "
            "look for unsanitized data written to HTML responses, HTTP headers, or reflected in URLs.\n"
            "- Dynamic code: Injection or misuse of dynamically loaded, generated, or evaluated code — "
            "look for eval(), exec(), compile(), and template engines processing user-controlled data.\n"
            "- Path-related: Path traversal, injection via paths, or insecure path construction — "
            "look for user-supplied path components passed to file operations without normalization.\n"
            "- Meta: Improper handling of escape, meta, or control sequences in input/output — "
            "look for unescaped special characters in SQL, shell, log, or format strings.\n"
            "- Comparison: Incorrect or inconsistent comparison logic leading to security impact — "
            "look for type-unsafe comparisons (== vs ===), off-by-one in length checks, or "
            "signed/unsigned mismatches used in validation guards.\n"
            "- Expression: Dangerous or incorrect expressions, operator precedence, or evaluation order — "
            "look for expression evaluation on user-controlled data (formula injection, template "
            "expressions, or operator-precedence bugs in security conditions)."
        ),
        "py_keywords":  r"eval|exec|subprocess|pickle|yaml\.load|os\.path|\.query\b|render|sanitize|escape|lxml|template|compile\b",
        "js_keywords":  r"eval|Function\(|child_process|exec|spawn|fs\.|vm\.|yaml|deserialize|innerHTML|document\.write|dangerouslySet|path\.join",
        "c_keywords":   r"system\(|popen|execv|sprintf|snprintf|gets\b|scanf|sscanf|strcpy|strncpy|strcmp|strncmp",
    },
    {
        "name": "memory_safety",
        "label": "Memory, Numeric & Low-Level Safety",
        "cwe_groups": [
            "Ante buffer operation", "Post buffer operation", "Memory allocation",
            "Memory release", "Memory leak", "Expired memory", "Invalid pointer",
            "Numeric errors", "Calculation", "Strings", "Undefined behavior",
            "Free of stack memory", "Initialization", "Type-related",
            "Data structure", "Function call",
        ],
        "focus": (
            "Memory corruption, unsafe numeric handling, and low-level programming errors that lead to "
            "exploitable conditions. Covered CWE groups:\n"
            "- Ante buffer operation: Buffer overflows, underflows, out-of-bounds read/write before or "
            "during buffer access — look for missing bounds checks before memcpy/strcpy or array indexing.\n"
            "- Post buffer operation: Errors after buffer operations, e.g. missing null termination — "
            "look for strncpy without explicit null termination or off-by-one in terminal writes.\n"
            "- Memory allocation: Incorrect allocation size, failed allocation not checked, or allocation "
            "abuse — look for malloc/new without NULL check, or sizes derived from user input.\n"
            "- Memory release: Double free, incorrect free, or improper release of memory — "
            "look for free() called twice on the same pointer or free() applied to stack memory.\n"
            "- Memory leak: Failure to free allocated memory leading to resource exhaustion — "
            "look for early-return paths that bypass free/delete.\n"
            "- Expired memory: Use of freed or expired memory, use-after-free, or dangling references — "
            "look for pointer use after free() or after container reallocation invalidates iterators.\n"
            "- Invalid pointer: Dereference of null, invalid, or incorrectly computed pointers — "
            "look for missing NULL checks after allocation or pointer arithmetic errors.\n"
            "- Numeric errors: Integer overflow/underflow, truncation, or incorrect numeric handling — "
            "look for arithmetic on size_t/int without overflow guards before use as buffer sizes.\n"
            "- Calculation: Incorrect buffer/size/length calculations, off-by-one, divide-by-zero, "
            "pointer scaling — look for size expressions like strlen(s)+1 passed to allocation functions.\n"
            "- Strings: Unsafe string handling, missing bounds checks, or improper encoding — "
            "look for unbounded string copies or format strings sourced from user input.\n"
            "- Undefined behavior: Reliance on undefined, unspecified, or implementation-defined behavior "
            "— look for signed integer overflow, null pointer arithmetic, or unsequenced side effects.\n"
            "- Free of stack memory: Incorrect freeing of stack memory or stack-based buffer misuse — "
            "look for free() called on VLA or stack-allocated arrays.\n"
            "- Initialization: Uninitialized variables, incorrect initialization order, or missing init — "
            "look for variables used before assignment, especially on early-exit code paths.\n"
            "- Type-related: Type confusion, unsafe casting, or incorrect type handling — "
            "look for void* casts, union misuse, or reinterpret_cast in security-sensitive paths.\n"
            "- Data structure: Unsafe or incorrect use of data structures causing corruption or abuse — "
            "look for concurrent mutation of shared containers without locking, or index aliasing bugs.\n"
            "- Function call: Incorrect or unsafe function call conventions, arguments, or callbacks — "
            "look for wrong size/count arguments to memcpy/read/write, or incorrect variadic argument types."
        ),
        "py_keywords":  r"ctypes|struct\.pack|array\.|memoryview|bytearray|c_char|POINTER\b|cast\b|cffi|cython",
        "js_keywords":  r"Buffer\b|ArrayBuffer|DataView|TypedArray|SharedArrayBuffer|Uint8Array|byteLength|\.offset\b|WebAssembly",
        "c_keywords":   r"malloc|calloc|realloc\b|free\(|strcpy|strncpy|memcpy|memmove|memset|strlen\b|sizeof\b|alloca\b",
    },
    {
        "name": "access_control",
        "label": "Access Control, Identity & Confidentiality",
        "cwe_groups": [
            "Access control", "Authentication", "Privileges", "Credentials management",
            "Confidentiality", "Encapsulation", "Information loss", "Environment induced",
            "Malware-related",
        ],
        "focus": (
            "Weaknesses in who can access what, how identity is established, and how sensitive data is "
            "protected. Covered CWE groups:\n"
            "- Access control: Improper permissions, privileges, authorization, or exposure of resources "
            "to wrong parties — look for missing authorization checks before sensitive operations or IDOR patterns.\n"
            "- Authentication: Weak or bypassed authentication, session handling, or reliance on untrusted "
            "identity — look for skippable login steps, predictable tokens, or identity derived from "
            "user-controlled data.\n"
            "- Privileges: Privilege escalation, incorrect privilege assignment, or privilege confusion — "
            "look for setuid/seteuid calls, sudo invocations, or role elevation without re-verification.\n"
            "- Credentials management: Hard-coded credentials, weak storage, or improper handling of "
            "secrets — look for passwords/API keys in source, weak hashing (MD5/SHA1), or plaintext logging.\n"
            "- Confidentiality: Information disclosure, exposure of sensitive data, or weak encryption — "
            "look for debug endpoints leaking stack traces, weak cipher suites, or unencrypted sensitive fields.\n"
            "- Encapsulation: Violation of encapsulation exposing internals or mutable shared state — "
            "look for public fields that should be private, or returning internal mutable structures to callers.\n"
            "- Information loss: Loss or corruption of security-relevant information — "
            "look for audit log truncation, silent error swallowing that discards security events, or "
            "lossy encoding of user identity.\n"
            "- Environment induced: Vulnerabilities introduced or triggered by environment configuration — "
            "look for secrets read from unprotected env vars, insecure defaults enabled in production, "
            "or trust of externally-set HTTP headers (X-Forwarded-For, X-Real-IP).\n"
            "- Malware-related: Behaviors or patterns that enable or resemble malware — "
            "look for hidden backdoors, covert data exfiltration channels, or code that disables security controls."
        ),
        "py_keywords":  r"auth|permission|role\b|token|password|secret|session|credential|admin|privilege|login|verify|is_admin|has_perm|os\.environ|getenv\b",
        "js_keywords":  r"auth|permission|role\b|token|password|secret|session|credential|admin|privilege|login|verify|isAdmin|jwt\b|bcrypt|process\.env",
        "c_keywords":   r"auth|password|token|secret|session|credential|admin|privilege|uid\b|gid\b|setuid|getuid|getenv\b|environ\b",
    },
    {
        "name": "reliability_api",
        "label": "Reliability, API Misuse & Resource Management",
        "cwe_groups": [
            "Concurrency", "API", "Resource management", "Control flow",
            "Error condition", "Unhandled errors", "Return value",
            "Denial of Service", "Cleanup", "Loop and recursion",
            "Code quality", "Design and implementation",
        ],
        "focus": (
            "Weaknesses in program reliability, correct API usage, and resource lifecycle that enable "
            "denial-of-service, silent security failures, or exploitable edge cases. Covered CWE groups:\n"
            "- Concurrency: Race conditions, improper locking, or unsafe use of shared state in "
            "multithreaded code — look for TOCTOU patterns, check-then-act on shared variables without locks.\n"
            "- API: Misuse of APIs, dangerous functions, violation of API contracts or specifications — "
            "look for deprecated/unsafe API calls or functions used contrary to their documented preconditions.\n"
            "- Resource management: Leaks, double-free, or improper lifecycle of files, handles, or "
            "resources — look for opened files/sockets/handles that are never closed on all code paths.\n"
            "- Control flow: Bypassed or incorrect control flow, unreachable code, or unexpected branching "
            "— look for missing break in switch-case, fall-through to privileged branches, or logic inversion.\n"
            "- Error condition: Improper handling of error conditions, return values, or status codes — "
            "look for missing checks on the return value of security-relevant calls (open, recv, send).\n"
            "- Unhandled errors: Errors or exceptions that are not handled or propagate incorrectly — "
            "look for bare except/catch-all blocks that swallow exceptions and continue insecurely.\n"
            "- Return value: Ignored or misinterpreted return values from security-relevant functions — "
            "look for unchecked results from crypto, auth, or I/O calls that indicate failure.\n"
            "- Denial of Service: Resource exhaustion, crash-inducing inputs, or algorithmic complexity "
            "attacks — look for unbounded loops on user-controlled input, ReDoS-susceptible regexes, "
            "or missing rate limits.\n"
            "- Cleanup: Improper resource shutdown, incomplete cleanup, or faulty finalization — "
            "look for finally/defer blocks missing critical cleanup steps, or destructors leaving "
            "state inconsistent.\n"
            "- Loop and recursion: Incorrect loop bounds, infinite recursion, or iteration errors — "
            "look for recursion depth not bounded by input size, or off-by-one loop bounds on "
            "security-relevant iteration.\n"
            "- Code quality: Poor patterns, dead code, suspicious comments, generic exception handling "
            "— look for TODO/FIXME/HACK comments near security checks, or catch-all handlers that hide failures.\n"
            "- Design and implementation: Flaws in design or implementation that create security weaknesses "
            "— look for security-by-obscurity patterns, missing defense-in-depth layers, or security logic "
            "duplicated inconsistently across the codebase."
        ),
        "py_keywords":  r"thread|Lock\b|RLock\b|async\b|await\b|open\(|socket|finally\b|contextmanager|timeout|Semaphore|except\b|raise\b",
        "js_keywords":  r"Promise\b|async\b|await\b|setTimeout|setInterval|EventEmitter|stream\b|socket|fs\.open|\.lock\b|catch\b|\.finally\b",
        "c_keywords":   r"pthread|mutex|lock\b|unlock\b|sem_|fopen|fclose\b|open\(|close\(|socket\(|signal\b|errno\b|assert\b",
    },
]


_REPO_EXPLORE_TASK_TEMPLATE = """\
You are working in the project workspace for **{project}**.
The source checkout is available under `/src/{project}`.

## Goal
Explore the source code and identify **{top_n} vulnerability injection candidates**:
locations where removing or weakening a security checkpoint would let a sensitive operation execute unsafely. In particular, identify and analyze all sanitization, vulnerability mitigation or any other elements that make the current benign code actually non-vulnerable. Note that it doesn't allways have to be about modifying the code to make it vulnerable, but it can also be about finding relevant places for new vulnerabilities in the code.
It is important to understand the code and the context in which it is used, so that you can identify the most relevant places for new vulnerabilities.
The candidates should be relevant to the project and the context in which it is used, and should NOT disrupt the existing functionality of the code.

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
      "injection_hint": "<one sentence: how to weaken or remove the checkpoint or to introduce the new vulnerability>",
      "reasoning": "<one sentence: why removing this checkpoint is dangerous or why introducing this new vulnerability is dangerous>"
    }}
  ]
}}
```

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
- Handle file paths, shell args, SQL, deserialization, auth, template rendering, or similar
- Live in real runtime/library code, not tests, fixtures, examples, docs, or vendored code

**4. Grep for exact line numbers** of dangerous calls. But you have freedom to choose the most relevant places for new vulnerabilities in the code. The candidates should be relevant to the project and the context in which it is used, and should NOT disrupt the existing functionality of the code.
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
- Prefer candidates with a clearly meaningful checkpoint guarding a genuinely dangerous op or a new vulnerability.
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
Explore the source code and identify up to **{top_n} {role_label} vulnerability injection candidates**:
A candidate is a location where removing or weakening a security checkpoint would let a sensitive operation execute unsafely. In particular, identify and analyze all sanitization, vulnerability mitigation or any other elements that make the current benign code actually non-vulnerable. Note that it doesn't allways have to be about modifying the code to make it vulnerable, but it can also be about finding relevant places for new vulnerabilities in the code.
It is important to understand the code and the context in which it is used, so that you can identify the most relevant places for new vulnerabilities.
The candidates should be relevant to the project and the context in which it is used, and should NOT disrupt the existing functionality of the code.


Target language: **{language_label}**.

**Breadth over exhaustion.** Explore many different files and functions rather than deep-diving into a few.
A few candidates for each file is better than many from a few files. Budget your steps wisely — exploration should take most of your effort; writing takes only 1-2 steps at the end.

{codebase_tree_block}

{runtime_files_block}

{already_found_section}
---

## Output schema

```json
{{
  "repo": "/src/{project}",
  "role": "{role_name}",
  "exploration_notes": "<which files you read, what patterns you found>",
  "candidates": [
    {{
      "file": "/absolute/path/to/file",
      "function": "function_name",
      "line_range": [start_line, end_line],
      "checkpoint": {{"type": "<type>", "text": "<exact source line>", "line": <n>}},
      "operation": {{"type": "<type>", "text": "<exact source line>", "line": <n>}},
      "cwe_candidates": ["CWE-XXX"],
      "cwe_groups": ["<group name>"],
      "injection_hint": "<one sentence: how to weaken or remove the checkpoint or to introduce the new vulnerability>",
      "reasoning": "<one sentence: why removing this checkpoint is dangerous or why introducing this new vulnerability is dangerous>"
      "confidence": <0.0–1.0>
    }}
  ]
}}
```

---

## Workflow — explore, then write once

**Step 0 — Read your CWE reference:**
```bash
cat /tmp/cwe_reference.json
```
Use **only** these IDs in `cwe_candidates`. Do not invent CWE IDs.

**Step 1 — Orient — find the source tree:**
find the source tree:**
```bash
ls /src/ && {orient_cmd}
```

**Step 2 — Find files matching your specialty:**
```bash
{search_cmd}
```

**Step 3 — Read a promising file** (repeat this for multiple files):
```bash
{read_cmd}
```

Look for functions that:
- Accept external/user-controlled input
- Have a guard (if / assert / raise) **before** a dangerous call
- Handle file paths, shell args, SQL, deserialization, auth, template rendering, or similar
- Live in real runtime/library code, not tests, fixtures, examples, docs, or vendored code

**Step 4 — Grep for exact line numbers** of dangerous calls. But you have freedom to choose the most relevant places for new vulnerabilities in the code. The candidates should be relevant to the project and the context in which it is used, and should NOT disrupt the existing functionality of the code.
```bash
{detail_cmd}
```

**Build your candidate list as you explore:**
1. For each file, note **up to 5** promising candidates MAX
2. Move to next file - **breadth is prioritized over depth**
3. Aim to explore at least 8-10 different files if possible
4. Only read a second time from a file if you missed something critical

**Quality over quantity**: 3 high-confidence candidates from 3 different files is better than 10 low-confidence from 1 file.

**Step 4 — Write all candidates to `/tmp/candidates.json` (single write, once)**

When you have explored enough files (prioritize breadth over completeness), write all findings at once:

```bash
python3 << 'JSONEOF'
import json

data = {{
    "repo": "/src/{project}",
    "role": "{role_name}",
    "exploration_notes": "Explored [list files you read here]. Found [describe patterns/vulnerabilities].",
    "candidates": [
        # Add all candidate dicts you identified. Example for Flask SQL injection:
        # {{
        #   "file": "/src/{project}/app/views.py",
        #   "function": "show_user",
        #   "line_range": [42, 48],
        #   "checkpoint": {{"type": "input_validation", "text": "if not user_id.isdigit():", "line": 43}},
        #   "operation": {{"type": "sql_exec", "text": "db.execute('SELECT * FROM users WHERE id = ' + user_id)", "line": 45}},
        #   "cwe_candidates": ["CWE-89"],
        #   "cwe_groups": ["Input Validation"],
        #   "injection_hint": "Remove the digit check or use string directly",
        #   "reasoning": "User ID concatenated directly into SQL allows injection",
        #   "confidence": 0.9
        # }}
        # Example for Flask XSS:
        # {{
        #   "file": "/src/{project}/app/views.py",
        #   "function": "comment",
        #   "line_range": [67, 75],
        #   "checkpoint": {{"type": "escape", "text": "from markupsafe import escape", "line": 12}},
        #   "operation": {{"type": "template_render", "text": "return render_template_string('<h1>' + comment + '</h1>')", "line": 70}},
        #   "cwe_candidates": ["CWE-79"],
        #   "cwe_groups": ["Dynamic code"],
        #   "injection_hint": "<one sentence: how to weaken or remove the checkpoint or to introduce the new vulnerability>",
        #   "reasoning": "<one sentence: why removing this checkpoint is dangerous or why introducing this new vulnerability is dangerous>",
        #   "confidence": 0.85
        # }}
    ]
}}

with open('/tmp/candidates.json', 'w') as f:
    json.dump(data, f, indent=2)
print(f"Wrote {{len(data['candidates'])}} candidates")
JSONEOF
```

**Step 5 — Verify and submit:**
```bash
python3 -c "import json; d=json.load(open('/tmp/candidates.json')); print('Verified:', len(d['candidates']), 'candidates in valid JSON')"
```
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

---

## Rules
- `/tmp/candidates.json` MUST exist and contain valid JSON before you submit.
- Explore broadly across different files. Do NOT spend all steps on a single file.
- Every candidate MUST reference a real file, a real function name, and real line numbers you observed.
- `cwe_candidates` MUST only contain IDs from `/tmp/cwe_reference.json`.
- Only report candidates that genuinely fit your specialty CWE groups
- Prefer candidates with a clearly meaningful checkpoint guarding a genuinely dangerous op or a new vulnerability..
- The candidates should be relevant to the project and the context in which it is used, and should NOT disrupt the existing functionality of the code.
- Do NOT combine the submit echo with any other command.
"""

_ALREADY_FOUND_SECTION_TEMPLATE = """\
## Already identified — DO NOT RE-PROPOSE
The following `(file, function)` pairs were found by a previous specialist.
Skip them and focus on fresh locations only.

{entries}
"""


_MAX_FILES_IN_PROMPT = 150  # cap to avoid bloating the context window


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

    if lang in {"javascript", "js", "node", "nodejs", "typescript", "ts"}:
        language_label = "JavaScript / TypeScript"
        kw = role["js_keywords"]
        read_cmd = "cat -n <chosen_file> | head -220"
        orient_cmd = (
            f'find /src/{project} \\( -name "*.js" -o -name "*.cjs" -o -name "*.mjs" '
            f'-o -name "*.ts" \\) -not -path "*/test/*" -not -path "*/tests/*" '
            f'-not -path "*/spec/*" -not -path "*/specs/*" -not -path "*/node_modules/*" '
            f'-not -path "*/vendor/*" -not -path "*/dist/*" -not -path "*/build/*" '
            f'2>/dev/null | sort | head -60'
        )
    elif lang in {"c", "cpp", "c++"}:
        language_label = "C / C++"
        kw = role["c_keywords"]
        read_cmd = "cat -n <chosen_file> | head -220"
        orient_cmd = (
            f'find /src/{project} \\( -name "*.c" -o -name "*.cc" -o -name "*.cpp" -o -name "*.cxx" '
            f'-o -name "*.h" -o -name "*.hpp" \\) -not -path "*/test/*" -not -path "*/tests/*" '
            f'-not -path "*/vendor/*" -not -path "*/build/*" '
            f'2>/dev/null | sort | head -60'
        )
    else:
        language_label = "Python"
        kw = role["py_keywords"]
        read_cmd = "cat -n <chosen_file> | head -200"
        orient_cmd = (
            f'find /src/{project} -name "*.py" -not -path "*/test*" -not -path "*/spec*" '
            f'-not -path "*/site-packages/*" -not -path "*/build/*" -not -path "*/__pycache__/*" '
            f'2>/dev/null | sort | head -60'
        )

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
        language_label=language_label,
        codebase_tree_block=codebase_tree_block,
        runtime_files_block=runtime_files_block,
        orient_cmd=orient_cmd,
        search_cmd=search_cmd,
        read_cmd=read_cmd,
        detail_cmd=detail_cmd,
        already_found_section=already_found_section,
    )
