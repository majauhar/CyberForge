"""Prompts for vulnerability injection and exploit generation."""

from __future__ import annotations


def _fuzz_edit_shape_guidance(fuzz: dict) -> str:
    bug_shape = str(fuzz.get("bug_shape") or "").strip()
    target_function = fuzz.get("target_function") or fuzz.get("symbol") or "the target function"
    role = str(fuzz.get("function_role") or "target").replace("_", " ")
    shape_map = {
        "removed_bounds_check": {
            "good": [
                "Edit one existing comparison guarding an access, parse span, or buffer boundary.",
                "Prefer a tiny operator or constant change such as `<` to `<=`, `>=` to `>`, or subtracting/adding `1` to the checked bound.",
                "Keep the guarded access and surrounding control flow intact so the same path still runs.",
            ],
            "bad": [
                "Do not invent a new special-case branch, magic input token, or hidden feature flag.",
                "Do not replace the whole code path with a broad semantic rewrite.",
            ],
        },
        "removed_length_restriction": {
            "good": [
                "Weaken one existing length, remaining-bytes, or end-pointer validation already present near the target operation.",
                "Prefer a local change to the comparison or the variable used for the limit, while leaving the downstream parser/copy call unchanged.",
                "Stay close to the original parser state machine instead of adding new control paths.",
            ],
            "bad": [
                "Do not introduce unrelated fallback behavior or continue-on-error logic in multiple places.",
                "Do not make the mutation depend on an input string literal or a bespoke trigger token.",
            ],
        },
        "unchecked_index": {
            "good": [
                "Loosen one real index or slot validation already in the function.",
                "Good shapes are allowing `idx == len`, removing one half of a signed/range check, or using the wrong nearby bound variable.",
                "Keep the same container access and caller path reachable.",
            ],
            "bad": [
                "Do not fabricate an impossible index value or assign a sentinel index by hand.",
                "Do not add a special string/name branch just to force the bad index.",
            ],
        },
        "removed_copy_size_constraint": {
            "good": [
                "Target one existing capacity, resize, or remaining-space check immediately before a copy, append, or pool-growth operation.",
                "Prefer a local change that underestimates required space or skips one resize failure path while keeping the same copy call.",
                "Preserve the same data structure and copy primitive already in use.",
            ],
            "bad": [
                "Do not replace a safe API with a completely different unsafe API across the file.",
                "Do not touch build macros, unrelated helpers, or project-wide configuration to realize the bug.",
            ],
        },
        "conversion_boundary_regression": {
            "good": [
                "Weaken one existing width, continuation-byte, surrogate, or encoding-boundary validation already guarding the conversion.",
                "Prefer an off-by-one or wrong-limit change on the real boundary check, while keeping the conversion logic itself intact.",
                "Stay on naturally reachable text/decoder inputs for the selected harness.",
            ],
            "bad": [
                "Do not invent impossible high-bit/codepoint branches that normal harness inputs will never hit.",
                "Do not add a magic literal, sentinel codepoint, or ad hoc fallback output format.",
            ],
        },
        "off_by_one_iteration": {
            "good": [
                "Change one real loop or count boundary that already controls iteration over attacker-influenced data.",
                "Best shape is a single local edit like `<` to `<=` or using a count one step too far.",
                "Keep the same loop body, data flow, and output operation.",
            ],
            "bad": [
                "Do not add a new branch inside the loop to special-case one input.",
                "Do not add unrelated arithmetic or extra loop passes outside the original structure.",
            ],
        },
        "parser_state_misuse": {
            "good": [
                "Relax one existing parser state, token, null, or kind precondition that already gates the selected operation.",
                "Prefer a single local guard weakening that lets malformed-but-plausible input continue deeper on the same parser path.",
                "Keep the original parser entrypoint and surrounding state machine intact.",
            ],
            "bad": [
                "Do not introduce magic token names, hidden flags, or exploit-only branches.",
                "Do not scatter error-handling changes across multiple unrelated parser helpers.",
            ],
        },
    }
    info = shape_map.get(bug_shape)
    if not info:
        return (
            f"Work inside `{target_function}` as a {role} target. "
            "Make one local guard or boundary regression and avoid special-case triggers or broad rewrites."
        )
    good_block = "\n".join(f"- {item}" for item in info["good"])
    bad_block = "\n".join(f"- {item}" for item in info["bad"])
    return f"""\
Concrete edit shape for `{bug_shape}` inside `{target_function}`:
Good patterns:
{good_block}
Avoid these anti-patterns:
{bad_block}
"""


def _fuzz_edit_execution_rules() -> str:
    return """\
Edit execution rules:
- Mutate an existing local check, loop boundary, size comparison, pointer/end comparison, or parser precondition that is already present in the provided slice.
- Stay on the exact checkpoint-to-operation path already identified for you; do not relocate the bug elsewhere in the function.
- Prefer one of these tiny edit forms:
  - change `<` to `<=`
  - change `>` to `>=`
  - change `>=` to `>`
  - change `==` to `!=` or remove one conjunct from an existing guard
  - add or subtract exactly `1` from an existing bound
  - swap to a nearby wrong bound/count variable already in scope
- Preserve the downstream access/copy/append/parse call. The point is to weaken the guard, not replace the operation.
- Keep control flow structure the same whenever possible.

Hard bans:
- Do not invent a new branch, sentinel, trigger token, magic string, or exploit-only input literal.
- Do not introduce a new impossible constant or high-bit/codepoint condition that normal harness inputs are unlikely to hit.
- Do not broaden the patch into helpers, build files, tests, harnesses, or configuration.
- Do not add backup-dependent behavior, source-tree cloning, or patch-text inspection to prove the exploit.
- Do not turn the task into a standalone helper-program vulnerability unless the selected path already requires that exact project entrypoint.

Before you submit, verify these conditions yourself:
- the patch is small and local
- the patch weakens an existing check in the selected slice
- the target source file is the only file changed unless an extra file is absolutely necessary
- the same reachable operation still executes after the edit
"""


def _fuzzer_specific_hints(fuzz: dict) -> str:
    preferred = str(fuzz.get("preferred_fuzzer") or "").strip()
    subsystem = str(fuzz.get("subsystem") or "").strip()
    input_model = str(fuzz.get("input_model") or "").strip()
    bug_shape = str(fuzz.get("bug_shape") or "").strip()
    hints: list[str] = []

    if preferred:
        hints.append(f"The selected harness is `{preferred}`. Treat that as a strong clue about the real entrypoint and input style you should preserve.")
    if preferred.startswith("fuzz_compile"):
        hints.append("Bias toward parser / compile-time text handling that malformed but still parseable scripts can naturally reach.")
    elif preferred.startswith("fuzz_eval"):
        hints.append("Bias toward runtime-evaluation and parser paths that small executable snippets can naturally exercise, not deep standalone helper logic.")
    elif preferred.startswith("fuzz_regexp"):
        hints.append("Bias toward regex parsing, range handling, escape decoding, and regexp bytecode construction paths.")
    elif preferred.startswith("hb-"):
        hints.append("Bias toward font-table parsing and shaping/subsetting paths that a real font corpus member would already drive.")

    if subsystem:
        hints.append(f"Keep the mutation aligned with subsystem `{subsystem}` rather than drifting into unrelated helpers.")
    if input_model:
        hints.append(f"Assume inputs should remain compatible with `{input_model}`.")
    if bug_shape in {"off_by_one_iteration", "removed_copy_size_constraint", "unchecked_index"}:
        hints.append("Prefer a memory-adjacent loop/count/index/copy boundary weakening over a parser-semantics-only relaxation.")
    elif bug_shape in {"conversion_boundary_regression", "parser_state_misuse"}:
        hints.append("Prefer a boundary or state weakening that still feeds a nearby memory-sensitive or decode-sensitive operation.")

    if not hints:
        return ""
    return "Fuzzer and input-path hints:\n" + "\n".join(f"- {item}" for item in hints) + "\n"


def build_fuzz_execution_context_section(execution_context: dict | None) -> str:
    if not execution_context:
        return ""

    conditions = execution_context.get("required_conditions") or []
    generators = execution_context.get("input_generators") or []
    generator_hints = execution_context.get("generator_hints") or []
    preferred_exts = execution_context.get("preferred_extensions") or []
    exploit_hints = execution_context.get("exploit_hints") or []
    cond_block = "\n".join(f"- {item}" for item in conditions) or "- Keep the current harness path reachable."
    gen_block = "\n".join(f"- `{item}`" for item in generators) or "- `generic_small_binary_variants`"
    gen_hint_block = "\n".join(f"- {item}" for item in generator_hints) or "- Stay close to small seed-like inputs."
    ext_block = ", ".join(preferred_exts) or "generic binary or text seeds"
    exploit_block = "\n".join(f"- {item}" for item in exploit_hints) or "- Keep the exploit input small, local, and close to a realistic seed."
    return f"""\
## Downstream Fuzzing Context

Assume the later fuzz-PoC stage will treat this candidate as:
- Format family: `{execution_context.get("format_family") or "unknown"}`
- Bug shape: `{execution_context.get("bug_shape") or "minimal sanitizer-visible regression"}`
- Preferred seed extensions: {ext_block}

You must preserve these conditions:
{cond_block}

Likely input-generator families:
{gen_block}

Assume those generators behave like this:
{gen_hint_block}

Use this exploit-writing guidance:
{exploit_block}

When you write the exploit, make it look like a realistic starter input the harness could already consume.
If the target consumes files, create a tiny concrete sample on disk before invoking the vulnerable path.
Use deterministic one-shot execution through an existing built target or harness, not open-ended fuzzing.
If a binary, harness, helper file, or path is missing, treat that as `NO_TRIGGER` and fix the exploit.
Do not inspect `/tmp/vuln.patch`, run `git diff`, or grep source files as part of the exploit oracle.

---

"""


def build_fuzz_guidance_section(fuzz: dict | None, execution_context: dict | None = None) -> str:
    if not fuzz:
        return ""

    preferred = fuzz.get("preferred_fuzzer") or "unknown"
    alternates = ", ".join(fuzz.get("alternate_fuzzers") or []) or "none"
    subsystem = fuzz.get("subsystem") or "unknown"
    format_family = fuzz.get("format_family") or "unknown"
    input_model = fuzz.get("input_model") or "unknown"
    reachability = fuzz.get("reachability_kind") or "unknown"
    validation = fuzz.get("validation_likelihood") or "unknown"
    bug_shape = fuzz.get("bug_shape") or "minimal sanitizer-visible regression"
    target_function = fuzz.get("target_function") or fuzz.get("symbol") or "unknown"
    function_role = fuzz.get("function_role") or "unknown"
    hot_path_bucket = fuzz.get("hot_path_bucket") or "unknown"
    helper_judgment = fuzz.get("helper_judgment") or "unknown"
    runtime_fuzzers = ", ".join(fuzz.get("runtime_fuzzers") or []) or "unknown"
    static_fuzzers = ", ".join(fuzz.get("static_fuzzers") or []) or "unknown"
    triggerability_score = fuzz.get("triggerability_score")
    path_signal_score = fuzz.get("path_signal_score")
    parser_proximity_score = fuzz.get("parser_proximity_score")
    triggerability_rationale = fuzz.get("triggerability_rationale") or ""
    target_line_range = fuzz.get("target_line_range") or []
    guard_to_sink_distance = fuzz.get("guard_to_sink_distance")
    call_depth = fuzz.get("call_depth")
    functions_reached_count = fuzz.get("functions_reached_count")
    undiscovered_complexity = fuzz.get("undiscovered_complexity")
    slice_excerpt = fuzz.get("slice_excerpt") or ""
    mutation_goal = fuzz.get("mutation_goal") or "preserve the harness path and introduce a minimal sanitizer-visible regression"
    harness_context = fuzz.get("harness_context") or ""
    selection_rationale = fuzz.get("selection_rationale") or ""
    instruction_hints = fuzz.get("instruction_hints") or []
    edit_shape_guidance = _fuzz_edit_shape_guidance(fuzz)
    instruction_block = ""
    if instruction_hints:
        instruction_block = "\n".join(f"- {hint}" for hint in instruction_hints)
    compact_slice_line = (
        f"- Compact target slice: `{target_line_range[0]}-{target_line_range[1]}`\n"
        if len(target_line_range) >= 2
        else ""
    )
    triggerability_score_line = (
        f"- Triggerability score: `{triggerability_score}`\n"
        if triggerability_score is not None
        else ""
    )
    path_signal_line = f"- Path-signal score: `{path_signal_score}`\n" if path_signal_score is not None else ""
    parser_proximity_line = (
        f"- Parser-proximity score: `{parser_proximity_score}`\n" if parser_proximity_score is not None else ""
    )
    call_depth_line = f"- Call depth from harness: `{call_depth}`\n" if call_depth is not None else ""
    fanout_line = f"- Functions reached below target: `{functions_reached_count}`\n" if functions_reached_count is not None else ""
    complexity_line = (
        f"- Undiscovered complexity: `{undiscovered_complexity}`\n" if undiscovered_complexity is not None else ""
    )
    triggerability_detail = f"Triggerability rationale: {triggerability_rationale}\n" if triggerability_rationale else ""
    guard_distance_detail = (
        f"Guard-to-sink distance: {guard_to_sink_distance} lines.\n"
        if guard_to_sink_distance is not None
        else ""
    )
    slice_excerpt_block = f"Compact slice excerpt:\n```\n{slice_excerpt}\n```\n" if slice_excerpt else ""
    return f"""\
## Fuzzability Constraints

- Preferred harness: `{preferred}`
- Alternate harnesses: {alternates}
- Target function: `{target_function}`
- Function role: `{function_role}`
- Target subsystem: `{subsystem}`
- Input family: `{format_family}`
- Input model: `{input_model}`
- Runtime-visible fuzzers for this function: {runtime_fuzzers}
- Static-reachability fuzzers for this function: {static_fuzzers}
- Desired bug shape: `{bug_shape}`
- Reachability evidence: `{reachability}`
- Expected validation likelihood: `{validation}`
- Hot-path bucket: `{hot_path_bucket}`
- Helper judgment: `{helper_judgment}`
{compact_slice_line}{triggerability_score_line}{path_signal_line}{parser_proximity_line}{call_depth_line}{fanout_line}{complexity_line}
- Mutation goal: {mutation_goal}

{harness_context}
{selection_rationale}
{triggerability_detail}{guard_distance_detail}{slice_excerpt_block}
{_fuzzer_specific_hints(fuzz)}

Follow these instruction hints:
{instruction_block or "- Preserve the current harness path and make a narrow, sanitizer-visible change."}

{edit_shape_guidance}
{_fuzz_edit_execution_rules()}

Keep the mutation compile-clean and sanitizer-visible.
Preserve harness reachability and parser structure.
Preserve the current input path and favor sanitizer-visible failures.
Prefer minimal guard regressions such as removed bounds checks, removed length checks, unchecked indexes, copy-size regressions, or off-by-one boundaries.
Do not make broad semantic rewrites, function signature changes, or type rewrites unless absolutely necessary.
Anchor the patch on an existing check, loop bound, size comparison, or parser precondition already present in the target function.
Prefer changing an operator, bound, constant, or one nearby variable over inventing a new branch.
Do not introduce magic values, exploit-only string comparisons, impossible codepoint checks, or artificial trigger tokens.
Keep the patch scoped to the target file and the selected function whenever possible.
If you accidentally edit unrelated files, revert those edits before you submit.

Exploit quality bar:
- The exploit must be deterministic and patch-specific.
- Patch-specific means behaviorally specific: distinguish secure vs injected behavior by runtime behavior only.
- Do NOT read `/tmp/vuln.patch`, `git diff`, or source files to decide whether the exploit succeeded.
- On the secure/original code path it must print `NO_TRIGGER` and exit `0`.
- On the injected code path it must print a clear success marker such as `EXPLOIT_TRIGGERED` and exit non-zero.
- Missing binaries, bad paths, command-not-found errors, missing helper files, or sanitizer-internal failures do NOT count as success.
- A generic parse failure or non-zero exit is not enough unless you can tie it to the injected bug shape and show it does not happen on the secure code.
- Prefer existing built binaries or OSS-Fuzz targets already present in `/out` or normal repo build products over ad hoc standalone recompilation.
- Keep `/tmp/exploit/` minimal and runtime-focused; do not submit duplicate clean/vuln builds, copied trees, or bulky logs unless they are strictly required.

---

""" + build_fuzz_execution_context_section(execution_context)


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
```bash
grep -n "{checkpoint_snippet}" "{file_path}" 2>/dev/null \
  && echo "CHECKPOINT_PRESENT" || echo "CHECKPOINT_REMOVED"
```
   If not applied, apply it now:
```bash
patch -p0 <<'PEOF'
{patch_diff}
PEOF
```

2. **Study the vulnerable function:**
```bash
grep -n "" "{file_path}" | sed -n '{line_start},{line_end}p'
```

3. **Write the exploit to `/tmp/attack.py`:**
```bash
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
```bash
cd /src/{project} && python3 /tmp/attack.py 2>&1; echo "ATTACK_EXIT:$?"
```

5. **Iterate** if the exploit didn't trigger — refine input and retry.

6. **Submit:**
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/attack.py` MUST exist and be a complete, runnable Python script.
- `/tmp/attack.py` MUST exit with code **1** when the vulnerability is triggered, **0** if not triggered.
- Do NOT combine the submit echo with any other command.
"""


VULN_INJECT_TASK = """\
You are a security researcher, working on creating realistic vulnerability+PoC pairs to train cybersecurity agents. 
The project you are operating on, is not deployed in the real world, and not used by any real users. Its a prototype for cybersecurity research.

You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — packages are installed.

## Goal
Inject a minimal vulnerability, then immediately write a PoC exploit for it —
all in this single container session so the exploit targets exactly the patch you apply.

---

# Part A — Inject the Vulnerability

## Target

CWEs     : {cwes}
Hint     : **{injection_hint}**

### Secure Checkpoint to weaken or remove 
- File : `{checkpoint_file}`
- Type : `{checkpoint_type}`
- Code : `{checkpoint_text}`
- Line : {checkpoint_line}

### Sensitive operation (keep intact — it must still execute, and you must write an exploit script targeting this)
- File : `{operation_file}`
- Type : `{operation_type}`
- Code : `{operation_text}`
- Line : {operation_line}


**A1. Locate the file:**
```bash
find /src -type f -name "{file_basename}" 2>/dev/null | head -10
```

**A2. Read the file** (replace TFILE with the path found above):
```bash
TFILE="<path>"; cat -n "$TFILE" | head -120
```

**A3. **Backup and inject** — make ONE minimal, realistic change: backup the target file to <path>.orig, and edit the file to induce a weakened vulnerable code.

{syntax_check_section}

**A5. Save the unified diff to `/tmp/vuln.patch`:**
```bash
diff -u "<path>.orig" "<path>" > /tmp/vuln.patch || true
cat /tmp/vuln.patch
```

---

# Part B — Verify with Test Harness

{harness_note}

```bash
bash /tmp/test_harness.sh 2>&1 | tail -30; echo "HARNESS_EXIT:$?"
```

---

# Part C — Write the Exploit

**C1. Study the vulnerable function** to understand what inputs reach the operation:
```bash
cat -n "<path>" | head -80
```

{exploit_template_section}

{run_exploit_cmd}

Iterate and refine if the exploit did not trigger the vulnerability.

---

# Submit

When both `/tmp/vuln.patch` and the exploit script are ready:
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/vuln.patch` MUST exist and contain a non-empty unified diff.
{exploit_file_rule}
- Make ONE minimal patch change — a plausible developer mistake.
- Do NOT combine the submit echo with any other command.
"""


FUZZER_VULN_INJECT_TASK = """\
You are an agent operating inside a disposable OSS-Fuzz research container for **{project}**.
The source tree is under `/src/{project}`.

Your job is to:
1. inject one minimal realistic vulnerability at the selected location
2. write one reproducible exploit bundle that demonstrates the regression
3. self-check that the exploit is tied to the patch rather than to setup noise

## Goal
Produce a small, plausible regression and an exploit that exercises the same checkpoint/operation pair you edited.
Do not make the binary merely fail. Do not use missing files, wrong flags, or build errors as your oracle.
Do not prove success by reading patch files, `git diff`, or source text.

---

{fuzz_guidance_section}

# Part A — Inject the Vulnerability

## Target

CWEs     : {cwes}
Hint     : **{injection_hint}**

### Secure checkpoint to weaken or remove
- File : `{checkpoint_file}`
- Type : `{checkpoint_type}`
- Code : `{checkpoint_text}`
- Line : {checkpoint_line}

### Sensitive operation to keep reachable
- File : `{operation_file}`
- Type : `{operation_type}`
- Code : `{operation_text}`
- Line : {operation_line}

**A1. Locate the target file**
```bash
find /src -type f -name "{file_basename}" 2>/dev/null | head -10
```

**A2. Read the exact local context**
- Confirm the listed checkpoint and operation are really present.
- If the line numbers drift slightly, stay on the same logical checkpoint/operation pair.

```bash
TFILE="<path>"
cat -n "$TFILE" | sed -n '{line_start},{line_end}p'
```

**A3. Back up and inject**
- Make exactly one minimal, realistic source change.
- Prefer weakening the listed checkpoint while preserving the sensitive operation.
- Keep the patch local.
- Edit the exact existing local check in the provided slice instead of inventing a new condition elsewhere.
- Prefer a tiny operator/bound/count change over any broader rewrite.
- Do not edit build files, tests, harnesses, or unrelated source files unless absolutely necessary.
- Your default target is the listed source file only.
- If your edit spills into any unrelated file, revert that drift before continuing.

{syntax_check_section}

**A4. Save the patch**
```bash
cd /src/{project} && git diff HEAD > /tmp/vuln.patch
test -s /tmp/vuln.patch && echo PATCH_READY || echo PATCH_MISSING
```

**A5. Check the patch scope before moving on**
```bash
cd /src/{project} && git diff --name-only HEAD
```
- The patch should normally touch only `{checkpoint_file}`.
- If other files appear, assume that is drift unless the edit is absolutely required for the same target path.
- Revert unrelated edits before you continue.
- Write a short self-check note to `/tmp/injection_review.txt` describing:
  - which exact check you weakened
  - which operation remains reachable
  - why the edit is likely to be fuzz-rediscoverable under the selected harness

---

# Part B — Self-Check the Vulnerable Build

{harness_note}

If the harness exists, run it:
```bash
bash /workspace/run/unit_tests/test.sh 2>&1 | tail -30; echo "HARNESS_EXIT:$?"
```

If the harness fails, do not immediately discard the patch. First decide whether:
- the failure is directly caused by the injected regression and still leaves a realistic trigger path, or
- the patch is simply broken or too broad and needs to be tightened

---

# Part C — Write the Exploit

**C1. Study the reachable path**
- Understand what input reaches the edited function.
- Keep the exploit tied to the selected checkpoint and operation.
- Prefer the simplest real project entrypoint that already exercises this path.
- Do not build a mini research project inside `/tmp/exploit/`; keep it small.

```bash
nl -ba "$TFILE" | sed -n '{line_start},{line_end}p'
if [ "{function}" != "unknown" ] && [ -n "{function}" ]; then
  grep -Rsn "{function}" /src/{project} 2>/dev/null | head -20 || true
fi
```

**C2. Choose the most controllable real entrypoint**
- Prefer a real project CLI/tool/helper if it already consumes the right input.
- Otherwise use a tiny API-level helper or an OSS-Fuzz target.
- If you use a fuzzer target, prefer a one-shot deterministic run such as `/out/<fuzzer> -runs=1 <seed>`.
- Put every helper file, testcase, or tiny driver under `/tmp/exploit/`.
- Keep `/tmp/exploit/` minimal. Do not copy clean/vuln source trees, `.git` directories, large build outputs, or whole project workspaces into it.

{exploit_template_section}

{execution_context_section}

{run_exploit_cmd}

**C3. Self-verify the exploit**
- Make sure the exploit is patch-specific.
- Patch-specific means the runtime behavior differs between secure and injected code.
- Do not use `/tmp/vuln.patch`, `git diff`, or source-file inspection as part of the runtime check.
- A good result is: secure build stays quiet or prints `NO_TRIGGER`, vulnerable build prints a clear trigger marker or sanitizer signal.
- Missing binaries, wrong command-line usage, shell errors, unrelated parse failures, and sanitizer setup noise do not count.

Iterate until the exploit is deterministic, local, and credible.

---

# Submit

When `/tmp/vuln.patch` and the exploit are ready:
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/vuln.patch` must exist and contain a non-empty unified diff.
{exploit_file_rule}
- Make one minimal patch change — a plausible developer mistake.
- The patch should normally touch only the target source file.
- Before submitting, run `git diff --name-only HEAD` and make sure unrelated files are not part of the patch.
- If unrelated files were changed, revert them and regenerate `/tmp/vuln.patch`.
- Do not print or inspect `/tmp/vuln.patch` to decide whether the exploit succeeded.
- Do not disable tests, alter build flags, or edit harness/project configuration to make the exploit easier.
- Do not run `git add`, `git commit`, or stage files.
- If the exploit helper causes build trouble, fix files under `/tmp/exploit`; do not rewrite project build/config files to accommodate it.
- Do not read `/tmp/vuln.patch`, run `git diff`, or inspect source files inside the exploit to decide success.
- Do not combine the submit echo with any other command.
"""


VULN_ONLY_INJECT_TASK = """\
You are an agent operating inside a controlled OSS-Fuzz research container.
Your only job is to make the target code vulnerable with one minimal, realistic patch.

You are inside the OSS-Fuzz Docker container for **{project}**.
`bash /src/build.sh` has already been run — packages are installed.

## Goal
Produce exactly one minimal vulnerability patch that weakens the target code while keeping the project buildable.
Do not spend time building an exploit.
Do not create `/tmp/exploit/`.
Do not create `/tmp/attack.sh` or `/tmp/attack.py`.

## Patch Quality Bar
- Change only what is necessary to introduce the vulnerability.
- Preserve the target function, caller chain, and general input path.
- Keep the edit local and plausible.
- Do not make broad semantic rewrites.
- Do not edit unrelated files unless the build absolutely requires a tiny companion fix.
- Prefer keeping the patch in the target source file only.
- If unrelated files change, revert them before you submit.

---

{fuzz_guidance_section}

# Part A — Inject the Vulnerability

## Target

CWEs     : {cwes}
Hint     : **{injection_hint}**

### Secure Checkpoint to weaken or remove
- File : `{checkpoint_file}`
- Type : `{checkpoint_type}`
- Code : `{checkpoint_text}`
- Line : {checkpoint_line}

### Sensitive operation (keep intact and still reachable)
- File : `{operation_file}`
- Type : `{operation_type}`
- Code : `{operation_text}`
- Line : {operation_line}

**A1. Locate the file:**
```bash
find /src -type f -name "{file_basename}" 2>/dev/null | head -10
```

**A2. Read the target file around the candidate:**
```bash
TFILE="<path>"; cat -n "$TFILE" | sed -n '{line_start},{line_end}p'
```

**A3. Back up and edit the file:**
- Make exactly one vulnerability-oriented change.
- Stay as close as possible to the checkpoint and operation above.
- Edit an existing local check in the shown slice; do not invent a new special-case branch elsewhere.
- Prefer a tiny operator/bound/count mutation over a broader semantic rewrite.
- Do not add exploit scaffolding, helper scripts, or unrelated edits.

{syntax_check_section}

**A4. Save the final patch to `/tmp/vuln.patch`:**
```bash
git diff HEAD > /tmp/vuln.patch || true
test -s /tmp/vuln.patch && echo PATCH_READY || echo PATCH_MISSING
```

**A5. Sanity-check the patch scope:**
- Make sure `/tmp/vuln.patch` is non-empty.
- Prefer the patch to touch only the intended target file.
- If the patch drifts into unrelated files, revise it before submitting.
```bash
cd /src/{project} && git diff --name-only HEAD
```
- Write a short self-check note to `/tmp/injection_review.txt` describing:
  - which exact check you weakened
  - which operation still remains reachable
  - why the edit is a natural fuzz target rather than an artificial trigger

---

# Submit

When `/tmp/vuln.patch` is ready:
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- `/tmp/vuln.patch` MUST exist and contain a non-empty unified diff.
- Do not create exploit artifacts in this mode.
- Make ONE minimal patch change — a plausible developer mistake.
- Do NOT combine the submit echo with any other command.
"""
