"""Prompt templates for the vulnerability injection workflow."""

STEP1_ANALYZE = """You are a software security researcher building a benchmark dataset of realistic buggy code. \
This dataset will be used to train and evaluate AI-based bug-detection tools. \
Your task is to study a codebase and then introduce a single subtle but realistic bug — the kind a real developer \
might accidentally write — that has security implications (e.g., missing bounds check, off-by-one, \
incorrect permission test, unsafe deserialization).

This is purely a local research activity on a copy of the codebase that will never be deployed.

Step 1: Analyze the codebase. Do not edit any files yet.

Cover:
1. Languages, frameworks, and build/runtime model.
2. Architecture and trust boundaries between components.
3. External input entry points and end-to-end data flow.
4. Locations where a subtle developer mistake could have security-relevant consequences (specific files/functions).
5. Why those locations are realistic candidates.

Be concise but concrete. Mention exact paths/symbols whenever possible.

This is the codebase:
{codebase}
"""

STEP2_THREAT_MODEL = """Next, produce a project-specific threat model that complements your codebase analysis.

Analyze the repository to understand the security-relevant structure of the system and write a concise threat model that captures:

1. **What the system does** — main purpose, key features, and critical workflows from a security perspective.
2. **What it trusts** — trust boundaries, assumptions about inputs and callers, trusted vs untrusted data sources, and dependencies.
3. **Where it is most exposed** — high-value or high-risk components, entry points that handle untrusted input, sensitive operations (auth, crypto, parsing, persistence), and areas where a subtle bug would have the most security impact.

Be concrete: reference specific components, entry points, and file/function names where relevant. This threat model will guide the choice of a realistic vulnerability to inject."""

STEP3_SELECT_GROUP = """You are continuing the benchmark-dataset generation task described earlier.

Using your codebase analysis and threat model, choose exactly one CWE group that best matches a realistic developer mistake in this codebase.

Selection criteria:
- Natural fit for this codebase's language and patterns.
- The resulting bug should look like an honest developer oversight.
- The bug class should have meaningful security implications if it occurred in production.

CWE groups (name -> short description):
{cwe_groups}

Return only valid JSON:
{{"reasoning":"<brief reasoning>","group":"<exact group name from list>"}}"""

STEP4_SELECT_CWE_AND_PLAN = """You are continuing the benchmark-dataset generation task.

Now choose one specific CWE from the selected group and plan the code change.

Requirements:
1. Pick exactly one CWE from the list below.
2. Specify exact file path(s) and symbol(s) you will modify.
3. Plan a minimal, realistic code change that introduces a bug matching the CWE — \
it should look like a plausible developer mistake (e.g., forgot a check, wrong comparison operator, \
off-by-one in a loop bound, missing input sanitization).
4. The codebase should still mostly function normally — the bug should be subtle.
5. Explain in 2-4 sentences what the bug does and why it has security implications.

CWEs in the selected group (CWE# -> Description):
{cwes}

Do not edit files yet."""

STEP5_EXECUTE = """Now apply the planned code change to create the benchmark sample.

Remember: you are generating a realistic buggy-code sample for a research dataset used to train \
AI bug-detection models. The change should look like a genuine developer mistake.

Instructions:
- Make the minimal edit(s) needed to introduce the planned bug.
- The change should resemble a natural developer error (e.g., missing validation, wrong bound, \
unsafe default, incorrect operator).
- Do not add any comments or markers hinting that the change is intentional.
- You may edit one or more files as needed for realism.

After editing, confirm:
1) The CWE number of the introduced bug.
2) Which file(s) and symbol(s) you changed.
3) A one-line description of the bug and its security implication."""



STEP6_GENERATE_EXPLOIT = """You are writing a non-destructive behavioral proof-of-vulnerability harness for a local research benchmark.

Goal:
- Create `exploit_files/exploit.sh` as a deterministic script that demonstrates the introduced bug by exercising the code through its real runtime interface.
- The script must verify a bug-specific observable behavior, not merely the presence of changed source code.

Hard requirements:
- Exit with `0` only if the script reproduces the bug condition on the current snapshot through program behavior.
- Exit with `1` if the bug condition cannot be reproduced.
- The script must be safe, local-only, and repeatable.
- Do not disrupt service availability, delete data, corrupt state, or affect anything outside this local environment.

Forbidden shortcuts:
- Do not inspect source files, diffs, commit history, or patch artifacts to decide success.
- Do not grep for injected strings, comments, file names, or exact code snippets.
- Do not determine success from static repository contents alone.
- Do not rely on the known location of the injected change.
- The result must come from executing the target system and observing its behavior.
- Any script that decides success by reading repository files instead of exercising runtime behavior is invalid and must be rejected by you as cheating.

Behavioral validation requirements:
- Interact with the smallest real interface that reaches the bug: e.g. CLI, API, parser entry point, request handler, file input, or test harness.
- Check a bug-specific effect that should occur only on the buggy snapshot.
- Prefer a precise semantic check over generic crashes or exit-code-only checks.
- The harness should be written so that it would fail on a patched snapshot where the bug is removed.

Authoring guidance:
- Make the script self-contained and runnable as `bash exploit_files/exploit.sh`.
- Before you finish, run the script locally yourself, inspect its output and exit code, and fix it if the behavior is incorrect or non-deterministic.
- If your first attempt uses static file inspection, string matching on source code, or any other shortcut, discard it and replace it with a real behavioral proof.
- Print short diagnostics describing:
  1. the interface exercised,
  2. the input used,
  3. the observed bug-specific behavior,
  4. why that behavior implies success or failure.
- If prior feedback indicates failure, revise the script, run it again, and keep iterating until the check is behavior-based and reliable.

Attempt number: {attempt}
Feedback from previous execution (if any):
{feedback}

When done, briefly summarize:
1. Which runtime interface the script exercises.
2. What observable behavior proves the bug is present.
3. Why the same script should fail on a patched snapshot.
4. Confirm that you tested the final script locally and that it does not rely on source inspection.
"""


STEP6_EXPLOIT_NOT_REAL = """The exploit script `exploit_files/exploit.sh` succeeded on the MODIFIED codebase (as expected), \
but it ALSO succeeded when run against the ORIGINAL, unmodified codebase. \
This means the exploit is not a real exploit — it does not actually demonstrate the vulnerability. \
It passes regardless of whether the bug is present (e.g. it may be checking something unrelated or using static inspection), \
making it useless as a behavioral proof.

Attempt number: {attempt}
Output from running exploit on the clean (original) codebase:
{feedback}

You must rewrite `exploit_files/exploit.sh` so that it is a real exploit:
1. It exits 0 (success) ONLY when the introduced vulnerability is present (modified codebase).
2. It exits 1 (failure) on the original, unmodified codebase where the bug does not exist.
3. The distinction is determined purely through runtime behavior — no grepping source files, \
no inspecting diffs, no reading file contents to detect the change.

Your rewritten script must exercise the actual runtime behavior that differs between the two versions. \
Run the script yourself locally to verify it exits 0 on the current (modified) codebase. \
Do not use grep, cat, head, tail, or any form of static file inspection to decide success or failure."""


STEP6_FIX_EXPLOIT = """The previous run of `exploit_files/exploit.sh` failed or was rejected. You must fix the script and then run it yourself until it succeeds before finishing.

Attempt number: {attempt}
Feedback from the last run (use this to fix the script):
{feedback}

Your task in this step:
1. Read the feedback above and identify why the script failed (wrong behavior, verifier rejection, missing file, wrong exit code, etc.).
2. Edit `exploit_files/exploit.sh` to address the issue. Do not use grep, cat, head, tail, or any static inspection of source files — success must be determined by exercising the program's runtime behavior.
3. Run the script yourself in this environment: `bash exploit_files/exploit.sh`. Check its exit code and output.
4. If it does not exit 0, fix the script again and repeat step 3. You must iterate until the script exits 0 when run locally, or you have made a clear fix and documented what you changed.
5. Only when the script succeeds locally (exit 0), summarize what you fixed and how the script now verifies the bug behavior.

You are not done until you have run `bash exploit_files/exploit.sh` at least once in this turn and it properly exit 0. Make sure to analyze and justify."""