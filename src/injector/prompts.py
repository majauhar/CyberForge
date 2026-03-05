"""Prompt templates for the 4-step vulnerability injection workflow."""

STEP1_ANALYZE = """You are helping prepare to inject a single realistic software vulnerability into this codebase for security research (e.g. training detection models).

**Task — Analyze this codebase.**

Explore the project thoroughly and summarize:

1. **Languages and build system**: Primary languages, frameworks, and how the project is built.
2. **Architecture**: Main components, layers, and how they interact (e.g. frontend/backend, libs, services).
3. **Entry points and data flow**: Where external or user-controlled input enters (APIs, CLI, config, network, files). Trace how that data flows through the code.
4. **Attack surface**: Which parts of the code would be most realistic to contain a subtle vulnerability (e.g. parsers, auth checks, memory/string handling, file I/O, deserialization).

Do not make any code changes. Your analysis will be used in the next step to choose a vulnerability category and location. Be concise but specific (mention key files or modules where relevant)."""

STEP2_SELECT_GROUP = """Based on your analysis of this codebase, choose exactly ONE CWE group that is best suited for injecting a realistic vulnerability here. Consider: languages used, existing patterns (e.g. buffer handling, input validation, auth), and where a subtle mistake would be plausible.

**CWE groups (name → short description):**

{cwe_groups}

Reply with only a JSON object with "reasoning" (brief) and "group" (exact group name from the list above). Example: {{"reasoning": "...", "group": "Input validation"}}"""

STEP3_SELECT_CWE_AND_PLAN = """You have chosen the CWE group for this codebase. Now:

1. **Pick one specific CWE** from the list below that fits this codebase and would be realistic to introduce as a subtle bug.
2. **Plan the injection**: Identify exact file(s) and function(s) where you will introduce the vulnerability. The bug should look like a plausible developer mistake (e.g. missing check, wrong bound, unsafe API use). It may span multiple functions/files (interprocedural) if that makes it more realistic. Do NOT remove or bypass existing security code in an obvious way.
3. **Describe the change in 2-4 sentences**: What you will add, remove, or modify, and why it is exploitable.

**CWEs in the selected group (CWE# → Description):**

{cwes}

Reply with: (1) the chosen CWE number, (2) the exact file path(s) and symbol(s) to modify, (3) a short description of the planned code change. Do not edit any files yet."""

STEP4_EXECUTE = """Implement the vulnerability injection you planned.

**Instructions:**
- Make the minimal code changes necessary to introduce the chosen vulnerability.
- The change should look like a plausible developer mistake (e.g. off-by-one, missing validation, wrong comparison, unsafe copy).
- Do not add comments or markers that say "vulnerability" or "TODO"; keep the code looking normal.
- You may edit one or more files as needed.

Apply the changes now using your file editing tools. When done, briefly confirm what you changed (file(s) and a one-line summary)."""
