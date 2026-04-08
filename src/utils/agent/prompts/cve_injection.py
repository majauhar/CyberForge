"""Prompt for CVE-inspired vulnerability injection."""

from __future__ import annotations


CVE_INJECT_TASK = """\
Packages are installed and the project is built. Do not re-run the build.

## Goal
Re-introduce a vulnerability in **{project}** inspired by a real CVE from its history,
then immediately write a PoC exploit for it — all in this single container session.

---

# CVE Reference

CVE ID     : {cve_id}
CVSS       : {cvss}
CWEs       : {cwes}
Description: {cve_description}

## Fixing Commit Diff

The developer made the following changes to **patch** the vulnerability.
This diff may contain non-security-related changes (tests, refactoring, docs) —
your first task is to identify only the security-relevant hunks.

```diff
{fix_diff}
```

---

# Part A — Understand and Locate

**A1. Identify the security-relevant hunks:**
Study the `-` lines (removed code). Answer concretely:
- What dangerous operation exists in the vulnerable code?
- What check or guard did the fix add (or what dangerous code did it remove)?
- Without that guard, what bad state or operation can occur?

**A2. Identify the exploit vector:**
From A1, derive: what specific input or condition would bypass the removed check and
reach the dangerous operation? Write this down explicitly — it will directly determine
both your injection target and your exploit. If you cannot state the exploit vector
clearly, re-read the diff.

**A3. Search the current codebase for an equivalent pattern:**
```bash
grep -rn "<key_identifier_from_fix>" /src/{project} 2>/dev/null | head -20
```

**A4. Read the target file and pick the best injection point:**
```bash
cat -n <identified_file> | head -120
```

---

# Part B — Inject the Vulnerability

**B1. Backup and inject** — ONE minimal, realistic change:
```bash
TFILE="<path>"; cp "$TFILE" "$TFILE.orig" && python3 - <<'PYEOF'
path = "<path>"
src = open(path).read()
patched = src.replace(
    "<exact original code>",
    "<weakened version>"
)
assert patched != src, "No change made — check your replacement strings"
open(path, "w").write(patched)
print("Patch applied successfully")
PYEOF
```
   Alternative: `sed -i 's/old/new/' <path>`

{syntax_check_section}

**B3. Save the unified diff to `/tmp/vuln.patch`:**
```bash
cd /src/{project} && git diff HEAD > /tmp/vuln.patch && cat /tmp/vuln.patch
```

---

# Part C — Write the Exploit

**C1. Study the vulnerable function** to understand what inputs reach the operation:
```bash
cat -n <path> | head -80
```

{exploit_template_section}

{run_exploit_cmd}

**C3. Differential check — CRITICAL:**
Before moving on, reason through these two scenarios:
- **On CLEAN code** (original, with the fix in place): does your exploit reach the dangerous
  operation? It **must NOT** — the guard blocks it.
- **On your INJECTED code** (guard removed): does your exploit reach the dangerous operation?
  It **MUST** — and the operation must trigger a detectable effect (crash, error, non-zero exit).

If your exploit would trigger on BOTH versions, either your injection did not actually remove
the guard, or your exploit does not specifically exercise the guarded code path. Fix whichever
is wrong before continuing.

Iterate and refine if the exploit did not trigger the vulnerability.

---

# Part D — Verify with Test Harness

{harness_note}

```bash
bash /workspace/run/unit_tests/test.sh 2>&1 | tail -30; echo "HARNESS_EXIT:$?"
```

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
- The injected vulnerability should match CWE: {cwes}.
- The exploit MUST trigger on the injected code and NOT trigger on the original code.
- Do NOT combine the submit echo with any other command.
"""
