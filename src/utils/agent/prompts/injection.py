"""Prompts for vulnerability injection and exploit generation."""

from __future__ import annotations


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
