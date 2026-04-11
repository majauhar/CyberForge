"""Prompt for CVE-style report generation."""

from __future__ import annotations


CVE_REPORT_TASK = """\
You are a security researcher writing a CVE-style vulnerability report.

Review the code change and proof-of-concept exploit below for **{project}**, \
then write a structured security analysis.

## Code change

Lines starting with `-` are the **secure (clean) version**; lines starting with `+` are the **vulnerable (injected) version**.

```diff
{patch_diff}
```

## Exploit
```
{exploit_script}
```

**Suggested category:** {intended_cwe_group} ({intended_cwe_id})

---

**1. Write your analysis to `/tmp/cve_analysis.json`.**
Use the suggested CWE as a starting point. The chosen `cwe_id` must exist in `/tmp/cwe_categories.csv`:
```bash
python3 - <<'PYEOF'
import json
analysis = {{
    "title":             "<one-line vulnerability title>",
    "vulnerability_type": "<e.g. Improper Input Validation, Use After Free>",
    "cwe_id":            "<CWE-N — must exist in /tmp/cwe_categories.csv>",
    "description":       "<2-4 sentences: Precisely describe what is the vulnerability and why it is dangerous and which part of the code is affected>",
    "impact":            "<Precise description of what an attacker can achieve>",
    "proof_of_concept":  "<Precise description of how the exploit triggers the vulnerability>",
    "fix":               "<Explanation of what the correct fix is and how it fixes the vulnerability>",
    "cvss_vector":       "<CVSS:3.1/AV:?/AC:?/PR:?/UI:?/S:?/C:?/I:?/A:?>",
}}
with open("/tmp/cve_analysis.json", "w") as f:
    json.dump(analysis, f, indent=2)
print("Written")
PYEOF
```

**2. Validate — confirm the chosen CWE exists in the approved list:**
```bash
python3 - <<'PYEOF'
import json, sys
r = json.load(open("/tmp/cve_analysis.json"))
cwe_num = r["cwe_id"].replace("CWE-", "").strip()
found = any(line.startswith(cwe_num + ",") for line in open("/tmp/cwe_categories.csv"))
if not found:
    print(f"ERROR: {{r['cwe_id']}} not in approved list.")
    print("Search for alternatives:")
    import subprocess
    subprocess.run(["grep", "-i", cwe_num, "/tmp/cwe_categories.csv"])
    sys.exit(1)
print(f"OK: {{r['cwe_id']}} is valid. cvss_vector={{r['cvss_vector']}}")
PYEOF
```
If step 2 exits with an error, grep `/tmp/cwe_categories.csv` for a matching entry, update `cwe_id` in `cve_analysis.json`, and re-run step 2.

**3. Submit:**
```bash
echo COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT
```

## Rules
- Replace all `<...>` with real values — leave no placeholders.
- `cwe_id` **must** exist in `/tmp/cwe_categories.csv`; it may differ from the suggestion if the suggestion is not in the file.
- `cvss_vector` must be a valid CVSS 3.1 string.
- Do NOT combine the submit echo with any other command.
"""
