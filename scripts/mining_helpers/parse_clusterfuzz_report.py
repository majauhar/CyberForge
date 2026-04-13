from __future__ import annotations

import re


_CF_PATTERNS: dict[str, re.Pattern[str]] = {
    "project": re.compile(r"^Project:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "fuzz_engine": re.compile(r"^Fuzzing Engine:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "fuzz_target": re.compile(r"^Fuzz Target:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "job_type": re.compile(r"^Job Type:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "crash_type": re.compile(r"^Crash Type:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "crash_address": re.compile(r"^Crash Address:[ \t]*([^\n]+)$", re.MULTILINE | re.IGNORECASE),
    "sanitizer": re.compile(r"^Sanitizer:[ \t]*(.+)$", re.MULTILINE | re.IGNORECASE),
    "security_severity": re.compile(
        r"^Recommended Security Severity:[ \t]*(.+)$",
        re.MULTILINE | re.IGNORECASE,
    ),
}

_CRASH_STATE_RE = re.compile(
    r"Crash State:\s*\n((?:[ \t]+\S[^\n]*\n?){1,5})",
    re.MULTILINE | re.IGNORECASE,
)
_REGRESSED_RE = re.compile(r"range=(\d+):(\d+)")
_TESTCASE_ID_RE = re.compile(r"testcase_id=(\d+)")


def parse_clusterfuzz_report(text: str) -> dict:
    """Extract structured fields from a ClusterFuzz report blob."""
    fields: dict = {}

    for field, pattern in _CF_PATTERNS.items():
        match = pattern.search(text)
        if match:
            fields[field] = match.group(1).strip()

    crash_state_match = _CRASH_STATE_RE.search(text)
    if crash_state_match:
        frames = [
            line.strip()
            for line in crash_state_match.group(1).splitlines()
            if line.strip()
        ]
        if frames:
            fields["crash_state"] = frames

    regressed_match = _REGRESSED_RE.search(text)
    if regressed_match:
        fields["regression_range"] = {
            "start": regressed_match.group(1),
            "end": regressed_match.group(2),
        }

    testcase_match = _TESTCASE_ID_RE.search(text)
    if testcase_match:
        fields["testcase_id"] = testcase_match.group(1)

    return fields
