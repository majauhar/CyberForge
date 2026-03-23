"""Stage 5 — CWE Assignment.

CWE labels are a consequence of what checkpoint type and operation type were found,
not what was searched for. This keeps the labeling mechanistic and reproducible.

Also integrates cwe_groups.json to attach group-level labels (e.g. "Dynamic code",
"Access control") to every candidate.
"""

from __future__ import annotations
import json
from pathlib import Path
from functools import lru_cache
from selector.static_analysis.models import CheckpointOperationPair


# ─────────────────────────────────────────────────────────────────────────────
# Core lookup table: (checkpoint_type, operation_type) → list[CWE IDs]
# ─────────────────────────────────────────────────────────────────────────────

CWE_FROM_PAIR: dict[tuple[str, str], list[str]] = {
    # null checks
    ("null_check",       "memory_write"):      ["CWE-476", "CWE-787"],
    ("null_check",       "array_index"):       ["CWE-476", "CWE-125"],
    ("null_check",       "file_op"):           ["CWE-476", "CWE-73"],
    ("null_check",       "deser"):             ["CWE-476", "CWE-502"],
    ("null_check",       "data_return"):       ["CWE-476", "CWE-200"],
    ("null_check",       "state_mutation"):    ["CWE-476", "CWE-284"],
    ("null_check",       "subprocess"):        ["CWE-476", "CWE-78"],
    ("null_check",       "sql_exec"):          ["CWE-476", "CWE-89"],
    ("null_check",       "http_request"):      ["CWE-476", "CWE-918"],
    ("null_check",       "eval_exec"):         ["CWE-476", "CWE-94"],
    ("null_check",       "alloc"):             ["CWE-476", "CWE-401"],

    # bounds checks
    ("bounds_check",     "memory_write"):      ["CWE-787", "CWE-119"],
    ("bounds_check",     "array_index"):       ["CWE-125", "CWE-787"],
    ("bounds_check",     "alloc"):             ["CWE-131", "CWE-190"],
    ("bounds_check",     "memory_view"):       ["CWE-125", "CWE-843"],
    ("bounds_check",     "data_return"):       ["CWE-200", "CWE-862"],
    ("bounds_check",     "state_mutation"):    ["CWE-787", "CWE-119"],

    # type checks
    ("type_check",       "memory_view"):       ["CWE-843", "CWE-704"],
    ("type_check",       "alloc"):             ["CWE-131", "CWE-190"],
    ("type_check",       "deser"):             ["CWE-502", "CWE-20"],
    ("type_check",       "eval_exec"):         ["CWE-94",  "CWE-20"],
    ("type_check",       "array_index"):       ["CWE-843", "CWE-125"],
    ("type_check",       "state_mutation"):    ["CWE-704", "CWE-843"],
    ("type_check",       "data_return"):       ["CWE-200", "CWE-704"],
    ("type_check",       "subprocess"):        ["CWE-78",  "CWE-20"],
    ("type_check",       "sql_exec"):          ["CWE-89",  "CWE-20"],
    ("type_check",       "file_op"):           ["CWE-22",  "CWE-20"],
    ("type_check",       "http_request"):      ["CWE-918", "CWE-20"],
    ("type_check",       "xml_parse"):         ["CWE-611", "CWE-20"],
    ("type_check",       "template_render"):   ["CWE-94",  "CWE-1336"],

    # overflow checks
    ("overflow_check",   "alloc"):             ["CWE-190", "CWE-122"],
    ("overflow_check",   "array_index"):       ["CWE-190", "CWE-125"],
    ("overflow_check",   "memory_write"):      ["CWE-190", "CWE-787"],
    ("overflow_check",   "memory_view"):       ["CWE-190", "CWE-843"],

    # error checks
    ("error_check",      "alloc"):             ["CWE-772", "CWE-401"],
    ("error_check",      "file_op"):           ["CWE-772", "CWE-755"],
    ("error_check",      "state_mutation"):    ["CWE-755", "CWE-390"],
    ("error_check",      "data_return"):       ["CWE-390", "CWE-200"],
    ("error_check",      "subprocess"):        ["CWE-755", "CWE-78"],
    ("error_check",      "sql_exec"):          ["CWE-755", "CWE-89"],
    ("error_check",      "deser"):             ["CWE-755", "CWE-502"],
    ("error_check",      "http_request"):      ["CWE-755", "CWE-918"],

    # auth guards
    ("auth_guard",       "data_return"):       ["CWE-862", "CWE-200"],
    ("auth_guard",       "state_mutation"):    ["CWE-284", "CWE-269"],
    ("auth_guard",       "file_op"):           ["CWE-862", "CWE-732"],
    ("auth_guard",       "sql_exec"):          ["CWE-862", "CWE-89"],
    ("auth_guard",       "eval_exec"):         ["CWE-862", "CWE-94"],
    ("auth_guard",       "subprocess"):        ["CWE-862", "CWE-78"],
    ("auth_guard",       "deser"):             ["CWE-862", "CWE-502"],
    ("auth_guard",       "http_request"):      ["CWE-862", "CWE-918"],
    ("auth_guard",       "template_render"):   ["CWE-862", "CWE-94"],
    ("auth_guard",       "xml_parse"):         ["CWE-862", "CWE-611"],
    ("auth_guard",       "alloc"):             ["CWE-862", "CWE-400"],
    ("auth_guard",       "array_index"):       ["CWE-862", "CWE-125"],
    ("auth_guard",       "memory_view"):       ["CWE-862", "CWE-843"],
    ("auth_guard",       "crypto_op"):         ["CWE-862", "CWE-327"],

    # ownership checks
    ("ownership_check",  "state_mutation"):    ["CWE-284"],
    ("ownership_check",  "data_return"):       ["CWE-200", "CWE-862"],
    ("ownership_check",  "file_op"):           ["CWE-284", "CWE-732"],
    ("ownership_check",  "sql_exec"):          ["CWE-284", "CWE-89"],

    # signature checks
    ("signature_check",  "state_mutation"):    ["CWE-347"],
    ("signature_check",  "data_return"):       ["CWE-347", "CWE-200"],
    ("signature_check",  "eval_exec"):         ["CWE-347", "CWE-94"],
    ("signature_check",  "file_op"):           ["CWE-347", "CWE-732"],

    # format / input validation
    ("format_check",     "eval_exec"):         ["CWE-94",  "CWE-78"],
    ("format_check",     "subprocess"):        ["CWE-78",  "CWE-88"],
    ("format_check",     "sql_exec"):          ["CWE-89"],
    ("format_check",     "template_render"):   ["CWE-94",  "CWE-1336"],
    ("format_check",     "http_request"):      ["CWE-918"],
    ("format_check",     "xml_parse"):         ["CWE-611"],
    ("format_check",     "file_op"):           ["CWE-22"],
    ("format_check",     "deser"):             ["CWE-502", "CWE-20"],
    ("format_check",     "state_mutation"):    ["CWE-20",  "CWE-284"],
    ("format_check",     "data_return"):       ["CWE-79",  "CWE-200"],
    ("format_check",     "log_op"):            ["CWE-117"],
    ("format_check",     "memory_view"):       ["CWE-843", "CWE-20"],
    ("format_check",     "array_index"):       ["CWE-125", "CWE-20"],
    ("format_check",     "alloc"):             ["CWE-190", "CWE-131"],

    # assertions
    ("assert",           "array_index"):       ["CWE-617", "CWE-125"],
    ("assert",           "memory_view"):       ["CWE-617", "CWE-843"],
    ("assert",           "alloc"):             ["CWE-617", "CWE-401"],
    ("assert",           "data_return"):       ["CWE-617", "CWE-200"],
    ("assert",           "state_mutation"):    ["CWE-617", "CWE-284"],

    # shape checks (numpy / ML)
    ("shape_check",      "memory_view"):       ["CWE-843", "CWE-125"],
    ("shape_check",      "array_index"):       ["CWE-125", "CWE-787"],
    ("shape_check",      "alloc"):             ["CWE-131", "CWE-190"],

    # lock / concurrency
    ("lock_acquire",     "state_mutation"):    ["CWE-362", "CWE-367"],
    ("lock_acquire",     "file_op"):           ["CWE-362", "CWE-367"],
    ("lock_acquire",     "data_return"):       ["CWE-362", "CWE-200"],

    # rate limiting
    ("rate_limit",       "data_return"):       ["CWE-770", "CWE-400"],
    ("rate_limit",       "sql_exec"):          ["CWE-770"],
    ("rate_limit",       "alloc"):             ["CWE-770", "CWE-400"],
    ("rate_limit",       "subprocess"):        ["CWE-770", "CWE-78"],

    # CSRF
    ("csrf_check",       "state_mutation"):    ["CWE-352"],
    ("csrf_check",       "sql_exec"):          ["CWE-352", "CWE-89"],
    ("csrf_check",       "file_op"):           ["CWE-352", "CWE-732"],

    # sanitization
    ("sanitize",         "eval_exec"):         ["CWE-94"],
    ("sanitize",         "data_return"):       ["CWE-79"],
    ("sanitize",         "subprocess"):        ["CWE-78"],
    ("sanitize",         "sql_exec"):          ["CWE-89"],
    ("sanitize",         "template_render"):   ["CWE-94", "CWE-79"],

    # path traversal check × file operations
    ("path_traversal_check", "file_op"):          ["CWE-22"],
    ("path_traversal_check", "subprocess"):       ["CWE-22", "CWE-78"],
    ("path_traversal_check", "http_request"):     ["CWE-22", "CWE-918"],
    ("path_traversal_check", "deser"):            ["CWE-22", "CWE-502"],
    ("path_traversal_check", "data_return"):      ["CWE-22", "CWE-200"],

    # content-type / MIME check × file / upload operations (unrestricted upload — CWE-434)
    ("content_type_check", "file_op"):            ["CWE-434", "CWE-22"],
    ("content_type_check", "deser"):              ["CWE-434", "CWE-502"],
    ("content_type_check", "eval_exec"):          ["CWE-434", "CWE-94"],
    ("content_type_check", "subprocess"):         ["CWE-434", "CWE-78"],
    ("content_type_check", "data_return"):        ["CWE-200", "CWE-434"],

    # size check × allocation / DoS
    ("size_check",       "alloc"):               ["CWE-770", "CWE-400"],
    ("size_check",       "file_op"):             ["CWE-770", "CWE-400"],
    ("size_check",       "deser"):               ["CWE-400", "CWE-770"],
    ("size_check",       "http_request"):        ["CWE-770", "CWE-400"],
    ("size_check",       "data_return"):         ["CWE-400", "CWE-200"],
    ("size_check",       "memory_view"):         ["CWE-131", "CWE-190"],
    ("size_check",       "regex_exec"):          ["CWE-1333", "CWE-400"],

    # redirect check × redirect / SSRF (open redirect — CWE-601)
    ("redirect_check",   "redirect_op"):         ["CWE-601"],
    ("redirect_check",   "http_request"):        ["CWE-601", "CWE-918"],
    ("redirect_check",   "data_return"):         ["CWE-601", "CWE-200"],
    ("null_check",       "redirect_op"):         ["CWE-601", "CWE-476"],
    ("format_check",     "redirect_op"):         ["CWE-601"],
    ("auth_guard",       "redirect_op"):         ["CWE-601", "CWE-862"],
    ("type_check",       "redirect_op"):         ["CWE-601", "CWE-20"],
    ("sanitize",         "redirect_op"):         ["CWE-601"],

    # header injection (CWE-113)
    ("format_check",     "header_inject"):       ["CWE-113"],
    ("null_check",       "header_inject"):       ["CWE-113", "CWE-476"],
    ("sanitize",         "header_inject"):       ["CWE-113"],
    ("auth_guard",       "header_inject"):       ["CWE-113", "CWE-862"],
    ("type_check",       "header_inject"):       ["CWE-113", "CWE-20"],

    # cookie operations (CWE-614 = missing Secure flag, CWE-1004 = no HttpOnly)
    ("format_check",     "cookie_op"):           ["CWE-614", "CWE-1004"],
    ("auth_guard",       "cookie_op"):           ["CWE-614", "CWE-862"],
    ("csrf_check",       "cookie_op"):           ["CWE-352", "CWE-614"],
    ("sanitize",         "cookie_op"):           ["CWE-614"],
    ("null_check",       "cookie_op"):           ["CWE-476", "CWE-614"],
    ("signature_check",  "cookie_op"):           ["CWE-347", "CWE-614"],

    # regex execution (ReDoS — CWE-1333)
    ("format_check",     "regex_exec"):          ["CWE-1333", "CWE-400"],
    ("null_check",       "regex_exec"):          ["CWE-1333", "CWE-476"],
    ("bounds_check",     "regex_exec"):          ["CWE-1333", "CWE-125"],
    ("type_check",       "regex_exec"):          ["CWE-1333", "CWE-20"],

    # environment variable / config writes (CWE-15 — external control of system or config)
    ("auth_guard",       "env_write"):           ["CWE-15", "CWE-284"],
    ("format_check",     "env_write"):           ["CWE-15", "CWE-20"],
    ("null_check",       "env_write"):           ["CWE-15", "CWE-476"],
    ("ownership_check",  "env_write"):           ["CWE-15", "CWE-284"],
    ("type_check",       "env_write"):           ["CWE-15", "CWE-20"],

    # privilege operations (CWE-250 — excessive privilege, CWE-269 — improper privilege management)
    ("auth_guard",       "priv_op"):             ["CWE-250", "CWE-269"],
    ("error_check",      "priv_op"):             ["CWE-755", "CWE-269"],
    ("ownership_check",  "priv_op"):             ["CWE-269", "CWE-284"],
    ("null_check",       "priv_op"):             ["CWE-476", "CWE-269"],
    ("format_check",     "priv_op"):             ["CWE-78", "CWE-269"],

    # socket / network binding (CWE-918 / SSRF-adjacent)
    ("auth_guard",       "socket_op"):           ["CWE-862", "CWE-918"],
    ("format_check",     "socket_op"):           ["CWE-918", "CWE-20"],
    ("null_check",       "socket_op"):           ["CWE-476", "CWE-918"],
    ("error_check",      "socket_op"):           ["CWE-755", "CWE-918"],
    ("rate_limit",       "socket_op"):           ["CWE-770", "CWE-400"],

    # reflection / dynamic attribute access (CWE-470)
    ("format_check",     "reflection_op"):       ["CWE-470", "CWE-94"],
    ("auth_guard",       "reflection_op"):       ["CWE-470", "CWE-862"],
    ("type_check",       "reflection_op"):       ["CWE-470", "CWE-20"],
    ("null_check",       "reflection_op"):       ["CWE-470", "CWE-476"],
    ("sanitize",         "reflection_op"):       ["CWE-470"],
}


# ─────────────────────────────────────────────────────────────────────────────
# CWE ID → group name mapping (populated from cwe_groups.json labels)
# ─────────────────────────────────────────────────────────────────────────────

CWE_TO_GROUP: dict[str, str] = {
    "CWE-476":  "Invalid pointer",
    "CWE-787":  "Ante buffer operation",
    "CWE-119":  "Ante buffer operation",
    "CWE-125":  "Ante buffer operation",
    "CWE-122":  "Ante buffer operation",
    "CWE-73":   "Path-related",
    "CWE-502":  "Data structure",
    "CWE-200":  "Confidentiality",
    "CWE-284":  "Access control",
    "CWE-78":   "Dynamic code",
    "CWE-88":   "Dynamic code",
    "CWE-89":   "Input validation",
    "CWE-918":  "Web",
    "CWE-94":   "Dynamic code",
    "CWE-401":  "Memory leak",
    "CWE-131":  "Memory allocation",
    "CWE-190":  "Numeric errors",
    "CWE-843":  "Type-related",
    "CWE-704":  "Type-related",
    "CWE-22":   "Path-related",
    "CWE-611":  "Web",
    "CWE-1336": "Dynamic code",
    "CWE-772":  "Memory leak",
    "CWE-755":  "Unhandled errors",
    "CWE-390":  "Error condition",
    "CWE-862":  "Access control",
    "CWE-269":  "Privileges",
    "CWE-732":  "Privileges",
    "CWE-347":  "Authentication",
    "CWE-617":  "Error condition",
    "CWE-416":  "Expired memory",
    "CWE-415":  "Memory release",
    "CWE-362":  "Concurrency",
    "CWE-367":  "Concurrency",
    "CWE-327":  "Confidentiality",
    "CWE-330":  "Confidentiality",
    "CWE-352":  "Web",
    "CWE-79":   "Web",
    "CWE-117":  "Input validation",
    "CWE-770":  "Denial of Service",
    "CWE-400":  "Denial of Service",
    "CWE-20":   "Input validation",
    # New entries
    "CWE-601":  "Web",             # Open redirect
    "CWE-113":  "Web",             # HTTP response header injection
    "CWE-614":  "Web",             # Sensitive cookie without Secure flag
    "CWE-1004": "Web",             # Sensitive cookie without HttpOnly
    "CWE-434":  "Input validation", # Unrestricted file upload
    "CWE-798":  "Authentication",  # Hardcoded credentials
    "CWE-1333": "Denial of Service", # Inefficient regex (ReDoS)
    "CWE-639":  "Access control",  # Insecure direct object reference (IDOR)
    "CWE-15":   "Input validation", # External control of system/config setting
    "CWE-250":  "Privileges",      # Execution with unnecessary privileges
    "CWE-470":  "Dynamic code",    # Use of externally-controlled input to select classes/code
    "CWE-863":  "Access control",  # Incorrect authorization
}


# ─────────────────────────────────────────────────────────────────────────────
# Injection hints — what needs to change to introduce the vulnerability
# ─────────────────────────────────────────────────────────────────────────────

_INJECTION_HINTS: dict[str, str] = {
    "eval_exec":            "remove format_check before eval/exec call",
    "deser":                "weaken type_check before deserialization",
    "file_op":              "remove path sanitization before file operation",
    "subprocess":           "bypass format_check on shell command argument",
    "data_return":          "remove auth_guard before returning sensitive data",
    "state_mutation":       "remove ownership_check before object mutation",
    "memory_view":          "weaken shape_check before memory reinterpretation",
    "array_index":          "remove bounds_check before array access",
    "alloc":                "remove overflow_check before allocation",
    "sql_exec":             "bypass format_check / parameterization before SQL",
    "template_render":      "remove input validation before template rendering",
    "http_request":         "remove URL validation before outbound request (SSRF)",
    "xml_parse":            "remove format_check before XML parsing (XXE)",
    "log_op":               "bypass sanitization before logging (log injection)",
    "crypto_op":            "swap to weak algorithm or remove crypto entirely",
    # new operation types
    "redirect_op":          "remove URL validation before redirect (open redirect)",
    "header_inject":        "inject CRLF into response header value without sanitization",
    "cookie_op":            "set cookie without Secure/HttpOnly flags or with user-controlled value",
    "regex_exec":           "feed unbounded user input to catastrophic backtracking regex (ReDoS)",
    "env_write":            "allow user input to overwrite environment/config variable",
    "priv_op":              "drop privilege check before setuid/setgid or privileged API call",
    "socket_op":            "remove host/port validation before network connection",
    "reflection_op":        "allow user-controlled string to select attribute or method via getattr",
}

_CHECKPOINT_HINTS: dict[str, str] = {
    "null_check":            "remove null check guard",
    "type_check":            "weaken or remove type check",
    "bounds_check":          "remove bounds check",
    "auth_guard":            "remove authorization check",
    "ownership_check":       "remove ownership verification",
    "assert":                "remove or weaken assertion",
    "error_check":           "ignore return value / error",
    "shape_check":           "remove shape/type validation",
    "format_check":          "remove or bypass format validation",
    "overflow_check":        "remove integer overflow check",
    "signature_check":       "bypass signature verification",
    "lock_acquire":          "remove lock acquisition (race condition)",
    "rate_limit":            "remove rate limit guard",
    "csrf_check":            "remove CSRF token verification",
    "sanitize":              "remove sanitization step",
    # new checkpoint types
    "path_traversal_check":  "remove path normalization / realpath guard",
    "content_type_check":    "remove MIME/content-type validation before upload",
    "size_check":            "remove payload/file size limit check",
    "redirect_check":        "remove URL safety validation before redirect",
}


def injection_hint(pair: CheckpointOperationPair) -> str:
    """Generate a human-readable injection hint for a pair."""
    op_hint  = _INJECTION_HINTS.get(pair.operation.type, "weaken operation guard")
    cp_hint  = _CHECKPOINT_HINTS.get(pair.checkpoint.type, "weaken checkpoint")
    return f"{cp_hint} → {op_hint}"


@lru_cache(maxsize=1)
def _load_cwe_groups() -> dict[str, str]:
    """Load cwe_groups.json from the project root (cached)."""
    # Search upward from this file's location
    here = Path(__file__).parent
    for _ in range(4):
        candidate = here / "cwe_groups.json"
        if candidate.exists():
            with open(candidate) as f:
                return json.load(f)
        here = here.parent
    return {}


def assign_cwes(pair: CheckpointOperationPair) -> tuple[list[str], list[str]]:
    """
    Return (cwe_ids, cwe_groups) for a checkpoint × operation pair.
    Fallback to CWE-20 (Improper Input Validation) if no specific mapping exists.
    """
    key = (pair.checkpoint.type, pair.operation.type)
    cwe_ids = CWE_FROM_PAIR.get(key, ["CWE-20"])

    # Map each CWE ID to a group name
    cwe_group_names = []
    for cwe_id in cwe_ids:
        group_name = CWE_TO_GROUP.get(cwe_id)
        if group_name and group_name not in cwe_group_names:
            cwe_group_names.append(group_name)

    # Fallback group
    if not cwe_group_names:
        cwe_group_names = ["Input validation"]

    return cwe_ids, cwe_group_names
