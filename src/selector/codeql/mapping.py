"""Map raw CodeQL query results to SelectionCandidate objects."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from vuljector.io_contracts import SelectionCandidate

# ─── Sink text → operation type heuristics ────────────────────────────────────
# These mirror the operation type labels in static_analysis plugins so that
# CWE_FROM_PAIR lookups remain consistent.

_OP_TYPE_PATTERNS: list[tuple[str, str]] = [
    ("sql_exec",        r"cursor\.execute|\.query\s*\(|\.exec\s*\(|db\.run|sqlite3|sequelize|knex"),
    ("subprocess",      r"subprocess\.|os\.system|os\.popen|exec[vle]\s*\(|child_process|execa"),
    ("file_op",         r"open\s*\(|fs\.(read|write|unlink|mkdir|rename)|fopen|fwrite|fread"),
    ("eval_exec",       r"\beval\s*\(|\bexec\s*\(|Function\s*\(|vm\.run|importlib"),
    ("deser",           r"pickle\.|yaml\.load|json\.parse|JSON\.parse|deserializ|marshal\."),
    ("http_request",    r"requests\.(get|post|put)|fetch\s*\(|axios\.|urllib\.request"),
    ("template_render", r"render_template|\.render\s*\(|jinja2|nunjucks|handlebars|pug\."),
    ("xml_parse",       r"xml\.(parse|etree)|ElementTree|xmlParse|DOMParser|xml2js"),
    ("redirect_op",     r"redirect\s*\(|location\.href|res\.redirect|history\.push"),
    ("data_return",     r"\breturn\b|res\.send|res\.json|jsonify|ctx\.body"),
    ("state_mutation",  r"\[.*\]\s*=|self\.\w+\s*=|setattr\s*\(|globals\(\)"),
    ("alloc",           r"\bmalloc\s*\(|\bcalloc\s*\(|\brealloc\s*\(|\bnew\b"),
    ("memory_write",    r"\bmemcpy\s*\(|\bstrcpy\s*\(|\bsprintf\s*\(|\bmemset\s*\("),
    ("array_index",     r"\w+\[\s*\w"),
    ("crypto_op",       r"hashlib\.|bcrypt\.|crypto\.|EVP_|openssl"),
    ("log_op",          r"logging\.|logger\.|console\.log|syslog"),
]

# ─── Guard text → checkpoint type heuristics ──────────────────────────────────
_CP_TYPE_PATTERNS: list[tuple[str, str]] = [
    ("auth_guard",           r"is_authenticated|@login_required|hasRole|req\.user|isAdmin|check_permission"),
    ("null_check",           r"is None|=== null|!== null|!== undefined|== null|\bnot\s+\w"),
    ("bounds_check",         r"len\s*\(|\.length\b|< \w+_max|> 0|>= 0|\bin range\b|Math\.(min|max)"),
    ("type_check",           r"isinstance\s*\(|typeof |Array\.isArray|\.isdigit\(\)|is_instance"),
    ("format_check",         r"\.match\s*\(|re\.(match|fullmatch|search)|\.test\s*\(|schema\.validate|Joi\.|Yup\."),
    ("path_traversal_check", r"path\.normalize|realpath|safe_join|strstr.*\.\.|\.startswith\s*\("),
    ("sanitize",             r"escape\s*\(|sanitize|htmlspecialchars|DOMPurify|bleach\.|markupsafe"),
    ("csrf_check",           r"csrf|xsrf|_token|csrfToken"),
    ("rate_limit",           r"rate.?limit|throttle|ratelimit|limiter"),
    ("error_check",          r"try:|except |catch\s*\(|\.catch\s*\(|== -1|FAILED\s*\("),
    ("size_check",           r"MAX_SIZE|MAX_LEN|content.length|file\.size|payload\.size"),
    ("signature_check",      r"hmac\.|verify\s*\(|HMAC_Final|EVP_DigestVerify"),
    ("jwt_verify",           r"jwt\.verify|jsonwebtoken\.verify|jose\.jwtVerify"),
    ("schema_validate",      r"ajv\.|\.validate\s*\(|io-ts|zod\.|TypeCompiler"),
    ("lock_acquire",         r"mutex\.lock|acquire\s*\(|pthread_mutex_lock|synchronized"),
    ("overflow_check",       r"__builtin_.*_overflow|> INT_MAX|> UINT_MAX|safe_add|safe_mul"),
]


def _infer_op_type(text: str) -> str:
    for op_type, pattern in _OP_TYPE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return op_type
    return "data_return"


def _infer_cp_type(text: str) -> str | None:
    if not text:
        return None
    for cp_type, pattern in _CP_TYPE_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return cp_type
    return "format_check"  # generic fallback when guard is present but unrecognised


def _cwe_from_pair(cp_type: str | None, op_type: str) -> tuple[str, str]:
    """Return (cwe_id, cwe_group) using the static_analysis CWE lookup table."""
    # Import lazily to avoid circular imports
    from selector.static_analysis.cwe import CWE_FROM_PAIR, CWE_TO_GROUP

    if cp_type:
        cwe_ids = CWE_FROM_PAIR.get((cp_type, op_type))
        if cwe_ids:
            cwe_id = cwe_ids[0]
            return cwe_id, CWE_TO_GROUP.get(cwe_id, "Input validation")

    # Fallback: just the operation type, no specific checkpoint
    op_fallbacks: dict[str, tuple[str, str]] = {
        "sql_exec":        ("CWE-89",  "SQL Injection"),
        "subprocess":      ("CWE-78",  "Command Injection"),
        "file_op":         ("CWE-22",  "Path Traversal"),
        "eval_exec":       ("CWE-94",  "Dynamic code"),
        "deser":           ("CWE-502", "Deserialization"),
        "http_request":    ("CWE-918", "SSRF"),
        "template_render": ("CWE-94",  "Dynamic code"),
        "xml_parse":       ("CWE-611", "XXE"),
        "redirect_op":     ("CWE-601", "Open Redirect"),
        "memory_write":    ("CWE-787", "Memory safety"),
        "array_index":     ("CWE-125", "Memory safety"),
        "alloc":           ("CWE-401", "Memory safety"),
        "crypto_op":       ("CWE-327", "Cryptographic failures"),
        "data_return":     ("CWE-200", "Information disclosure"),
    }
    cwe_id, group = op_fallbacks.get(op_type, ("CWE-20", "Input validation"))
    return cwe_id, group


def _location_hint(cp_type: str | None, op_type: str, cp_text: str, sink_text: str) -> str:
    """Generate an LLM-facing injection hint."""
    from selector.static_analysis.cwe import _CHECKPOINT_HINTS, _INJECTION_HINTS  # type: ignore[attr-defined]

    op_hint = _INJECTION_HINTS.get(op_type, f"weaken {op_type} guard")
    if cp_type:
        cp_hint = _CHECKPOINT_HINTS.get(cp_type, f"remove {cp_type}")
        return f"{cp_hint} → {op_hint}"
    # No checkpoint found — recommend adding a vulnerable guard
    return f"introduce a bypassable guard before {op_type}: {op_hint}"


def _confidence(path_length: int, has_checkpoint: bool) -> float:
    """
    Confidence score in [0, 1].

    path_length ≥ 1  → taint-tracked: base 0.95 decaying with hops
    path_length = 0  → sink-only (no taint trace): base 0.70
    path_length = -1 → combinatorial (function-scope checkpoint × sink): base 0.75
                       (always has a checkpoint by definition — no bonus needed)
    Checkpoint presence adds +0.05 for taint/sink-only tiers.
    """
    if path_length == -1:
        # Combinatorial: checkpoint verified to be in same function as sink.
        # Higher than sink-only because a specific guard is always identified.
        return 0.75
    elif path_length == 0:
        base = 0.70
        bonus = 0.05 if has_checkpoint else 0.0
    else:
        # Taint-tracked: shorter path = higher confidence (1 hop → 0.95, 8 hops → 0.60)
        base = max(0.55, 1.0 - (path_length - 1) * 0.05)
        bonus = 0.05 if has_checkpoint else 0.0
    return round(min(base + bonus, 0.99), 4)


def map_results(
    rows: list[dict],
    repo_path: Path,
    project: str,
) -> list[SelectionCandidate]:
    """Convert raw CodeQL result rows to SelectionCandidate objects."""
    candidates: list[SelectionCandidate] = []

    for i, row in enumerate(rows, start=1):
        sink_text = row.get("sink_text", "")
        op_type = row.get("sink_kind") or _infer_op_type(sink_text)

        cp_text = row.get("cp_text", "")
        cp_type = row.get("cp_kind") or _infer_cp_type(cp_text)

        cwe_id, cwe_group = _cwe_from_pair(cp_type, op_type)

        sink_file = row.get("sink_file", "")
        try:
            rel_path = str(Path(sink_file).relative_to(repo_path))
        except ValueError:
            rel_path = sink_file

        sink_line = row.get("sink_line", 0) or 0
        path_length = row.get("path_length", 0)
        is_taint_tracked = path_length > 0
        has_checkpoint = bool(cp_text)
        language = row.get("language", "python")

        hint = _location_hint(cp_type, op_type, cp_text, sink_text)

        is_combinatorial = path_length == -1
        if is_taint_tracked:
            strategy  = "codeql_taint"
            rationale = f"codeql: taint_path (hops={path_length})"
        elif is_combinatorial:
            strategy  = "codeql_combinatorial"
            rationale = "codeql: combinatorial (checkpoint × sink, same function)"
        else:
            strategy  = "codeql_sink_only"
            rationale = "codeql: sink_only (no taint source required)"

        extra: dict[str, Any] = {
            "strategy": strategy,
            "path_length": path_length,
            "query": row.get("query_id", ""),
            "source": {
                "file": row.get("source_file", ""),
                "line": row.get("source_line", 0),
                "url":  row.get("source_url", ""),
            },
            "checkpoint": {
                "type": cp_type,
                "text": cp_text,
                "line": row.get("cp_line", 0),
                "file": row.get("cp_file", ""),
            },
            "operation": {
                "type": op_type,
                "text": sink_text,
                "line": sink_line,
                "file": sink_file,
            },
        }

        candidates.append(SelectionCandidate(
            candidate_id=f"cq_{i:04d}",
            rank=i,
            cwe_id=cwe_id,
            cwe_group=cwe_group,
            repo_path=rel_path,
            symbol=row.get("sink_function", ""),
            location_hint=hint,
            rationale=rationale,
            confidence=_confidence(path_length, has_checkpoint),
            language=language,
            line_range=(sink_line, sink_line + 5) if sink_line else None,
            extra=extra,
        ))

    return candidates
