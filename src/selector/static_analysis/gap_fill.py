"""Stage 6 — Gap-fill Detectors.

Covers three CWE classes that are structurally invisible to the graph approach:

1. Crypto misuse (CWE-327/330)
   - Weak random number generator used in a security context
   - Weak cryptographic algorithm (MD5, SHA1, DES, RC4, etc.)
   Graph misses it because there's no taint flow — just a wrong API choice.

2. TOCTOU race conditions (CWE-362/367)
   - Check-then-use patterns on filesystem paths without locking
   Graph misses it because the vulnerability is temporal, not structural.

3. Missing check / broken access control (CWE-862/863)
   - A function performs the same operation as a sibling function but
     lacks a security checkpoint that the sibling has.
   Graph misses it because it's an absence of code, not a present pattern.
"""

from __future__ import annotations
import ast
import re
from pathlib import Path

from selector.static_analysis.models import VulnCandidate, Checkpoint, Operation
from selector.static_analysis.plugins.python_plugin import (
    WEAK_RANDOM, WEAK_ALGOS, SECURITY_CONTEXTS,
    TOCTOU_CHECK_OPS, TOCTOU_USE_OPS, LOCK_SIGNALS,
    HARDCODED_STRING_RE_PARTS, REDOS_RISK_RE_PARTS, HEADER_INJECT_SOURCES,
    PythonPlugin,
)
from selector.static_analysis.cwe import CWE_TO_GROUP

_python_plugin = PythonPlugin()

_WEAK_RANDOM_RE       = re.compile("|".join(re.escape(s) for s in WEAK_RANDOM))
_WEAK_ALGO_RE         = re.compile("|".join(re.escape(s) for s in WEAK_ALGOS))
_SECURITY_CTX_RE      = re.compile("|".join(re.escape(s) for s in SECURITY_CONTEXTS), re.IGNORECASE)
_LOCK_RE              = re.compile("|".join(re.escape(s) for s in LOCK_SIGNALS))
_TOCTOU_CHECK_RE      = re.compile("|".join(re.escape(s) for s in TOCTOU_CHECK_OPS))
_TOCTOU_USE_RE        = re.compile("|".join(re.escape(s) for s in TOCTOU_USE_OPS))
_HARDCODED_CREDS_RE   = re.compile("|".join(HARDCODED_STRING_RE_PARTS), re.IGNORECASE)
_REDOS_RE             = re.compile("|".join(REDOS_RISK_RE_PARTS))
_HEADER_SRC_RE        = re.compile("|".join(HEADER_INJECT_SOURCES))


def _make_candidate(
    file: str,
    fn_name: str,
    line_range: tuple[int, int],
    strategy: str,
    checkpoint: Checkpoint | None,
    operation: Operation | None,
    cwe_candidates: list[str],
    difficulty: str,
    evidence: dict,
    injection_hint: str,
) -> VulnCandidate:
    """Helper to build a VulnCandidate for gap-fill findings."""
    cwe_groups = []
    for cid in cwe_candidates:
        grp = CWE_TO_GROUP.get(cid)
        if grp and grp not in cwe_groups:
            cwe_groups.append(grp)
    if not cwe_groups:
        cwe_groups = ["Confidentiality"]

    complexity_scores = {"easy": 2.0, "medium": 7.0, "hard": 13.0, "expert": 20.0}

    return VulnCandidate(
        file=file,
        function=fn_name,
        line_range=line_range,
        language="python",
        strategy=strategy,
        checkpoint=checkpoint,
        operation=operation,
        call_path=[],
        cwe_candidates=cwe_candidates,
        cwe_groups=cwe_groups,
        complexity_score=complexity_scores.get(difficulty, 7.0),
        difficulty=difficulty,
        evidence=evidence,
        injection_hint=injection_hint,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Detector 1: Crypto Misuse
# ─────────────────────────────────────────────────────────────────────────────

def _window_around(lines: list[str], center: int, radius: int = 5) -> str:
    """Return a text window of ±radius lines around a center line index."""
    start = max(0, center - radius)
    end   = min(len(lines), center + radius + 1)
    return "\n".join(lines[start:end])


def detect_crypto_misuse(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Find weak random or weak algorithm usage near security-context variable names.
    """
    candidates = []
    fn_name = fn_node.name
    start = fn_node.lineno - 1
    end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1

    for lineno_idx in range(start, min(end + 1, len(source_lines))):
        line = source_lines[lineno_idx]

        # Weak random in security context
        if _WEAK_RANDOM_RE.search(line):
            window = _window_around(source_lines, lineno_idx)
            if _SECURITY_CTX_RE.search(window):
                candidates.append(_make_candidate(
                    file=file_str,
                    fn_name=fn_name,
                    line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
                    strategy="crypto_misuse",
                    checkpoint=None,
                    operation=Operation(
                        type="crypto_op",
                        text=line.strip()[:200],
                        line=lineno_idx + 1,
                        function=fn_name,
                        file=file_str,
                        cwe_class="Confidentiality",
                    ),
                    cwe_candidates=["CWE-330"],
                    difficulty="medium",
                    evidence={
                        "weak_random_line": line.strip(),
                        "security_context_found": True,
                        "window": window[:400],
                    },
                    injection_hint="replace secrets.token_bytes with random.random in security context",
                ))

        # Weak algorithm instantiation
        if _WEAK_ALGO_RE.search(line):
            candidates.append(_make_candidate(
                file=file_str,
                fn_name=fn_name,
                line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
                strategy="crypto_misuse",
                checkpoint=None,
                operation=Operation(
                    type="crypto_op",
                    text=line.strip()[:200],
                    line=lineno_idx + 1,
                    function=fn_name,
                    file=file_str,
                    cwe_class="Confidentiality",
                ),
                cwe_candidates=["CWE-327"],
                difficulty="easy",
                evidence={
                    "weak_algo_line": line.strip(),
                    "algo_detected": _WEAK_ALGO_RE.search(line).group(),
                },
                injection_hint="swap strong algorithm for weak one (MD5/SHA1/DES/RC4)",
            ))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Detector 2: TOCTOU (Check-Then-Use)
# ─────────────────────────────────────────────────────────────────────────────

def _extract_path_variable(line: str) -> str | None:
    """Try to extract the variable name used as a path argument."""
    # Match: os.path.exists(var), open(var), etc.
    m = re.search(r'(?:exists|isfile|isdir|access|open|remove|rename|unlink)\s*\(\s*(\w+)', line)
    return m.group(1) if m else None


def detect_toctou(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Find check-then-use patterns on file paths without a lock.
    Pattern: os.path.exists(x) followed by open(x) with same variable.
    """
    candidates = []
    fn_name = fn_node.name
    start = fn_node.lineno - 1
    end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    fn_text = "\n".join(source_lines[start:end + 1])

    # Quick bail: no TOCTOU check ops at all
    if not _TOCTOU_CHECK_RE.search(fn_text):
        return []

    # No lock present — TOCTOU requires absence of synchronization
    has_lock = bool(_LOCK_RE.search(fn_text))
    if has_lock:
        return []

    check_sites: list[tuple[int, str, str]] = []  # (abs_lineno, line, path_var)
    use_sites:   list[tuple[int, str, str]] = []

    for lineno_idx in range(start, min(end + 1, len(source_lines))):
        line = source_lines[lineno_idx]
        abs_lineno = lineno_idx + 1

        if _TOCTOU_CHECK_RE.search(line):
            path_var = _extract_path_variable(line)
            if path_var:
                check_sites.append((abs_lineno, line.strip(), path_var))

        if _TOCTOU_USE_RE.search(line):
            path_var = _extract_path_variable(line)
            if path_var:
                use_sites.append((abs_lineno, line.strip(), path_var))

    # Pair check → use with matching variable
    for check_line, check_text, check_var in check_sites:
        for use_line, use_text, use_var in use_sites:
            if use_line > check_line and check_var == use_var:
                candidates.append(_make_candidate(
                    file=file_str,
                    fn_name=fn_name,
                    line_range=(check_line, use_line),
                    strategy="toctou",
                    checkpoint=Checkpoint(
                        type="error_check",
                        text=check_text,
                        line=check_line,
                        function=fn_name,
                        file=file_str,
                    ),
                    operation=Operation(
                        type="file_op",
                        text=use_text,
                        line=use_line,
                        function=fn_name,
                        file=file_str,
                        cwe_class="Path-related",
                    ),
                    cwe_candidates=["CWE-367", "CWE-362"],
                    difficulty="hard",
                    evidence={
                        "check_line": check_text,
                        "check_lineno": check_line,
                        "use_line": use_text,
                        "use_lineno": use_line,
                        "shared_variable": check_var,
                        "has_lock": False,
                    },
                    injection_hint="remove lock between os.path.exists check and open/use",
                ))
                break  # one use per check site is enough

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Detector 3: Missing Check (Sibling Comparison)
# ─────────────────────────────────────────────────────────────────────────────

def detect_missing_check(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    siblings: list[ast.FunctionDef | ast.AsyncFunctionDef],
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Compare a function to its siblings (same module, same class).
    If a sibling performs the same operation but also has a checkpoint
    that this function lacks → flag as missing check.
    """
    candidates = []
    fn_name = fn_node.name

    # Get checkpoint and operation types for this function
    fn_start = fn_node.lineno - 1
    fn_end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    fn_text  = "\n".join(source_lines[fn_start:fn_end + 1])

    fn_cp_types:  set[str] = set()
    fn_op_types:  set[str] = set()

    for lineno_idx in range(fn_start, min(fn_end + 1, len(source_lines))):
        line = source_lines[lineno_idx].strip()
        for cp_type, _ in _python_plugin.match_checkpoints(line):
            fn_cp_types.add(cp_type)
        for op_type, _, _ in _python_plugin.match_operations(line):
            fn_op_types.add(op_type)

    if not fn_op_types:
        return []

    # Dedup: only emit one missing_check per (op_type, missing_cp_type) pair
    emitted: set[tuple[str, str]] = set()

    for sibling in siblings:
        if sibling.name == fn_node.name:
            continue

        sib_start = sibling.lineno - 1
        sib_end   = (sibling.end_lineno or sibling.lineno + 50) - 1

        sib_cp_types: set[str] = set()
        sib_op_types: set[str] = set()

        for lineno_idx in range(sib_start, min(sib_end + 1, len(source_lines))):
            line = source_lines[lineno_idx].strip()
            for cp_type, _ in _python_plugin.match_checkpoints(line):
                sib_cp_types.add(cp_type)
            for op_type, _, _ in _python_plugin.match_operations(line):
                sib_op_types.add(op_type)

        # Shared operations: both functions do the same security-critical thing
        shared_ops = fn_op_types & sib_op_types
        # Only consider high-value checkpoint types to reduce false positives
        _HIGH_VALUE_CPS = {"auth_guard", "bounds_check", "null_check", "type_check",
                           "signature_check", "csrf_check", "ownership_check", "format_check"}
        # Checkpoints sibling has (high-value only) that this function lacks
        missing_cps = (sib_cp_types & _HIGH_VALUE_CPS) - fn_cp_types

        # Only flag if there's at least one meaningful shared operation
        # (exclude array_index / state_mutation as they're too common)
        _HIGH_VALUE_OPS = {"eval_exec", "deser", "file_op", "subprocess", "sql_exec",
                           "template_render", "http_request", "xml_parse", "data_return",
                           "memory_view", "alloc", "crypto_op"}
        meaningful_shared_ops = shared_ops & _HIGH_VALUE_OPS

        if meaningful_shared_ops and missing_cps:
            # Pick the most security-relevant missing checkpoint to report
            missing_cp_type = sorted(missing_cps)[0]
            op_type = sorted(meaningful_shared_ops)[0]

            # Dedup: one candidate per (op_type, missing_cp_type)
            dedup_key = (op_type, missing_cp_type)
            if dedup_key in emitted:
                continue
            emitted.add(dedup_key)

            candidates.append(_make_candidate(
                file=file_str,
                fn_name=fn_name,
                line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
                strategy="missing_check",
                checkpoint=None,
                operation=Operation(
                    type=op_type,
                    text=f"[operation: {op_type}]",
                    line=fn_node.lineno,
                    function=fn_name,
                    file=file_str,
                    cwe_class="Access control",
                ),
                cwe_candidates=["CWE-862", "CWE-863"],
                difficulty="hard",
                evidence={
                    "sibling_function": sibling.name,
                    "missing_checkpoint_types": sorted(missing_cps),
                    "shared_operation_types": sorted(meaningful_shared_ops),
                    "description": (
                        f"Sibling '{sibling.name}' performs {sorted(meaningful_shared_ops)} and has "
                        f"{sorted(missing_cps)} guards; this function lacks them."
                    ),
                },
                injection_hint=f"sibling '{sibling.name}' checks {sorted(missing_cps)} before {sorted(meaningful_shared_ops)}; inject bug by removing those guards",
            ))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Detector 4: Hardcoded Credentials (CWE-798)
# ─────────────────────────────────────────────────────────────────────────────

def detect_hardcoded_creds(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Find credential variable assignments to hardcoded string literals.
    e.g.: password = "s3cr3t", SECRET_KEY = "abc123"
    → CWE-798 (Use of Hard-coded Credentials)
    """
    candidates = []
    fn_name = fn_node.name
    start = fn_node.lineno - 1
    end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    emitted: set[str] = set()

    for lineno_idx in range(start, min(end + 1, len(source_lines))):
        line = source_lines[lineno_idx]
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = _HARDCODED_CREDS_RE.search(line)
        if m:
            matched_text = m.group()
            # Avoid re-emitting the same pattern within this function
            pattern_key = matched_text[:60]
            if pattern_key in emitted:
                continue
            emitted.add(pattern_key)

            candidates.append(_make_candidate(
                file=file_str,
                fn_name=fn_name,
                line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
                strategy="hardcoded_creds",
                checkpoint=None,
                operation=Operation(
                    type="crypto_op",
                    text=stripped[:200],
                    line=lineno_idx + 1,
                    function=fn_name,
                    file=file_str,
                    cwe_class="Authentication",
                ),
                cwe_candidates=["CWE-798"],
                difficulty="easy",
                evidence={
                    "matched_pattern": matched_text[:120],
                    "line": stripped[:200],
                },
                injection_hint="hardcoded credential — attacker needs only static analysis of binary/source to extract",
            ))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Detector 5: ReDoS — Catastrophic Regex Backtracking (CWE-1333)
# ─────────────────────────────────────────────────────────────────────────────

# Parameters passed directly to re.* that look like user-supplied variables
_RE_CALL_WITH_VAR = re.compile(
    r"re\.(?:match|search|fullmatch|findall|finditer|sub|subn)\s*\(\s*\w[\w.]*\s*,\s*(\w[\w.]*)"
)
# Variables commonly sourced from requests
_REQUEST_VAR_RE = re.compile(
    r"\b(?:request|req|data|body|payload|query|input|user_input|text|value|param)\b",
    re.IGNORECASE,
)


def detect_redos(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Find regex operations on potentially user-supplied input strings without
    any length/size bound before the call → CWE-1333 (ReDoS).

    Heuristic: re.* call where the subject argument name looks like a
    request/user variable, and there is no bounds_check / size_check
    on that variable within the same function.
    """
    candidates = []
    fn_name = fn_node.name
    start = fn_node.lineno - 1
    end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    fn_text = "\n".join(source_lines[start:end + 1])

    # Quick bail
    if "re." not in fn_text:
        return []

    # Check if there's any size / bounds guard in the function
    _SIZE_GUARD_RE = re.compile(
        r"(?:len\s*\(|\.content_length|MAX_|LIMIT_|if\s+\w[\w.]*\s*(?:>|>=|<|<=)\s*\d)"
    )
    has_size_guard = bool(_SIZE_GUARD_RE.search(fn_text))

    emitted: set[str] = set()

    for lineno_idx in range(start, min(end + 1, len(source_lines))):
        line = source_lines[lineno_idx]
        stripped = line.strip()
        if stripped.startswith("#"):
            continue

        m = _RE_CALL_WITH_VAR.search(line)
        if not m:
            continue

        subject_var = m.group(1)
        # Only flag if subject looks like user input
        if not _REQUEST_VAR_RE.search(subject_var):
            continue

        dedup_key = f"{fn_name}:{subject_var}"
        if dedup_key in emitted:
            continue
        emitted.add(dedup_key)

        candidates.append(_make_candidate(
            file=file_str,
            fn_name=fn_name,
            line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
            strategy="redos",
            checkpoint=None,
            operation=Operation(
                type="regex_exec",
                text=stripped[:200],
                line=lineno_idx + 1,
                function=fn_name,
                file=file_str,
                cwe_class="Denial of Service",
            ),
            cwe_candidates=["CWE-1333", "CWE-400"],
            difficulty="medium" if has_size_guard else "hard",
            evidence={
                "regex_call": stripped[:200],
                "subject_var": subject_var,
                "has_size_guard": has_size_guard,
            },
            injection_hint="supply pathological string to trigger catastrophic backtracking in regex",
        ))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Detector 6: Header Injection (CWE-113)
# ─────────────────────────────────────────────────────────────────────────────

# Patterns that write to response headers
_HEADER_WRITE_RE = re.compile(
    r"response\.headers\[|response\.set_cookie\s*\(|\.headers\.(?:set|add|update)\s*\("
    r"|make_response.*\.headers|HttpResponse.*\[.+\]\s*=|flask\.Response"
)
# Newline characters that enable header injection
_CRLF_GUARD_RE = re.compile(
    r"(?:replace|strip|encode|escape|sanitize|clean)\s*\(.*(?:\\r|\\n|CRLF|newline)",
    re.IGNORECASE,
)


def detect_header_injection(
    fn_node: ast.FunctionDef | ast.AsyncFunctionDef,
    source_lines: list[str],
    file_str: str,
) -> list[VulnCandidate]:
    """
    Find functions that:
    1. Read from request (user-controlled source)
    2. Write that value into a response header
    3. Without stripping newlines (CRLF injection guard)
    → CWE-113 (Improper Neutralization of CRLF Sequences in HTTP Headers)
    """
    candidates = []
    fn_name = fn_node.name
    start = fn_node.lineno - 1
    end   = (fn_node.end_lineno or fn_node.lineno + 50) - 1
    fn_text = "\n".join(source_lines[start:end + 1])

    # Must write to headers AND read from request
    has_header_write  = bool(_HEADER_WRITE_RE.search(fn_text))
    has_request_read  = bool(_HEADER_SRC_RE.search(fn_text))

    if not (has_header_write and has_request_read):
        return []

    # If there's a CRLF guard, skip
    if _CRLF_GUARD_RE.search(fn_text):
        return []

    # Find the header write line for the finding
    write_line_idx = start
    write_text = ""
    for lineno_idx in range(start, min(end + 1, len(source_lines))):
        line = source_lines[lineno_idx]
        if _HEADER_WRITE_RE.search(line):
            write_line_idx = lineno_idx
            write_text = line.strip()
            break

    candidates.append(_make_candidate(
        file=file_str,
        fn_name=fn_name,
        line_range=(fn_node.lineno, fn_node.end_lineno or fn_node.lineno),
        strategy="header_injection",
        checkpoint=None,
        operation=Operation(
            type="header_inject",
            text=write_text[:200] or f"[header write in {fn_name}]",
            line=write_line_idx + 1,
            function=fn_name,
            file=file_str,
            cwe_class="Web",
        ),
        cwe_candidates=["CWE-113"],
        difficulty="medium",
        evidence={
            "has_request_read": True,
            "has_header_write": True,
            "has_crlf_guard": False,
            "header_write_line": write_text[:200],
        },
        injection_hint="inject CRLF (\\r\\n) into user-supplied header value to split HTTP response",
    ))

    return candidates


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def run_gap_fill(
    repo_root: Path,
    nodes: dict,          # GraphNode registry (for file lookup)
    profile,              # RepoProfile
) -> list[VulnCandidate]:
    """Run all gap-fill detectors across the repo. Returns combined candidates."""
    candidates: list[VulnCandidate] = []

    _skip = {".venv", "venv", "__pycache__", ".git", "node_modules", ".tox"}
    py_files = [
        f for f in repo_root.rglob("*.py")
        if not any(p in _skip for p in f.relative_to(repo_root).parts)
    ]

    for py_file in py_files:
        try:
            source = py_file.read_text(errors="ignore")
            tree   = ast.parse(source, filename=str(py_file))
        except (SyntaxError, OSError):
            continue

        source_lines = source.splitlines()
        file_str = str(py_file.relative_to(repo_root))

        # Collect all function nodes in this file
        all_fns: list[ast.FunctionDef | ast.AsyncFunctionDef] = [
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        ]

        for fn_node in all_fns:
            # Detector 1: Crypto misuse
            candidates.extend(detect_crypto_misuse(fn_node, source_lines, file_str))

            # Detector 2: TOCTOU
            candidates.extend(detect_toctou(fn_node, source_lines, file_str))

            # Detector 3: Missing check (sibling comparison)
            siblings = [f for f in all_fns if f is not fn_node]
            candidates.extend(detect_missing_check(fn_node, siblings, source_lines, file_str))

            # Detector 4: Hardcoded credentials
            candidates.extend(detect_hardcoded_creds(fn_node, source_lines, file_str))

            # Detector 5: ReDoS
            candidates.extend(detect_redos(fn_node, source_lines, file_str))

            # Detector 6: Header injection
            candidates.extend(detect_header_injection(fn_node, source_lines, file_str))

    return candidates
