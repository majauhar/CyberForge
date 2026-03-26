"""C / C++ language plugin — comprehensive checkpoint and operation pattern catalogs.

Patterns are regex-matched line-by-line (stripped of leading whitespace), identical
in contract to python_plugin.py.  The plugin also exposes constants used by the
gap-fill stage (call_graph_c.py, gap_fill.py) and by the pipeline.

Covers both C (C99/C11) and C++ (C++11 through C++23), including common POSIX,
Win32, OpenSSL, libxml2, and Linux-kernel idioms.
"""

from __future__ import annotations
import re
from selector.static_analysis.models import CheckpointPattern, OperationPattern


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

_RAW_CHECKPOINT_PATTERNS: list[tuple[str, str]] = [

    # ── null / nullptr checks ─────────────────────────────────────────────────
    ("null_check",      r"if\s*\(\s*\w[\w>*.]*\s*==\s*NULL\b"),
    ("null_check",      r"if\s*\(\s*!\s*\w[\w>*.]"),
    ("null_check",      r"if\s*\(\s*\w[\w>*.]*\s*!=\s*NULL\b"),
    ("null_check",      r"if\s*\(\s*\w[\w>*.]*\s*==\s*nullptr\b"),
    ("null_check",      r"if\s*\(\s*\w[\w>*.]*\s*!=\s*nullptr\b"),
    ("null_check",      r"if\s*\(\s*NULL\s*==\s*\w[\w>*.]"),
    ("null_check",      r"if\s*\(\s*nullptr\s*==\s*\w[\w>*.]"),
    ("null_check",      r"if\s*\(\s*\w[\w>*.]*\s*&&\s*\w[\w>*.]"),       # short-circuit guard
    ("null_check",      r"assert\s*\(\s*\w[\w>*.]"),
    ("null_check",      r"\?\s*\w[\w>*.]*\s*:\s*NULL"),                  # ternary fallback

    # ── bounds / range checks ─────────────────────────────────────────────────
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*[<>]=?\s*\d+"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*>=\s*0\s*&&\s*\w[\w>*.]*\s*<"),
    ("bounds_check",    r"if\s*\(\s*\d+\s*<=\s*\w[\w>*.]*\s*&&\s*\w[\w>*.]*\s*<=\s*\d+"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*<\s*sizeof\s*\("),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*>=?\s*(?:MAX_\w+|BUFSIZ|PATH_MAX|NAME_MAX)\b"),
    ("bounds_check",    r"if\s*\(\s*offset\s*[+]\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]"),
    ("bounds_check",    r"if\s*\(\s*end\s*-\s*ptr\s*[<>]=?\s*\d+"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*-\s*\w[\w>*.]*\s*[<>]=?\s*\d+"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*%\s*sizeof\s*\("),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*>\s*\w[\w>*.]*\s*-\s*\d+"),
    ("bounds_check",    r"if\s*\(\s*\w[\w>*.]*\s*[<>]=?\s*\(\s*\w[\w>*.]*\s*-\s*\w[\w>*.]"),

    # ── integer overflow checks ───────────────────────────────────────────────
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*>\s*(?:INT_MAX|UINT_MAX|SIZE_MAX|LLONG_MAX|ULLONG_MAX)\b"),
    ("overflow_check",  r"__builtin_(?:add|sub|mul)_overflow\s*\("),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*>\s*\w[\w>*.]*\s*-\s*\w[\w>*.]"),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*>\s*\(\s*(?:SIZE_MAX|UINT_MAX)\s*/\s*\w[\w>*.]"),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*\*\s*\w[\w>*.]*\s*/\s*\w[\w>*.]*\s*!=\s*\w"),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*\+\s*\w[\w>*.]*\s*<\s*\w[\w>*.]"),
    ("overflow_check",  r"(?:CHECKED_ADD|SAFE_ADD|safe_mul|safe_add|overflow_check)\s*\("),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*>>\s*\d+"),
    ("overflow_check",  r"if\s*\(\s*\(\s*unsigned|size_t\s*\)\s*\w[\w>*.]*\s*!=\s*\w"),
    ("overflow_check",  r"if\s*\(\s*\w[\w>*.]*\s*<\s*0\s*\|\|\s*\w[\w>*.]*\s*>\s*\w"),

    # ── divide-by-zero guards ─────────────────────────────────────────────────
    ("zero_check",      r"if\s*\(\s*\w[\w>*.]*\s*==\s*0\s*\)"),
    ("zero_check",      r"if\s*\(\s*\w[\w>*.]*\s*!=\s*0\s*\)"),
    ("zero_check",      r"if\s*\(\s*!\s*\w[\w>*.]*\s*\)(?:.*return|.*abort)"),
    ("zero_check",      r"if\s*\(\s*\w[\w>*.]*\s*<=\s*0\s*\)"),
    ("zero_check",      r"assert\s*\(\s*\w[\w>*.]*\s*!=\s*0"),
    ("zero_check",      r"if\s*\(\s*divisor\s*==\s*0\s*\)"),

    # ── string length checks ──────────────────────────────────────────────────
    ("length_check",    r"if\s*\(\s*strlen\s*\(\s*\w[\w>*.]*\s*\)\s*[<>]=?\s*\d+"),
    ("length_check",    r"if\s*\(\s*strlen\s*\(\s*\w[\w>*.]*\s*\)\s*[<>]=?\s*sizeof\s*\("),
    ("length_check",    r"if\s*\(\s*strlen\s*\(\s*\w[\w>*.]*\s*\)\s*[<>]=?\s*\w[\w>*.]"),
    ("length_check",    r"if\s*\(\s*\w[\w>*.]*\s*==\s*0\s*\)"),
    ("length_check",    r"if\s*\(\s*\w[\w>*.]*\.length\s*\(\s*\)\s*[<>]=?\s*\d+"),      # C++ string
    ("length_check",    r"if\s*\(\s*\w[\w>*.]*\.size\s*\(\s*\)\s*[<>]=?\s*\d+"),
    ("length_check",    r"if\s*\(\s*len\s*==\s*0\s*\)"),
    ("length_check",    r"if\s*\(\s*\w[\w>*.]*_len\s*[<>]=?\s*(?:MAX_\w+|\d+)"),

    # ── integer range / narrowing-cast safety ─────────────────────────────────
    ("range_check",     r"if\s*\(\s*\w[\w>*.]*\s*[<>]=?\s*(?:CHAR_MAX|SCHAR_MAX|UCHAR_MAX|SHRT_MAX|USHRT_MAX)\b"),
    ("range_check",     r"if\s*\(\s*\w[\w>*.]*\s*>=\s*0\s*&&\s*\w[\w>*.]*\s*<=\s*\d+"),
    ("range_check",     r"if\s*\(\s*\(\s*unsigned\s*(?:char|short|int)\s*\)\s*\w[\w>*.]*\s*!=\s*\w"),
    ("range_check",     r"if\s*\(\s*\w[\w>*.]*\s*>=?\s*(?:INT_MIN|LONG_MIN|SHRT_MIN)\b"),
    ("range_check",     r"if\s*\(\s*\w[\w>*.]*\s*<=?\s*(?:INT_MAX|LONG_MAX|SHRT_MAX)\b"),
    ("range_check",     r"if\s*\(\s*\w[\w>*.]*\s*>=\s*\w[\w>*.]*\s*&&\s*\w[\w>*.]*\s*<=\s*\w[\w>*.]"),

    # ── remaining buffer capacity ─────────────────────────────────────────────
    ("capacity_check",  r"if\s*\(\s*\w[\w>*.]*\s*\+\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]"),
    ("capacity_check",  r"if\s*\(\s*buf_pos\s*\+\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]"),
    ("capacity_check",  r"if\s*\(\s*remaining\s*[<>]=?\s*\w[\w>*.]"),
    ("capacity_check",  r"if\s*\(\s*\w[\w>*.]*_remaining\s*[<>]=?\s*\d+"),
    ("capacity_check",  r"if\s*\(\s*\(\s*end\s*-\s*\w[\w>*.]*\s*\)\s*[<>]=?\s*\w[\w>*.]"),
    ("capacity_check",  r"if\s*\(\s*avail\s*<\s*\w[\w>*.]"),

    # ── file descriptor / handle validity ─────────────────────────────────────
    ("resource_check",  r"if\s*\(\s*\w[\w>*.]*\s*<\s*0\s*\)"),
    ("resource_check",  r"if\s*\(\s*\w[\w>*.]*\s*==\s*-1\s*\)"),
    ("resource_check",  r"if\s*\(\s*\w[\w>*.]*\s*==\s*INVALID_HANDLE_VALUE\b"),
    ("resource_check",  r"if\s*\(\s*\w[\w>*.]*\s*==\s*INVALID_SOCKET\b"),
    ("resource_check",  r"if\s*\(\s*fd\s*[<>]=?\s*0\s*\)"),
    ("resource_check",  r"if\s*\(\s*FAILED\s*\(\s*\w[\w>*.]"),
    ("resource_check",  r"if\s*\(\s*\w[\w>*.]*\s*==\s*NULL\s*\).*(?:fopen|open|socket)\b"),

    # ── lifecycle / state machine ─────────────────────────────────────────────
    ("lifecycle_check", r"if\s*\(\s*!\s*\w[\w>*.]*\.initialized\b"),
    ("lifecycle_check", r"if\s*\(\s*\w[\w>*.]*\.state\s*!=\s*\w*(?:INIT|OPEN|READY)\w*"),
    ("lifecycle_check", r"if\s*\(\s*\w[\w>*.]*\s*==\s*\w*(?:CLOSED|FREED|INVALID|DESTROYED)\w*"),
    ("lifecycle_check", r"if\s*\(\s*!\s*\w[\w>*.]*_initialized\b"),
    ("lifecycle_check", r"if\s*\(\s*\w[\w>*.]*\.magic\s*!=\s*\w"),
    ("lifecycle_check", r"if\s*\(\s*\w[\w>*.]*\.refcount\s*[<>]=?\s*0"),

    # ── free / delete guards ──────────────────────────────────────────────────
    ("free_check",      r"if\s*\(\s*\w[\w>*.]*\s*!=\s*NULL\s*\)(?:\s*\{)?\s*free\s*\("),
    ("free_check",      r"if\s*\(\s*\w[\w>*.]*\s*\)(?:\s*\{)?\s*free\s*\("),
    ("free_check",      r"if\s*\(\s*\w[\w>*.]*\s*!=\s*nullptr\s*\)"),
    ("free_check",      r"if\s*\(\s*\w[\w>*.]*\s*\)\s*delete\b"),
    ("free_check",      r"if\s*\(\s*\w[\w>*.]*_freed\s*\)"),

    # ── error / return-value checks ───────────────────────────────────────────
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*[!=<>]=?\s*-1\b"),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*<\s*0\b"),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*!=\s*0\b"),
    ("error_check",     r"if\s*\(\s*errno\b"),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*!=\s*(?:EXIT_SUCCESS|0|NULL)\b"),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*==\s*SOCKET_ERROR\b"),
    ("error_check",     r"if\s*\(\s*FAILED\s*\(\s*\w[\w>*.]"),
    ("error_check",     r"if\s*\(\s*!\s*\w[\w>*.]*\s*\)(?:.*return|.*goto|.*abort)"),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*!=\s*(?:ERROR_SUCCESS|S_OK)\b"),
    ("error_check",     r"perror\s*\(|strerror\s*\("),
    ("error_check",     r"if\s*\(\s*\w[\w>*.]*\s*==\s*EOF\b"),
    ("error_check",     r"if\s*\(\s*ferror\s*\(\s*\w[\w>*.]"),

    # ── auth / privilege guards ───────────────────────────────────────────────
    ("auth_guard",      r"if\s*\(\s*!\s*\w*(?:auth|perm|access|allow|admin|cap|priv)\w*"),
    ("auth_guard",      r"if\s*\(\s*uid\s*!=\s*0\b"),
    ("auth_guard",      r"if\s*\(\s*euid\s*!=\s*0\b"),
    ("auth_guard",      r"if\s*\(\s*getuid\s*\(\s*\)\s*!=\s*0"),
    ("auth_guard",      r"if\s*\(\s*geteuid\s*\(\s*\)\s*!=\s*0"),
    ("auth_guard",      r"(?:check|verify|require)_(?:permission|auth|access|capability|priv)\s*\("),
    ("auth_guard",      r"if\s*\(\s*\w*(?:role|privilege|capability)\w*\s*[!=]"),
    ("auth_guard",      r"if\s*\(\s*!is_(?:admin|root|privileged|authorized|authenticated)\s*\("),
    ("auth_guard",      r"cap_get_proc\s*\(|cap_get_flag\s*\("),
    ("auth_guard",      r"if\s*\(\s*\w[\w>*.]*\.uid\s*!=\s*\w[\w>*.]"),

    # ── mutex / lock acquisition ──────────────────────────────────────────────
    ("lock_acquire",    r"pthread_mutex_lock\s*\("),
    ("lock_acquire",    r"pthread_rwlock_(?:rd|wr)lock\s*\("),
    ("lock_acquire",    r"(?:std::)?unique_lock\s*<"),
    ("lock_acquire",    r"(?:std::)?lock_guard\s*<"),
    ("lock_acquire",    r"(?:std::)?scoped_lock\s*<"),
    ("lock_acquire",    r"sem_wait\s*\("),
    ("lock_acquire",    r"EnterCriticalSection\s*\("),
    ("lock_acquire",    r"WaitForSingleObject\s*\("),
    ("lock_acquire",    r"spin_lock\s*\(|spin_lock_irqsave\s*\("),

    # ── format / input validation ─────────────────────────────────────────────
    ("format_check",    r"if\s*\(\s*sscanf\s*\(.*\)\s*==\s*\d"),
    ("format_check",    r"if\s*\(\s*sscanf\s*\(.*\)\s*<\s*\d"),
    ("format_check",    r"strncmp\s*\(\s*\w[\w>*.]*\s*,\s*['\"]"),
    ("format_check",    r"regexec\s*\("),
    ("format_check",    r"if\s*\(\s*isdigit\s*\(|isalpha\s*\(|isalnum\s*\("),
    ("format_check",    r"if\s*\(\s*\w[\w>*.]*\[0\]\s*[=!]=\s*['\"]"),
    ("format_check",    r"strtol\s*\(.*endptr.*if.*endptr"),
    ("format_check",    r"if\s*\(\s*\w[\w>*.]*_valid\s*\)|\w[\w>*.]*_is_valid\s*\("),

    # ── payload / file size limits ────────────────────────────────────────────
    ("size_check",      r"if\s*\(\s*\w[\w>*.]*\s*>\s*(?:MAX_\w+|BUFSIZ|PATH_MAX|NAME_MAX)\b"),
    ("size_check",      r"if\s*\(\s*\w[\w>*.]*\s*>=\s*sizeof\s*\("),
    ("size_check",      r"if\s*\(\s*strlen\s*\(\s*\w[\w>*.]*\s*\)\s*[<>]=?\s*\d"),
    ("size_check",      r"if\s*\(\s*\w[\w>*.]*\s*>\s*(?:MAXPATHLEN|MAXNAMELEN|MAXHOSTNAMELEN)\b"),
    ("size_check",      r"if\s*\(\s*\w[\w>*.]*\s*>\s*\w[\w>*.]*_SIZE\b"),
    ("size_check",      r"if\s*\(\s*nbytes\s*[<>]=?\s*\d+"),
    ("size_check",      r"if\s*\(\s*\w[\w>*.]*_size\s*[<>]=?\s*(?:MAX_\w+|\d+)"),

    # ── crypto signature / HMAC / cert verification ───────────────────────────
    ("signature_check", r"(?:verify|check)_(?:signature|hmac|mac|hash|digest)\s*\("),
    ("signature_check", r"HMAC_Final\s*\("),
    ("signature_check", r"EVP_DigestVerify(?:Final|Update)?\s*\("),
    ("signature_check", r"RSA_verify\s*\(|DSA_verify\s*\(|ECDSA_verify\s*\("),
    ("signature_check", r"if\s*\(\s*memcmp\s*\(.*(?:hmac|digest|hash)"),
    ("signature_check", r"X509_verify\s*\(|SSL_CTX_set_verify\s*\("),

    # ── memory alignment ──────────────────────────────────────────────────────
    ("alignment_check", r"if\s*\(\s*\(\s*\w[\w>*.]*\s*%\s*(?:sizeof|\d+)\s*\)\s*!=\s*0"),
    ("alignment_check", r"if\s*\(\s*\(\s*uintptr_t\s*\)\s*\w[\w>*.]*\s*%\s*\w"),
    ("alignment_check", r"if\s*\(\s*\(\s*\w[\w>*.]*\s*&\s*(?:0x[0-9a-fA-F]+|\d+)\s*\)\s*!=\s*0"),
    ("alignment_check", r"__alignof__\s*\(|alignof\s*\("),
    ("alignment_check", r"if\s*\(\s*!IS_ALIGNED\s*\("),

    # ── type / tag checks ─────────────────────────────────────────────────────
    ("type_check",      r"if\s*\(\s*\w[\w>*.]*\.type\s*[=!]=\s*\w"),
    ("type_check",      r"if\s*\(\s*\w[\w>*.]*\.tag\s*[=!]=\s*\w"),
    ("type_check",      r"if\s*\(\s*\w[\w>*.]*\.kind\s*[=!]=\s*\w"),
    ("type_check",      r"dynamic_cast\s*<"),
    ("type_check",      r"typeid\s*\(\s*\w[\w>*.]*\s*\)\s*=="),
    ("type_check",      r"if\s*\(\s*\w[\w>*.]*->type\s*[=!]=\s*\w"),
    ("type_check",      r"switch\s*\(\s*\w[\w>*.]*\.type\s*\)"),

    # ── pointer arithmetic range validation ───────────────────────────────────
    ("pointer_arith_check", r"if\s*\(\s*\w[\w>*.]*\s*\+\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]"),
    ("pointer_arith_check", r"if\s*\(\s*\w[\w>*.]*\s*<=?\s*end\b"),
    ("pointer_arith_check", r"if\s*\(\s*\w[\w>*.]*\s*>=?\s*base\b"),
    ("pointer_arith_check", r"if\s*\(\s*\w[\w>*.]*\s*-\s*\w[\w>*.]*\s*[<>]=?\s*\d"),
    ("pointer_arith_check", r"if\s*\(\s*\w[\w>*.]*\s*[<>]=?\s*\w[\w>*.]*\s*\+\s*\d"),

    # ── initialization checks ─────────────────────────────────────────────────
    ("init_check",      r"if\s*\(\s*!\s*\w[\w>*.]*\.initialized\b"),
    ("init_check",      r"if\s*\(\s*\w[\w>*.]*\.state\s*==\s*\w*INIT\w*"),
    ("init_check",      r"if\s*\(\s*!\w[\w>*.]*_initialized\b"),
    ("init_check",      r"if\s*\(\s*\w[\w>*.]*\.magic\s*!=\s*\w"),
    ("init_check",      r"if\s*\(\s*\w[\w>*.]*\.refcount\s*<=?\s*0"),
    ("init_check",      r"if\s*\(\s*\w[\w>*.]*\s*==\s*\w*(?:INVALID|UNINITIALIZED)\w*"),

    # ── ownership / user-identity checks ──────────────────────────────────────
    ("ownership_check", r"if\s*\(\s*\w[\w>*.]*\.(?:uid|owner_id|user_id)\s*!=\s*\w"),
    ("ownership_check", r"if\s*\(\s*getuid\s*\(\s*\)\s*!=\s*\w[\w>*.]"),
    ("ownership_check", r"if\s*\(\s*geteuid\s*\(\s*\)\s*!=\s*\w[\w>*.]"),
    ("ownership_check", r"if\s*\(\s*\w[\w>*.]*\.owner\s*!=\s*\w[\w>*.]"),
    ("ownership_check", r"if\s*\(\s*\w[\w>*.]*->creator\s*!=\s*\w"),
    ("ownership_check", r"if\s*\(\s*current_uid\s*[=!]=\s*\w[\w>*.]"),

    # ── assertions ────────────────────────────────────────────────────────────
    ("assert",          r"\bassert\s*\("),
    ("assert",          r"\bstatic_assert\s*\("),
    ("assert",          r"\bASSERT\s*\(|\bVERIFY\s*\(|\bREQUIRE\s*\("),
    ("assert",          r"\bBUG_ON\s*\(|\bWARN_ON\s*\("),

    # ── rate / connection limiting ────────────────────────────────────────────
    ("rate_limit",      r"if\s*\(\s*\w*(?:rate|limit|quota|count|burst)\w*\s*[><!]=?\s*\w"),
    ("rate_limit",      r"if\s*\(\s*\w[\w>*.]*\s*>\s*MAX_(?:CONNECTIONS|REQUESTS|RETRIES)\b"),
    ("rate_limit",      r"if\s*\(\s*connection_count\s*[<>]=?\s*\w"),
    ("rate_limit",      r"if\s*\(\s*request_count\s*[<>]=?\s*\w"),

    # ── input sanitization ────────────────────────────────────────────────────
    ("sanitize",        r"(?:html_encode|xml_escape|sql_escape|sanitize|escape_string)\s*\("),
    ("sanitize",        r"(?:strtol|strtoul|strtoull|strtoll)\s*\("),
    ("sanitize",        r"(?:strtoimax|strtoumax)\s*\("),
    ("sanitize",        r"mysql_real_escape_string\s*\("),
    ("sanitize",        r"sqlite3_mprintf\s*\(\s*\"%q\""),
    ("sanitize",        r"(?:htmlspecialchars|htmlentities|strip_tags)\s*\("),

    # ── path traversal guards ─────────────────────────────────────────────────
    ("path_traversal_check", r"realpath\s*\("),
    ("path_traversal_check", r"if\s*\(\s*strstr\s*\(\s*\w[\w>*.]*\s*,\s*[\"\']\\.\\."),
    ("path_traversal_check", r"if\s*\(\s*strncmp\s*\(\s*\w[\w>*.]*\s*,\s*base_dir"),
    ("path_traversal_check", r"if\s*\(\s*!\s*is_safe_path\s*\("),
    ("path_traversal_check", r"chroot\s*\("),

    # ── C++ exception guards ──────────────────────────────────────────────────
    ("exception_guard", r"\btry\s*\{"),
    ("exception_guard", r"\bcatch\s*\("),
    ("exception_guard", r"\bcatch\s*\(\s*const\s+std::(?:bad_alloc|exception|overflow_error|runtime_error)"),
    ("exception_guard", r"\bcatch\s*\(\s*\.\.\.\s*\)"),
]


# ─────────────────────────────────────────────────────────────────────────────
# OPERATION PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

_RAW_OPERATION_PATTERNS: list[tuple[str, str, str]] = [

    # ── unsafe memory writes ──────────────────────────────────────────────────
    ("memory_write",    r"\bmemcpy\s*\(",                               "Ante buffer operation"),
    ("memory_write",    r"\bmemmove\s*\(",                              "Ante buffer operation"),
    ("memory_write",    r"\bstrcpy\s*\(",                               "Ante buffer operation"),
    ("memory_write",    r"\bstrcat\s*\(",                               "Ante buffer operation"),
    ("memory_write",    r"\bsprintf\s*\(",                              "Ante buffer operation"),
    ("memory_write",    r"\bgets\s*\(",                                 "Ante buffer operation"),
    ("memory_write",    r"\bvsprintf\s*\(",                             "Ante buffer operation"),
    ("memory_write",    r"\bwcscpy\s*\(",                               "Ante buffer operation"),
    ("memory_write",    r"\bwcscat\s*\(",                               "Ante buffer operation"),
    ("memory_write",    r"\bwsprintfW?\s*\(",                           "Ante buffer operation"),
    ("memory_write",    r"\*\s*\w[\w>*.]*\s*=(?!=)",                   "Ante buffer operation"),
    ("memory_write",    r"\w[\w>*.]*\[\s*\w[\w>*.]*\s*\]\s*=",         "Ante buffer operation"),

    # ── bounded-but-risky writes ──────────────────────────────────────────────
    ("memory_write_bounded", r"\bstrncpy\s*\(",                        "Ante buffer operation"),
    ("memory_write_bounded", r"\bstrncat\s*\(",                        "Ante buffer operation"),
    ("memory_write_bounded", r"\bsnprintf\s*\(",                       "Ante buffer operation"),
    ("memory_write_bounded", r"\bmemcpy_s\s*\(",                       "Ante buffer operation"),
    ("memory_write_bounded", r"\bstrlcpy\s*\(",                        "Ante buffer operation"),
    ("memory_write_bounded", r"\bstrlcat\s*\(",                        "Ante buffer operation"),

    # ── array / pointer indexing ──────────────────────────────────────────────
    ("array_index",     r"\w[\w>*.]*\[\s*\w[\w>*.]*\s*\](?!\s*=)",     "Ante buffer operation"),
    ("array_index",     r"\*\s*\(\s*\w[\w>*.]*\s*\+\s*\w[\w>*.]",      "Ante buffer operation"),
    ("array_index",     r"\w[\w>*.]*\[\s*\w[\w>*.]*\s*\]\s*\[",        "Ante buffer operation"),
    ("array_index",     r"\w[\w>*.]*\[\s*-\s*\w[\w>*.]",               "Ante buffer operation"),
    ("array_index",     r"\*\s*\(\s*\(\s*\w[\w\s*]*\*\s*\)\s*\w[\w>*.]*\s*\+", "Ante buffer operation"),

    # ── memory allocation ─────────────────────────────────────────────────────
    ("alloc",           r"\bmalloc\s*\(",                               "Memory allocation"),
    ("alloc",           r"\bcalloc\s*\(",                               "Memory allocation"),
    ("alloc",           r"\brealloc\s*\(",                              "Memory allocation"),
    ("alloc",           r"\bnew\b(?!\s*\()",                            "Memory allocation"),
    ("alloc",           r"\bnew\s*\[",                                  "Memory allocation"),
    ("alloc",           r"\balloca\s*\(",                               "Memory allocation"),
    ("alloc",           r"\bHeapAlloc\s*\(",                            "Memory allocation"),
    ("alloc",           r"\bVirtualAlloc\s*\(",                         "Memory allocation"),
    ("alloc",           r"\b_alloca\s*\(",                              "Memory allocation"),
    ("alloc",           r"\boperator\s+new\s*\(",                       "Memory allocation"),

    # ── memory deallocation ───────────────────────────────────────────────────
    ("free_op",         r"\bfree\s*\(",                                 "Memory release"),
    ("free_op",         r"\bdelete\s+\w",                               "Memory release"),
    ("free_op",         r"\bdelete\s*\[\]",                             "Memory release"),
    ("free_op",         r"\bHeapFree\s*\(",                             "Memory release"),
    ("free_op",         r"\bVirtualFree\s*\(",                          "Memory release"),
    ("free_op",         r"\bCoTaskMemFree\s*\(",                        "Memory release"),
    ("free_op",         r"\boperator\s+delete\s*\(",                    "Memory release"),

    # ── pointer dereference ───────────────────────────────────────────────────
    ("deref",           r"\*\s*\w[\w>*.]*(?!\s*=)",                     "Invalid pointer"),
    ("deref",           r"\w[\w>*.]*\s*->\s*\w",                        "Invalid pointer"),
    ("deref",           r"\(\s*\*\s*\w[\w>*.]*\s*\)\s*\.",              "Invalid pointer"),
    ("deref",           r"\w[\w>*.]*\s*\[\s*\w[\w>*.]*\s*\]\s*\.",      "Invalid pointer"),

    # ── format string functions ───────────────────────────────────────────────
    ("format_string_op", r"\bprintf\s*\(",                              "Input validation"),
    ("format_string_op", r"\bfprintf\s*\(",                             "Input validation"),
    ("format_string_op", r"\bsprintf\s*\(",                             "Input validation"),
    ("format_string_op", r"\bsnprintf\s*\(",                            "Input validation"),
    ("format_string_op", r"\bvprintf\s*\(",                             "Input validation"),
    ("format_string_op", r"\bvfprintf\s*\(",                            "Input validation"),
    ("format_string_op", r"\bvsprintf\s*\(",                            "Input validation"),
    ("format_string_op", r"\bvsnprintf\s*\(",                           "Input validation"),
    ("format_string_op", r"\bsyslog\s*\(",                              "Input validation"),
    ("format_string_op", r"\berr\s*\(\s*\d+",                          "Input validation"),
    ("format_string_op", r"\bwarn\s*\(",                                "Input validation"),

    # ── process / shell execution ─────────────────────────────────────────────
    ("subprocess",      r"\bsystem\s*\(",                               "Dynamic code"),
    ("subprocess",      r"\bpopen\s*\(",                                "Dynamic code"),
    ("subprocess",      r"\bexecv[pe]?\s*\(",                           "Dynamic code"),
    ("subprocess",      r"\bexecl[pe]?\s*\(",                           "Dynamic code"),
    ("subprocess",      r"\bexeclp\s*\(",                               "Dynamic code"),
    ("subprocess",      r"\bposix_spawn\s*\(",                          "Dynamic code"),
    ("subprocess",      r"\bShellExecute\s*\(",                         "Dynamic code"),
    ("subprocess",      r"\bCreateProcess\s*\(",                        "Dynamic code"),

    # ── file / path operations ────────────────────────────────────────────────
    ("file_op",         r"\bfopen\s*\(",                                "Path-related"),
    ("file_op",         r"\bopen\s*\(\s*\w[\w>*.]*\s*,\s*O_",          "Path-related"),
    ("file_op",         r"\bfwrite\s*\(",                               "Path-related"),
    ("file_op",         r"\bfread\s*\(",                                "Path-related"),
    ("file_op",         r"\bunlink\s*\(",                               "Path-related"),
    ("file_op",         r"\brename\s*\(",                               "Path-related"),
    ("file_op",         r"\bremove\s*\(",                               "Path-related"),
    ("file_op",         r"\bchmod\s*\(",                                "Path-related"),
    ("file_op",         r"\bchown\s*\(",                                "Path-related"),
    ("file_op",         r"\bmkdir\s*\(",                                "Path-related"),
    ("file_op",         r"\bCreateFile\s*\(",                           "Path-related"),
    ("file_op",         r"\bWriteFile\s*\(|\bReadFile\s*\(",            "Path-related"),

    # ── database execution ────────────────────────────────────────────────────
    ("sql_exec",        r"\bmysql_query\s*\(",                          "Input validation"),
    ("sql_exec",        r"\bsqlite3_exec\s*\(",                         "Input validation"),
    ("sql_exec",        r"\bPQexec\s*\(",                               "Input validation"),
    ("sql_exec",        r"\bOCIStmtExecute\s*\(",                       "Input validation"),
    ("sql_exec",        r"\bdb2_exec\s*\(",                             "Input validation"),
    ("sql_exec",        r"\bsql_exec\s*\(",                             "Input validation"),

    # ── weak crypto ───────────────────────────────────────────────────────────
    ("crypto_op",       r"\brand\s*\(",                                 "Confidentiality"),
    ("crypto_op",       r"\bsrand\s*\(",                                "Confidentiality"),
    ("crypto_op",       r"\brandom\s*\(",                               "Confidentiality"),
    ("crypto_op",       r"\blrand48\s*\(|\bmrand48\s*\(",               "Confidentiality"),
    ("crypto_op",       r"\bMD5\s*\(",                                  "Confidentiality"),
    ("crypto_op",       r"\bSHA1\s*\(",                                 "Confidentiality"),
    ("crypto_op",       r"\bDES_\w+\s*\(",                              "Confidentiality"),
    ("crypto_op",       r"EVP_EncryptInit\w*\s*\(.*(?:DES|RC4|MD5)",   "Confidentiality"),
    ("crypto_op",       r"\bRC4_\w+\s*\(",                              "Confidentiality"),
    ("crypto_op",       r"\bdes_\w+\s*\(",                              "Confidentiality"),

    # ── privilege escalation ──────────────────────────────────────────────────
    ("priv_op",         r"\bsetuid\s*\(",                               "Privileges"),
    ("priv_op",         r"\bsetgid\s*\(",                               "Privileges"),
    ("priv_op",         r"\bsetgroups\s*\(",                            "Privileges"),
    ("priv_op",         r"\bsetresuid\s*\(",                            "Privileges"),
    ("priv_op",         r"\bsetresgid\s*\(",                            "Privileges"),
    ("priv_op",         r"\bcapset\s*\(",                               "Privileges"),
    ("priv_op",         r"\bAdjustTokenPrivileges\s*\(",                "Privileges"),
    ("priv_op",         r"\bseteuid\s*\(|\bsetegid\s*\(",               "Privileges"),

    # ── socket / network ──────────────────────────────────────────────────────
    ("socket_op",       r"\bsocket\s*\(",                               "Web"),
    ("socket_op",       r"\bconnect\s*\(",                              "Web"),
    ("socket_op",       r"\bbind\s*\(",                                 "Web"),
    ("socket_op",       r"\baccept\s*\(",                               "Web"),
    ("socket_op",       r"\brecv\s*\(",                                 "Web"),
    ("socket_op",       r"\brecvfrom\s*\(",                             "Web"),
    ("socket_op",       r"\brecvmsg\s*\(",                              "Web"),
    ("socket_op",       r"\bsend\s*\(",                                 "Web"),
    ("socket_op",       r"\bWSARecv\s*\(|\bWSASend\s*\(",               "Web"),

    # ── network data reception ────────────────────────────────────────────────
    ("network_recv",    r"\bread\s*\(\s*\w[\w>*.]*\s*,",               "Input validation"),
    ("network_recv",    r"\brecv\s*\(",                                 "Input validation"),
    ("network_recv",    r"\bfgets\s*\(",                                "Input validation"),
    ("network_recv",    r"\bfgetc\s*\(|\bfread\s*\(",                  "Input validation"),
    ("network_recv",    r"\bgetline\s*\(|\bgetdelim\s*\(",             "Input validation"),

    # ── unsafe type casts ─────────────────────────────────────────────────────
    ("type_cast",       r"\(\s*\w[\w\s*]*\*\s*\)\s*\w[\w>*.]",         "Type-related"),
    ("type_cast",       r"\breinterpret_cast\s*<",                      "Type-related"),
    ("type_cast",       r"\bstatic_cast\s*<.*\*>",                      "Type-related"),
    ("type_cast",       r"\(\s*int\s*\)\s*\w[\w>*.]",                  "Type-related"),
    ("type_cast",       r"\(\s*char\s*\)\s*\w[\w>*.]",                 "Type-related"),
    ("type_cast",       r"\(\s*unsigned\s+\w+\s*\)\s*\w[\w>*.]",       "Type-related"),
    ("type_cast",       r"\(\s*size_t\s*\)\s*-\s*\d",                  "Type-related"),

    # ── integer arithmetic (overflow vectors) ─────────────────────────────────
    ("integer_arith",   r"\w[\w>*.]*\s*\*\s*sizeof\s*\(",              "Numeric errors"),
    ("integer_arith",   r"\w[\w>*.]*\s*\*\s*\w[\w>*.]*(?=\s*\))",      "Numeric errors"),
    ("integer_arith",   r"\w[\w>*.]*\s*\+\s*\w[\w>*.]*(?=\s*[,;)])",  "Numeric errors"),
    ("integer_arith",   r"\w[\w>*.]*\s*<<\s*\d+",                      "Numeric errors"),
    ("integer_arith",   r"\(\s*\w[\w>*.]*\s*-\s*\w[\w>*.]*\s*\)\s*\*","Numeric errors"),
    ("integer_arith",   r"\w[\w>*.]*\s*\*\s*\w[\w>*.]*\s*\+\s*\w[\w>*.]","Numeric errors"),

    # ── unsafe integer conversions ────────────────────────────────────────────
    ("integer_convert", r"\batoi\s*\(",                                 "Numeric errors"),
    ("integer_convert", r"\batol\s*\(|\batoll\s*\(",                   "Numeric errors"),
    ("integer_convert", r"\batof\s*\(",                                 "Numeric errors"),
    ("integer_convert", r"\bsscanf\s*\(",                               "Numeric errors"),
    ("integer_convert", r"\(\s*int\s*\)\s*strlen\s*\(",                "Numeric errors"),

    # ── signal handler registration ───────────────────────────────────────────
    ("signal_handler",  r"\bsignal\s*\(",                               "Concurrency"),
    ("signal_handler",  r"\bsigaction\s*\(",                            "Concurrency"),
    ("signal_handler",  r"\braise\s*\(",                                "Concurrency"),
    ("signal_handler",  r"\bkill\s*\(\s*\d",                           "Concurrency"),
    ("signal_handler",  r"\bpthread_kill\s*\(",                         "Concurrency"),

    # ── memory mapping ────────────────────────────────────────────────────────
    ("mmap_op",         r"\bmmap\s*\(",                                 "Memory allocation"),
    ("mmap_op",         r"\bmunmap\s*\(",                               "Memory release"),
    ("mmap_op",         r"\bmprotect\s*\(",                             "Privileges"),
    ("mmap_op",         r"\bVirtualAlloc\s*\(",                         "Memory allocation"),
    ("mmap_op",         r"\bVirtualProtect\s*\(",                       "Privileges"),
    ("mmap_op",         r"\bMapViewOfFile\s*\(",                        "Memory allocation"),

    # ── IPC ───────────────────────────────────────────────────────────────────
    ("ipc_op",          r"\bpipe\s*\(",                                 "Concurrency"),
    ("ipc_op",          r"\bsocketpair\s*\(",                           "Web"),
    ("ipc_op",          r"\bmsgget\s*\(|\bmsgsnd\s*\(|\bmsgrcv\s*\(",  "Data structure"),
    ("ipc_op",          r"\bshmget\s*\(|\bshmat\s*\(",                 "Memory allocation"),
    ("ipc_op",          r"\bmq_open\s*\(|\bmq_send\s*\(|\bmq_receive\s*\(", "Web"),
    ("ipc_op",          r"\bshm_open\s*\(",                             "Memory allocation"),

    # ── thread creation ───────────────────────────────────────────────────────
    ("thread_op",       r"\bpthread_create\s*\(",                       "Concurrency"),
    ("thread_op",       r"\bstd::thread\s*\(",                          "Concurrency"),
    ("thread_op",       r"\bCreateThread\s*\(",                         "Concurrency"),
    ("thread_op",       r"\b_beginthread\s*\(|\b_beginthreadex\s*\(",  "Concurrency"),
    ("thread_op",       r"\bpthread_detach\s*\(|\bpthread_join\s*\(",  "Concurrency"),

    # ── shared / global state mutation ────────────────────────────────────────
    ("state_mutation",  r"\bglobal_\w+\s*=",                           "Encapsulation"),
    ("state_mutation",  r"\bshared_\w+\s*=",                           "Encapsulation"),
    ("state_mutation",  r"\bg_\w+\s*=",                                "Encapsulation"),
    ("state_mutation",  r"\w[\w>*.]*\s*->\s*\w[\w>*.]*\s*=",           "Encapsulation"),
    ("state_mutation",  r"\batomic_store\s*\(|\bstd::atomic\b",        "Encapsulation"),

    # ── environment variable writes ───────────────────────────────────────────
    ("env_write",       r"\bsetenv\s*\(",                               "Encapsulation"),
    ("env_write",       r"\bputenv\s*\(",                               "Encapsulation"),
    ("env_write",       r"\b_putenv\s*\(",                              "Encapsulation"),
    ("env_write",       r"\b_wputenv\s*\(",                             "Encapsulation"),

    # ── XML parsing ───────────────────────────────────────────────────────────
    ("xml_parse",       r"\bxmlParseMemory\s*\(",                       "Web"),
    ("xml_parse",       r"\bxmlReadMemory\s*\(",                        "Web"),
    ("xml_parse",       r"\bXML_Parse\s*\(",                            "Web"),
    ("xml_parse",       r"\bxmlParseFile\s*\(",                         "Web"),
    ("xml_parse",       r"\bxmlSAXParseMemory\s*\(",                    "Web"),

    # ── logging ───────────────────────────────────────────────────────────────
    ("log_op",          r"\bsyslog\s*\(",                               "Input validation"),
    ("log_op",          r"\bfprintf\s*\(\s*stderr",                     "Input validation"),
    ("log_op",          r"\bperror\s*\(",                               "Input validation"),
    ("log_op",          r"\bprintf\s*\(.*%s.*\w",                      "Input validation"),
    ("log_op",          r"\berr\s*\(\s*\d|\bwarn\s*\(",                "Input validation"),

    # ── data returned to caller ───────────────────────────────────────────────
    ("data_return",     r"\breturn\s+\w[\w>*.]",                        "Confidentiality"),
    ("data_return",     r"\*\s*out_\w+\s*=",                           "Confidentiality"),
    ("data_return",     r"\*\s*result\s*=",                             "Confidentiality"),
    ("data_return",     r"\bwrite\s*\(\s*\w[\w>*.]*\s*,.*\w[\w>*.]",   "Confidentiality"),

    # ── stack allocation / VLA ────────────────────────────────────────────────
    ("stack_alloc",     r"\balloca\s*\(",                               "Memory allocation"),
    ("stack_alloc",     r"\b_alloca\s*\(",                              "Memory allocation"),
    ("stack_alloc",     r"\w+\s+\w+\s*\[\s*\w[\w>*.]*\s*\]",           "Memory allocation"),
    ("stack_alloc",     r"char\s+\w+\s*\[\s*\w[\w>*.]*\s*\]",          "Memory allocation"),

    # ── pointer arithmetic ────────────────────────────────────────────────────
    ("ptr_arith",       r"\w[\w>*.]*\s*\+\s*\w[\w>*.]*(?=\s*[;,)])",   "Ante buffer operation"),
    ("ptr_arith",       r"\w[\w>*.]*\s*\+=\s*\w[\w>*.]",               "Ante buffer operation"),
    ("ptr_arith",       r"\w[\w>*.]*\s*-\s*\w[\w>*.]*(?=\s*[;,)])",    "Ante buffer operation"),
    ("ptr_arith",       r"\(\s*char\s*\*\s*\)\s*\w[\w>*.]*\s*\+",      "Ante buffer operation"),
]


# ─────────────────────────────────────────────────────────────────────────────
# GAP-FILL CONSTANTS (used by gap_fill.py and call_graph_c.py)
# ─────────────────────────────────────────────────────────────────────────────

UAF_FREE_PATTERNS = ["free(", "delete ", "delete[]", "HeapFree(", "VirtualFree("]
UAF_USE_PATTERNS  = ["->", "*ptr", "ptr["]

DOUBLE_FREE_SIGNALS = ["free(", "delete ", "delete[]"]

TOCTOU_CHECK_OPS = [
    "stat(", "lstat(", "access(", "fstat(", "faccessat("]
TOCTOU_USE_OPS   = [
    "fopen(", "open(", "unlink(", "rename(", "chmod(", "chown(", "mkdir("]

FORMAT_STRING_SINKS = [
    "printf(", "fprintf(", "sprintf(", "snprintf(",
    "vprintf(", "vfprintf(", "vsprintf(", "syslog(", "err(", "warn("]

WEAK_RANDOM = ["rand(", "srand(", "random(", "lrand48(", "mrand48("]
WEAK_ALGOS  = ["MD5(", "SHA1(", "DES_", "RC4_", "des_"]
SECURITY_CONTEXTS = [
    "token", "key", "nonce", "salt", "password", "passwd",
    "session", "csrf", "auth", "secret", "iv", "seed", "credential",
    "otp", "pin", "signing", "signature", "hmac", "cookie"]

LOCK_SIGNALS = [
    "pthread_mutex_lock", "lock_guard", "unique_lock", "scoped_lock",
    "sem_wait", "EnterCriticalSection", "WaitForSingleObject", "spin_lock"]

FFI_PATTERNS = [
    r"JNIEnv\s*\*",
    r"JNIEXPORT\b",
    r"__asm__?\s*\(",
    r"__declspec\s*\(",
    r"extern\s+['\"]C['\"]",
    r"#pragma\s+comment\s*\(\s*lib",
    r"\bdlopen\s*\(|\bdlsym\s*\(",
]

SANITIZER_NAMES = [
    "sanitize", "escape", "encode_html", "xml_escape", "sql_escape",
    "validate_input", "strip_tags", "htmlspecialchars", "htmlentities",
    "strtol", "strtoul", "strtoull", "strtoll", "strtoimax", "strtoumax",
    "atoi_safe", "safe_atoi", "safe_strtol", "mysql_real_escape_string"]


# ─────────────────────────────────────────────────────────────────────────────
# PLUGIN CLASS
# ─────────────────────────────────────────────────────────────────────────────

class CPlugin:
    """C / C++ language plugin."""

    language: str = "c"
    file_extensions: list[str] = [".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh"]

    _checkpoint_patterns: list[CheckpointPattern] = [
        CheckpointPattern(type=t, pattern=p) for t, p in _RAW_CHECKPOINT_PATTERNS
    ]
    _operation_patterns: list[OperationPattern] = [
        OperationPattern(type=t, pattern=p, cwe_class=c)
        for t, p, c in _RAW_OPERATION_PATTERNS
    ]

    _compiled_checkpoints: list[tuple[str, re.Pattern]] = [
        (t, re.compile(p)) for t, p in _RAW_CHECKPOINT_PATTERNS
    ]
    _compiled_operations: list[tuple[str, re.Pattern, str]] = [
        (t, re.compile(p), c) for t, p, c in _RAW_OPERATION_PATTERNS
    ]

    def get_checkpoint_patterns(self) -> list[CheckpointPattern]:
        return self._checkpoint_patterns

    def get_operation_patterns(self) -> list[OperationPattern]:
        return self._operation_patterns

    def get_ffi_patterns(self) -> list[str]:
        return FFI_PATTERNS

    def get_sanitizer_names(self) -> list[str]:
        return SANITIZER_NAMES

    def is_public_function(self, fn_name: str, context: dict) -> bool:
        """
        A C/C++ function is public if:
        - Its declaration line does NOT contain 'static '
        - Name does not start with '_' or '__'

        context keys expected:
          declaration_line: str  — the full text of the function's declaration
        """
        decl: str = context.get("declaration_line", "")

        # static functions have internal linkage — not public API
        if re.search(r"\bstatic\b", decl):
            return False

        # underscore-prefixed = implementation detail
        if fn_name.startswith("_"):
            return False

        return True

    def extract_imports(self, source: str) -> dict[str, str]:
        """Parse #include directives. Returns stem → header path mapping."""
        imports: dict[str, str] = {}
        for line in source.splitlines():
            stripped = line.strip()
            m = re.match(r'#\s*include\s+[<"]([^>"]+)[>"]', stripped)
            if m:
                header = m.group(1)
                stem = header.rsplit("/", 1)[-1].replace(".h", "").replace(".hpp", "")
                imports[stem] = header
        return imports

    def preferred_backend(self) -> str:
        return "treesitter"

    def match_checkpoints(self, line: str) -> list[tuple[str, str]]:
        """Return list of (type, line) for all matching checkpoint patterns."""
        results = []
        for cp_type, regex in self._compiled_checkpoints:
            if regex.search(line):
                results.append((cp_type, line))
        return results

    def match_operations(self, line: str) -> list[tuple[str, str, str]]:
        """Return list of (type, line, cwe_class) for all matching operation patterns."""
        results = []
        for op_type, regex, cwe_class in self._compiled_operations:
            if regex.search(line):
                results.append((op_type, line, cwe_class))
        return results
