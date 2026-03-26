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

    # ── C/C++ null_check × memory ops ─────────────────────────────────────────
    ("null_check",       "deref"):               ["CWE-476"],
    ("null_check",       "free_op"):             ["CWE-476", "CWE-415"],
    ("null_check",       "memory_write"):        ["CWE-476", "CWE-787"],
    ("null_check",       "format_string_op"):    ["CWE-476", "CWE-134"],
    ("null_check",       "integer_arith"):       ["CWE-476", "CWE-190"],
    ("null_check",       "type_cast"):           ["CWE-476", "CWE-704"],
    ("null_check",       "network_recv"):        ["CWE-476", "CWE-125"],
    ("null_check",       "mmap_op"):             ["CWE-476", "CWE-401"],
    ("null_check",       "ptr_arith"):           ["CWE-476", "CWE-823"],
    ("null_check",       "integer_convert"):     ["CWE-476", "CWE-190"],
    ("null_check",       "thread_op"):           ["CWE-476", "CWE-362"],
    ("null_check",       "stack_alloc"):         ["CWE-476", "CWE-121"],
    ("null_check",       "memory_write_bounded"):["CWE-476", "CWE-193"],

    # ── C/C++ bounds_check × buffer/memory ops ────────────────────────────────
    ("bounds_check",     "memory_write"):        ["CWE-787", "CWE-120"],
    ("bounds_check",     "memory_write_bounded"):["CWE-193", "CWE-787"],
    ("bounds_check",     "stack_alloc"):         ["CWE-121", "CWE-131"],
    ("bounds_check",     "format_string_op"):    ["CWE-134", "CWE-787"],
    ("bounds_check",     "type_cast"):           ["CWE-787", "CWE-704"],
    ("bounds_check",     "deref"):               ["CWE-125", "CWE-476"],
    ("bounds_check",     "integer_arith"):       ["CWE-190", "CWE-193"],
    ("bounds_check",     "ptr_arith"):           ["CWE-823", "CWE-125"],
    ("bounds_check",     "network_recv"):        ["CWE-125", "CWE-787"],
    ("bounds_check",     "integer_convert"):     ["CWE-197", "CWE-190"],
    ("bounds_check",     "mmap_op"):             ["CWE-131", "CWE-789"],

    # ── C/C++ overflow_check × arithmetic/alloc ───────────────────────────────
    ("overflow_check",   "integer_arith"):       ["CWE-190", "CWE-191"],
    ("overflow_check",   "stack_alloc"):         ["CWE-121", "CWE-190"],
    ("overflow_check",   "memory_write"):        ["CWE-190", "CWE-787"],
    ("overflow_check",   "type_cast"):           ["CWE-190", "CWE-197"],
    ("overflow_check",   "ptr_arith"):           ["CWE-190", "CWE-823"],
    ("overflow_check",   "integer_convert"):     ["CWE-197", "CWE-190"],
    ("overflow_check",   "mmap_op"):             ["CWE-190", "CWE-789"],
    ("overflow_check",   "memory_write_bounded"):["CWE-190", "CWE-193"],

    # ── zero_check × division ─────────────────────────────────────────────────
    ("zero_check",       "integer_arith"):       ["CWE-369"],
    ("zero_check",       "alloc"):               ["CWE-369", "CWE-131"],
    ("zero_check",       "array_index"):         ["CWE-369", "CWE-125"],
    ("zero_check",       "integer_convert"):     ["CWE-369", "CWE-197"],

    # ── length_check × string/memory ops ──────────────────────────────────────
    ("length_check",     "memory_write"):        ["CWE-120", "CWE-787"],
    ("length_check",     "memory_write_bounded"):["CWE-193", "CWE-120"],
    ("length_check",     "format_string_op"):    ["CWE-134", "CWE-787"],
    ("length_check",     "stack_alloc"):         ["CWE-121", "CWE-131"],
    ("length_check",     "network_recv"):        ["CWE-120", "CWE-125"],
    ("length_check",     "alloc"):               ["CWE-131", "CWE-122"],

    # ── range_check × integer narrowing ───────────────────────────────────────
    ("range_check",      "type_cast"):           ["CWE-197", "CWE-704"],
    ("range_check",      "integer_convert"):     ["CWE-197", "CWE-190"],
    ("range_check",      "array_index"):         ["CWE-129", "CWE-125"],
    ("range_check",      "integer_arith"):       ["CWE-190", "CWE-193"],

    # ── capacity_check × write ops ────────────────────────────────────────────
    ("capacity_check",   "memory_write"):        ["CWE-787", "CWE-120"],
    ("capacity_check",   "memory_write_bounded"):["CWE-193", "CWE-787"],
    ("capacity_check",   "network_recv"):        ["CWE-787", "CWE-125"],
    ("capacity_check",   "ptr_arith"):           ["CWE-823", "CWE-787"],

    # ── resource_check × resource use ─────────────────────────────────────────
    ("resource_check",   "deref"):               ["CWE-476", "CWE-824"],
    ("resource_check",   "free_op"):             ["CWE-415", "CWE-772"],
    ("resource_check",   "memory_write"):        ["CWE-476", "CWE-787"],
    ("resource_check",   "mmap_op"):             ["CWE-476", "CWE-401"],
    ("resource_check",   "priv_op"):             ["CWE-755", "CWE-269"],
    ("resource_check",   "socket_op"):           ["CWE-755", "CWE-404"],

    # ── lifecycle_check × use-after-free patterns ─────────────────────────────
    ("lifecycle_check",  "deref"):               ["CWE-416", "CWE-476"],
    ("lifecycle_check",  "memory_write"):        ["CWE-416", "CWE-787"],
    ("lifecycle_check",  "free_op"):             ["CWE-415"],
    ("lifecycle_check",  "array_index"):         ["CWE-416", "CWE-125"],
    ("lifecycle_check",  "priv_op"):             ["CWE-269", "CWE-416"],

    # ── free_check × free/deref ───────────────────────────────────────────────
    ("free_check",       "free_op"):             ["CWE-415"],
    ("free_check",       "deref"):               ["CWE-416", "CWE-476"],
    ("free_check",       "memory_write"):        ["CWE-416", "CWE-787"],
    ("free_check",       "array_index"):         ["CWE-416", "CWE-125"],

    # ── error_check × C memory/resource ops ───────────────────────────────────
    ("error_check",      "deref"):               ["CWE-476", "CWE-824"],
    ("error_check",      "mmap_op"):             ["CWE-401", "CWE-772"],
    ("error_check",      "ipc_op"):              ["CWE-755", "CWE-404"],
    ("error_check",      "thread_op"):           ["CWE-755", "CWE-362"],
    ("error_check",      "integer_convert"):     ["CWE-391", "CWE-197"],
    ("error_check",      "network_recv"):        ["CWE-755", "CWE-125"],
    ("error_check",      "signal_handler"):      ["CWE-364", "CWE-362"],
    ("error_check",      "memory_write"):        ["CWE-120", "CWE-787"],
    ("error_check",      "free_op"):             ["CWE-415", "CWE-772"],

    # ── pointer_arith_check × pointer ops ─────────────────────────────────────
    ("pointer_arith_check", "deref"):            ["CWE-823", "CWE-476"],
    ("pointer_arith_check", "array_index"):      ["CWE-125", "CWE-823"],
    ("pointer_arith_check", "memory_write"):     ["CWE-787", "CWE-823"],
    ("pointer_arith_check", "ptr_arith"):        ["CWE-823", "CWE-125"],

    # ── alignment_check × casts ───────────────────────────────────────────────
    ("alignment_check",  "type_cast"):           ["CWE-704", "CWE-587"],
    ("alignment_check",  "deref"):               ["CWE-704", "CWE-476"],
    ("alignment_check",  "memory_write"):        ["CWE-704", "CWE-787"],

    # ── init_check × uninitialized use ────────────────────────────────────────
    ("init_check",       "deref"):               ["CWE-457", "CWE-824"],
    ("init_check",       "memory_write"):        ["CWE-457", "CWE-787"],
    ("init_check",       "array_index"):         ["CWE-457", "CWE-125"],
    ("init_check",       "free_op"):             ["CWE-457", "CWE-415"],

    # ── auth_guard × C/C++ ops (beyond Python table) ──────────────────────────
    ("auth_guard",       "mmap_op"):             ["CWE-862", "CWE-284"],
    ("auth_guard",       "ipc_op"):              ["CWE-862", "CWE-732"],
    ("auth_guard",       "network_recv"):        ["CWE-862", "CWE-125"],

    # ── lock_acquire × C/C++ shared state ─────────────────────────────────────
    ("lock_acquire",     "free_op"):             ["CWE-362", "CWE-415"],
    ("lock_acquire",     "deref"):               ["CWE-362", "CWE-476"],
    ("lock_acquire",     "signal_handler"):      ["CWE-364", "CWE-362"],
    ("lock_acquire",     "thread_op"):           ["CWE-362", "CWE-764"],
    ("lock_acquire",     "memory_write"):        ["CWE-362", "CWE-787"],
    ("lock_acquire",     "mmap_op"):             ["CWE-362", "CWE-401"],
    ("lock_acquire",     "ipc_op"):              ["CWE-362", "CWE-367"],

    # ── size_check × buffer ───────────────────────────────────────────────────
    ("size_check",       "memory_write"):        ["CWE-120", "CWE-787"],
    ("size_check",       "stack_alloc"):         ["CWE-121", "CWE-770"],
    ("size_check",       "network_recv"):        ["CWE-120", "CWE-787"],
    ("size_check",       "mmap_op"):             ["CWE-789", "CWE-400"],
    ("size_check",       "memory_write_bounded"):["CWE-193", "CWE-120"],

    # ── type_check × C/C++ casts ──────────────────────────────────────────────
    ("type_check",       "type_cast"):           ["CWE-843", "CWE-704"],
    ("type_check",       "deref"):               ["CWE-843", "CWE-476"],
    ("type_check",       "memory_write"):        ["CWE-704", "CWE-787"],
    ("type_check",       "integer_convert"):     ["CWE-704", "CWE-197"],

    # ── format_check × C format string ────────────────────────────────────────
    ("format_check",     "format_string_op"):    ["CWE-134", "CWE-20"],
    ("format_check",     "network_recv"):        ["CWE-20",  "CWE-125"],
    ("format_check",     "integer_convert"):     ["CWE-20",  "CWE-190"],
    ("format_check",     "memory_write"):        ["CWE-120", "CWE-787"],

    # ── assert × C/C++ ops ────────────────────────────────────────────────────
    ("assert",           "deref"):               ["CWE-617", "CWE-476"],
    ("assert",           "free_op"):             ["CWE-617", "CWE-415"],
    ("assert",           "type_cast"):           ["CWE-617", "CWE-843"],
    ("assert",           "memory_write"):        ["CWE-617", "CWE-787"],
    ("assert",           "integer_arith"):       ["CWE-617", "CWE-190"],

    # ── ownership_check × C/C++ ops ───────────────────────────────────────────
    ("ownership_check",  "priv_op"):             ["CWE-269", "CWE-284"],
    ("ownership_check",  "mmap_op"):             ["CWE-284", "CWE-732"],

    # ── signature_check × C/C++ crypto ────────────────────────────────────────
    ("signature_check",  "crypto_op"):           ["CWE-347", "CWE-327"],
    ("signature_check",  "memory_write"):        ["CWE-347", "CWE-787"],

    # ── integer ops ───────────────────────────────────────────────────────────
    ("overflow_check",   "integer_convert"):     ["CWE-197", "CWE-190"],
    ("bounds_check",     "integer_convert"):     ["CWE-197", "CWE-129"],
    ("range_check",      "integer_arith"):       ["CWE-190", "CWE-193"],

    # ── network receive ───────────────────────────────────────────────────────
    ("format_check",     "network_recv"):        ["CWE-20",  "CWE-125"],
    ("null_check",       "network_recv"):        ["CWE-476", "CWE-125"],

    # ── mmap / IPC ────────────────────────────────────────────────────────────
    ("null_check",       "ipc_op"):              ["CWE-476", "CWE-404"],
    ("error_check",      "mmap_op"):             ["CWE-401", "CWE-772"],

    # ── stack alloc ───────────────────────────────────────────────────────────
    ("overflow_check",   "stack_alloc"):         ["CWE-121", "CWE-190"],
    ("null_check",       "stack_alloc"):         ["CWE-476", "CWE-121"],

    # ── ptr_arith ─────────────────────────────────────────────────────────────
    ("overflow_check",   "ptr_arith"):           ["CWE-190", "CWE-823"],
    ("null_check",       "ptr_arith"):           ["CWE-476", "CWE-823"],

    # ── exception guard ───────────────────────────────────────────────────────
    ("exception_guard",  "alloc"):               ["CWE-390", "CWE-401"],
    ("exception_guard",  "free_op"):             ["CWE-390", "CWE-415"],
    ("exception_guard",  "file_op"):             ["CWE-390", "CWE-772"],
    ("exception_guard",  "socket_op"):           ["CWE-390", "CWE-404"],

    # ═══════════════════════════════════════════════════════════════════════════
    # JS / TypeScript pairs
    # ═══════════════════════════════════════════════════════════════════════════

    # ── sanitize × JS sinks ───────────────────────────────────────────────────
    ("sanitize",         "xss_op"):              ["CWE-79"],
    ("sanitize",         "sql_exec"):            ["CWE-89"],
    ("sanitize",         "subprocess"):          ["CWE-78"],
    ("sanitize",         "eval_exec"):           ["CWE-94"],
    ("sanitize",         "xml_parse"):           ["CWE-611"],
    ("sanitize",         "nosql_exec"):          ["CWE-943"],
    ("sanitize",         "template_render"):     ["CWE-94", "CWE-1336"],
    ("sanitize",         "log_op"):              ["CWE-117"],
    ("sanitize",         "redirect_op"):         ["CWE-601"],
    ("sanitize",         "graphql_op"):          ["CWE-89"],
    ("sanitize",         "dom_op"):              ["CWE-79"],
    ("sanitize",         "postmessage_op"):      ["CWE-79"],
    ("sanitize",         "url_construct"):       ["CWE-601", "CWE-918"],

    # ── format_check × JS sinks ───────────────────────────────────────────────
    ("format_check",     "xss_op"):              ["CWE-79", "CWE-20"],
    ("format_check",     "nosql_exec"):          ["CWE-943"],
    ("format_check",     "eval_exec"):           ["CWE-94"],
    ("format_check",     "deser"):               ["CWE-502", "CWE-20"],
    ("format_check",     "redirect_op"):         ["CWE-601"],
    ("format_check",     "ssrf_op"):             ["CWE-918"],
    ("format_check",     "template_render"):     ["CWE-94", "CWE-1336"],
    ("format_check",     "regex_op"):            ["CWE-1333", "CWE-400"],
    ("format_check",     "url_construct"):       ["CWE-601", "CWE-918"],
    ("format_check",     "proto_op"):            ["CWE-1321", "CWE-20"],
    ("format_check",     "jwt_op"):              ["CWE-347", "CWE-20"],
    ("format_check",     "cookie_op"):           ["CWE-614", "CWE-1004"],
    ("format_check",     "postmessage_op"):      ["CWE-79", "CWE-20"],
    ("format_check",     "graphql_op"):          ["CWE-89"],
    ("format_check",     "file_upload"):         ["CWE-434", "CWE-22"],
    ("format_check",     "ipc_op"):              ["CWE-20"],
    ("format_check",     "dom_op"):              ["CWE-79"],
    ("format_check",     "storage_op"):          ["CWE-200"],
    ("format_check",     "socket_op"):           ["CWE-200"],

    # ── path_traversal_check × JS sinks ──────────────────────────────────────
    ("path_traversal_check", "file_op"):         ["CWE-22"],
    ("path_traversal_check", "path_join"):       ["CWE-22"],
    ("path_traversal_check", "subprocess"):      ["CWE-22", "CWE-78"],
    ("path_traversal_check", "http_request"):    ["CWE-22", "CWE-918"],
    ("path_traversal_check", "data_return"):     ["CWE-22", "CWE-200"],
    ("path_traversal_check", "file_upload"):     ["CWE-22", "CWE-434"],
    ("path_traversal_check", "ssrf_op"):         ["CWE-918"],

    # ── auth_guard × JS sinks ─────────────────────────────────────────────────
    ("auth_guard",       "xss_op"):              ["CWE-862", "CWE-79"],
    ("auth_guard",       "nosql_exec"):          ["CWE-862", "CWE-943"],
    ("auth_guard",       "cookie_op"):           ["CWE-862", "CWE-614"],
    ("auth_guard",       "jwt_op"):              ["CWE-862", "CWE-347"],
    ("auth_guard",       "proto_op"):            ["CWE-862", "CWE-1321"],
    ("auth_guard",       "storage_op"):          ["CWE-862", "CWE-200"],
    ("auth_guard",       "postmessage_op"):      ["CWE-862", "CWE-79"],
    ("auth_guard",       "url_construct"):       ["CWE-862", "CWE-918"],
    ("auth_guard",       "env_write"):           ["CWE-15", "CWE-284"],
    ("auth_guard",       "state_mutation"):      ["CWE-284", "CWE-269"],
    ("auth_guard",       "ipc_op"):              ["CWE-862", "CWE-284"],
    ("auth_guard",       "graphql_op"):          ["CWE-862", "CWE-200"],
    ("auth_guard",       "file_upload"):         ["CWE-862", "CWE-434"],
    ("auth_guard",       "ssrf_op"):             ["CWE-862", "CWE-918"],
    ("auth_guard",       "dom_op"):              ["CWE-862", "CWE-79"],
    ("auth_guard",       "redirect_op"):         ["CWE-862", "CWE-601"],

    # ── csrf_check × JS sinks ────────────────────────────────────────────────
    ("csrf_check",       "state_mutation"):      ["CWE-352"],
    ("csrf_check",       "nosql_exec"):          ["CWE-352", "CWE-943"],
    ("csrf_check",       "file_op"):             ["CWE-352", "CWE-732"],
    ("csrf_check",       "http_request"):        ["CWE-352", "CWE-918"],
    ("csrf_check",       "env_write"):           ["CWE-352", "CWE-15"],
    ("csrf_check",       "proto_op"):            ["CWE-352", "CWE-1321"],
    ("csrf_check",       "file_upload"):         ["CWE-352", "CWE-434"],

    # ── proto_check × JS sinks ───────────────────────────────────────────────
    ("proto_check",      "proto_op"):            ["CWE-1321"],
    ("proto_check",      "state_mutation"):      ["CWE-1321", "CWE-284"],
    ("proto_check",      "deser"):               ["CWE-1321", "CWE-502"],
    ("proto_check",      "eval_exec"):           ["CWE-1321", "CWE-94"],
    ("proto_check",      "ipc_op"):              ["CWE-1321", "CWE-284"],

    # ── jwt_verify × JS sinks ────────────────────────────────────────────────
    ("jwt_verify",       "jwt_op"):              ["CWE-347"],
    ("jwt_verify",       "state_mutation"):      ["CWE-347", "CWE-284"],
    ("jwt_verify",       "nosql_exec"):          ["CWE-347", "CWE-943"],
    ("jwt_verify",       "file_op"):             ["CWE-347", "CWE-22"],
    ("jwt_verify",       "graphql_op"):          ["CWE-347", "CWE-200"],

    # ── xss_check × JS sinks ─────────────────────────────────────────────────
    ("xss_check",        "xss_op"):              ["CWE-79"],
    ("xss_check",        "dom_op"):              ["CWE-79"],
    ("xss_check",        "postmessage_op"):      ["CWE-79"],
    ("xss_check",        "url_construct"):       ["CWE-601"],

    # ── origin_check × JS sinks ──────────────────────────────────────────────
    ("origin_check",     "postmessage_op"):      ["CWE-79", "CWE-345"],
    ("origin_check",     "http_request"):        ["CWE-918"],
    ("origin_check",     "xss_op"):              ["CWE-79", "CWE-346"],
    ("origin_check",     "ssrf_op"):             ["CWE-918", "CWE-346"],
    ("origin_check",     "socket_op"):           ["CWE-200", "CWE-346"],

    # ── schema_validate × JS sinks ───────────────────────────────────────────
    ("schema_validate",  "nosql_exec"):          ["CWE-943", "CWE-20"],
    ("schema_validate",  "proto_op"):            ["CWE-1321", "CWE-20"],
    ("schema_validate",  "eval_exec"):           ["CWE-94", "CWE-20"],
    ("schema_validate",  "file_op"):             ["CWE-434", "CWE-22"],
    ("schema_validate",  "state_mutation"):      ["CWE-20", "CWE-284"],
    ("schema_validate",  "graphql_op"):          ["CWE-89"],
    ("schema_validate",  "file_upload"):         ["CWE-434"],
    ("schema_validate",  "xss_op"):              ["CWE-79", "CWE-20"],
    ("schema_validate",  "redirect_op"):         ["CWE-601"],
    ("schema_validate",  "ssrf_op"):             ["CWE-918"],

    # ── content_type_check × JS sinks ────────────────────────────────────────
    ("content_type_check", "file_op"):           ["CWE-434", "CWE-22"],
    ("content_type_check", "deser"):             ["CWE-434", "CWE-502"],
    ("content_type_check", "eval_exec"):         ["CWE-434", "CWE-94"],
    ("content_type_check", "subprocess"):        ["CWE-434", "CWE-78"],
    ("content_type_check", "file_upload"):       ["CWE-434"],
    ("content_type_check", "nosql_exec"):        ["CWE-434", "CWE-943"],

    # ── rate_limit × JS sinks ────────────────────────────────────────────────
    ("rate_limit",       "nosql_exec"):          ["CWE-770"],
    ("rate_limit",       "graphql_op"):          ["CWE-400"],
    ("rate_limit",       "eval_exec"):           ["CWE-770", "CWE-94"],

    # ── size_check × JS sinks ────────────────────────────────────────────────
    ("size_check",       "file_upload"):         ["CWE-400", "CWE-434"],
    ("size_check",       "ipc_op"):              ["CWE-400"],
    ("size_check",       "nosql_exec"):          ["CWE-770"],
    ("size_check",       "graphql_op"):          ["CWE-400"],

    # ── crypto_check × JS sinks ──────────────────────────────────────────────
    ("crypto_check",     "crypto_op"):           ["CWE-327", "CWE-338"],
    ("crypto_check",     "jwt_op"):              ["CWE-327", "CWE-347"],
    ("crypto_check",     "cookie_op"):           ["CWE-614", "CWE-327"],

    # ── null_check × JS sinks ────────────────────────────────────────────────
    ("null_check",       "xss_op"):              ["CWE-79", "CWE-476"],
    ("null_check",       "eval_exec"):           ["CWE-94", "CWE-476"],
    ("null_check",       "proto_op"):            ["CWE-1321", "CWE-476"],
    ("null_check",       "redirect_op"):         ["CWE-601", "CWE-476"],
    ("null_check",       "storage_op"):          ["CWE-200", "CWE-476"],
    ("null_check",       "jwt_op"):              ["CWE-347", "CWE-476"],
    ("null_check",       "ssrf_op"):             ["CWE-918", "CWE-476"],
    ("null_check",       "nosql_exec"):          ["CWE-943", "CWE-476"],
    ("null_check",       "postmessage_op"):      ["CWE-79", "CWE-476"],
    ("null_check",       "graphql_op"):          ["CWE-89", "CWE-476"],
    ("null_check",       "dom_op"):              ["CWE-79", "CWE-476"],
    ("null_check",       "file_upload"):         ["CWE-434", "CWE-476"],
    ("null_check",       "cookie_op"):           ["CWE-614", "CWE-476"],

    # ── type_check × JS sinks ────────────────────────────────────────────────
    ("type_check",       "xss_op"):              ["CWE-79", "CWE-20"],
    ("type_check",       "nosql_exec"):          ["CWE-943", "CWE-20"],
    ("type_check",       "postmessage_op"):      ["CWE-79", "CWE-20"],
    ("type_check",       "redirect_op"):         ["CWE-601", "CWE-20"],
    ("type_check",       "graphql_op"):          ["CWE-89"],
    ("type_check",       "ssrf_op"):             ["CWE-918", "CWE-20"],
    ("type_check",       "storage_op"):          ["CWE-200", "CWE-20"],
    ("type_check",       "dom_op"):              ["CWE-79", "CWE-20"],
    ("type_check",       "file_upload"):         ["CWE-434", "CWE-20"],
    ("type_check",       "jwt_op"):              ["CWE-347", "CWE-20"],
    ("type_check",       "cookie_op"):           ["CWE-614", "CWE-20"],

    # ── param_check × JS sinks ───────────────────────────────────────────────
    ("param_check",      "sql_exec"):            ["CWE-89", "CWE-20"],
    ("param_check",      "nosql_exec"):          ["CWE-943", "CWE-20"],
    ("param_check",      "xss_op"):              ["CWE-79", "CWE-20"],
    ("param_check",      "redirect_op"):         ["CWE-601"],
    ("param_check",      "file_op"):             ["CWE-22"],
    ("param_check",      "ssrf_op"):             ["CWE-918"],
    ("param_check",      "graphql_op"):          ["CWE-89"],
    ("param_check",      "subprocess"):          ["CWE-78"],
    ("param_check",      "eval_exec"):           ["CWE-94"],
    ("param_check",      "proto_op"):            ["CWE-1321"],

    # ── encoding_check × JS sinks ─────────────────────────────────────────────
    ("encoding_check",   "xss_op"):              ["CWE-79", "CWE-116"],
    ("encoding_check",   "log_op"):              ["CWE-117", "CWE-116"],
    ("encoding_check",   "sql_exec"):            ["CWE-89", "CWE-116"],
    ("encoding_check",   "nosql_exec"):          ["CWE-943", "CWE-116"],
    ("encoding_check",   "dom_op"):              ["CWE-79", "CWE-116"],

    # ── error_check × JS sinks ───────────────────────────────────────────────
    ("error_check",      "xss_op"):              ["CWE-755", "CWE-79"],
    ("error_check",      "nosql_exec"):          ["CWE-755", "CWE-943"],
    ("error_check",      "jwt_op"):              ["CWE-755", "CWE-347"],
    ("error_check",      "proto_op"):            ["CWE-755", "CWE-1321"],
    ("error_check",      "deser"):               ["CWE-755", "CWE-502"],
    ("error_check",      "log_op"):              ["CWE-209"],
    ("error_check",      "cookie_op"):           ["CWE-755", "CWE-614"],
    ("error_check",      "crypto_op"):           ["CWE-755", "CWE-327"],
    ("error_check",      "redirect_op"):         ["CWE-755", "CWE-601"],
    ("error_check",      "ssrf_op"):             ["CWE-755", "CWE-918"],
    ("error_check",      "storage_op"):          ["CWE-755", "CWE-200"],

    # ── regex_match × JS sinks ───────────────────────────────────────────────
    ("regex_match",      "nosql_exec"):          ["CWE-943", "CWE-20"],
    ("regex_match",      "eval_exec"):           ["CWE-94", "CWE-20"],
    ("regex_match",      "xss_op"):              ["CWE-79", "CWE-20"],
    ("regex_match",      "redirect_op"):         ["CWE-601"],
    ("regex_match",      "ssrf_op"):             ["CWE-918"],

    # ── bounds_check × JS sinks ──────────────────────────────────────────────
    ("bounds_check",     "regex_op"):            ["CWE-400", "CWE-1333"],
    ("bounds_check",     "xss_op"):              ["CWE-79", "CWE-20"],
    ("bounds_check",     "storage_op"):          ["CWE-200", "CWE-20"],
    ("bounds_check",     "ipc_op"):              ["CWE-400"],
    ("bounds_check",     "nosql_exec"):          ["CWE-943", "CWE-20"],

    # ── jwt_verify (already partially covered above, add remaining) ───────────
    ("jwt_verify",       "data_return"):         ["CWE-347", "CWE-200"],
    ("jwt_verify",       "cookie_op"):           ["CWE-347", "CWE-614"],

    # ── xss_check (remaining) ────────────────────────────────────────────────
    ("xss_check",        "template_render"):     ["CWE-79", "CWE-94"],
    ("xss_check",        "data_return"):         ["CWE-79", "CWE-200"],
    ("xss_check",        "redirect_op"):         ["CWE-601"],

    # ── origin_check (remaining) ──────────────────────────────────────────────
    ("origin_check",     "redirect_op"):         ["CWE-601"],
    ("origin_check",     "data_return"):         ["CWE-200", "CWE-346"],

    # ── csrf_check (remaining) ───────────────────────────────────────────────
    ("csrf_check",       "sql_exec"):            ["CWE-352", "CWE-89"],
    ("csrf_check",       "data_return"):         ["CWE-352", "CWE-200"],
    ("csrf_check",       "cookie_op"):           ["CWE-352", "CWE-614"],

    # ── rate_limit (remaining) ───────────────────────────────────────────────
    ("rate_limit",       "data_return"):         ["CWE-770", "CWE-400"],
    ("rate_limit",       "sql_exec"):            ["CWE-770"],
    ("rate_limit",       "regex_op"):            ["CWE-400", "CWE-1333"],
    ("rate_limit",       "http_request"):        ["CWE-770", "CWE-400"],
    ("rate_limit",       "subprocess"):          ["CWE-770", "CWE-78"],

    # ── size_check (remaining) ───────────────────────────────────────────────
    ("size_check",       "regex_op"):            ["CWE-1333", "CWE-400"],
    ("size_check",       "file_op"):             ["CWE-770", "CWE-400"],
    ("size_check",       "deser"):               ["CWE-400", "CWE-770"],
    ("size_check",       "http_request"):        ["CWE-770", "CWE-400"],
    ("size_check",       "sql_exec"):            ["CWE-89", "CWE-770"],

    # ── auth_guard (remaining) ───────────────────────────────────────────────
    ("auth_guard",       "data_return"):         ["CWE-862", "CWE-200"],
    ("auth_guard",       "http_request"):        ["CWE-862", "CWE-918"],
    ("auth_guard",       "template_render"):     ["CWE-862", "CWE-94"],
    ("auth_guard",       "socket_op"):           ["CWE-862", "CWE-200"],
    ("auth_guard",       "log_op"):              ["CWE-862", "CWE-200"],
    ("auth_guard",       "eval_exec"):           ["CWE-862", "CWE-94"],
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

    # ── JS / TypeScript specific ──────────────────────────────────────────────
    "CWE-1321": "Type-related",            # Prototype pollution
    "CWE-345":  "Authentication",          # Insufficient verification of data authenticity
    "CWE-346":  "Web",                     # Origin validation error
    "CWE-943":  "Input validation",        # NoSQL injection
    "CWE-116":  "Strings",                 # Improper encoding/escaping for output
    "CWE-209":  "Confidentiality",         # Error message information exposure
    "CWE-338":  "Numeric errors",          # Use of cryptographically weak PRNG

    # ── C/C++ specific ────────────────────────────────────────────────────────
    "CWE-120":  "Ante buffer operation",   # classic buffer overflow (strcpy etc.)
    "CWE-121":  "Ante buffer operation",   # stack-based buffer overflow
    "CWE-122":  "Ante buffer operation",   # heap-based buffer overflow
    "CWE-126":  "Ante buffer operation",   # buffer over-read
    "CWE-129":  "Ante buffer operation",   # improper validation of array index
    "CWE-134":  "Input validation",        # uncontrolled format string
    "CWE-191":  "Numeric errors",          # integer underflow
    "CWE-193":  "Numeric errors",          # off-by-one error
    "CWE-197":  "Numeric errors",          # numeric truncation error
    "CWE-242":  "API",                     # use of inherently dangerous function
    "CWE-364":  "Concurrency",             # signal handler race condition
    "CWE-369":  "Numeric errors",          # divide by zero
    "CWE-391":  "Error condition",         # unchecked error condition
    "CWE-404":  "Resource management",     # improper resource shutdown
    "CWE-415":  "Memory release",          # double free
    "CWE-416":  "Expired memory",          # use after free
    "CWE-426":  "Path-related",            # untrusted search path
    "CWE-457":  "Initialization",          # use of uninitialized variable
    "CWE-467":  "Calculation",             # use of sizeof on pointer type
    "CWE-562":  "Return value",            # return of stack variable address
    "CWE-587":  "Invalid pointer",         # assignment of fixed address to pointer
    "CWE-590":  "Memory release",          # free of memory not on the heap
    "CWE-672":  "Expired memory",          # operation after expiration or release
    "CWE-690":  "Error condition",         # NULL return from malloc not checked
    "CWE-761":  "Memory release",          # free of pointer not at start of buffer
    "CWE-762":  "Memory release",          # mismatched memory management routines
    "CWE-763":  "Invalid pointer",         # release of invalid pointer
    "CWE-764":  "Concurrency",             # multiple locks of same mutex
    "CWE-789":  "Memory allocation",       # memory allocation with excessive size value
    "CWE-823":  "Invalid pointer",         # use of out-of-range pointer offset
    "CWE-824":  "Invalid pointer",         # access of uninitialized pointer
    "CWE-825":  "Expired memory",          # expired pointer dereference
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
    "redirect_op":          "remove URL validation before redirect (open redirect)",
    "header_inject":        "inject CRLF into response header value without sanitization",
    "cookie_op":            "set cookie without Secure/HttpOnly flags or with user-controlled value",
    "regex_exec":           "feed unbounded user input to catastrophic backtracking regex (ReDoS)",
    "env_write":            "allow user input to overwrite environment/config variable",
    "priv_op":              "drop privilege check before setuid/setgid or privileged API call",
    "socket_op":            "remove host/port validation before network connection",
    "reflection_op":        "allow user-controlled string to select attribute or method via getattr",
    # JS / TypeScript operation hints
    "xss_op":               "remove XSS sanitization before innerHTML/document.write",
    "proto_op":             "remove prototype check before Object.assign/_.merge on req.body",
    "jwt_op":               "replace jwt.verify() with jwt.decode() — skips signature check",
    "regex_op":             "pass user-controlled string directly to new RegExp() (ReDoS)",
    "path_join":            "remove path.normalize/traversal check before path.join",
    "storage_op":           "write sensitive data to localStorage without encryption",
    "postmessage_op":       "remove origin check before accessing event.data",
    "url_construct":        "pass user string to new URL() — open redirect / SSRF",
    "nosql_exec":           "pass req.body directly as MongoDB query object (NoSQL injection)",
    "ssrf_op":              "use user-controlled URL in server-side fetch/request call",
    "graphql_op":           "allow user-supplied query string in graphql() execution",
    "dom_op":               "assign user input to element.style or setAttribute without encoding",
    "file_upload":          "remove MIME type check — allow upload of arbitrary file type",
    # C/C++ operation hints
    "memory_write":         "remove bounds/null check before memcpy/strcpy (buffer overflow)",
    "memory_write_bounded": "remove size argument or inflate length in strncpy/snprintf",
    "deref":                "remove null check before pointer dereference (null-ptr / use-after-free)",
    "free_op":              "remove free-check to enable double-free",
    "format_string_op":     "pass user-controlled string as printf format arg (format string vuln)",
    "type_cast":            "remove type/alignment check before unsafe cast (type confusion)",
    "stack_alloc":          "remove size check before VLA/alloca (stack overflow)",
    "signal_handler":       "remove lock before signal handler shared state access",
    "integer_arith":        "remove overflow check before arithmetic feeding alloc/index",
    "integer_convert":      "remove range check before narrowing cast or atoi (integer truncation)",
    "network_recv":         "remove length check before reading into fixed buffer",
    "mmap_op":              "remove size check / error check on mmap (heap exhaustion / null deref)",
    "ipc_op":               "remove access check before IPC message/shared memory operation",
    "thread_op":            "remove lock around shared resource accessed from new thread",
    "ptr_arith":            "remove bounds check before pointer arithmetic (out-of-bounds access)",
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
    "path_traversal_check":  "remove path normalization / realpath guard",
    "content_type_check":    "remove MIME/content-type validation before upload",
    "size_check":            "remove payload/file size limit check",
    "redirect_check":        "remove URL safety validation before redirect",
    # JS / TypeScript checkpoint hints
    "origin_check":          "remove origin validation from CORS / postMessage handler",
    "xss_check":             "remove HTML encoding before DOM write",
    "proto_check":           "remove hasOwnProperty guard enabling prototype pollution",
    "jwt_verify":            "replace jwt.verify() with jwt.decode() — no signature check",
    "schema_validate":       "remove JSON schema validation before processing untrusted input",
    "regex_match":           "remove regex-based input allowlist validation",
    "param_check":           "skip existence/type check on request parameters",
    "encoding_check":        "skip character encoding validation before processing input",
    "crypto_check":          "remove minimum key length / algorithm safety check",
    # C/C++ checkpoint hints
    "zero_check":            "remove divide-by-zero guard",
    "length_check":          "remove string length check before buffer operation",
    "range_check":           "remove integer range check before narrowing cast",
    "capacity_check":        "remove remaining-capacity check before write",
    "resource_check":        "remove file descriptor / handle validity check",
    "lifecycle_check":       "remove lifecycle/state check enabling use-after-free",
    "free_check":            "remove NULL guard before free (enable double-free or UAF)",
    "pointer_arith_check":   "remove pointer range check before arithmetic",
    "alignment_check":       "remove alignment check before unsafe pointer cast",
    "init_check":            "remove initialization check enabling uninitialized variable use",
    "exception_guard":       "remove try/catch allowing uncaught exception with resource leak",
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
