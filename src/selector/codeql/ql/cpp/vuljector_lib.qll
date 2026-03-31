/**
 * Vuljector shared library for C/C++ CodeQL queries.
 * Imported by cpp_pairs.ql, cpp_sinks.ql, and cpp_combinatorial.ql.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

// ── Sink detection ────────────────────────────────────────────────────────────
// Inspired by AST plugin operation categories (c_plugin.py).

predicate vuljectorSink(DataFlow::Node sink, string kind) {
  // Unbounded / bounded memory writes
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("memcpy|memmove|strcpy|strncpy|strcat|strncat|sprintf|snprintf|vsprintf|gets|wcscpy|wcsncpy|mbstowcs|wcstombs|memset|memmove") and
    kind = "memory_write"
  )
  or
  // Shell / process execution
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("system|popen|execl|execle|execlp|execv|execve|execvp|execvpe|_popen|ShellExecute|CreateProcess|WinExec|posix_spawn") and
    kind = "subprocess"
  )
  or
  // File operations
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("fopen|freopen|open|creat|unlink|rename|mkdir|rmdir|chmod|chown|remove|fwrite|fputs|stat|lstat|access|realpath|openat|mkstemp|tmpfile") and
    kind = "file_op"
  )
  or
  // SQL execution
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("mysql_query|mysql_real_query|sqlite3_exec|sqlite3_prepare|sqlite3_prepare_v2|PQexec|PQexecParams|PQprepare|SQLExecDirect|SQLPrepare|OCIStmtPrepare") and
    kind = "sql_exec"
  )
  or
  // Memory allocation (tainted size → heap overflow)
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("malloc|calloc|realloc|alloca|VirtualAlloc|HeapAlloc|mmap") and
    kind = "alloc"
  )
  or
  // Format string sinks
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("printf|fprintf|sprintf|snprintf|vprintf|vfprintf|vsprintf|syslog|wprintf|swprintf|dprintf") and
    kind = "format_string"
  )
  or
  // Network send (data exfiltration / protocol injection)
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("send|sendto|sendmsg|write|writev|SSL_write|BIO_write|fwrite|fputs") and
    kind = "net_send"
  )
  or
  // Integer type conversions (tainted value → narrowing cast → truncation)
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("atoi|atol|atoll|strtol|strtoll|strtoul|strtoull|atof|strtod") and
    kind = "type_conversion"
  )
  or
  // Crypto operations with potentially tainted key/IV material
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("EVP_EncryptInit|EVP_DecryptInit|AES_set_encrypt_key|DES_set_key|HMAC_Init|EVP_DigestInit|RAND_bytes|RAND_pseudo_bytes") and
    kind = "crypto_op"
  )
  or
  // Logging (log injection)
  exists(FunctionCall fc |
    fc = sink.asExpr() and
    fc.getTarget().getName()
       .regexpMatch("syslog|vsyslog|openlog|fprintf|printf") and
    kind = "log_op"
  )
}

// ── Combinatorial checkpoint detection ────────────────────────────────────────
// checkpointInFunction: all checkpoint patterns in function f.
// Returns one result per checkpoint — enables combinatorial (sink × checkpoint) pairing.
// Inspired by the full AST checkpoint pattern set (c_plugin.py).

predicate checkpointInFunction(Function f, Location cpLoc, string cpKind, string cpText) {
  // null_check: if (!ptr), if (ptr == NULL), if (ptr != NULL)
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    (guard.getCondition() instanceof NotExpr or
     guard.getCondition().toString().regexpMatch(".*== NULL.*|.*!= NULL.*|.*== nullptr.*|.*!= nullptr.*")) and
    cpKind = "null_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // bounds_check: relational comparisons (size < MAX, len >= 0, index < count)
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    guard.getCondition() instanceof RelationalOperation and
    not guard.getCondition() instanceof NotExpr and
    cpKind = "bounds_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // equality_check: if (x == y), if (x != y), if (ret == -1)
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    guard.getCondition() instanceof EqualityOperation and
    cpKind = "equality_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // overflow_check: __builtin_*_overflow, > INT_MAX, safe_add, safe_mul
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName()
       .regexpMatch("__builtin_add_overflow|__builtin_sub_overflow|__builtin_mul_overflow|__builtin_sadd_overflow|__builtin_smul_overflow|__builtin_uadd_overflow|safe_add|safe_mul|checked_add") and
    cpKind = "overflow_check" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // overflow_check: comparisons against INT_MAX, UINT_MAX, SIZE_MAX
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    guard.getCondition().toString()
        .regexpMatch(".*INT_MAX.*|.*UINT_MAX.*|.*SIZE_MAX.*|.*LONG_MAX.*|.*SSIZE_MAX.*") and
    cpKind = "overflow_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // error_check: if (ret < 0), if (ret == -1), if (errno != 0), if (!result)
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    guard.getCondition().toString()
        .regexpMatch(".*== -1.*|.*< 0.*|.*errno.*|.*!= 0.*|.*FAILED.*|.*ERROR.*|.*< 0\\b.*") and
    not guard.getCondition() instanceof RelationalOperation and
    cpKind = "error_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // auth_guard: function calls to auth/permission check functions
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName()
       .regexpMatch("(?i)check_auth|verify_perm|is_authorized|require_auth|authenticate|check_permission|validate_user|is_admin|has_privilege|check_access|verify_credentials") and
    cpKind = "auth_guard" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // sanitize: input validation / sanitization functions
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName()
       .regexpMatch("(?i)sanitize|escape|validate|check_input|filter_input|strip_tags|htmlspecialchars|encode_html|clean_input|safe_str") and
    cpKind = "sanitize" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // format_check: regex / pattern matching functions
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName()
       .regexpMatch("(?i)regcomp|regexec|pcre_exec|pcre2_match|re_match|fnmatch|glob|strpbrk|strspn|strcspn") and
    cpKind = "format_check" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // size_check: strlen comparison, sizeof guard, strnlen
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName().regexpMatch("strlen|strnlen|wcslen|sizeof") and
    cpKind = "size_check" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // lock_acquire: mutex/semaphore acquisition
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = f and
    fc.getTarget().getName()
       .regexpMatch("pthread_mutex_lock|pthread_mutex_trylock|sem_wait|sem_trywait|EnterCriticalSection|WaitForSingleObject|std::lock|lock_guard") and
    cpKind = "lock_acquire" and cpText = fc.toString() and cpLoc = fc.getLocation()
  )
  or
  // crypto_check: key/IV length validation before crypto ops
  exists(IfStmt guard |
    guard.getEnclosingFunction() = f and
    guard.getCondition().toString()
        .regexpMatch(".*key.*len.*|.*iv.*len.*|.*salt.*len.*|.*AES.*|.*EVP.*") and
    cpKind = "crypto_check" and cpText = guard.getCondition().toString() and cpLoc = guard.getLocation()
  )
  or
  // whitelist_check: switch statement as value whitelist
  exists(SwitchStmt sw |
    sw.getEnclosingFunction() = f and
    cpKind = "whitelist_check" and cpText = sw.getExpr().toString() and cpLoc = sw.getLocation()
  )
}

// ── File-scope checkpoint helpers (used by *_sinks.ql and *_pairs.ql) ─────────

bindingset[sink]
string cpTextNearSink(DataFlow::Node sink) {
  exists(IfStmt guard |
    guard.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    (
      guard.getCondition() instanceof NotExpr or
      guard.getCondition() instanceof RelationalOperation or
      guard.getCondition() instanceof EqualityOperation or
      exists(BinaryArithmeticOperation bo | bo = guard.getCondition()) or
      exists(ComparisonOperation co | co = guard.getCondition())
    ) and
    result = guard.getCondition().toString()
  )
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    fc.getTarget().getName()
       .regexpMatch("__builtin_add_overflow|__builtin_sub_overflow|__builtin_mul_overflow|__builtin_sadd_overflow|__builtin_smul_overflow") and
    result = fc.toString()
  )
  or
  exists(IfStmt guard |
    guard.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    guard.getCondition().toString().regexpMatch(".*errno.*|.*== NULL.*|.*!= NULL.*|.*== -1.*|.*< 0.*|.*> 0.*") and
    result = guard.getCondition().toString()
  )
}

bindingset[sink]
string cpKindNearSink(DataFlow::Node sink) {
  exists(IfStmt guard |
    guard.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    guard.getCondition() instanceof NotExpr
  ) and result = "null_check"
  or
  exists(IfStmt guard |
    guard.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    guard.getCondition() instanceof RelationalOperation and
    not guard.getCondition() instanceof NotExpr
  ) and result = "bounds_check"
  or
  exists(IfStmt guard |
    guard.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    guard.getCondition() instanceof EqualityOperation
  ) and result = "equality_check"
  or
  exists(FunctionCall fc |
    fc.getEnclosingFunction() = sink.asExpr().getEnclosingFunction() and
    fc.getTarget().getName()
       .regexpMatch("__builtin_add_overflow|__builtin_sub_overflow|__builtin_mul_overflow|__builtin_sadd_overflow|__builtin_smul_overflow")
  ) and result = "overflow_check"
}

// ── Aggregate helpers (default to "" on empty domain) ─────────────────────────

bindingset[sink]
string cpText(DataFlow::Node sink) {
  result = min(string t | t = cpTextNearSink(sink) | t)
  or
  not exists(string t | t = cpTextNearSink(sink)) and result = ""
}

bindingset[sink]
string cpKind(DataFlow::Node sink) {
  result = min(string k | k = cpKindNearSink(sink) | k)
  or
  not exists(string k | k = cpKindNearSink(sink)) and result = ""
}
