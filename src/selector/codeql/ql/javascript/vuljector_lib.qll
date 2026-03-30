/**
 * Vuljector shared library for JavaScript/TypeScript CodeQL queries.
 * Imported by js_pairs.ql, js_sinks.ql, and js_combinatorial.ql.
 */

import javascript

// ── Sink detection ────────────────────────────────────────────────────────────
// Inspired by AST plugin operation categories (js_plugin.py).

predicate vuljectorSink(DataFlow::Node sink, string kind) {
  // SQL: .query(), .execute(), .exec() on DB clients
  exists(DataFlow::MethodCallNode call |
    sink = call.getAnArgument() and
    call.getMethodName().regexpMatch("query|execute|exec|prepare|run") and
    kind = "sql_exec"
  )
  or
  // Command injection: child_process exec/spawn/fork
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName()
        .regexpMatch("exec|execSync|execFile|execFileSync|spawn|spawnSync|fork") and
    kind = "subprocess"
  )
  or
  // File operations (fs module)
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName()
        .regexpMatch("readFile|readFileSync|writeFile|writeFileSync|unlink|unlinkSync|mkdir|mkdirSync|rename|renameSync|open|openSync|appendFile|appendFileSync|createReadStream|createWriteStream|access|stat|chmod|lstat") and
    kind = "file_op"
  )
  or
  // Path operations (path traversal)
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName().regexpMatch("join|resolve|normalize|relative") and
    call.getReceiver().toString().regexpMatch("(?i)path|posix|win32") and
    kind = "file_op"
  )
  or
  // eval / vm / Function constructor / require with dynamic arg
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName()
        .regexpMatch("eval|runInContext|runInNewContext|runInThisContext|runScript|Function") and
    kind = "eval_exec"
  )
  or
  exists(DataFlow::CallNode call |
    sink = call.getArgument(0) and
    call.getCalleeName() = "require" and
    kind = "eval_exec"
  )
  or
  // XSS: innerHTML / outerHTML / srcdoc assignment
  exists(DataFlow::PropWrite pw |
    sink = pw.getRhs() and
    pw.getPropertyName().regexpMatch("innerHTML|outerHTML|srcdoc") and
    kind = "xss_op"
  )
  or
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName().regexpMatch("write|writeln") and
    call.getReceiver().toString().regexpMatch("(?i)document") and
    kind = "xss_op"
  )
  or
  // SSRF: fetch / axios / got / request / superagent / http.request
  exists(DataFlow::CallNode call |
    sink = call.getArgument(0) and
    call.getCalleeName().regexpMatch("fetch|get|request|head|post|put|delete|patch") and
    kind = "http_request"
  )
  or
  // Open redirect
  exists(DataFlow::MethodCallNode call |
    sink = call.getArgument(0) and
    call.getMethodName().regexpMatch("redirect|location") and
    kind = "redirect_op"
  )
  or
  // Deserialization: unserialize / deserialize / parse / JSON.parse / inflate
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName()
        .regexpMatch("unserialize|deserialize|parse|fromJSON|inflate|ungzip") and
    kind = "deser"
  )
  or
  // Template rendering: nunjucks.renderString, handlebars.compile, pug.render
  exists(DataFlow::MethodCallNode call |
    sink = call.getAnArgument() and
    call.getMethodName().regexpMatch("renderString|compile|render|fromString") and
    kind = "template_render"
  )
  or
  // Cookie operations (missing httpOnly/secure flags)
  exists(DataFlow::MethodCallNode call |
    sink = call.getAnArgument() and
    call.getMethodName().regexpMatch("cookie|setCookie|clearCookie") and
    kind = "cookie_op"
  )
  or
  // postMessage with potentially wildcard origin
  exists(DataFlow::MethodCallNode call |
    sink = call.getAnArgument() and
    call.getMethodName() = "postMessage" and
    kind = "postmessage_op"
  )
  or
  // localStorage / sessionStorage (client-side storage injection)
  exists(DataFlow::MethodCallNode call |
    sink = call.getAnArgument() and
    call.getMethodName().regexpMatch("setItem|removeItem") and
    call.getReceiver().toString().regexpMatch("(?i)localStorage|sessionStorage|storage") and
    kind = "storage_op"
  )
  or
  // Prototype pollution: Object.assign / merge / extend with user-controlled keys
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName().regexpMatch("assign|merge|extend|defaults|deepmerge|deepExtend") and
    kind = "proto_op"
  )
  or
  // XML / HTML parsing
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName().regexpMatch("parseXml|parseHTML|DOMParser|parseFromString|xml2js") and
    kind = "xml_parse"
  )
  or
  // Log injection
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName().regexpMatch("log|info|warn|error|debug|trace") and
    call.getReceiver().toString().regexpMatch("(?i)console|logger|winston|bunyan|pino") and
    kind = "log_op"
  )
  or
  // ReDoS: new RegExp(userInput)
  exists(DataFlow::CallNode call |
    sink = call.getAnArgument() and
    call.getCalleeName() = "RegExp" and
    kind = "regex_exec"
  )
}

// ── Combinatorial checkpoint detection ────────────────────────────────────────
// checkpointInFunction: all checkpoint patterns in function f.
// Returns one result per checkpoint — enables combinatorial (sink × checkpoint) pairing.
// Inspired by the full AST checkpoint pattern set (js_plugin.py).

predicate checkpointInFunction(Function f, Location cpLoc, string cpKind, string cpText) {
  // null_check: strict equality / inequality (=== null, !== undefined, == null)
  exists(IfStmt s |
    s.getContainer() = f and
    (s.getCondition() instanceof StrictEqualityTest or
     s.getCondition() instanceof EqualityTest) and
    cpKind = "null_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // null_check (negation): if (!x), if (!user), if (!token)
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition() instanceof LogicalNotExpr and
    cpKind = "null_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // bounds_check: relational comparisons (.length < N, size > limit)
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition() instanceof RelationalComparison and
    cpKind = "bounds_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // type_check: typeof === "string", instanceof
  exists(IfStmt s |
    s.getContainer() = f and
    (s.getCondition().(EqualityTest).getAnOperand() instanceof TypeofExpr or
     s.getCondition() instanceof InstanceofExpr) and
    cpKind = "type_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // whitelist_check: "key" in obj
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition() instanceof InExpr and
    cpKind = "whitelist_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // auth_guard: isAuthenticated(), requireAuth(), hasRole(), etc.
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (
      call.getCalleeName()
          .regexpMatch("(?i)isAuthenticated|requireAuth|checkAuth|ensureAuth|ensureLoggedIn|isLoggedIn|hasRole|verifyToken|isAdmin|checkPermission|authorize|requiresAuth") or
      call.getMethodName()
          .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|requireAuth|isAdmin|can|isAuthorized|isSignedIn")
    ) and
    cpKind = "auth_guard" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // auth_guard: res.sendStatus(401/403), res.status(401/403)
  exists(DataFlow::MethodCallNode call |
    call.getContainer() = f and
    call.getMethodName().regexpMatch("sendStatus|status") and
    (call.getArgument(0).getIntValue() = 401 or call.getArgument(0).getIntValue() = 403) and
    cpKind = "auth_guard" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // schema_validate: Joi.validate(), ajv.validate(), zod.parse(), Yup.validate()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    call.getMethodName()
        .regexpMatch("validate|parse|safeParse|parseAsync|check|assert|validateOrReject") and
    cpKind = "schema_validate" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // jwt_verify: jwt.verify(), jose.jwtVerify(), verifyToken()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getCalleeName().regexpMatch("(?i)verifyToken|validateJwt|verifyJwt|checkToken") or
     call.getMethodName() = "verify" and
     call.getReceiver().toString().regexpMatch("(?i)jwt|jsonwebtoken|jose|jws")) and
    cpKind = "jwt_verify" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // csrf_check: req.csrfToken(), validateCsrfToken(), verifyCsrf()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getCalleeName().regexpMatch("(?i)validateCsrf|checkCsrf|verifyCsrf|csrfProtect") or
     call.getMethodName() = "csrfToken") and
    cpKind = "csrf_check" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // rate_limit: rateLimit(), limiter.consume(), throttle()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getCalleeName().regexpMatch("(?i)rateLimit|rateLimiter|throttle|slowDown") or
     call.getMethodName().regexpMatch("(?i)consume|check|increment") and
     call.getReceiver().toString().regexpMatch("(?i)limiter|ratelimit|throttle")) and
    cpKind = "rate_limit" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // path_traversal_check: path.normalize, path.resolve, includes('..')
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    call.getMethodName().regexpMatch("normalize|resolve|relative") and
    call.getReceiver().toString().regexpMatch("(?i)^path$|posix|win32") and
    cpKind = "path_traversal_check" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // sanitize: DOMPurify.sanitize, validator.escape, encodeURIComponent
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getMethodName().regexpMatch("(?i)sanitize|escape|encode|purify|clean|strip") or
     call.getCalleeName().regexpMatch("encodeURIComponent|encodeURI|htmlspecialchars")) and
    cpKind = "sanitize" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // proto_check: hasOwnProperty(), Object.hasOwn()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getMethodName() = "hasOwnProperty" or
     call.getCalleeName() = "hasOwn") and
    cpKind = "proto_check" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // error_check: try/catch block
  exists(TryStmt t |
    t.getContainer() = f and
    cpKind = "error_check" and cpText = "try_catch" and cpLoc = t.getLocation()
  )
  or
  // format_check: .test(), .match(), validator.isEmail(), .isURL()
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition().(MethodCallExpr).getMethodName()
        .regexpMatch("test|match|matches|isEmail|isURL|isAlphanumeric|isNumeric|isIP|isValid") and
    cpKind = "format_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // size_check: if (data.length > MAX), Buffer.byteLength check
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition().(RelationalComparison).getAnOperand().(PropAccess).getPropertyName()
        .regexpMatch("length|byteLength|size") and
    cpKind = "size_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
  or
  // origin_check: allowedOrigins.includes(), validateOrigin()
  exists(DataFlow::CallNode call |
    call.getContainer() = f and
    (call.getMethodName().regexpMatch("(?i)includes|has") and
     call.getReceiver().toString().regexpMatch("(?i)origin|allowed|whitelist") or
     call.getCalleeName().regexpMatch("(?i)validateOrigin|checkOrigin")) and
    cpKind = "origin_check" and cpText = call.toString() and cpLoc = call.getLocation()
  )
  or
  // crypto_check: bcrypt.getRounds(), checking key/salt length
  exists(IfStmt s |
    s.getContainer() = f and
    s.getCondition().toString().regexpMatch("(?i).*salt.*length.*|.*key.*length.*|.*iterations.*|.*rounds.*") and
    cpKind = "crypto_check" and cpText = s.getCondition().toString() and cpLoc = s.getLocation()
  )
}

// ── File-scope checkpoint helpers (used by *_sinks.ql and *_pairs.ql) ─────────

bindingset[sink]
string cpTextNearSink(DataFlow::Node sink) {
  // Auth / permission function calls
  exists(DataFlow::CallNode call |
    call.getFile() = sink.getFile() and
    (
      call.getCalleeName()
          .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin|requireAuth|isAuthorized|checkAuth|verify|authenticate") or
      call.getMethodName()
          .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin|requireAuth|isAuthorized|checkAuth")
    ) and
    result = call.toString()
  )
  or
  // Schema/input validation calls
  exists(DataFlow::CallNode call |
    call.getFile() = sink.getFile() and
    call.getMethodName().regexpMatch("validate|parse|safeParse|check|assert|verify") and
    not call.getCalleeName()
            .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin") and
    result = call.toString()
  )
  or
  // if-statement with strict equality / null checks
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    (s.getCondition() instanceof StrictEqualityTest or s.getCondition() instanceof EqualityTest) and
    result = s.getCondition().toString()
  )
  or
  // if-statement with relational comparison
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof RelationalComparison and
    result = s.getCondition().toString()
  )
  or
  // if-statement with logical NOT
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof LogicalNotExpr and
    result = s.getCondition().toString()
  )
  or
  // typeof guard
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition().(EqualityTest).getAnOperand() instanceof TypeofExpr and
    result = s.getCondition().toString()
  )
  or
  // instanceof guard
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof InstanceofExpr and
    result = s.getCondition().toString()
  )
  or
  // in operator guard
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof InExpr and
    result = s.getCondition().toString()
  )
}

bindingset[sink]
string cpKindNearSink(DataFlow::Node sink) {
  exists(DataFlow::CallNode call |
    call.getFile() = sink.getFile() and
    (
      call.getCalleeName()
          .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin|requireAuth|isAuthorized|checkAuth|verify|authenticate") or
      call.getMethodName()
          .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin|requireAuth|isAuthorized|checkAuth")
    )
  ) and result = "auth_guard"
  or
  exists(DataFlow::CallNode call |
    call.getFile() = sink.getFile() and
    call.getMethodName().regexpMatch("validate|parse|safeParse|check|assert|verify") and
    not call.getCalleeName()
            .regexpMatch("(?i)isAuthenticated|hasRole|checkPermission|verifyToken|isAdmin")
  ) and result = "schema_validate"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    (s.getCondition() instanceof StrictEqualityTest or s.getCondition() instanceof EqualityTest)
  ) and result = "null_check"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof RelationalComparison
  ) and result = "bounds_check"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof LogicalNotExpr
  ) and result = "null_check"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition().(EqualityTest).getAnOperand() instanceof TypeofExpr
  ) and result = "type_check"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof InstanceofExpr
  ) and result = "type_check"
  or
  exists(IfStmt s |
    s.getFile() = sink.getFile() and
    s.getCondition() instanceof InExpr
  ) and result = "whitelist_check"
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
