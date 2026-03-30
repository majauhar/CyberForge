/**
 * Vuljector shared library for Python CodeQL queries.
 * Imported by python_pairs.ql, python_sinks.ql, and python_combinatorial.ql.
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.Concepts

// ── Sink detection ────────────────────────────────────────────────────────────
// Inspired by AST plugin operation categories (python_plugin.py).

predicate vuljectorSink(DataFlow::Node sink, string kind) {
  // ── Concepts-based (CodeQL standard library) ───────────────────────────────
  sink = any(SqlExecution e).getSql()                and kind = "sql_exec"
  or
  sink = any(SystemCommandExecution e).getCommand()  and kind = "subprocess"
  or
  sink = any(FileSystemAccess e).getAPathArgument()  and kind = "file_op"
  or
  sink = any(CodeExecution e).getCode()              and kind = "eval_exec"
  or
  sink = any(Http::Client::Request r).getAUrlPart()  and kind = "http_request"
  or
  // ── Method-call based ──────────────────────────────────────────────────────
  // Deserialization: pickle.loads, yaml.load, marshal.loads, dill.loads, joblib.load
  exists(DataFlow::MethodCallNode call |
    sink = call.getArg(_) and
    call.getMethodName()
        .regexpMatch("loads?|load_all|unsafe_load|unmarshal|from_buffer") and
    kind = "deser"
  )
  or
  // Template injection: jinja2 Environment.from_string, Template.render
  exists(DataFlow::MethodCallNode call |
    sink = call.getArg(_) and
    call.getMethodName()
        .regexpMatch("render_template_string|from_string|render_string|render") and
    kind = "template_render"
  )
  or
  // LDAP injection
  exists(DataFlow::MethodCallNode call |
    sink = call.getArg(_) and
    call.getMethodName()
        .regexpMatch("search|search_s|search_ext|simple_bind_s|bind_s") and
    kind = "ldap_op"
  )
  or
  // Log injection: logging.info(user_data), logger.warning(...)
  exists(DataFlow::MethodCallNode call |
    sink = call.getArg(_) and
    call.getMethodName()
        .regexpMatch("info|warning|warn|error|debug|critical|exception|log") and
    kind = "log_op"
  )
  or
  // Open redirect: Flask redirect(url), werkzeug redirect
  exists(Call call |
    sink.asExpr() = call.getArg(0) and
    call.getFunc().(Name).getId().regexpMatch("redirect|HttpResponseRedirect|url_for") and
    kind = "redirect_op"
  )
  or
  // ReDoS: re.compile / re.match / re.search with user-controlled pattern
  exists(Call call |
    sink.asExpr() = call.getArg(0) and
    call.getFunc().(Name).getId().regexpMatch("compile|match|fullmatch|search|findall|sub") and
    kind = "regex_exec"
  )
  or
  // Data return: jsonify, render_template, HttpResponse, Response
  exists(Call call |
    sink.asExpr() = call.getArg(_) and
    call.getFunc().(Name).getId()
        .regexpMatch("jsonify|render_template|HttpResponse|JsonResponse|make_response") and
    kind = "data_return"
  )
  or
  // XML parsing: unsafe parsers susceptible to XXE
  exists(DataFlow::MethodCallNode call |
    sink = call.getArg(_) and
    call.getMethodName().regexpMatch("parse|fromstring|parseString|iterparse") and
    kind = "xml_parse"
  )
}

// ── Combinatorial checkpoint detection ────────────────────────────────────────
// checkpointInFunction: all checkpoint patterns in function f, returning
// the checkpoint location, kind, and text. One result per checkpoint found.
// Inspired by the full AST checkpoint pattern set (python_plugin.py).

predicate checkpointInFunction(Function f, Location cpLoc, string cpKind, string cpText) {
  // null_check: if x is None / if x is not None
  exists(If guard, Compare cmp |
    guard.getScope() = f and cmp = guard.getTest() and
    (cmp.getOp(_) instanceof Is or cmp.getOp(_) instanceof IsNot) and
    cpKind = "null_check" and cpText = cmp.toString() and cpLoc = guard.getLocation()
  )
  or
  // null_check (negation): if not x
  exists(If guard |
    guard.getScope() = f and guard.getTest() instanceof UnaryExpr and
    cpKind = "null_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // bounds_check: if len(x) > N / if x < limit
  exists(If guard |
    guard.getScope() = f and
    (
      guard.getTest().(Call).getFunc().(Name).getId() = "len"
      or
      exists(Compare cmp | cmp = guard.getTest() and
        (cmp.getOp(_) instanceof Lt or cmp.getOp(_) instanceof Gt or
         cmp.getOp(_) instanceof LtE or cmp.getOp(_) instanceof GtE))
    ) and
    cpKind = "bounds_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // type_check: isinstance(x, T), hasattr(x, y), callable(x)
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Name).getId()
        .regexpMatch("isinstance|type|hasattr|callable") and
    cpKind = "type_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // whitelist_check: if x in allowed / if x not in blacklist
  exists(If guard, Compare cmp |
    guard.getScope() = f and cmp = guard.getTest() and
    (cmp.getOp(_) instanceof In or cmp.getOp(_) instanceof NotIn) and
    cpKind = "whitelist_check" and cpText = cmp.toString() and cpLoc = guard.getLocation()
  )
  or
  // equality_check: if x == y / if x != y
  exists(If guard, Compare cmp |
    guard.getScope() = f and cmp = guard.getTest() and
    (cmp.getOp(_) instanceof Eq or cmp.getOp(_) instanceof NotEq) and
    cpKind = "equality_check" and cpText = cmp.toString() and cpLoc = guard.getLocation()
  )
  or
  // auth_guard via if-statement: if not user.is_authenticated(), if not user
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("(?i)is_authenticated|has_perm|verify_token|is_authorized|has_role|is_admin|has_permission|check_access|is_superuser|is_active") and
    cpKind = "auth_guard" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // auth_guard via abort(401/403)
  exists(Call c |
    c.getScope() = f and
    c.getFunc().(Name).getId() = "abort" and
    (c.getArg(0).(IntegerLiteral).getN() = "401" or
     c.getArg(0).(IntegerLiteral).getN() = "403") and
    cpKind = "auth_guard" and cpText = c.toString() and cpLoc = c.getLocation()
  )
  or
  // auth_guard via decorator: @login_required, @requires_auth (as a Call)
  exists(Call deco |
    deco = f.getADecorator() and
    deco.getFunc().(Name).getId()
        .regexpMatch("login_required|requires_auth|require_permission|jwt_required|roles_required|auth_required|permission_required") and
    cpKind = "auth_guard" and cpText = deco.getFunc().(Name).getId() and cpLoc = deco.getLocation()
  )
  or
  // auth_guard via decorator: @login_required as a plain Name (no call parens)
  exists(Name deco |
    deco = f.getADecorator() and
    deco.getId()
        .regexpMatch("login_required|requires_auth|jwt_required|auth_required|permission_required") and
    cpKind = "auth_guard" and cpText = deco.getId() and cpLoc = deco.getLocation()
  )
  or
  // format_check: if x.match(), .validate(), .startswith(), .endswith()
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("match|fullmatch|search|validate|startswith|endswith|test|is_valid|is_email|is_url") and
    cpKind = "format_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // format_check: re.match / re.fullmatch / re.search call in if
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("match|fullmatch|search|compile") and
    cpKind = "format_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // path_traversal_check: os.path.abspath, .realpath, .normpath, safe_join
  exists(Call pathCheck |
    pathCheck.getScope() = f and
    pathCheck.getFunc().(Attribute).getName()
        .regexpMatch("realpath|abspath|normpath|safe_join|resolve|is_relative_to") and
    cpKind = "path_traversal_check" and cpText = pathCheck.getFunc().(Attribute).getName() and
    cpLoc = pathCheck.getLocation()
  )
  or
  // sanitize: escape(), sanitize(), bleach.clean(), markupsafe.escape()
  exists(Call sanitizeCall |
    sanitizeCall.getScope() = f and
    sanitizeCall.getFunc().(Attribute).getName()
        .regexpMatch("escape|sanitize|clean|strip_tags|encode|quote|quote_plus") and
    cpKind = "sanitize" and cpText = sanitizeCall.getFunc().(Attribute).getName() and
    cpLoc = sanitizeCall.getLocation()
  )
  or
  // signature_check: hmac.compare_digest(), .verify()
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("compare_digest|verify|check_signature|validate_hmac") and
    cpKind = "signature_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // error_check: try/except block
  exists(Try t |
    t.getScope() = f and
    cpKind = "error_check" and cpText = "try_except" and cpLoc = t.getLocation()
  )
  or
  // assert_guard: assert statement
  exists(Assert a |
    a.getScope() = f and
    cpKind = "assert_guard" and cpText = a.getTest().toString() and cpLoc = a.getLocation()
  )
  or
  // rate_limit: rate_limit(), throttle() call
  exists(Call rateCall |
    rateCall.getScope() = f and
    rateCall.getFunc().(Name).getId()
        .regexpMatch("(?i)rate_limit|throttle|ratelimit|check_rate|limit") and
    cpKind = "rate_limit" and cpText = rateCall.getFunc().(Name).getId() and
    cpLoc = rateCall.getLocation()
  )
  or
  // csrf_check: validate_csrf(), check_csrf()
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("(?i)validate_csrf|check_csrf|verify_csrf") and
    cpKind = "csrf_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // size_check: if len(x) > MAX_SIZE, if content_length >
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Call).getFunc().(Name).getId() = "len" and
    cpKind = "size_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
  or
  // overflow_check: if x > sys.maxsize
  exists(If guard |
    guard.getScope() = f and
    guard.getTest().(Compare).getAComparator().(Attribute).getName()
        .regexpMatch("maxsize|maxint|INT_MAX|MAX_SIZE") and
    cpKind = "overflow_check" and cpText = guard.getTest().toString() and cpLoc = guard.getLocation()
  )
}

// ── File-scope checkpoint helpers (used by *_sinks.ql and *_pairs.ql) ─────────
// These retain file-scope for backwards compatibility.

bindingset[sink]
string cpTextNearSink(DataFlow::Node sink) {
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    (
      guard.getTest().(Call).getFunc().(Name).getId()
          .regexpMatch("isinstance|hasattr|callable|len|any|all|bool|type")
      or
      guard.getTest().(Call).getFunc().(Attribute).getName()
          .regexpMatch("(?i)is_authenticated|has_perm|check_perm|verify_token|require_login|is_authorized|has_role|is_admin|is_staff|check_access|is_superuser|is_active|has_permission")
      or
      exists(Compare cmp | cmp = guard.getTest() and
        (cmp.getOp(_) instanceof Is or cmp.getOp(_) instanceof IsNot))
      or
      exists(Compare cmp | cmp = guard.getTest() and
        (cmp.getOp(_) instanceof Eq or cmp.getOp(_) instanceof NotEq))
      or
      exists(Compare cmp | cmp = guard.getTest() and
        (cmp.getOp(_) instanceof Lt or cmp.getOp(_) instanceof Gt or
         cmp.getOp(_) instanceof LtE or cmp.getOp(_) instanceof GtE))
      or
      exists(Compare cmp | cmp = guard.getTest() and
        (cmp.getOp(_) instanceof In or cmp.getOp(_) instanceof NotIn))
      or
      guard.getTest().(Call).getFunc().(Attribute).getName()
          .regexpMatch("startswith|endswith|match|fullmatch|search|findall|validate|test")
      or
      guard.getTest() instanceof UnaryExpr
    ) and
    result = guard.getTest().toString()
  )
  or
  exists(Assert a |
    a.getLocation().getFile() = sink.getLocation().getFile() and
    result = a.getTest().toString()
  )
}

bindingset[sink]
string cpKindNearSink(DataFlow::Node sink) {
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    guard.getTest().(Call).getFunc().(Name).getId()
        .regexpMatch("isinstance|type|hasattr|callable")
  ) and result = "type_check"
  or
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    (
      guard.getTest().(Call).getFunc().(Name).getId() = "len"
      or exists(Compare cmp | cmp = guard.getTest() and
           (cmp.getOp(_) instanceof Lt or cmp.getOp(_) instanceof Gt or
            cmp.getOp(_) instanceof LtE or cmp.getOp(_) instanceof GtE))
    )
  ) and result = "bounds_check"
  or
  exists(If guard, Compare cmp |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    cmp = guard.getTest() and
    (cmp.getOp(_) instanceof Is or cmp.getOp(_) instanceof IsNot)
  ) and result = "null_check"
  or
  exists(If guard, Compare cmp |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    cmp = guard.getTest() and
    (cmp.getOp(_) instanceof Eq or cmp.getOp(_) instanceof NotEq)
  ) and result = "equality_check"
  or
  exists(If guard, Compare cmp |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    cmp = guard.getTest() and
    (cmp.getOp(_) instanceof In or cmp.getOp(_) instanceof NotIn)
  ) and result = "whitelist_check"
  or
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("(?i)is_authenticated|has_perm|check_perm|verify_token|require_login|is_authorized|has_role|is_admin|is_staff|check_access|is_superuser|is_active|has_permission")
  ) and result = "auth_guard"
  or
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    guard.getTest().(Call).getFunc().(Attribute).getName()
        .regexpMatch("startswith|endswith|match|fullmatch|search|findall|validate|test")
  ) and result = "format_check"
  or
  exists(Assert a |
    a.getLocation().getFile() = sink.getLocation().getFile()
  ) and result = "assert_guard"
  or
  exists(If guard |
    guard.getLocation().getFile() = sink.getLocation().getFile() and
    guard.getTest() instanceof UnaryExpr
  ) and result = "null_check"
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
