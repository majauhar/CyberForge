"""JavaScript / TypeScript language plugin for Vuljector static analysis.

Provides checkpoint and operation pattern catalogs for JS/TS source files.
Pattern matching is regex-based on stripped source lines (same approach as
python_plugin.py and c_plugin.py).

Tree-sitter is used for call-graph construction (call_graph_js.py) — this
file contains only pattern definitions and the plugin class.
"""

from __future__ import annotations
import re
from selector.static_analysis.models import CheckpointPattern, OperationPattern


# ── FFI / Native boundary patterns ───────────────────────────────────────────

FFI_PATTERNS: list[str] = [
    r"require\s*\(\s*['\"].*\.node['\"]\s*\)",   # native addon .node file
    r"\bNAPI_\w+\b",                              # N-API macro
    r"node-ffi-napi\b",                           # ffi-napi library
    r"WebAssembly\.instantiate\s*\(",
    r"WebAssembly\.instantiateStreaming\s*\(",
    r"new\s+WebAssembly\.Module\s*\(",
    r"WebAssembly\.compile\s*\(",
]

# ── Sanitizer function names (noise reduction) ────────────────────────────────

SANITIZER_NAMES: list[str] = [
    "sanitize", "escape", "encode", "DOMPurify", "sanitizeHtml",
    "xss", "validator", "clean", "strip", "filter",
    "htmlEntities", "encodeURIComponent", "encodeHTML", "escapeHtml",
    "he", "xssFilters", "striptags", "bleach", "createPolicy",
    "escapeXml", "escapeHtml", "encodeForHTML", "encodeForURL",
]

# ── Gap-fill constants (used by gap_fill.py) ──────────────────────────────────

WEAK_RANDOM: list[str] = ["Math.random", "Date.now"]

WEAK_ALGOS: list[str] = ["md5", "sha1", "MD5", "SHA1", "DES", "RC4", "des", "rc4"]

SECURITY_CONTEXTS: list[str] = [
    "token", "key", "nonce", "salt", "secret", "password", "passwd",
    "session", "csrf", "otp", "pin", "auth", "credential", "cookie",
    "signing", "signature", "hmac", "iv", "seed", "apikey", "api_key",
    "privatekey", "private_key", "clientsecret", "client_secret",
]

TOCTOU_CHECK_OPS: list[str] = [
    "fs.access(", "fs.stat(", "fs.exists(", "fs.accessSync(", "fs.statSync(",
]

TOCTOU_USE_OPS: list[str] = [
    "fs.readFile(", "fs.writeFile(", "fs.unlink(", "fs.rename(",
    "fs.readFileSync(", "fs.writeFileSync(", "fs.unlinkSync(",
]

PROTO_POLLUTION_SINKS: list[str] = ["__proto__", "constructor", "prototype"]

PROTO_POLLUTION_SOURCES: list[str] = [
    "req.body", "req.query", "req.params", "body", "data", "payload", "input",
]

HARDCODED_SECRET_PATTERNS: list[str] = [
    r"(?:password|passwd|secret|api_key|apiKey|token|private_key|clientSecret)"
    r"\s*[=:]\s*['\"][A-Za-z0-9+/=_\-!@#$%^&*]{8,}['\"]",
    r"(?:SECRET_KEY|JWT_SECRET|DATABASE_PASSWORD|API_KEY|SIGNING_KEY)"
    r"\s*=\s*['\"][A-Za-z0-9+/=_\-!@#$%^&*]{6,}['\"]",
]


# ─────────────────────────────────────────────────────────────────────────────
# Checkpoint patterns
# Each entry: (type_label, regex_string)
# Matched against stripped source lines.
# ─────────────────────────────────────────────────────────────────────────────

_RAW_CHECKPOINT_PATTERNS: list[tuple[str, str]] = [

    # ── null_check ────────────────────────────────────────────────────────────
    ("null_check", r"=== null\b"),
    ("null_check", r"!== null\b"),
    ("null_check", r"== null\b"),
    ("null_check", r"!= null\b"),
    ("null_check", r"=== undefined\b"),
    ("null_check", r"!== undefined\b"),
    ("null_check", r"== undefined\b"),
    ("null_check", r"!= undefined\b"),
    ("null_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]undefined['\"]"),
    ("null_check", r"typeof\s+\w[\w.$]*\s*!==\s*['\"]undefined['\"]"),
    ("null_check", r"if\s*\(\s*!\s*\w[\w.$]*\s*\)"),
    ("null_check", r"\?\?="),
    ("null_check", r"\?\?"),
    ("null_check", r"\?\."),
    ("null_check", r"\w[\w.$]*\s*!==\s*null\s*&&\s*\w[\w.$]*\s*!==\s*undefined"),
    ("null_check", r"Object\.is\s*\(\s*\w[\w.$]*\s*,\s*null\s*\)"),

    # ── type_check ────────────────────────────────────────────────────────────
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]string['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]number['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]boolean['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]object['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]function['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]symbol['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*===\s*['\"]bigint['\"]"),
    ("type_check", r"typeof\s+\w[\w.$]*\s*!==\s*['\"]"),
    ("type_check", r"\binstanceof\s+\w"),
    ("type_check", r"Array\.isArray\s*\("),
    ("type_check", r"Number\.isInteger\s*\("),
    ("type_check", r"Number\.isFinite\s*\("),
    ("type_check", r"Number\.isNaN\s*\("),
    ("type_check", r"Buffer\.isBuffer\s*\("),
    ("type_check", r"Object\.prototype\.toString\.call\s*\("),
    ("type_check", r"Object\.getPrototypeOf\s*\("),

    # ── bounds_check ──────────────────────────────────────────────────────────
    ("bounds_check", r"\.length\s*[<>]=?\s*\d+"),
    ("bounds_check", r"\.length\s*[<>]=?\s*\w[\w.$]*"),
    ("bounds_check", r"\.length\s*===\s*0"),
    ("bounds_check", r"\.length\s*!==\s*0"),
    ("bounds_check", r"\.size\s*[<>]=?\s*\d+"),
    ("bounds_check", r"\.size\s*[<>]=?\s*\w[\w.$]*"),
    ("bounds_check", r"if\s*\(\s*i\s*[<>]=?\s*\w[\w.$]*\.length"),
    ("bounds_check", r"if\s*\(\s*index\s*[<>]=?\s*\w[\w.$]*\.length"),
    ("bounds_check", r"if\s*\(\s*offset\s*\+\s*\w[\w.$]*\s*[<>]=?\s*\w[\w.$]*\.byteLength"),
    ("bounds_check", r"\bMath\.min\s*\(|\bMath\.max\s*\("),
    ("bounds_check", r"\.slice\s*\(\s*0\s*,"),
    ("bounds_check", r"if\s*\(\s*\w[\w.$]*\s*>=\s*0\s*&&\s*\w[\w.$]*\s*<"),
    ("bounds_check", r"\.byteLength\s*[<>]=?\s*\d+"),
    ("bounds_check", r"if\s*\(\s*count\s*[<>]=?\s*\w[\w.$]*"),

    # ── auth_guard ────────────────────────────────────────────────────────────
    ("auth_guard", r"req\.isAuthenticated\s*\("),
    ("auth_guard", r"if\s*\(\s*!\s*req\.user\b"),
    ("auth_guard", r"if\s*\(\s*!\s*req\.session"),
    ("auth_guard", r"if\s*\(\s*!\s*session\.user\b"),
    ("auth_guard", r"if\s*\(\s*!\s*user\b"),
    # Token / credential nil checks (common Express/Fastify auth guards)
    ("auth_guard", r"if\s*\(\s*!\s*(?:token|accessToken|authToken|bearerToken|idToken|refreshToken|apiKey|api_key)\b"),
    ("auth_guard", r"if\s*\(\s*(?:token|accessToken|authToken)\s*===?\s*(?:undefined|null)\b"),
    ("auth_guard", r"if\s*\(\s*(?:token|accessToken)\s*==\s*(?:undefined|null)\b"),
    # Returning 401/403 HTTP status (guard pattern)
    ("auth_guard", r"res\.sendStatus\s*\(\s*(?:401|403)\s*\)"),
    ("auth_guard", r"res\.status\s*\(\s*(?:401|403)\s*\)"),
    ("auth_guard", r"reply\.code\s*\(\s*(?:401|403)\s*\)"),
    ("auth_guard", r"ctx\.throw\s*\(\s*(?:401|403)\b"),
    ("auth_guard", r"next\s*\(\s*createError\s*\(\s*(?:401|403)"),
    ("auth_guard", r"h\.unauthenticated\s*\("),            # Hapi.js
    ("auth_guard", r"if\s*\(\s*!\s*req\.auth\b"),          # Hapi.js / express auth
    ("auth_guard", r"if\s*\(\s*!\s*ctx\.state\.user\b"),
    ("auth_guard", r"if\s*\(\s*!\s*request\.user\b"),      # NestJS
    ("auth_guard", r"if\s*\(\s*!\s*c\.get\s*\(\s*['\"](?:user|jwtPayload)['\"]"),  # Hono
    # Role / permission checks
    ("auth_guard", r"\.hasPermission\s*\("),
    ("auth_guard", r"\.hasRole\s*\("),
    ("auth_guard", r"\.can\s*\(\s*['\"]"),
    ("auth_guard", r"\.isAdmin\b"),
    ("auth_guard", r"\.isAuthorized\b"),
    ("auth_guard", r"user\.role\s*(?:!==?|===?)\s*['\"]"),
    ("auth_guard", r"if\s*\(\s*role\s*!==\s*['\"]"),
    ("auth_guard", r"if\s*\(\s*!\s*roles\.includes\s*\("),
    ("auth_guard", r"if\s*\(\s*!\s*permissions\.includes\s*\("),
    # Library-specific guards
    ("auth_guard", r"passport\.authenticate\s*\("),
    ("auth_guard", r"verifyToken\s*\("),
    ("auth_guard", r"checkAuth\s*\("),
    ("auth_guard", r"requireAuth\s*\("),
    ("auth_guard", r"ensureAuth\s*\("),
    ("auth_guard", r"requiresAuth\s*\("),
    ("auth_guard", r"checkPermission\s*\("),
    ("auth_guard", r"authorize\s*\("),
    ("auth_guard", r"if\s*\(\s*!\s*req\.headers\.authorization\b"),
    ("auth_guard", r"throw\s+new\s+\w*(?:Unauthorized|Forbidden|AuthError|AuthenticationError)\w*"),
    ("auth_guard", r"isLoggedIn\s*\(|isSignedIn\s*\("),
    ("auth_guard", r"session\.isAuthenticated\s*===\s*true"),
    ("auth_guard", r"@UseGuards\s*\("),                    # NestJS decorator
    ("auth_guard", r"@Roles\s*\("),                        # NestJS roles decorator

    # ── sanitize ──────────────────────────────────────────────────────────────
    ("sanitize", r"DOMPurify\.sanitize\s*\("),
    ("sanitize", r"createDOMPurify\s*\("),
    ("sanitize", r"sanitizeHtml\s*\("),
    ("sanitize", r"\bxss\s*\("),
    ("sanitize", r"validator\.escape\s*\("),
    ("sanitize", r"he\.encode\s*\("),
    ("sanitize", r"he\.escape\s*\("),
    ("sanitize", r"htmlEntities\s*\("),
    ("sanitize", r"encodeHTML\s*\("),
    ("sanitize", r"escapeHtml\s*\("),
    ("sanitize", r"marked\.parseInline\s*\("),
    ("sanitize", r"\bbleach\s*\("),
    ("sanitize", r"striptags\s*\("),
    ("sanitize", r"\bsanitize\s*\("),
    ("sanitize", r"\bencode\s*\("),
    ("sanitize", r"encodeForHTML\s*\("),
    ("sanitize", r"createPolicy\s*\("),
    ("sanitize", r"TrustedHTML\.fromLiteral\s*\("),
    ("sanitize", r"xssFilters\.\w+\s*\("),
    ("sanitize", r"_\.escape\s*\("),
    ("sanitize", r"S\s*\(\s*\w[\w.$]*\s*\)\.escapeHTML\s*\("),
    ("sanitize", r"entities\.encode\s*\("),
    ("sanitize", r"\.replace\s*\(\s*/[<>&\"']/g"),

    # ── path_traversal_check ──────────────────────────────────────────────────
    ("path_traversal_check", r"\.includes\s*\(\s*['\"]\.\.['\"]\s*\)"),
    ("path_traversal_check", r"\.startsWith\s*\(\s*['\"][./]"),
    ("path_traversal_check", r"path\.normalize\s*\("),
    ("path_traversal_check", r"path\.resolve\s*\("),
    ("path_traversal_check", r"realpathSync\s*\(|realpath\s*\("),
    ("path_traversal_check", r"path\.relative\s*\("),
    ("path_traversal_check", r"\.replace\s*\(\s*/\.\.\//g"),
    ("path_traversal_check", r"if\s*\(\s*!\s*\w[\w.$]*\.startsWith\s*\(\s*(?:basePath|uploadDir|rootDir|__dirname)"),
    ("path_traversal_check", r"str\.indexOf\s*\(\s*['\"]\.\.['\"]\s*\)\s*[!=]="),
    ("path_traversal_check", r"if\s*\(\s*resolvedPath\.startsWith\s*\("),
    ("path_traversal_check", r"validatePath\s*\(|checkPath\s*\("),
    ("path_traversal_check", r"!allowedPaths\.includes\s*\("),
    ("path_traversal_check", r"if\s*\(\s*relative\.startsWith\s*\(\s*['\"]\.\.['\"]\s*\)"),
    ("path_traversal_check", r"\.match\s*\(\s*/\.\.\//"),

    # ── format_check ──────────────────────────────────────────────────────────
    ("format_check", r"/[^/]{2,}/[gimsuy]*\.test\s*\("),
    ("format_check", r"\.match\s*\(\s*/[^/]"),
    ("format_check", r"validator\.\w+\s*\("),
    ("format_check", r"Joi\.\w+\s*\("),
    ("format_check", r"Yup\.\w+\s*\("),
    ("format_check", r"ajv\.validate\s*\("),
    ("format_check", r"ajv\.compile\s*\("),
    ("format_check", r"zod\.\w+\s*\(|z\.\w+\s*\("),
    ("format_check", r"\.validate\s*\("),
    ("format_check", r"\.isEmail\s*\("),
    ("format_check", r"\.isURL\s*\("),
    ("format_check", r"\.isAlphanumeric\s*\("),
    ("format_check", r"\.isNumeric\s*\("),
    ("format_check", r"\.isIP\s*\("),
    ("format_check", r"\.isValid\s*\("),
    ("format_check", r"\.matches\s*\(\s*/[^/]"),
    ("format_check", r"checkSchema\s*\("),
    ("format_check", r"jsonschema\.validate\s*\("),
    ("format_check", r"tv4\.validate\s*\("),

    # ── csrf_check ────────────────────────────────────────────────────────────
    ("csrf_check", r"req\.csrfToken\s*\("),
    ("csrf_check", r"verifyCsrfToken\s*\("),
    ("csrf_check", r"validateCsrfToken\s*\("),
    ("csrf_check", r"csrf\.protect\s*\("),
    ("csrf_check", r"\bcsurf\s*\("),
    ("csrf_check", r"doubleCsrf\s*\("),
    ("csrf_check", r"req\.headers\[.[xX]-[cC][sS][rR][fF]-[tT]oken.\]"),
    ("csrf_check", r"req\.headers\[.[xX]-[xX][sS][rR][fF]-[tT]oken.\]"),
    ("csrf_check", r"checkCsrf\s*\(|validateCsrf\s*\("),
    ("csrf_check", r"lusca\.csrf\s*\("),

    # ── rate_limit ────────────────────────────────────────────────────────────
    ("rate_limit", r"rateLimit\s*\("),
    ("rate_limit", r"rateLimiter\s*\("),
    ("rate_limit", r"createRateLimiter\s*\("),
    ("rate_limit", r"limiter\.check\s*\("),
    ("rate_limit", r"limiter\.consume\s*\("),
    ("rate_limit", r"limiter\.get\s*\("),
    ("rate_limit", r"\bthrottle\s*\("),
    ("rate_limit", r"\bbottleneck\b"),
    ("rate_limit", r"slowDown\s*\("),
    ("rate_limit", r"if\s*\(\s*requestCount\s*>=\s*MAX"),
    ("rate_limit", r"if\s*\(\s*hits\s*[>]=\s*(?:LIMIT|limit|MAX)"),
    ("rate_limit", r"if\s*\(\s*remaining\s*===\s*0"),

    # ── error_check ───────────────────────────────────────────────────────────
    ("error_check", r"if\s*\(\s*err\b"),
    ("error_check", r"if\s*\(\s*error\b"),
    ("error_check", r"\bcatch\s*\(\s*\w"),
    ("error_check", r"\.catch\s*\(\s*(?:err|error|\w+)\s*=>"),
    ("error_check", r"if\s*\(\s*!\s*result\b"),
    ("error_check", r"if\s*\(\s*!ok\b"),
    ("error_check", r"if\s*\(\s*\w[\w.$]*\.error\b"),
    ("error_check", r"if\s*\(\s*response\.status\s*[>]=?\s*400"),
    ("error_check", r"\btry\s*\{"),
    ("error_check", r"\w[\w.$]*\s+instanceof\s+Error"),
    ("error_check", r"if\s*\(\s*err\s*!==?\s*null"),
    ("error_check", r"if\s*\(\s*err\?\.code\b"),
    ("error_check", r"\.finally\s*\("),
    ("error_check", r"\.on\s*\(\s*['\"]error['\"]"),

    # ── origin_check ──────────────────────────────────────────────────────────
    ("origin_check", r"req\.headers\.origin\b"),
    ("origin_check", r"allowedOrigins\.includes\s*\("),
    ("origin_check", r"\bCORS\s*\(\s*\{"),
    ("origin_check", r"if\s*\(\s*origin\b"),
    ("origin_check", r"validateOrigin\s*\("),
    ("origin_check", r"checkOrigin\s*\("),
    ("origin_check", r"if\s*\(\s*!\s*allowedOrigin"),
    ("origin_check", r"e\.origin\s*!==\s*\w[\w.$]*"),
    ("origin_check", r"req\.headers\[.[aA]ccess-[cC]ontrol"),
    ("origin_check", r"if\s*\(\s*!origins\.has\s*\("),

    # ── xss_check ─────────────────────────────────────────────────────────────
    ("xss_check", r"encodeURIComponent\s*\("),
    ("xss_check", r"encodeURI\s*\("),
    ("xss_check", r"htmlspecialchars\s*\("),
    ("xss_check", r"htmlentities\s*\("),
    ("xss_check", r"\.replace\s*\(\s*/[<>&\"']+/g"),
    ("xss_check", r"entities\.encode\s*\("),
    ("xss_check", r"xssFilters\.\w+\s*\("),
    ("xss_check", r"\.escapeHtml\s*\(|htmlEscape\s*\("),
    ("xss_check", r"_\.escape\s*\("),
    ("xss_check", r"\.escapeHTML\s*\("),
    ("xss_check", r"encodeForHTMLAttribute\s*\("),
    ("xss_check", r"document\.createTextNode\s*\("),
    ("xss_check", r"\.textContent\s*="),

    # ── proto_check ───────────────────────────────────────────────────────────
    ("proto_check", r"\.hasOwnProperty\s*\("),
    ("proto_check", r"Object\.prototype\.hasOwnProperty\.call\s*\("),
    ("proto_check", r"Object\.hasOwn\s*\("),
    ("proto_check", r"Object\.create\s*\(\s*null\s*\)"),
    ("proto_check", r"if\s*\(\s*['\"]__proto__['\"]\s*in\b"),
    ("proto_check", r"if\s*\(\s*['\"]constructor['\"]\s*in\b"),
    ("proto_check", r"key\s*===\s*['\"]__proto__['\"]\s*\|\|"),
    ("proto_check", r"key\s*!==\s*['\"]__proto__['\"]"),
    ("proto_check", r"PROTO_POLLUTION_SINKS\.includes\s*\("),
    ("proto_check", r"Object\.freeze\s*\(\s*\w+\.prototype\s*\)"),

    # ── jwt_verify ────────────────────────────────────────────────────────────
    ("jwt_verify", r"jwt\.verify\s*\("),
    ("jwt_verify", r"jsonwebtoken\.verify\s*\("),
    ("jwt_verify", r"jose\.jwtVerify\s*\("),
    ("jwt_verify", r"verifyToken\s*\("),
    ("jwt_verify", r"validateJwt\s*\(|verifyJwt\s*\("),
    ("jwt_verify", r"checkToken\s*\("),
    ("jwt_verify", r"jws\.verify\s*\("),
    ("jwt_verify", r"njwt\.verify\s*\("),
    ("jwt_verify", r"if\s*\(\s*!\s*decoded\b"),
    ("jwt_verify", r"verifyAccessToken\s*\(|verifyRefreshToken\s*\("),

    # ── schema_validate ───────────────────────────────────────────────────────
    ("schema_validate", r"ajv\.validate\s*\("),
    ("schema_validate", r"ajv\.compile\s*\("),
    ("schema_validate", r"Joi\.object\s*\("),
    ("schema_validate", r"Joi\.string\s*\("),
    ("schema_validate", r"Yup\.object\s*\("),
    ("schema_validate", r"Yup\.string\s*\("),
    ("schema_validate", r"z\.parse\s*\(|zod\.parse\s*\("),
    ("schema_validate", r"\.safeParse\s*\("),
    ("schema_validate", r"\.parseAsync\s*\("),
    ("schema_validate", r"jsonschema\.validate\s*\("),
    ("schema_validate", r"tv4\.validate\s*\("),
    ("schema_validate", r"validateOrReject\s*\("),
    ("schema_validate", r"TypeCompiler\.Compile\s*\("),
    ("schema_validate", r"Superstruct\.assert\s*\("),
    ("schema_validate", r"io-ts\b"),

    # ── content_type_check ────────────────────────────────────────────────────
    ("content_type_check", r"req\.is\s*\(\s*['\"]"),
    ("content_type_check", r"req\.headers\[.[cC]ontent-[tT]ype.\]"),
    ("content_type_check", r"allowedTypes\.includes\s*\("),
    ("content_type_check", r"mime\.getType\s*\("),
    ("content_type_check", r"mime\.lookup\s*\("),
    ("content_type_check", r"fileTypeFromBuffer\s*\("),
    ("content_type_check", r"fileType\.fromStream\s*\("),
    ("content_type_check", r"multer.*fileFilter"),
    ("content_type_check", r"if\s*\(\s*!\s*contentType\.startsWith"),
    ("content_type_check", r"allowedMimeTypes\.has\s*\("),

    # ── size_check ────────────────────────────────────────────────────────────
    ("size_check", r"\.length\s*>\s*(?:MAX|max|LIMIT|limit)\w*"),
    ("size_check", r"if\s*\(\s*req\.headers\[.[cC]ontent-[lL]ength.\]\s*>"),
    ("size_check", r"Buffer\.byteLength\s*\("),
    ("size_check", r"if\s*\(\s*file\.size\s*>"),
    ("size_check", r"if\s*\(\s*data\.length\s*>\s*\d"),
    ("size_check", r"express\.json\s*\(\s*\{.*limit"),
    ("size_check", r"bodyParser\.json\s*\(\s*\{.*limit"),
    ("size_check", r"maxBodyLength\s*:"),
    ("size_check", r"maxContentLength\s*:"),
    ("size_check", r"MAX_(?:FILE|UPLOAD|PAYLOAD|BODY)_SIZE\b"),
    ("size_check", r"if\s*\(\s*input\.length\s*>\s*\d"),
    ("size_check", r"multer.*limits\s*:\s*\{.*fileSize"),

    # ── regex_match ───────────────────────────────────────────────────────────
    ("regex_match", r"/\^[a-zA-Z0-9\\w\\W_\-.*+?]+\$/.test\s*\("),
    ("regex_match", r"/\^[\[\\w\\-\]]+\$/.test\s*\("),
    ("regex_match", r"/\^\\d\+\$/.test\s*\("),
    ("regex_match", r"SAFE_PATTERN\.test\s*\("),
    ("regex_match", r"VALID_\w+_RE\.test\s*\("),
    ("regex_match", r"if\s*\(\s*pattern\.test\s*\("),
    ("regex_match", r"validator\.matches\s*\("),
    ("regex_match", r"if\s*\(\s*!\s*ALLOWED_\w+\.test\s*\("),
    ("regex_match", r"/\^[a-z]\{2,\d+\}\$/.test\s*\("),
    ("regex_match", r"\.test\s*\(\s*\w[\w.$]*\s*\)"),

    # ── encoding_check ────────────────────────────────────────────────────────
    ("encoding_check", r"Buffer\.from\s*\(\s*\w[\w.$]*\s*,\s*['\"]utf-?8['\"]"),
    ("encoding_check", r"iconv\.decode\s*\("),
    ("encoding_check", r"iconv\.encode\s*\("),
    ("encoding_check", r"isValidUTF8\s*\("),
    ("encoding_check", r"chardet\.detect\s*\("),
    ("encoding_check", r"if\s*\(\s*encoding\s*!==\s*['\"]utf-?8['\"]"),
    ("encoding_check", r"normalizeEncoding\s*\("),
    ("encoding_check", r"\.normalize\s*\(\s*['\"](?:NFC|NFD|NFKC|NFKD)['\"]"),
    ("encoding_check", r"new\s+TextDecoder\s*\(\s*['\"]"),
    ("encoding_check", r"if\s*\(\s*!validEncodings\.includes\s*\("),

    # ── param_check ───────────────────────────────────────────────────────────
    ("param_check", r"if\s*\(\s*!\s*req\.params\.\w+"),
    ("param_check", r"if\s*\(\s*!\s*req\.query\.\w+"),
    ("param_check", r"if\s*\(\s*!\s*req\.body\.\w+"),
    ("param_check", r"req\.params\.\w+\s*&&\s*isValid"),
    ("param_check", r"typeof\s+req\.params\.\w+\s*!==\s*['\"]"),
    ("param_check", r"if\s*\(\s*!Object\.keys\s*\(\s*req\.body\s*\)\.length"),
    ("param_check", r"if\s*\(\s*req\.query\.\w+\s*&&\s*isNaN"),
    ("param_check", r"if\s*\(\s*!req\.body\s*\|\|\s*typeof\s+req\.body"),
    ("param_check", r"Object\.keys\s*\(\s*req\.body\s*\)\.some\s*\("),
    ("param_check", r"allowedParams\s*=\s*\[.*\];\s*if\s*\(\s*!allowedParams\.includes"),

    # ── crypto_check ──────────────────────────────────────────────────────────
    ("crypto_check", r"if\s*\(\s*salt\.length\s*<\s*MIN_SALT"),
    ("crypto_check", r"if\s*\(\s*iterations\s*<\s*MIN_ITERATIONS"),
    ("crypto_check", r"if\s*\(\s*keyLength\s*<\s*(?:256|128|32)"),
    ("crypto_check", r"if\s*\(\s*algorithm\s*!==\s*['\"]sha(?:256|512)['\"]"),
    ("crypto_check", r"if\s*\(\s*!SAFE_ALGORITHMS\.includes\s*\("),
    ("crypto_check", r"if\s*\(\s*key\.length\s*<\s*(?:32|16)"),
    ("crypto_check", r"if\s*\(\s*iv\.length\s*!==\s*(?:12|16)"),
    ("crypto_check", r"pbkdf2.*iterations"),
    ("crypto_check", r"bcrypt\.getRounds\s*\("),
    ("crypto_check", r"if\s*\(\s*nonce\.length\s*!==\s*NONCE_SIZE"),
]


# ─────────────────────────────────────────────────────────────────────────────
# Operation patterns
# Each entry: (type_label, regex_string, cwe_class_string)
# ─────────────────────────────────────────────────────────────────────────────

_RAW_OPERATION_PATTERNS: list[tuple[str, str, str]] = [

    # ── eval_exec ─────────────────────────────────────────────────────────────
    ("eval_exec", r"\beval\s*\(", "Dynamic code"),
    ("eval_exec", r"new\s+Function\s*\(", "Dynamic code"),
    ("eval_exec", r"setTimeout\s*\(\s*['\"`][^'\"`]*(?:\$\{|\+)", "Dynamic code"),
    ("eval_exec", r"setInterval\s*\(\s*['\"`][^'\"`]*(?:\$\{|\+)", "Dynamic code"),
    ("eval_exec", r"setImmediate\s*\(\s*['\"`]", "Dynamic code"),
    ("eval_exec", r"vm\.runInThisContext\s*\(", "Dynamic code"),
    ("eval_exec", r"vm\.runInNewContext\s*\(", "Dynamic code"),
    ("eval_exec", r"vm\.runInContext\s*\(", "Dynamic code"),
    ("eval_exec", r"new\s+vm\.Script\s*\(", "Dynamic code"),
    ("eval_exec", r"vm\.compileFunction\s*\(", "Dynamic code"),
    # dynamic require/import — only flag variable form (not string literal)
    ("eval_exec", r"require\s*\(\s*(?!['\"]).+\)", "Dynamic code"),
    ("eval_exec", r"import\s*\(\s*(?!['\"]).+\)", "Dynamic code"),
    ("eval_exec", r"execScript\s*\(", "Dynamic code"),
    ("eval_exec", r"jsdom.*window\.eval\s*\(", "Dynamic code"),
    ("eval_exec", r"Function\.prototype\.call\s*\(.*eval", "Dynamic code"),
    ("eval_exec", r"eval\s*\(\s*`", "Dynamic code"),

    # ── sql_exec ──────────────────────────────────────────────────────────────
    ("sql_exec", r"db\.query\s*\(", "Input validation"),
    ("sql_exec", r"connection\.query\s*\(", "Input validation"),
    ("sql_exec", r"pool\.query\s*\(", "Input validation"),
    ("sql_exec", r"\.query\s*\(\s*`[^`]*\$\{", "Input validation"),
    ("sql_exec", r"connection\.execute\s*\(", "Input validation"),
    ("sql_exec", r"sequelize\.query\s*\(", "Input validation"),
    ("sql_exec", r"sequelize\.literal\s*\(", "Input validation"),
    ("sql_exec", r"knex\.raw\s*\(", "Input validation"),
    ("sql_exec", r"\bdb\.raw\s*\(", "Input validation"),
    ("sql_exec", r"prisma\.\$queryRaw\b", "Input validation"),
    ("sql_exec", r"prisma\.\$executeRaw\b", "Input validation"),
    ("sql_exec", r"mysql\.query\s*\(|mysql2\.query\s*\(", "Input validation"),
    ("sql_exec", r"pg\.query\s*\(|pgPool\.query\s*\(", "Input validation"),
    ("sql_exec", r"sqlite3\.run\s*\(|sqlite3\.all\s*\(", "Input validation"),
    ("sql_exec", r"mariadb.*connection\.query\s*\(", "Input validation"),
    ("sql_exec", r"oracledb\.execute\s*\(", "Input validation"),
    ("sql_exec", r"mssql\.query\s*\(|new\s+sql\.Request\s*\(", "Input validation"),
    ("sql_exec", r"redis\.eval\s*\(|redis\.evalsha\s*\(", "Input validation"),
    # TypeORM
    ("sql_exec", r"createQueryBuilder\s*\(", "Input validation"),
    ("sql_exec", r"\.createQueryBuilder\s*\(", "Input validation"),
    ("sql_exec", r"getRepository\s*\(\s*\w[\w.$]*\s*\)\.\w+\s*\(", "Input validation"),
    ("sql_exec", r"getManager\s*\(\s*\)\.\w+\s*\(", "Input validation"),
    ("sql_exec", r"\.where\s*\(\s*['\"`][^'\"`]*\$\{", "Input validation"),
    ("sql_exec", r"\.where\s*\(\s*\w[\w.$]*\s*,", "Input validation"),
    # Knex query chaining
    ("sql_exec", r"knex\s*\(\s*['\"]", "Input validation"),
    ("sql_exec", r"knex\.\w+\s*\(\s*['\"]", "Input validation"),
    ("sql_exec", r"\.whereRaw\s*\(", "Input validation"),
    ("sql_exec", r"\.havingRaw\s*\(", "Input validation"),
    ("sql_exec", r"\.joinRaw\s*\(", "Input validation"),
    # Drizzle ORM
    ("sql_exec", r"db\.select\s*\(", "Input validation"),
    ("sql_exec", r"db\.insert\s*\(", "Input validation"),
    ("sql_exec", r"db\.update\s*\(", "Input validation"),
    ("sql_exec", r"db\.delete\s*\(", "Input validation"),
    # General prepared statement / execute patterns
    ("sql_exec", r"\.execute\s*\(\s*['\"`]", "Input validation"),
    ("sql_exec", r"stmt\.run\s*\(|stmt\.all\s*\(|stmt\.get\s*\(", "Input validation"),
    # Supabase
    ("sql_exec", r"supabase\.from\s*\(\s*['\"]", "Input validation"),

    # ── xss_op ────────────────────────────────────────────────────────────────
    ("xss_op", r"\.innerHTML\s*=", "Web"),
    ("xss_op", r"\.outerHTML\s*=", "Web"),
    ("xss_op", r"document\.write\s*\(", "Web"),
    ("xss_op", r"document\.writeln\s*\(", "Web"),
    ("xss_op", r"\.insertAdjacentHTML\s*\(", "Web"),
    ("xss_op", r"dangerouslySetInnerHTML\s*=", "Web"),
    ("xss_op", r"\$\([^)]*\)\.html\s*\(", "Web"),
    ("xss_op", r"\$\([^)]*\)\.append\s*\(", "Web"),
    ("xss_op", r"\$\([^)]*\)\.prepend\s*\(", "Web"),
    ("xss_op", r"\$\([^)]*\)\.after\s*\(", "Web"),
    ("xss_op", r"\$\([^)]*\)\.before\s*\(", "Web"),
    ("xss_op", r"range\.createContextualFragment\s*\(", "Web"),
    ("xss_op", r"element\.src\s*=\s*\w", "Web"),
    ("xss_op", r"element\.href\s*=\s*\w", "Web"),
    ("xss_op", r"element\.setAttribute\s*\(\s*['\"](?:src|href|onclick|onload)['\"]", "Web"),
    ("xss_op", r"\$\([^)]*\)\.attr\s*\(\s*['\"](?:href|src)['\"]", "Web"),
    ("xss_op", r"nunjucks\.renderString\s*\(", "Web"),
    ("xss_op", r"\{\{\{[^}]+\}\}\}", "Web"),
    # Generic attribute assignment with user data
    ("xss_op", r"\.setAttribute\s*\(\s*['\"](?:href|src|action|data|srcdoc)['\"]", "Web"),
    ("xss_op", r"\w+\.src\s*=\s*(?!['\"]/)", "Web"),
    ("xss_op", r"\w+\.href\s*=\s*(?!['\"]/)", "Web"),
    # React dangerouslySetInnerHTML variations
    ("xss_op", r"__html\s*:\s*\w[\w.$]*", "Web"),

    # ── file_op ───────────────────────────────────────────────────────────────
    ("file_op", r"fs\.readFile\s*\(", "Path-related"),
    ("file_op", r"fs\.writeFile\s*\(", "Path-related"),
    ("file_op", r"fs\.readFileSync\s*\(", "Path-related"),
    ("file_op", r"fs\.writeFileSync\s*\(", "Path-related"),
    ("file_op", r"fs\.appendFile\s*\(", "Path-related"),
    ("file_op", r"fs\.appendFileSync\s*\(", "Path-related"),
    ("file_op", r"fs\.unlink\s*\(", "Path-related"),
    ("file_op", r"fs\.unlinkSync\s*\(", "Path-related"),
    ("file_op", r"fs\.rmdir\s*\(|fs\.rmdirSync\s*\(|fs\.rm\s*\(", "Path-related"),
    ("file_op", r"fs\.mkdir\s*\(|fs\.mkdirSync\s*\(", "Path-related"),
    ("file_op", r"fs\.rename\s*\(|fs\.renameSync\s*\(", "Path-related"),
    ("file_op", r"fs\.copyFile\s*\(|fs\.copyFileSync\s*\(", "Path-related"),
    ("file_op", r"fs\.open\s*\(|fs\.openSync\s*\(", "Path-related"),
    ("file_op", r"fs\.stat\s*\(|fs\.statSync\s*\(|fs\.lstat\s*\(", "Path-related"),
    ("file_op", r"fs\.readdir\s*\(|fs\.readdirSync\s*\(", "Path-related"),
    ("file_op", r"fs\.createReadStream\s*\(", "Path-related"),
    ("file_op", r"fs\.createWriteStream\s*\(", "Path-related"),
    ("file_op", r"fsPromises\.readFile\s*\(", "Path-related"),
    ("file_op", r"fsPromises\.writeFile\s*\(", "Path-related"),
    ("file_op", r"fsExtra\.\w+\s*\(", "Path-related"),

    # ── subprocess ────────────────────────────────────────────────────────────
    # NOTE: bare \bexec\( is intentionally excluded — too many false positives
    # from mongoose/knex query.exec(), promise chains, etc.
    ("subprocess", r"child_process\.exec\s*\(", "Input validation"),
    ("subprocess", r"child_process\.execSync\s*\(", "Input validation"),
    ("subprocess", r"child_process\.spawn\s*\(", "Input validation"),
    ("subprocess", r"child_process\.spawnSync\s*\(", "Input validation"),
    ("subprocess", r"child_process\.execFile\s*\(|child_process\.execFileSync\s*\(", "Input validation"),
    ("subprocess", r"child_process\.fork\s*\(", "Input validation"),
    ("subprocess", r"\bcp\.exec\s*\(|\bcp\.spawn\s*\(|\bcp\.execFile\s*\(", "Input validation"),
    ("subprocess", r"shell\.exec\s*\(|shelljs\.\w+\s*\(", "Input validation"),
    ("subprocess", r"execa\s*\(|execa\.command\s*\(", "Input validation"),
    ("subprocess", r"execa\.sync\s*\(|execa\.commandSync\s*\(", "Input validation"),
    # exec/spawn with string literal — likely shell command, not query
    ("subprocess", r"\bexec\s*\(\s*['\"`]", "Input validation"),
    ("subprocess", r"\bexecSync\s*\(\s*['\"`]", "Input validation"),
    ("subprocess", r"\bspawn\s*\(\s*['\"`]", "Input validation"),
    ("subprocess", r"\bspawnSync\s*\(\s*['\"`]", "Input validation"),
    ("subprocess", r"execFile\s*\(\s*['\"`]|execFileSync\s*\(\s*['\"`]", "Input validation"),
    # zx / template literal shell execution
    ("subprocess", r"\$\s*`[^`]*\$\{", "Input validation"),
    ("subprocess", r"node-pty.*spawn\s*\(", "Input validation"),
    ("subprocess", r"execPowerShell\s*\(|runCommand\s*\(", "Input validation"),

    # ── deser ─────────────────────────────────────────────────────────────────
    ("deser", r"JSON\.parse\s*\(", "Data structure"),
    ("deser", r"yaml\.load\s*\(", "Data structure"),
    ("deser", r"yaml\.safeLoad\s*\(", "Data structure"),
    ("deser", r"YAML\.parse\s*\(", "Data structure"),
    ("deser", r"deserialize\s*\(", "Data structure"),
    ("deser", r"unserialize\s*\(", "Data structure"),
    ("deser", r"node-serialize.*unserialize\s*\(", "Data structure"),
    ("deser", r"msgpack\.decode\s*\(|msgpack5.*decode\s*\(", "Data structure"),
    ("deser", r"cbor\.decode\s*\(|cbor\.decodeFirst\s*\(", "Data structure"),
    ("deser", r"bson\.deserialize\s*\(|BSON\.deserialize\s*\(", "Data structure"),
    ("deser", r"flatted\.parse\s*\(", "Data structure"),
    ("deser", r"JSON5\.parse\s*\(", "Data structure"),
    ("deser", r"ini\.parse\s*\(|toml\.parse\s*\(", "Data structure"),
    ("deser", r"protobuf\.decode\s*\(|proto\.decode\s*\(", "Data structure"),

    # ── http_request ──────────────────────────────────────────────────────────
    ("http_request", r"\bfetch\s*\(", "Confidentiality"),
    ("http_request", r"axios\.get\s*\(", "Confidentiality"),
    ("http_request", r"axios\.post\s*\(", "Confidentiality"),
    ("http_request", r"axios\.put\s*\(", "Confidentiality"),
    ("http_request", r"axios\.delete\s*\(", "Confidentiality"),
    ("http_request", r"axios\.request\s*\(|axios\s*\(\s*\{", "Confidentiality"),
    ("http_request", r"http\.get\s*\(|http\.request\s*\(", "Confidentiality"),
    ("http_request", r"https\.get\s*\(|https\.request\s*\(", "Confidentiality"),
    ("http_request", r"\brequest\s*\(\s*\{|\brequest\s*\(\s*['\"]", "Confidentiality"),
    ("http_request", r"\bgot\s*\(|\bgot\.get\s*\(|\bgot\.post\s*\(", "Confidentiality"),
    ("http_request", r"superagent\.get\s*\(|superagent\.post\s*\(", "Confidentiality"),
    ("http_request", r"needle\.get\s*\(|needle\.post\s*\(|needle\.request\s*\(", "Confidentiality"),
    ("http_request", r"node-fetch\b", "Confidentiality"),
    ("http_request", r"undici\.fetch\s*\(|undici\.request\s*\(", "Confidentiality"),
    ("http_request", r"\bhyperquest\s*\(|\bbent\s*\(", "Confidentiality"),
    ("http_request", r"\bphin\s*\(", "Confidentiality"),
    ("http_request", r"wretch\s*\(\s*\w", "Confidentiality"),
    ("http_request", r"ky\.get\s*\(|ky\.post\s*\(", "Confidentiality"),

    # ── data_return ───────────────────────────────────────────────────────────
    ("data_return", r"res\.send\s*\(", "Confidentiality"),
    ("data_return", r"res\.json\s*\(", "Confidentiality"),
    ("data_return", r"res\.write\s*\(", "Confidentiality"),
    ("data_return", r"res\.end\s*\(", "Confidentiality"),
    ("data_return", r"res\.sendFile\s*\(", "Confidentiality"),
    ("data_return", r"res\.download\s*\(", "Confidentiality"),
    ("data_return", r"ctx\.body\s*=", "Confidentiality"),
    ("data_return", r"ctx\.response\.body\s*=", "Confidentiality"),
    ("data_return", r"reply\.send\s*\(", "Confidentiality"),
    ("data_return", r"reply\.type\s*\(.*\)\.send\s*\(", "Confidentiality"),
    ("data_return", r"response\.write\s*\(|response\.end\s*\(", "Confidentiality"),
    ("data_return", r"return\s+NextResponse\.json\s*\(", "Confidentiality"),
    ("data_return", r"return\s+new\s+Response\s*\(", "Confidentiality"),
    ("data_return", r"stream\.push\s*\(|readable\.push\s*\(", "Confidentiality"),
    ("data_return", r"event\.respondWith\s*\(", "Confidentiality"),
    ("data_return", r"self\.clients\.matchAll.*postMessage\s*\(", "Confidentiality"),

    # ── redirect_op ───────────────────────────────────────────────────────────
    ("redirect_op", r"res\.redirect\s*\(", "Web"),
    ("redirect_op", r"location\.href\s*=", "Web"),
    ("redirect_op", r"location\.replace\s*\(", "Web"),
    ("redirect_op", r"location\.assign\s*\(", "Web"),
    ("redirect_op", r"window\.location\s*=", "Web"),
    ("redirect_op", r"window\.location\.href\s*=", "Web"),
    ("redirect_op", r"history\.pushState\s*\(", "Web"),
    ("redirect_op", r"history\.replaceState\s*\(", "Web"),
    ("redirect_op", r"ctx\.redirect\s*\(", "Web"),
    ("redirect_op", r"reply\.redirect\s*\(", "Web"),
    ("redirect_op", r"response\.redirect\s*\(", "Web"),
    ("redirect_op", r"return\s+NextResponse\.redirect\s*\(", "Web"),

    # ── cookie_op ─────────────────────────────────────────────────────────────
    ("cookie_op", r"res\.cookie\s*\(", "Web"),
    ("cookie_op", r"res\.clearCookie\s*\(", "Web"),
    ("cookie_op", r"document\.cookie\s*=", "Web"),
    ("cookie_op", r"document\.cookie\b", "Web"),
    ("cookie_op", r"req\.cookies\b", "Web"),
    ("cookie_op", r"Cookies\.set\s*\(|cookies\.set\s*\(", "Web"),
    ("cookie_op", r"cookie\.serialize\s*\(", "Web"),
    ("cookie_op", r"setCookie\s*\(", "Web"),
    ("cookie_op", r"ctx\.cookies\.set\s*\(", "Web"),
    ("cookie_op", r"reply\.setCookie\s*\(", "Web"),
    ("cookie_op", r"\bcookieParser\s*\(", "Web"),
    ("cookie_op", r"nookies\.set\s*\(", "Web"),
    ("cookie_op", r"cookies\.get\s*\(|cookies\.remove\s*\(", "Web"),
    ("cookie_op", r"js-cookie.*Cookies\.set\s*\(", "Web"),

    # ── template_render ───────────────────────────────────────────────────────
    ("template_render", r"res\.render\s*\(", "Dynamic code"),
    ("template_render", r"ejs\.render\s*\(", "Dynamic code"),
    ("template_render", r"ejs\.renderFile\s*\(", "Dynamic code"),
    ("template_render", r"ejs\.compile\s*\(", "Dynamic code"),
    ("template_render", r"pug\.render\s*\(|pug\.renderFile\s*\(", "Dynamic code"),
    ("template_render", r"pug\.compile\s*\(", "Dynamic code"),
    ("template_render", r"handlebars\.compile\s*\(|Handlebars\.compile\s*\(", "Dynamic code"),
    ("template_render", r"Handlebars\.render\s*\(", "Dynamic code"),
    ("template_render", r"mustache\.render\s*\(|Mustache\.render\s*\(", "Dynamic code"),
    ("template_render", r"nunjucks\.render\s*\(|nunjucks\.renderString\s*\(", "Dynamic code"),
    ("template_render", r"swig\.render\s*\(|swig\.renderFile\s*\(", "Dynamic code"),
    ("template_render", r"doT\.template\s*\(|dot\.template\s*\(", "Dynamic code"),
    ("template_render", r"liquid\.parseAndRender\s*\(", "Dynamic code"),
    ("template_render", r"new\s+Template\s*\(\s*\w", "Dynamic code"),

    # ── proto_op ──────────────────────────────────────────────────────────────
    ("proto_op", r"Object\.assign\s*\(\s*\w[\w.$]*\s*,\s*req\.", "Type-related"),
    ("proto_op", r"Object\.assign\s*\(\s*\w[\w.$]*\s*,\s*body\b", "Type-related"),
    ("proto_op", r"Object\.assign\s*\(\s*\w[\w.$]*\s*,\s*req\.body", "Type-related"),
    ("proto_op", r"_\.merge\s*\(", "Type-related"),
    ("proto_op", r"_\.extend\s*\(", "Type-related"),
    ("proto_op", r"_\.defaults\s*\(", "Type-related"),
    ("proto_op", r"\bdeepmerge\s*\(", "Type-related"),
    ("proto_op", r"\{\.{3}req\.body\b", "Type-related"),
    ("proto_op", r"\{\.{3}req\.query\b", "Type-related"),
    ("proto_op", r"\{\.{3}req\.params\b", "Type-related"),
    ("proto_op", r"\{\.{3}body\b", "Type-related"),
    ("proto_op", r"hoek\.merge\s*\(|hoek\.applyToDefaults\s*\(", "Type-related"),
    ("proto_op", r"jQuery\.extend\s*\(\s*true\s*,", "Type-related"),
    ("proto_op", r"config\.merge\s*\(\s*\w[\w.$]*", "Type-related"),

    # ── regex_op ──────────────────────────────────────────────────────────────
    ("regex_op", r"new\s+RegExp\s*\(\s*\w[\w.$]*\s*\)", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*req\.", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*body\.", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*params\.", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*query\.", "Denial of Service"),
    ("regex_op", r"RegExp\s*\(\s*\w[\w.$]*\s*\)", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*\w[\w.$]*\s*\+", "Denial of Service"),
    ("regex_op", r"eval\s*\(\s*'/'\s*\+\s*\w[\w.$]*", "Denial of Service"),
    ("regex_op", r"filter\s*\(\s*re\s*=>\s*re\.test\s*\(", "Denial of Service"),
    ("regex_op", r"new\s+RegExp\s*\(\s*userInput", "Denial of Service"),

    # ── path_join ─────────────────────────────────────────────────────────────
    ("path_join", r"path\.join\s*\(", "Path-related"),
    ("path_join", r"path\.resolve\s*\(\s*\w[\w.$]*\s*,", "Path-related"),
    ("path_join", r"path\.normalize\s*\(\s*\w[\w.$]*\s*\)", "Path-related"),
    ("path_join", r"__dirname\s*\+\s*['\"/]", "Path-related"),
    ("path_join", r"__dirname\s*\+\s*\w[\w.$]*", "Path-related"),
    ("path_join", r"join\s*\(\s*__dirname\s*,", "Path-related"),
    ("path_join", r"url\.resolve\s*\(", "Path-related"),
    ("path_join", r"resolve\s*\(\s*process\.cwd\s*\(\s*\)", "Path-related"),
    ("path_join", r"baseDir\s*\+\s*['\"/].*\+\s*\w[\w.$]*", "Path-related"),
    ("path_join", r"path\.join\s*\(\s*__dirname\s*,\s*\w[\w.$]*", "Path-related"),

    # ── env_write ─────────────────────────────────────────────────────────────
    ("env_write", r"process\.env\s*\[.*\]\s*=", "Privileges"),
    ("env_write", r"process\.env\.\w+\s*=", "Privileges"),
    ("env_write", r"Object\.assign\s*\(\s*process\.env", "Privileges"),
    ("env_write", r"dotenv\.config\s*\(\s*\{.*path\s*:", "Privileges"),
    ("env_write", r"process\.env\s*=\s*\{", "Privileges"),
    ("env_write", r"_\.extend\s*\(\s*process\.env", "Privileges"),
    ("env_write", r"config\.set\s*\(\s*['\"]env", "Privileges"),
    ("env_write", r"overrideEnv\s*\(", "Privileges"),
    ("env_write", r"\bsetenv\s*\(", "Privileges"),
    ("env_write", r"crossEnv\s*\(", "Privileges"),

    # ── socket_op ─────────────────────────────────────────────────────────────
    ("socket_op", r"io\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"socket\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"io\.to\s*\([^)]*\)\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"io\.in\s*\([^)]*\)\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"socket\.broadcast\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"io\.sockets\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"ws\.send\s*\(", "Confidentiality"),
    ("socket_op", r"wss\.clients\.forEach", "Confidentiality"),
    ("socket_op", r"new\s+WebSocket\s*\(", "Confidentiality"),
    ("socket_op", r"net\.createServer\s*\(|net\.connect\s*\(", "Confidentiality"),
    ("socket_op", r"dgram\.createSocket\s*\(|udp\.send\s*\(", "Confidentiality"),
    ("socket_op", r"socket\.join\s*\(", "Confidentiality"),
    ("socket_op", r"io\.of\s*\([^)]*\)\.emit\s*\(", "Confidentiality"),
    ("socket_op", r"res\.write\s*\(\s*`data:\s*\$\{", "Confidentiality"),

    # ── xml_parse ─────────────────────────────────────────────────────────────
    ("xml_parse", r"xml2js\.parseString\s*\(", "Input validation"),
    ("xml_parse", r"xml2js\.parseStringPromise\s*\(", "Input validation"),
    ("xml_parse", r"new\s+DOMParser\s*\(\s*\)\.parseFromString\s*\(", "Input validation"),
    ("xml_parse", r"libxmljs\.parseXml\s*\(|libxmljs\.parseXmlString\s*\(", "Input validation"),
    ("xml_parse", r"new\s+XMLParser\s*\(", "Input validation"),
    ("xml_parse", r"sax\.parser\s*\(|sax\.createStream\s*\(", "Input validation"),
    ("xml_parse", r"xmldoc\.XmlDocument\s*\(", "Input validation"),
    ("xml_parse", r"expat\.createParser\s*\(", "Input validation"),
    ("xml_parse", r"parseXML\s*\(|parseXml\s*\(", "Input validation"),
    ("xml_parse", r"xlsx\.read\s*\(", "Input validation"),
    ("xml_parse", r"new\s+ActiveXObject\s*\(\s*['\"]Microsoft\.XMLDOM['\"]", "Input validation"),
    ("xml_parse", r"saxes.*parse\s*\(", "Input validation"),

    # ── jwt_op ────────────────────────────────────────────────────────────────
    ("jwt_op", r"jwt\.sign\s*\(", "Authentication"),
    ("jwt_op", r"jsonwebtoken\.sign\s*\(", "Authentication"),
    ("jwt_op", r"jwt\.decode\s*\(", "Authentication"),
    ("jwt_op", r"jsonwebtoken\.decode\s*\(", "Authentication"),
    ("jwt_op", r"new\s+SignJWT\s*\(", "Authentication"),
    ("jwt_op", r"jose\.SignJWT\s*\(", "Authentication"),
    ("jwt_op", r"jose\.EncryptJWT\s*\(", "Authentication"),
    ("jwt_op", r"njwt\.create\s*\(", "Authentication"),
    ("jwt_op", r"jwt\.sign\s*\([^,]+,\s*['\"][^'\"]{1,20}['\"]", "Authentication"),
    ("jwt_op", r"jwt\.sign\s*\([^,]+,[^,]+,\s*\{[^}]*algorithm\s*:\s*['\"]none['\"]", "Authentication"),
    ("jwt_op", r"jws\.sign\s*\(", "Authentication"),
    ("jwt_op", r"jws\.decode\s*\(", "Authentication"),

    # ── crypto_op ─────────────────────────────────────────────────────────────
    ("crypto_op", r"Math\.random\s*\(", "Numeric errors"),
    ("crypto_op", r"crypto\.createHash\s*\(\s*['\"]md5['\"]", "Numeric errors"),
    ("crypto_op", r"crypto\.createHash\s*\(\s*['\"]sha1['\"]", "Numeric errors"),
    ("crypto_op", r"crypto\.createCipher\s*\(", "Numeric errors"),
    ("crypto_op", r"crypto\.pseudoRandomBytes\s*\(", "Numeric errors"),
    ("crypto_op", r"bcrypt.*saltRounds\s*[<]=?\s*9", "Numeric errors"),
    ("crypto_op", r"\bmd5\s*\(|\bsha1\s*\(", "Numeric errors"),
    ("crypto_op", r"crypto\.createHmac\s*\(\s*['\"]md5['\"]", "Numeric errors"),
    ("crypto_op", r"\buuid\s*\(\s*\)", "Numeric errors"),
    ("crypto_op", r"shortid\.generate\s*\(", "Numeric errors"),
    ("crypto_op", r"Math\.floor\s*\(\s*Math\.random\s*\(\s*\)\s*\*", "Numeric errors"),
    ("crypto_op", r"CryptoJS\.MD5\s*\(|CryptoJS\.SHA1\s*\(", "Numeric errors"),
    ("crypto_op", r"new\s+Hashes\.MD5\s*\(", "Numeric errors"),
    ("crypto_op", r"des\.encrypt\s*\(|rc4\.encrypt\s*\(", "Numeric errors"),

    # ── storage_op ────────────────────────────────────────────────────────────
    ("storage_op", r"localStorage\.setItem\s*\(", "Confidentiality"),
    ("storage_op", r"localStorage\.getItem\s*\(", "Confidentiality"),
    ("storage_op", r"sessionStorage\.setItem\s*\(", "Confidentiality"),
    ("storage_op", r"sessionStorage\.getItem\s*\(", "Confidentiality"),
    ("storage_op", r"localStorage\s*\[.*\]\s*=", "Confidentiality"),
    ("storage_op", r"sessionStorage\s*\[.*\]\s*=", "Confidentiality"),
    ("storage_op", r"window\.localStorage\b", "Confidentiality"),
    ("storage_op", r"window\.sessionStorage\b", "Confidentiality"),
    ("storage_op", r"IDBObjectStore\.(?:add|put)\s*\(", "Confidentiality"),
    ("storage_op", r"localForage\.setItem\s*\(", "Confidentiality"),

    # ── postmessage_op ────────────────────────────────────────────────────────
    ("postmessage_op", r"window\.postMessage\s*\(", "Web"),
    ("postmessage_op", r"self\.postMessage\s*\(", "Web"),
    ("postmessage_op", r"e\.source\.postMessage\s*\(", "Web"),
    ("postmessage_op", r"addEventListener\s*\(\s*['\"]message['\"]", "Web"),
    ("postmessage_op", r"\bonmessage\s*=", "Web"),
    ("postmessage_op", r"MessageChannel.*port.*postMessage\s*\(", "Web"),
    ("postmessage_op", r"BroadcastChannel.*postMessage\s*\(", "Web"),
    ("postmessage_op", r"\bevent\.data\b", "Web"),

    # ── url_construct ─────────────────────────────────────────────────────────
    ("url_construct", r"new\s+URL\s*\(\s*\w[\w.$]*\s*\)", "Web"),
    ("url_construct", r"new\s+URL\s*\(\s*req\.", "Web"),
    ("url_construct", r"url\.parse\s*\(\s*\w[\w.$]*\s*\)", "Web"),
    ("url_construct", r"URL\.createObjectURL\s*\(", "Web"),
    ("url_construct", r"buildUrl\s*\(", "Web"),
    ("url_construct", r"urlJoin\s*\(", "Web"),
    ("url_construct", r"qs\.stringify\s*\(\s*\w[\w.$]*\s*\)\s*\+", "Web"),
    ("url_construct", r"location\.origin\s*\+\s*['\"/].*\+\s*\w[\w.$]*", "Web"),
    ("url_construct", r"`\$\{.*\}/\$\{", "Web"),
    ("url_construct", r"new\s+URL\s*\(\s*req\.query\.", "Web"),

    # ── log_op ────────────────────────────────────────────────────────────────
    ("log_op", r"console\.log\s*\(", "Confidentiality"),
    ("log_op", r"console\.error\s*\(", "Confidentiality"),
    ("log_op", r"console\.warn\s*\(", "Confidentiality"),
    ("log_op", r"console\.info\s*\(", "Confidentiality"),
    ("log_op", r"console\.debug\s*\(", "Confidentiality"),
    ("log_op", r"logger\.info\s*\(", "Confidentiality"),
    ("log_op", r"logger\.error\s*\(", "Confidentiality"),
    ("log_op", r"logger\.warn\s*\(", "Confidentiality"),
    ("log_op", r"logger\.debug\s*\(", "Confidentiality"),
    ("log_op", r"logger\.trace\s*\(", "Confidentiality"),
    ("log_op", r"winston\.\w+\s*\(", "Confidentiality"),
    ("log_op", r"bunyan\.\w+\s*\(", "Confidentiality"),
    ("log_op", r"pino\.\w+\s*\(", "Confidentiality"),
    ("log_op", r"\bmorgan\s*\(", "Confidentiality"),
    ("log_op", r"log4js\.getLogger\s*\(\s*\)\.\w+\s*\(", "Confidentiality"),
    ("log_op", r"Sentry\.captureException\s*\(", "Confidentiality"),

    # ── state_mutation ────────────────────────────────────────────────────────
    ("state_mutation", r"global\.\w+\s*=\s*\w", "Privileges"),
    ("state_mutation", r"process\.\w+\s*=\s*\w", "Privileges"),
    ("state_mutation", r"globalThis\.\w+\s*=\s*\w", "Privileges"),
    ("state_mutation", r"module\.exports\s*=\s*\w", "Privileges"),
    ("state_mutation", r"exports\.\w+\s*=\s*\w", "Privileges"),
    ("state_mutation", r"Object\.defineProperty\s*\(\s*global", "Privileges"),
    ("state_mutation", r"Reflect\.set\s*\(\s*global", "Privileges"),
    ("state_mutation", r"singleton\.\w+\s*=\s*\w", "Privileges"),
    ("state_mutation", r"app\.set\s*\(\s*\w[\w.$]*\s*,\s*\w[\w.$]*", "Privileges"),
    ("state_mutation", r"\{\.{3}globalState\s*,\s*\.{3}\w", "Privileges"),

    # ── ipc_op ────────────────────────────────────────────────────────────────
    ("ipc_op", r"process\.send\s*\(", "Confidentiality"),
    ("ipc_op", r"worker\.postMessage\s*\(", "Confidentiality"),
    ("ipc_op", r"parentPort\.postMessage\s*\(", "Confidentiality"),
    ("ipc_op", r"cluster\.workers\[.*\]\.send\s*\(", "Confidentiality"),
    ("ipc_op", r"new\s+Worker\s*\([^,)]*,\s*\{\s*workerData\s*:", "Confidentiality"),
    ("ipc_op", r"workerThread\.postMessage\s*\(", "Confidentiality"),
    ("ipc_op", r"Atomics\.store\s*\(", "Confidentiality"),
    ("ipc_op", r"child\.stdin\.write\s*\(", "Confidentiality"),
    ("ipc_op", r"ipc\.send\s*\(|ipc\.broadcast\s*\(", "Confidentiality"),
    ("ipc_op", r"MessagePort\.postMessage\s*\(", "Confidentiality"),

    # ── dom_op ────────────────────────────────────────────────────────────────
    ("dom_op", r"element\.style\.cssText\s*=", "Web"),
    ("dom_op", r"element\.dataset\.\w+\s*=", "Web"),
    ("dom_op", r"element\.setAttribute\s*\(\s*['\"]style['\"]", "Web"),
    ("dom_op", r"CSSStyleSheet.*insertRule\s*\(", "Web"),
    ("dom_op", r"document\.styleSheets.*addRule\s*\(", "Web"),
    ("dom_op", r"svgElement\.innerHTML\s*=", "Web"),
    ("dom_op", r"shadowRoot\.innerHTML\s*=", "Web"),
    ("dom_op", r"element\.srcdoc\s*=", "Web"),
    ("dom_op", r"element\.contentWindow\.document\.write\s*\(", "Web"),
    ("dom_op", r"element\.setAttribute\s*\(\s*['\"](?:data-[^'\"]+)['\"].*\$\{", "Web"),

    # ── graphql_op ────────────────────────────────────────────────────────────
    ("graphql_op", r"graphql\s*\(\s*schema\s*,\s*\w", "Input validation"),
    ("graphql_op", r"client\.query\s*\(\s*\{.*gql\s*`[^`]*\$\{", "Input validation"),
    ("graphql_op", r"execute\s*\(\s*schema\s*,\s*parse\s*\(", "Input validation"),
    ("graphql_op", r"buildSchema\s*\(\s*\w", "Input validation"),
    ("graphql_op", r"introspection\s*:\s*true", "Input validation"),
    ("graphql_op", r"gql\s*`[^`]*\$\{", "Input validation"),
    ("graphql_op", r"graphqlHTTP\s*\(\s*\{[^}]*graphiql\s*:\s*true", "Input validation"),
    ("graphql_op", r"apolloClient\.query\s*\(", "Input validation"),

    # ── nosql_exec ────────────────────────────────────────────────────────────
    # Mongoose / MongoDB model operations (match regardless of model variable name)
    ("nosql_exec", r"\.find\s*\(\s*\{", "Input validation"),
    ("nosql_exec", r"\.find\s*\(\s*\w[\w.$]*\s*[,)]", "Input validation"),
    ("nosql_exec", r"\.findOne\s*\(", "Input validation"),
    ("nosql_exec", r"\.findById\s*\(", "Input validation"),
    ("nosql_exec", r"\.findByIdAndUpdate\s*\(", "Input validation"),
    ("nosql_exec", r"\.findOneAndUpdate\s*\(", "Input validation"),
    ("nosql_exec", r"\.findOneAndDelete\s*\(|\.findOneAndRemove\s*\(", "Input validation"),
    ("nosql_exec", r"\.aggregate\s*\(", "Input validation"),
    ("nosql_exec", r"\.updateOne\s*\(", "Input validation"),
    ("nosql_exec", r"\.updateMany\s*\(", "Input validation"),
    ("nosql_exec", r"\.deleteOne\s*\(", "Input validation"),
    ("nosql_exec", r"\.deleteMany\s*\(", "Input validation"),
    ("nosql_exec", r"\.countDocuments\s*\(", "Input validation"),
    ("nosql_exec", r"\.distinct\s*\(", "Input validation"),
    ("nosql_exec", r"\.replaceOne\s*\(", "Input validation"),
    # Explicit collection/db calls
    ("nosql_exec", r"collection\.find\s*\(", "Input validation"),
    ("nosql_exec", r"db\.collection\s*\(", "Input validation"),
    # Query operators used as values (NoSQL injection indicator)
    ("nosql_exec", r"\$where\s*:\s*\w[\w.$]*", "Input validation"),
    ("nosql_exec", r"\$regex\s*:\s*\w[\w.$]*", "Input validation"),
    ("nosql_exec", r"Model\.\w+\s*\(\s*\{[^}]*\$[a-z]+\s*:", "Input validation"),
    # Redis, Elasticsearch, Firebase, DynamoDB, CouchDB
    ("nosql_exec", r"redis\.eval\s*\(|redis\.evalsha\s*\(", "Input validation"),
    ("nosql_exec", r"client\.search\s*\(\s*\{", "Input validation"),
    ("nosql_exec", r"couchdb\.find\s*\(|\.find\s*\(\s*\{.*selector", "Input validation"),
    ("nosql_exec", r"dynamodb\.(?:scan|query|getItem|putItem|updateItem|deleteItem)\s*\(", "Input validation"),
    ("nosql_exec", r"firestore\s*\(\s*\)\.\w+\s*\(\s*\w", "Input validation"),

    # ── ssrf_op ───────────────────────────────────────────────────────────────
    ("ssrf_op", r"fetch\s*\(\s*req\.(?:query|body|params)\.", "Confidentiality"),
    ("ssrf_op", r"axios\.get\s*\(\s*req\.(?:query|body|params)\.", "Confidentiality"),
    ("ssrf_op", r"axios\.post\s*\(\s*req\.(?:query|body|params)\.", "Confidentiality"),
    ("ssrf_op", r"http\.get\s*\(\s*\w[\w.$]*\s*\)", "Confidentiality"),
    ("ssrf_op", r"https\.request\s*\(\s*\{[^}]*host\s*:\s*req\.", "Confidentiality"),
    ("ssrf_op", r"got\s*\(\s*req\.(?:query|body|params)\.", "Confidentiality"),
    ("ssrf_op", r"dns\.lookup\s*\(\s*req\.", "Confidentiality"),
    ("ssrf_op", r"net\.createConnection\s*\(\s*\{[^}]*host\s*:\s*req\.", "Confidentiality"),

    # ── file_upload ───────────────────────────────────────────────────────────
    ("file_upload", r"multer\s*\(\s*\)\s*\.(?:single|array|fields)\s*\(", "Path-related"),
    ("file_upload", r"busboy.*on\s*\(\s*['\"]file['\"]", "Path-related"),
    ("file_upload", r"formidable.*IncomingForm\s*\(", "Path-related"),
    ("file_upload", r"upload\.fields\s*\(", "Path-related"),
    ("file_upload", r"move\s*\(\s*tmpFile\s*,\s*destination\s*\+", "Path-related"),
    ("file_upload", r"ftp\.put\s*\(|sftp\.put\s*\(", "Path-related"),
    ("file_upload", r"s3\.upload\s*\(\s*\{[^}]*Key\s*:\s*\w[\w.$]*", "Path-related"),
    ("file_upload", r"multer\s*\(\s*\{[^}]*storage\b", "Path-related"),
]


# ─────────────────────────────────────────────────────────────────────────────
# JsPlugin class
# ─────────────────────────────────────────────────────────────────────────────

class JsPlugin:
    """Language plugin for JavaScript and TypeScript."""

    language: str = "js"
    file_extensions: list[str] = [".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"]

    # Pre-compiled at class load time — shared across all instances
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

    # ── Protocol methods ──────────────────────────────────────────────────────

    def get_checkpoint_patterns(self) -> list[CheckpointPattern]:
        return self._checkpoint_patterns

    def get_operation_patterns(self) -> list[OperationPattern]:
        return self._operation_patterns

    def get_ffi_patterns(self) -> list[str]:
        return FFI_PATTERNS

    def get_sanitizer_names(self) -> list[str]:
        return SANITIZER_NAMES

    def preferred_backend(self) -> str:
        return "treesitter"

    def is_public_function(self, fn_name: str, context: dict) -> bool:
        """Return True if function should be treated as a public API entry point.

        context keys:
          is_exported (bool)      — has 'export' keyword
          module_exports (bool)   — assigned to module.exports or exports.X
          is_route_handler (bool) — passed to app.get/post/... or router.*
        """
        if fn_name.startswith(("_", "#")):
            return False
        if (context.get("is_exported")
                or context.get("module_exports")
                or context.get("is_route_handler")):
            return True
        PUBLIC_PREFIXES = (
            "handle", "on", "get", "post", "put", "delete", "patch",
            "create", "update", "remove", "process", "render", "fetch",
            "load", "save", "send", "validate", "authorize",
        )
        return fn_name.startswith(PUBLIC_PREFIXES)

    def extract_imports(self, source: str) -> dict[str, str]:
        """Parse import/require statements → alias: qualified_name map."""
        imports: dict[str, str] = {}

        # ES6 default import: import fs from 'fs'
        for m in re.finditer(
            r"import\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]", source
        ):
            imports[m.group(1)] = m.group(2)

        # ES6 named import: import { exec, spawn as sp } from 'child_process'
        for m in re.finditer(
            r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]", source
        ):
            module = m.group(2)
            for spec in m.group(1).split(","):
                spec = spec.strip()
                if " as " in spec:
                    orig, alias = [s.strip() for s in spec.split(" as ")]
                    imports[alias] = f"{module}.{orig}"
                elif spec:
                    imports[spec] = f"{module}.{spec}"

        # ES6 namespace import: import * as yaml from 'js-yaml'
        for m in re.finditer(
            r"import\s*\*\s*as\s+(\w+)\s+from\s+['\"]([^'\"]+)['\"]", source
        ):
            imports[m.group(1)] = m.group(2)

        # CommonJS: const fs = require('fs')
        for m in re.finditer(
            r"(?:const|let|var)\s+(\w+)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            source,
        ):
            imports[m.group(1)] = m.group(2)

        # CommonJS destructured: const { exec, spawn } = require('child_process')
        for m in re.finditer(
            r"(?:const|let|var)\s*\{([^}]+)\}\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
            source,
        ):
            module = m.group(2)
            for spec in m.group(1).split(","):
                spec = spec.strip()
                if ":" in spec:
                    orig, alias = [s.strip() for s in spec.split(":")]
                    imports[alias] = f"{module}.{orig}"
                elif spec:
                    imports[spec] = f"{module}.{spec}"

        return imports

    # ── Pattern matching helpers (used by call_graph_js.py) ──────────────────

    def match_checkpoints(self, line: str) -> list[tuple[str, str]]:
        """Return [(type, matched_text), ...] for all checkpoint matches on line."""
        results = []
        for cp_type, pattern in self._compiled_checkpoints:
            if pattern.search(line):
                results.append((cp_type, line))
        return results

    def match_operations(self, line: str) -> list[tuple[str, str, str]]:
        """Return [(type, matched_text, cwe_class), ...] for all operation matches."""
        results = []
        for op_type, pattern, cwe_class in self._compiled_operations:
            if pattern.search(line):
                results.append((op_type, line, cwe_class))
        return results
