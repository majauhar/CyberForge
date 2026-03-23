"""Python language plugin — comprehensive checkpoint and operation pattern catalogs.

Patterns are intentionally handcrafted and cover broad Python security primitives,
not framework-specific idioms. The same patterns work on Flask, numpy, Django,
asyncio code, etc.

Each pattern tuple is (type_label, raw_regex_string) for checkpoints,
and (type_label, raw_regex_string, cwe_class_label) for operations.
"""

from __future__ import annotations
import re
import ast as pyast
from selector.static_analysis.models import CheckpointPattern, OperationPattern


# ─────────────────────────────────────────────────────────────────────────────
# CHECKPOINT PATTERNS
# Regex is matched against individual source lines (stripped of leading whitespace)
# ─────────────────────────────────────────────────────────────────────────────

_RAW_CHECKPOINT_PATTERNS: list[tuple[str, str]] = [

    # ── null / None checks ────────────────────────────────────────────────────
    ("null_check",      r"if\s+\w[\w.]*\s+is\s+None"),
    ("null_check",      r"if\s+\w[\w.]*\s*==\s*None"),
    ("null_check",      r"if\s+not\s+\w[\w.]*\s*(?::|#|$|and\s|or\s)"),
    ("null_check",      r"if\s+\w[\w.]*\s+is\s+not\s+None"),
    ("null_check",      r"if\s+\w[\w.]*\s*!=\s*None"),

    # ── type checks ───────────────────────────────────────────────────────────
    ("type_check",      r"\bisinstance\s*\("),
    ("type_check",      r"\btype\s*\(\s*\w[\w.]*\s*\)\s*(?:is\b|==|!=|in\b)"),
    ("type_check",      r"\bhasattr\s*\("),
    ("type_check",      r"\bcallable\s*\("),
    ("type_check",      r"assert\s+isinstance\s*\("),
    ("type_check",      r"\.dtype\s*(?:==|!=|in|not\s+in)\s"),
    ("type_check",      r"if\s+\w[\w.]*\s+not\s+in\s+\["),           # allowlist
    ("type_check",      r"if\s+\w[\w.]*\s+in\s+(?:ALLOWED|VALID|TYPES|WHITELIST)"),

    # ── bounds / size checks ──────────────────────────────────────────────────
    ("bounds_check",    r"if\s+\w[\w.]*\s*[<>]=?\s*\d+"),
    ("bounds_check",    r"if\s+len\s*\("),
    ("bounds_check",    r"if\s+\w[\w.]*\s*[<>]=?\s*\w[\w.]*"),
    ("bounds_check",    r"if\s+\w[\w.]*\s+(?:in\s+range|not\s+in\s+range)\s*\("),
    ("bounds_check",    r"if\s+\d+\s*<=\s*\w[\w.]*\s*<=\s*\d+"),
    ("bounds_check",    r"if\s+\w[\w.]*\s*%\s*\d+\s*==\s*0"),
    ("bounds_check",    r"if\s+\w[\w.]*\s*(?:>=|<=)\s*(?:MIN|MAX|LIMIT|SIZE|LEN|CAP)_?\w*"),

    # ── auth / access control guards ─────────────────────────────────────────
    ("auth_guard",      r"if\s+not\s+\w*(?:auth|permission|admin|role|access|allowed|authorized|can_)\w*"),
    ("auth_guard",      r"(?:require_auth|login_required|permission_required|authenticate|check_permission|verify_token)\s*\("),
    ("auth_guard",      r"@\s*(?:login_required|require_permission|requires_auth|authorized|permission_required|roles_required|jwt_required)"),
    ("auth_guard",      r"if\s+\w*user\w*\s+(?:is|==)\s+None"),
    ("auth_guard",      r"if\s+not\s+(?:request\.)?user\.is_authenticated"),
    ("auth_guard",      r"if\s+\w*(?:token|api_key|secret|bearer)\w*\s*(?:is\s*None|==\s*None|not\s+in\b)"),
    ("auth_guard",      r"abort\s*\(\s*(?:401|403)\s*\)"),
    ("auth_guard",      r"raise\s+\w*(?:Unauthorized|Forbidden|PermissionDenied|AuthenticationError)\w*"),
    ("auth_guard",      r"if\s+not\s+\w+\.has_(?:perm|permission|role|access)\s*\("),
    ("auth_guard",      r"if\s+current_user\.(?:is_anonymous|role\s*!=|is_admin)"),
    ("auth_guard",      r"g\.user\s+is\s+None"),

    # ── assertions ────────────────────────────────────────────────────────────
    ("assert",          r"^\s*assert\s+"),

    # ── error / return-value / status checks ─────────────────────────────────
    ("error_check",     r"if\s+\w*(?:err|error|errno|ret(?:val)?|status|rc|code|result)\w*\s*(?:[!<>=]=?\s*(?:None|0|False|-1|True)|is\s+(?:None|not\s+None))"),
    ("error_check",     r"if\s+not\s+\w*(?:ok|success|valid|result|status|response)\w*"),
    ("error_check",     r"if\s+\w[\w.]*\s*[!=]=\s*-1\b"),
    ("error_check",     r"if\s+\w[\w.]*\s*<\s*0\b"),
    ("error_check",     r"if\s+\w[\w.]*\s*!=\s*0\b"),
    ("error_check",     r"\btry\s*:"),
    ("error_check",     r"\bexcept\s+\w*(?:Error|Exception|Failure|Warning)\w*"),
    ("error_check",     r"if\s+response\.status_code\s*[!=]="),
    ("error_check",     r"if\s+\w[\w.]*\.returncode\s*[!=]="),

    # ── shape / tensor checks (numpy, TF, PyTorch, JAX) ──────────────────────
    ("shape_check",     r"if\s+\w[\w.]*\.shape"),
    ("shape_check",     r"if\s+\w[\w.]*\.ndim"),
    ("shape_check",     r"tf\.(?:debugging|ensure_shape|assert_)\w*\s*\("),
    ("shape_check",     r"torch\.(?:testing\.|is_tensor|is_floating_point)\s*\("),
    ("shape_check",     r"np\.testing\.\w+\s*\("),
    ("shape_check",     r"assert\s+\w[\w.]*\.shape\s*=="),
    ("shape_check",     r"if\s+\w[\w.]*\.size\s*(?:[=!<>]=?\s*\d+)"),
    ("shape_check",     r"if\s+\w[\w.]*\.dtype\s*not\s+in"),
    ("shape_check",     r"\.check_shape\s*\(|\.assert_shape\s*\("),

    # ── format / schema / regex validation ────────────────────────────────────
    ("format_check",    r"re\.(?:match|fullmatch|search|compile)\s*\("),
    ("format_check",    r"\w[\w.]*\.(?:match|fullmatch)\s*\("),
    ("format_check",    r"\.validate\s*\(|\.is_valid\s*\(\)|\.is_valid\s*\("),
    ("format_check",    r"jsonschema\.validate\s*\("),
    ("format_check",    r"(?:cerberus|marshmallow|pydantic|voluptuous|schema)\.\w+"),
    ("format_check",    r"if\s+\w[\w.]*\.startswith\s*\("),
    ("format_check",    r"if\s+\w[\w.]*\.endswith\s*\("),
    ("format_check",    r"if\s+\w[\w.]*\s+not\s+in\s+(?:ALLOWED|WHITELIST|VALID|PERMITTED)"),
    ("format_check",    r"validators\.\w+\s*\("),
    ("format_check",    r"wtforms\.|WTForms\.|form\.validate"),

    # ── integer overflow / arithmetic safety checks ───────────────────────────
    ("overflow_check",  r"if\s+\w[\w.]*\s*\*\s*\w[\w.]*\s*(?:>|>=|//)\s*\w[\w.]*"),
    ("overflow_check",  r"if\s+\w[\w.]*\s*>\s*(?:sys\.maxsize|MAX_\w+|0x[0-9a-fA-F]+)"),
    ("overflow_check",  r"if\s+\w[\w.]*\s*\+\s*\w[\w.]*\s*(?:>|>=)\s*\w[\w.]*"),
    ("overflow_check",  r"struct\.calcsize\s*\(|array\.itemsize"),

    # ── cryptographic signature / HMAC / certificate verification ─────────────
    ("signature_check", r"hmac\.compare_digest\s*\("),
    ("signature_check", r"\.verify\s*\("),
    ("signature_check", r"(?:check|verify|validate)_(?:signature|hmac|token|mac|digest)\s*\("),
    ("signature_check", r"ssl\.(?:match_hostname|create_default_context|check_hostname)"),
    ("signature_check", r"cryptography\.hazmat\."),
    ("signature_check", r"nacl\.signing\.|nacl\.public\."),

    # ── lock / mutex / concurrency guards ─────────────────────────────────────
    ("lock_acquire",    r"with\s+\w*(?:lock|Lock|mutex|RLock|Semaphore|Condition)\w*"),
    ("lock_acquire",    r"\w*(?:lock|mutex)\w*\.acquire\s*\("),
    ("lock_acquire",    r"async\s+with\s+\w*(?:lock|Lock|mutex|Semaphore)\w*"),
    ("lock_acquire",    r"threading\.(?:Lock|RLock|Semaphore)\s*\("),
    ("lock_acquire",    r"asyncio\.(?:Lock|Semaphore|Event)\s*\("),
    ("lock_acquire",    r"multiprocessing\.(?:Lock|RLock|Semaphore)\s*\("),

    # ── ownership / resource capability checks ────────────────────────────────
    ("ownership_check", r"if\s+\w[\w.]*\.(?:owner|created_by|user|author)\s*!="),
    ("ownership_check", r"\.has_(?:perm|permission|access|right)\s*\("),
    ("ownership_check", r"if\s+\w[\w.]*\s+(?:is\s+not|!=)\s+(?:request\.|current_)user"),
    ("ownership_check", r"object_permission|get_object_or_404"),

    # ── rate-limit / quota / throttle guards ─────────────────────────────────
    ("rate_limit",      r"if\s+\w*(?:rate|limit|quota|throttle|burst)\w*\s*(?:[><=!])"),
    ("rate_limit",      r"(?:rate_limit|throttle|ratelimit|slowapi)\s*\("),
    ("rate_limit",      r"@\s*(?:rate_limit|throttle|ratelimit|limits\.shared)"),
    ("rate_limit",      r"redis.*(?:incr|expire).*limit"),

    # ── CSRF guards ───────────────────────────────────────────────────────────
    ("csrf_check",      r"csrf_token|csrfmiddlewaretoken|X-CSRFToken"),
    ("csrf_check",      r"(?:validate_csrf|check_csrf|verify_csrf|csrf_protect)\s*\("),
    ("csrf_check",      r"@\s*csrf_(?:protect|required|exempt)"),
    ("csrf_check",      r"CSRFTokenField|FlaskForm"),

    # ── input sanitization ────────────────────────────────────────────────────
    ("sanitize",        r"(?:sanitize|escape|bleach\.clean|html\.escape|markupsafe\.escape|cgi\.escape)\s*\("),
    ("sanitize",        r"(?:strip_tags|clean_html|safe_join|DOMPurify)\s*\("),
    ("sanitize",        r"\.strip\s*\(\s*\)\.|\.replace\s*\("),
    ("sanitize",        r"werkzeug\.security\."),
    ("sanitize",        r"django\.utils\.html\.(?:escape|strip_tags)"),

    # ── path traversal guards ─────────────────────────────────────────────────
    ("path_traversal_check", r"os\.path\.(?:abspath|realpath|normpath)\s*\("),
    ("path_traversal_check", r"werkzeug\.utils\.safe_join\s*\(|flask\.safe_join\s*\("),
    ("path_traversal_check", r"if\s+\w[\w.]*\.startswith\s*\(\s*(?:base|root|upload|media|static)"),
    ("path_traversal_check", r"if\s+\.\.\s+in\s+\w|if\s+['\"]\\.\\.['\"]\s+in"),
    ("path_traversal_check", r"pathlib\.Path\s*\(.*\)\.resolve\s*\("),
    ("path_traversal_check", r"if\s+not\s+\w[\w.]*\.is_relative_to\s*\("),
    ("path_traversal_check", r"urllib\.parse\.quote\s*\(|quote_plus\s*\("),

    # ── content-type / MIME-type / upload validation ──────────────────────────
    ("content_type_check", r"if\s+\w[\w.]*\.(?:content_type|mimetype|mime_type|content_disposition)\s*(?:[!=]=|not\s+in|in)"),
    ("content_type_check", r"mimetypes\.guess_type\s*\("),
    ("content_type_check", r"magic\.from_(?:buffer|file)\s*\("),
    ("content_type_check", r"if\s+\w[\w.]*\.split\s*\(\s*['\"]\\.['\"]"),    # extension check
    ("content_type_check", r"ALLOWED_EXTENSIONS|VALID_EXTENSIONS|PERMITTED_TYPES"),
    ("content_type_check", r"imghdr\.what\s*\(|filetype\.\w+\s*\("),

    # ── size / length limits ──────────────────────────────────────────────────
    ("size_check",      r"if\s+\w[\w.]*\.content_length\s*(?:[><!]=?|>)\s*\d"),
    ("size_check",      r"if\s+(?:len|sys\.getsizeof)\s*\(\s*\w[\w.]*\s*\)\s*(?:[><!]=?)\s*\d"),
    ("size_check",      r"MAX_(?:CONTENT|FILE|UPLOAD|PAYLOAD|BODY)_(?:LENGTH|SIZE)\b"),
    ("size_check",      r"if\s+\w[\w.]*\s*(?:>|>=)\s*\w*(?:MAX|LIMIT|CAP|THRESHOLD)\w*"),
    ("size_check",      r"request\.max_content_length\b"),

    # ── redirect validation ───────────────────────────────────────────────────
    ("redirect_check",  r"is_safe_url\s*\(|url_is_trusted\s*\(|safe_url_string\s*\("),
    ("redirect_check",  r"if\s+\w[\w.]*\.netloc\s*(?:!=|not\s+in)\s*\w"),
    ("redirect_check",  r"urllib\.parse\.urlparse\s*\("),
    ("redirect_check",  r"if\s+\w[\w.]*\.startswith\s*\(\s*(?:['\"]https?://['\"]|ALLOWED)"),
    ("redirect_check",  r"if\s+\w[\w.]*\s+not\s+in\s+ALLOWED_(?:HOSTS|URLS|DOMAINS|REDIRECTS)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# OPERATION PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

_RAW_OPERATION_PATTERNS: list[tuple[str, str, str]] = [

    # ── eval / dynamic code execution ─────────────────────────────────────────
    ("eval_exec",       r"\beval\s*\(",                                     "Dynamic code"),
    ("eval_exec",       r"\bexec\s*\(",                                     "Dynamic code"),
    ("eval_exec",       r"\bcompile\s*\(",                                  "Dynamic code"),
    ("eval_exec",       r"importlib\.import_module\s*\(",                   "Dynamic code"),
    ("eval_exec",       r"\b__import__\s*\(",                               "Dynamic code"),
    ("eval_exec",       r"runpy\.run_(?:module|path)\s*\(",                 "Dynamic code"),
    ("eval_exec",       r"code\.(?:InteractiveConsole|compile_command)",    "Dynamic code"),
    ("eval_exec",       r"types\.FunctionType\s*\(",                        "Dynamic code"),
    ("eval_exec",       r"ast\.literal_eval\s*\(",                          "Dynamic code"),  # safer but still input-driven

    # ── deserialization ───────────────────────────────────────────────────────
    ("deser",           r"pickle\.(?:loads?|load|Unpickler)\s*\(",          "Data structure"),
    ("deser",           r"yaml\.(?:load|unsafe_load|full_load)\s*\(",       "Data structure"),
    ("deser",           r"marshal\.loads?\s*\(",                            "Data structure"),
    ("deser",           r"shelve\.open\s*\(",                               "Data structure"),
    ("deser",           r"dill\.(?:loads?|load)\s*\(",                      "Data structure"),
    ("deser",           r"jsonpickle\.decode\s*\(",                         "Data structure"),
    ("deser",           r"xmlrpc\.client\.\w+\s*\(",                        "Data structure"),
    ("deser",           r"cattrs\.structure\s*\(",                          "Data structure"),
    ("deser",           r"joblib\.load\s*\(",                               "Data structure"),
    ("deser",           r"cloudpickle\.loads?\s*\(",                        "Data structure"),

    # ── file / path operations ────────────────────────────────────────────────
    ("file_op",         r"\bopen\s*\(",                                     "Path-related"),
    ("file_op",         r"os\.(?:open|fdopen|remove|rename|unlink|symlink|link|chmod|chown|makedirs|mkdir)\s*\(", "Path-related"),
    ("file_op",         r"shutil\.(?:copy2?|move|rmtree|copyfile|copytree|disk_usage)\s*\(", "Path-related"),
    ("file_op",         r"send_file\s*\(",                                  "Path-related"),
    ("file_op",         r"send_from_directory\s*\(",                        "Path-related"),
    ("file_op",         r"pathlib\.Path\s*\(",                              "Path-related"),
    ("file_op",         r"io\.(?:open|FileIO|BufferedReader|BufferedWriter)\s*\(", "Path-related"),
    ("file_op",         r"tarfile\.(?:open|TarFile)\s*\(",                  "Path-related"),  # zip-slip risk
    ("file_op",         r"zipfile\.ZipFile\s*\(",                           "Path-related"),
    ("file_op",         r"gzip\.open\s*\(",                                 "Path-related"),
    ("file_op",         r"\.read_(?:csv|json|parquet|excel|table)\s*\(",    "Path-related"),  # pandas

    # ── subprocess / OS command injection ─────────────────────────────────────
    ("subprocess",      r"subprocess\.(?:Popen|run|call|check_output|check_call|getoutput|getstatusoutput)\s*\(", "Dynamic code"),
    ("subprocess",      r"os\.(?:system|popen|execv[pe]?|execl[pe]?|spawnl[pe]?|spawnv[pe]?)\s*\(", "Dynamic code"),
    ("subprocess",      r"\bPopen\s*\(",                                    "Dynamic code"),
    ("subprocess",      r"commands\.(?:getoutput|getstatusoutput)\s*\(",    "Dynamic code"),
    ("subprocess",      r"pty\.(?:spawn|openpty)\s*\(",                     "Dynamic code"),
    ("subprocess",      r"fabric\.\w+\.run\s*\(",                           "Dynamic code"),
    ("subprocess",      r"invoke\.run\s*\(",                                "Dynamic code"),
    ("subprocess",      r"sh\.\w+\s*\(",                                    "Dynamic code"),  # sh library

    # ── data returned to caller ───────────────────────────────────────────────
    ("data_return",     r"\breturn\s+\w",                                   "Confidentiality"),
    ("data_return",     r"jsonify\s*\(",                                    "Confidentiality"),
    ("data_return",     r"render(?:_template)?\s*\(",                       "Confidentiality"),
    ("data_return",     r"(?:make_)?Response\s*\(",                         "Confidentiality"),
    ("data_return",     r"HttpResponse\s*\(",                               "Confidentiality"),
    ("data_return",     r"JsonResponse\s*\(",                               "Confidentiality"),
    ("data_return",     r"redirect\s*\(",                                   "Confidentiality"),  # open redirect
    ("data_return",     r"yield\s+\w",                                      "Confidentiality"),

    # ── state / object mutation ────────────────────────────────────────────────
    ("state_mutation",  r"\w[\w.]*\s*\[.+\]\s*=",                          "Encapsulation"),
    ("state_mutation",  r"self\.\w+\s*=",                                   "Encapsulation"),
    ("state_mutation",  r"\bsetattr\s*\(",                                  "Encapsulation"),
    ("state_mutation",  r"\bglobals\s*\(\s*\)\s*\[",                        "Encapsulation"),
    ("state_mutation",  r"\bvars\s*\(\s*\)\s*\[",                           "Encapsulation"),
    ("state_mutation",  r"object\.__setattr__\s*\(",                        "Encapsulation"),
    ("state_mutation",  r"\bapp\.config\[",                                 "Encapsulation"),
    ("state_mutation",  r"\bos\.environ\[",                                 "Encapsulation"),

    # ── memory view / type reinterpretation (numpy / ctypes / struct) ─────────
    ("memory_view",     r"\.view\s*\(",                                     "Type-related"),
    ("memory_view",     r"\.reshape\s*\(",                                  "Type-related"),
    ("memory_view",     r"\.as_strided\s*\(",                               "Type-related"),
    ("memory_view",     r"np\.frombuffer\s*\(",                             "Type-related"),
    ("memory_view",     r"np\.ndarray\s*\(",                                "Type-related"),
    ("memory_view",     r"ctypes\.cast\s*\(",                               "Type-related"),
    ("memory_view",     r"ctypes\.string_at\s*\(",                          "Type-related"),
    ("memory_view",     r"ctypes\.from_buffer\s*\(",                        "Type-related"),
    ("memory_view",     r"np\.lib\.stride_tricks\.\w+\s*\(",               "Type-related"),
    ("memory_view",     r"struct\.(?:unpack|pack|pack_into)\s*\(",          "Type-related"),

    # ── array / buffer indexing ────────────────────────────────────────────────
    ("array_index",     r"\w[\w.]*\[\s*\w[\w.]*\s*\]",                     "Ante buffer operation"),
    ("array_index",     r"\w[\w.]*\[\s*\w[\w.]*\s*:\s*\w[\w.]*\s*\]",     "Ante buffer operation"),
    ("array_index",     r"\w[\w.]*\[\s*\w[\w.]*\s*,\s*\w[\w.]*\s*\]",     "Ante buffer operation"),

    # ── memory allocation (Python equivalents) ────────────────────────────────
    ("alloc",           r"\bbytearray\s*\(",                                "Memory allocation"),
    ("alloc",           r"\bbytes\s*\(\s*\w[\w.]*\s*\)",                    "Memory allocation"),
    ("alloc",           r"\bmemoryview\s*\(",                               "Memory allocation"),
    ("alloc",           r"\barray\.array\s*\(",                             "Memory allocation"),
    ("alloc",           r"\(ctypes\.\w+\s*\*\s*\w[\w.]*\)\s*\(",           "Memory allocation"),
    ("alloc",           r"np\.(?:empty|zeros|ones|full|allocate)\s*\(",     "Memory allocation"),

    # ── SQL / database injection ───────────────────────────────────────────────
    ("sql_exec",        r"\.execute\s*\(\s*(?:f['\"]|['\"].*?\%|['\"].*?\+)", "Input validation"),
    ("sql_exec",        r"\.executemany\s*\(",                              "Input validation"),
    ("sql_exec",        r"\.raw\s*\(",                                      "Input validation"),
    ("sql_exec",        r"text\s*\(\s*f['\"]",                              "Input validation"),
    ("sql_exec",        r"cursor\.execute\s*\(",                            "Input validation"),
    ("sql_exec",        r"engine\.execute\s*\(",                            "Input validation"),
    ("sql_exec",        r"db\.session\.execute\s*\(",                       "Input validation"),

    # ── template rendering (Server-Side Template Injection) ───────────────────
    ("template_render", r"jinja2\.Environment\s*\(",                        "Dynamic code"),
    ("template_render", r"jinja2\.Template\s*\(",                           "Dynamic code"),
    ("template_render", r"\.from_string\s*\(",                              "Dynamic code"),
    ("template_render", r"mako\.template\.Template\s*\(",                   "Dynamic code"),
    ("template_render", r"string\.Template\s*\(\s*\w",                     "Dynamic code"),
    ("template_render", r"pystache\.render\s*\(",                           "Dynamic code"),
    ("template_render", r"chevron\.render\s*\(",                            "Dynamic code"),

    # ── HTTP requests (SSRF) ──────────────────────────────────────────────────
    ("http_request",    r"requests\.(?:get|post|put|delete|patch|head|request|Session)\s*\(", "Web"),
    ("http_request",    r"urllib\.request\.(?:urlopen|urlretrieve)\s*\(",   "Web"),
    ("http_request",    r"httpx\.(?:get|post|put|delete|patch|Client|AsyncClient)\s*\(", "Web"),
    ("http_request",    r"aiohttp\.(?:ClientSession|request)\s*\(",         "Web"),
    ("http_request",    r"urllib3\.PoolManager\s*\(",                       "Web"),

    # ── XML parsing (XXE) ─────────────────────────────────────────────────────
    ("xml_parse",       r"xml\.etree\.(?:ElementTree|cElementTree)\.(?:parse|fromstring|iterparse)\s*\(", "Web"),
    ("xml_parse",       r"lxml\.etree\.(?:parse|fromstring|iterparse)\s*\(", "Web"),
    ("xml_parse",       r"minidom\.(?:parse|parseString)\s*\(",             "Web"),
    ("xml_parse",       r"SAX\.parse\s*\(|expat\.ParserCreate\s*\(",        "Web"),
    ("xml_parse",       r"xmltodict\.parse\s*\(",                           "Web"),

    # ── log injection ─────────────────────────────────────────────────────────
    ("log_op",          r"logging\.(?:info|warning|warn|error|debug|critical|exception)\s*\(", "Input validation"),
    ("log_op",          r"logger\.(?:info|warning|warn|error|debug|critical|exception)\s*\(", "Input validation"),
    ("log_op",          r"print\s*\(",                                      "Input validation"),

    # ── weak cryptographic operations ─────────────────────────────────────────
    ("crypto_op",       r"hashlib\.(?:md5|sha1|sha)\s*\(",                  "Confidentiality"),
    ("crypto_op",       r"random\.(?:random|randint|choice|seed|uniform|shuffle|sample)\s*\(", "Confidentiality"),
    ("crypto_op",       r"Cipher\s*\(",                                     "Confidentiality"),
    ("crypto_op",       r"DES\.|RC4\.|ARC4\.",                              "Confidentiality"),
    ("crypto_op",       r"Crypto\.Cipher\.(?:DES|ARC4|Blowfish)\s*\.",      "Confidentiality"),

    # ── HTTP redirect (open redirect — CWE-601) ────────────────────────────────
    ("redirect_op",     r"\bredirect\s*\(",                                 "Web"),
    ("redirect_op",     r"HttpResponseRedirect\s*\(",                       "Web"),
    ("redirect_op",     r"return\s+redirect\s*\(",                          "Web"),
    ("redirect_op",     r"(?:location|Location)\s*=\s*\w",                  "Web"),
    ("redirect_op",     r"response\.headers\[.Location.\]\s*=",             "Web"),
    ("redirect_op",     r"flask\.redirect\s*\(|werkzeug.*redirect\s*\(",    "Web"),

    # ── HTTP response header manipulation (header injection — CWE-113) ─────────
    ("header_inject",   r"response\.(?:headers|set_cookie)\[",              "Web"),
    ("header_inject",   r"response\.headers\.(?:set|add|update)\s*\(",      "Web"),
    ("header_inject",   r"make_response\s*\(.*\)\.headers",                 "Web"),
    ("header_inject",   r"HttpResponse\s*\(.*\)\[.+\]\s*=",                 "Web"),
    ("header_inject",   r"set_cookie\s*\(",                                 "Web"),
    ("header_inject",   r"flask\.Response\s*\(",                            "Web"),

    # ── cookie operations (CWE-614, CWE-1004 — missing Secure/HttpOnly) ────────
    ("cookie_op",       r"set_cookie\s*\(",                                 "Web"),
    ("cookie_op",       r"response\.cookies\[",                             "Web"),
    ("cookie_op",       r"Cookie\s*:\s*\w|Set-Cookie\b",                    "Web"),
    ("cookie_op",       r"\.set_cookie\s*\(",                               "Web"),
    ("cookie_op",       r"SESSION_COOKIE_(?:SECURE|HTTPONLY|SAMESITE)\b",   "Web"),

    # ── regex execution on untrusted input (ReDoS — CWE-1333) ─────────────────
    ("regex_exec",      r"re\.(?:match|search|fullmatch|findall|finditer|sub|subn)\s*\(", "Denial of Service"),
    ("regex_exec",      r"re\.compile\s*\(",                                "Denial of Service"),
    ("regex_exec",      r"\w[\w.]*\.match\s*\(|\.search\s*\(|\.findall\s*\(", "Denial of Service"),

    # ── environment variable / config mutation ────────────────────────────────
    ("env_write",       r"os\.environ\[.+\]\s*=",                           "Encapsulation"),
    ("env_write",       r"os\.environ\.(?:update|setdefault)\s*\(",         "Encapsulation"),
    ("env_write",       r"os\.putenv\s*\(",                                 "Encapsulation"),
    ("env_write",       r"app\.config\.update\s*\(|app\.config\[.+\]\s*=", "Encapsulation"),
    ("env_write",       r"settings\.\w+\s*=",                               "Encapsulation"),

    # ── process / privilege operations ────────────────────────────────────────
    ("priv_op",         r"os\.(?:setuid|setgid|setgroups|setresuid|setresgid)\s*\(", "Privileges"),
    ("priv_op",         r"ctypes\.(?:windll|cdll)\.(?:kernel32|advapi32)\.", "Privileges"),
    ("priv_op",         r"win32api\.\w+|win32security\.\w+",                "Privileges"),
    ("priv_op",         r"subprocess\.run\s*\(.*shell\s*=\s*True",          "Privileges"),
    ("priv_op",         r"sudo\.|root\s*=\s*True",                          "Privileges"),

    # ── network socket / binding operations ───────────────────────────────────
    ("socket_op",       r"socket\.socket\s*\(",                             "Web"),
    ("socket_op",       r"\.bind\s*\(\s*\(",                                "Web"),
    ("socket_op",       r"\.connect\s*\(\s*\(",                             "Web"),
    ("socket_op",       r"asyncio\.open_(?:connection|server)\s*\(",        "Web"),
    ("socket_op",       r"paramiko\.\w+Client\s*\(",                        "Web"),

    # ── object / attribute reflection (CWE-470) ───────────────────────────────
    ("reflection_op",   r"\bgetattr\s*\(",                                  "Dynamic code"),
    ("reflection_op",   r"\bhasattr\s*\(.*,\s*\w",                         "Dynamic code"),
    ("reflection_op",   r"\bcallable\s*\(\s*getattr",                       "Dynamic code"),
    ("reflection_op",   r"getattr\s*\(\s*\w+\s*,\s*\w",                    "Dynamic code"),
]


# ─────────────────────────────────────────────────────────────────────────────
# GAP-FILL: Weak random, crypto, TOCTOU patterns
# ─────────────────────────────────────────────────────────────────────────────

WEAK_RANDOM = [
    "random.random", "random.randint", "random.choice", "random.seed",
    "random.uniform", "random.shuffle", "random.sample", "random.randrange",
    "random.getrandbits",
]

WEAK_ALGOS = [
    "MD5", "SHA1", "SHA-1", "DES", "RC4", "ECB", "ARC4", "Blowfish",
    "md5", "sha1", "des", "rc4",
]

SECURITY_CONTEXTS = [
    "token", "key", "nonce", "salt", "secret", "password", "passwd",
    "session", "csrf", "otp", "pin", "code", "auth", "credential",
    "cookie", "signing", "signature", "hmac", "iv", "seed",
]

TOCTOU_CHECK_OPS = [
    "os.path.exists", "os.path.isfile", "os.path.isdir", "os.path.islink",
    "os.access", "os.stat", "os.lstat", "pathlib.Path.exists",
    "pathlib.Path.is_file", "pathlib.Path.is_dir",
]

TOCTOU_USE_OPS = [
    "open(", "os.remove", "os.rename", "os.unlink", "os.rmdir",
    "shutil.", "os.chmod", "os.chown", "os.link", "os.symlink",
    "os.truncate", "pathlib.Path.open", "pathlib.Path.unlink",
]

LOCK_SIGNALS = [
    "with lock", "with Lock", "mutex", "Lock()", ".acquire()",
    "RLock()", "Semaphore(", "asyncio.Lock", "threading.Lock",
]

FFI_PATTERNS = [
    r"ctypes\.CDLL\s*\(",
    r"ctypes\.cdll\.",
    r"cffi\.",
    r"pybind11",
    r"cython",
    r"PyArg_ParseTuple",
    r"Py_BuildValue",
    r"\.pyx",
    r"ffi\.cdef\s*\(",
    r"CFUNCTYPE\s*\(",
]

SANITIZER_NAMES = [
    "escape", "sanitize", "clean", "bleach", "strip_tags",
    "html.escape", "markupsafe.escape", "quote", "quote_plus",
    "parameterize", "validate", "encode",
]

# Hardcoded credential detection
CREDENTIAL_VAR_NAMES = [
    "password", "passwd", "secret", "api_key", "apikey", "private_key",
    "access_token", "auth_token", "bearer_token", "client_secret",
    "db_password", "database_password", "encryption_key", "signing_key",
    "jwt_secret", "oauth_secret", "hmac_key", "master_key", "admin_password",
    "root_password", "token_secret", "private_token", "service_key",
]

HARDCODED_STRING_RE_PARTS = [
    r"(?:password|passwd|secret|api_key|apikey|token|private_key|client_secret)\s*=\s*['\"][\w\-+/=@#$%^&*!]{8,}['\"]",
    r"(?:SECRET_KEY|PASSWORD|PASSWD|AUTH_TOKEN|API_KEY|SIGNING_KEY|HMAC_KEY|MASTER_KEY)\s*=\s*['\"][\w\-+/=@#$%^&*!]{6,}['\"]",
]

# ReDoS: patterns with catastrophic backtracking risk
REDOS_RISK_RE_PARTS = [
    r"re\.\w+\s*\(\s*r?['\"].*\(.*\+.*\).*[+*]",           # nested quantifiers
    r"re\.\w+\s*\(\s*r?['\"].*\(.*\*.*\).*[+*]",
    r"re\.\w+\s*\(\s*r?['\"].+\|.+[+*]['\"]",               # alternation with quantifier
]

# Header injection source patterns — user-controlled values used in headers
HEADER_INJECT_SOURCES = [
    r"request\.(?:args|form|json|headers|cookies|data)\[",
    r"request\.(?:args|form|json|headers|cookies|data)\.get\s*\(",
    r"request\.values\[",
    r"flask\.request\.",
]


class PythonPlugin:
    """Python language plugin."""

    language: str = "python"
    file_extensions: list[str] = [".py"]

    # Pre-compile pattern objects once at class load
    _checkpoint_patterns: list[CheckpointPattern] = [
        CheckpointPattern(type=t, pattern=p) for t, p in _RAW_CHECKPOINT_PATTERNS
    ]
    _operation_patterns: list[OperationPattern] = [
        OperationPattern(type=t, pattern=p, cwe_class=c)
        for t, p, c in _RAW_OPERATION_PATTERNS
    ]

    # Pre-compile regexes for performance
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
        A Python function is considered public API if ANY of:
        - explicitly listed in __all__
        - name does not start with _
        - has a docstring (documented = intended for external use)
        - called in test files

        Note: module-level dunder __init__, __new__ etc. are excluded.
        """
        module_all: list[str] = context.get("module_all", [])
        has_docstring: bool = context.get("has_docstring", False)
        called_in_tests: bool = context.get("called_in_tests", False)

        if fn_name.startswith("__") and fn_name.endswith("__"):
            return fn_name in ("__init__", "__new__", "__call__", "__enter__", "__exit__")

        if fn_name in module_all:
            return True
        if not fn_name.startswith("_"):
            return True
        if has_docstring:
            return True
        if called_in_tests:
            return True
        return False

    def extract_imports(self, source: str) -> dict[str, str]:
        """Parse import statements. Returns alias → qualified_name mapping."""
        imports: dict[str, str] = {}
        try:
            tree = pyast.parse(source)
        except SyntaxError:
            return imports

        for node in pyast.walk(tree):
            if isinstance(node, pyast.Import):
                for alias in node.names:
                    alias_name = alias.asname if alias.asname else alias.name.split(".")[0]
                    imports[alias_name] = alias.name
            elif isinstance(node, pyast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    alias_name = alias.asname if alias.asname else alias.name
                    qualified = f"{module}.{alias.name}" if module else alias.name
                    imports[alias_name] = qualified

        return imports

    def preferred_backend(self) -> str:
        return "ast"

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
