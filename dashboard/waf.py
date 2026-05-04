import re
from collections import defaultdict
import time
from urllib.parse import unquote

login_attempts = defaultdict(list)

# ============================================================
# SQL INJECTION
# ============================================================
SQLI_PATTERNS = [
    # Klasik
    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
    r"union.*select",
    r"select.*from",
    r"insert.*into",
    r"drop.*table",
    r"delete.*from",
    r"update.*set",
    r"or\s+1\s*=\s*1",
    r"or\s+\'1\'\s*=\s*\'1\'",
    r"and\s+1\s*=\s*1",
    r"and\s+1\s*=\s*2",
    # Boolean based
    r"and\s+sleep\s*\(",
    r"waitfor\s+delay",
    r"benchmark\s*\(",
    # Error based
    r"extractvalue\s*\(",
    r"updatexml\s*\(",
    r"floor\s*\(rand",
    # Stacked queries
    r";\s*drop",
    r";\s*insert",
    r";\s*update",
    r";\s*delete",
    # Comment bypass
    r"/\*.*\*/",
    r"0x[0-9a-f]+",
    # Information schema
    r"information_schema",
    r"sys\.tables",
    r"pg_tables",
    # Time based
    r"sleep\s*\(\d+\)",
    r"pg_sleep",
]

# ============================================================
# XSS
# ============================================================
XSS_PATTERNS = [
    r"<script.*?>",
    r"</script>",
    r"javascript:",
    r"vbscript:",
    r"onerror\s*=",
    r"onload\s*=",
    r"onclick\s*=",
    r"onmouseover\s*=",
    r"onfocus\s*=",
    r"onblur\s*=",
    r"onkeypress\s*=",
    r"alert\s*\(",
    r"confirm\s*\(",
    r"prompt\s*\(",
    r"document\.cookie",
    r"document\.write",
    r"window\.location",
    r"eval\s*\(",
    r"expression\s*\(",
    r"<iframe.*?>",
    r"<img.*?onerror",
    r"<svg.*?onload",
    r"base64.*script",
    r"&#x",
    r"%3Cscript",
]

# ============================================================
# LFI / PATH TRAVERSAL
# ============================================================
LFI_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"%2e%2e%2f",
    r"%2e%2e/",
    r"\.\.%2f",
    r"%2e%2e%5c",
    r"/etc/passwd",
    r"/etc/shadow",
    r"/etc/hosts",
    r"/proc/self",
    r"boot\.ini",
    r"win\.ini",
    r"system32",
    r"c:\\windows",
    r"/var/log",
    r"php://filter",
    r"php://input",
    r"data://",
    r"expect://",
]

# ============================================================
# RCE - Remote Code Execution
# ============================================================
RCE_PATTERNS = [
    r";\s*ls\s",
    r";\s*cat\s",
    r";\s*id\s*;",
    r";\s*whoami",
    r";\s*uname",
    r";\s*pwd\s*;",
    r"\|\s*ls",
    r"\|\s*cat",
    r"\|\s*id",
    r"\|\s*whoami",
    r"`.*`",
    r"\$\(.*\)",
    r"system\s*\(",
    r"exec\s*\(",
    r"passthru\s*\(",
    r"shell_exec\s*\(",
    r"popen\s*\(",
    r"proc_open\s*\(",
    r"eval\s*\(",
    r"assert\s*\(",
    r"base64_decode\s*\(",
    r"cmd\.exe",
    r"/bin/bash",
    r"/bin/sh",
]

# ============================================================
# SSRF - Server Side Request Forgery
# ============================================================
SSRF_PATTERNS = [
    r"http://localhost",
    r"http://127\.0\.0\.1",
    r"http://0\.0\.0\.0",
    r"http://169\.254\.169\.254",  # AWS metadata
    r"http://192\.168\.",
    r"http://10\.",
    r"http://172\.(1[6-9]|2[0-9]|3[0-1])\.",
    r"file://",
    r"dict://",
    r"gopher://",
    r"ftp://.*@",
]

# ============================================================
# XXE - XML External Entity
# ============================================================
XXE_PATTERNS = [
    r"<!ENTITY",
    r"<!DOCTYPE.*\[",
    r"SYSTEM\s+\"file://",
    r"SYSTEM\s+\"http://",
    r"SYSTEM\s+'file://",
    r"PUBLIC\s+\"-//",
    r"%xxe;",
    r"&xxe;",
]

# ============================================================
# IDOR
# ============================================================
IDOR_PATTERNS = [
    r"/api/users/\d+",
    r"/api/orders/\d+",
    r"/api/accounts/\d+",
    r"/admin/",
    r"/administrator/",
    r"user_id=\d+",
    r"account_id=\d+",
    r"customer_id=\d+",
    r"file_id=\d+",
]

# ============================================================
# OPEN REDIRECT
# ============================================================
REDIRECT_PATTERNS = [
    r"redirect=http",
    r"url=http",
    r"next=http",
    r"goto=http",
    r"return=http",
    r"returnto=http",
    r"redirect_uri=http",
]

def check_pattern(payload, patterns):
    payload = unquote(payload).lower()
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True
    return False

def check_brute_force(src_ip, url):
    now = time.time()
    login_keywords = ["login", "signin", "auth", "wp-login", "admin", "password", "passwd"]
    is_login = any(kw in url.lower() for kw in login_keywords)
    if not is_login:
        return False, None
    login_attempts[src_ip].append(now)
    login_attempts[src_ip] = [t for t in login_attempts[src_ip] if now - t <= 10]
    if len(login_attempts[src_ip]) > 5:
        return True, "Brute Force"
    return False, None

def analyze_request(src_ip, method, url, headers, body=""):
    full_payload = f"{url} {body}"
    threats = []

    if check_pattern(full_payload, SQLI_PATTERNS):
        threats.append({"type": "SQL Injection", "score": 95, "payload": url[:100]})

    if check_pattern(full_payload, XSS_PATTERNS):
        threats.append({"type": "XSS", "score": 90, "payload": url[:100]})

    if check_pattern(full_payload, LFI_PATTERNS):
        threats.append({"type": "LFI", "score": 85, "payload": url[:100]})

    if check_pattern(full_payload, RCE_PATTERNS):
        threats.append({"type": "RCE", "score": 98, "payload": url[:100]})

    if check_pattern(full_payload, SSRF_PATTERNS):
        threats.append({"type": "SSRF", "score": 92, "payload": url[:100]})

    if check_pattern(full_payload, XXE_PATTERNS):
        threats.append({"type": "XXE", "score": 90, "payload": url[:100]})

    if check_pattern(full_payload, IDOR_PATTERNS):
        threats.append({"type": "IDOR", "score": 60, "payload": url[:100]})

    if check_pattern(full_payload, REDIRECT_PATTERNS):
        threats.append({"type": "Open Redirect", "score": 70, "payload": url[:100]})

    is_bf, bf_type = check_brute_force(src_ip, url)
    if is_bf:
        threats.append({"type": bf_type, "score": 85, "payload": url[:100]})

    return threats
