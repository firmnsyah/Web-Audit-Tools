"""
Web Vulnerability Audit — defensive recon for your own website.

Run modes (cumulative):
- DEFAULT: passive checks (headers, TLS, cookies, CORS, CSRF forms,
  admin panels, error disclosure, HTTP methods, host header, robots).
- --deep:  probe sensitive files, private keys, directory listings.
- --active: send canary payloads for XSS / SQLi / SSTI / LFI / Open-Redirect /
  SSRF / JSONP. USE ONLY ON SYSTEMS YOU OWN OR HAVE PERMISSION TO TEST.

Authentication: pass --cookie, --header, or --bearer to probe protected pages.
Filtering: --skip xss,sqli  / --only xss,sqli to limit checks by category.
Output: CSV (default) and JSON (--json path).

NOT auto-tested (require manual / specialized work):
  RCE   — active probes are too dangerous to run unattended.
  XXE   — needs custom XML endpoints with raw POST bodies.
  IDOR & Auth Bypass — need authenticated comparison across roles.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import importlib.util
import json
import logging
import re
import secrets
import sys
import time
from collections import Counter, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from pathlib import Path
from threading import Lock
from typing import Callable, List, Optional, Sequence
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

HAS_BS4 = importlib.util.find_spec("bs4") is not None

logger = logging.getLogger("audit")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 SecurityAudit/3.0"
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_TAG = {
    "critical": "CRIT",
    "high": "HIGH",
    "medium": "MED ",
    "low": "LOW ",
    "info": "INFO",
}

# All check IDs — used by --skip / --only filters
PASSIVE_CHECKS = {
    "tls", "headers", "cookies", "cors", "recon", "fingerprint",
    "csrf", "admin", "errors", "methods", "host",
}
DEEP_CHECKS = {"files", "keys", "wordpress", "dirs"}
ACTIVE_CHECKS = {"xss", "sqli", "ssti", "lfi", "cmdi", "traversal", "redirect", "ssrf", "jsonp"}
ALL_CHECKS = PASSIVE_CHECKS | DEEP_CHECKS | ACTIVE_CHECKS


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class Finding:
    severity: str
    category: str
    title: str
    detail: str
    recommendation: str
    url: str = ""
    evidence: str = ""  # short one-liner with payload + matched signature
    cwe: str = ""       # CWE reference, e.g. "CWE-79"


@dataclass
class InputPoint:
    """A discovered HTTP injection point — URL parameter or form field."""
    url: str
    method: str  # "GET" | "POST"
    params: dict
    fuzz_param: str
    source_page: str

    def signature(self) -> tuple:
        return (self.url, self.method, self.fuzz_param)


@dataclass
class Baseline:
    status: int = 0
    body_size: int = 0
    body_hash: str = ""
    content_type: str = ""
    title: str = ""
    samples: List[int] = field(default_factory=list)


# =============================================================================
# Scan context — shared state for HTTP budget, rate limiting, findings, filters
# =============================================================================

class ScanContext:
    def __init__(self, session: requests.Session, base_url: str, timeout: int,
                 delay: float, max_requests: int, threads: int,
                 skip: set, only: Optional[set]):
        self.session = session
        self.base_url = base_url
        self.timeout = timeout
        self.delay = delay
        self.max_requests = max_requests
        self.threads = threads
        self.skip = skip
        self.only = only  # if set, only these checks run
        self.request_count = 0
        self.findings: list[Finding] = []
        self._lock = Lock()

    def should_run(self, check_id: str) -> bool:
        if self.only is not None:
            return check_id in self.only
        return check_id not in self.skip

    def _budget_ok(self) -> bool:
        with self._lock:
            if self.request_count >= self.max_requests:
                return False
            self.request_count += 1
            return True

    def request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        if not self._budget_ok():
            logger.debug("Request budget exhausted at %d", self.max_requests)
            return None
        kwargs.setdefault("timeout", self.timeout)
        if self.delay > 0:
            time.sleep(self.delay)
        try:
            return self.session.request(method, url, **kwargs)
        except requests.RequestException as e:
            logger.debug("%s %s failed: %s", method, url, e)
            return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self.request("POST", url, **kwargs)

    def add(self, *findings: Finding) -> None:
        if not findings:
            return
        with self._lock:
            self.findings.extend(findings)


# =============================================================================
# Helpers
# =============================================================================

def _attr_str(el, name: str, default: str = "") -> str:
    """Coerce a BeautifulSoup tag attribute to str (handles list-valued attrs)."""
    val = el.get(name, default) if el is not None else default
    if val is None:
        return default
    if isinstance(val, list):
        return " ".join(str(v) for v in val) if val else default
    return str(val)


def _normalize_proxy(proxy: Optional[str]) -> Optional[str]:
    if proxy and "://" not in proxy:
        return f"http://{proxy}"
    return proxy


def build_session(cookies: list, headers: list, bearer: Optional[str],
                  proxy: Optional[str] = None) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    for h in headers:
        if ":" not in h:
            continue
        name, _, value = h.partition(":")
        s.headers[name.strip()] = value.strip()
    for c in cookies:
        if "=" not in c:
            continue
        name, _, value = c.partition("=")
        s.cookies.set(name.strip(), value.strip())
    if bearer:
        s.headers["Authorization"] = f"Bearer {bearer}"
    proxy = _normalize_proxy(proxy)
    if proxy:
        s.proxies.update({"http": proxy, "https": proxy})
    retry = Retry(
        total=2, backoff_factor=0.3,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET", "POST", "OPTIONS", "HEAD"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


def _hash_body(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")[:8192]).hexdigest()


def _extract_title(text: str) -> str:
    lower = text.lower()
    start = lower.find("<title>")
    if start == -1:
        return ""
    end = lower.find("</title>", start)
    if end == -1:
        return ""
    return text[start + 7:end].strip()[:200]


def _trim(s: str, n: int = 120) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n - 1] + "…"


# =============================================================================
# Payload loader — reads from payload/ directory, falls back to builtins
# =============================================================================

def _load_payload_file(path: Path) -> list[str]:
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return [l.strip() for l in f if l.strip() and not l.startswith("#")]
    except OSError:
        return []


def _load_payload_dir(rel: str, base: Path,
                      pick: Optional[list[str]] = None) -> list[str]:
    """Load all .txt/.fuzz files under base/rel, deduped, capped at 500."""
    d = base / rel
    if not d.is_dir():
        return []
    raw: list[str] = []
    for ext in ("*.txt", "*.fuzz"):
        for p in sorted(d.rglob(ext)):
            if pick and p.name not in pick:
                continue
            raw.extend(_load_payload_file(p))
    seen: set[str] = set()
    out: list[str] = []
    for line in raw:
        if line not in seen:
            seen.add(line)
            out.append(line)
    return out[:500]


def init_payloads(payload_base: Path) -> None:
    """Replace built-in payload lists with content from the payload/ directory."""
    global XSS_PAYLOADS, SQLI_PAYLOADS, LFI_PAYLOADS, CMDI_PAYLOADS, TRAVERSAL_PAYLOADS

    xss = _load_payload_dir("XSS Injection/Intruders", payload_base,
                             pick=["xss_payloads_quick.txt", "XSSDetection.txt",
                                   "XSS_Polyglots.txt", "JHADDIX_XSS.txt"])
    if xss:
        XSS_PAYLOADS = xss
        logger.debug("XSS payloads: %d loaded from files", len(XSS_PAYLOADS))

    sqli = _load_payload_dir("SQL Injection/Intruder", payload_base,
                              pick=["Generic_Fuzz.txt", "Generic_ErrorBased.txt",
                                    "SQLi_Polyglots.txt", "Auth_Bypass.txt"])
    if sqli:
        SQLI_PAYLOADS = sqli
        logger.debug("SQLi payloads: %d loaded from files", len(SQLI_PAYLOADS))

    lfi = _load_payload_dir("File Inclusion/Intruders", payload_base,
                             pick=["JHADDIX_LFI.txt", "simple-check.txt",
                                   "Linux-files.txt", "Windows-files.txt"])
    if lfi:
        LFI_PAYLOADS = lfi
        logger.debug("LFI payloads: %d loaded from files", len(LFI_PAYLOADS))

    cmdi = _load_payload_dir("Command Injection/Intruder", payload_base)
    if cmdi:
        CMDI_PAYLOADS = cmdi
        logger.debug("CMDi payloads: %d loaded from files", len(CMDI_PAYLOADS))

    traversal = _load_payload_dir("Directory Traversal/Intruder", payload_base,
                                   pick=["directory_traversal.txt", "deep_traversal.txt",
                                         "traversals-8-deep-exotic-encoding.txt"])
    if traversal:
        TRAVERSAL_PAYLOADS = traversal
        logger.debug("Traversal payloads: %d loaded from files", len(TRAVERSAL_PAYLOADS))


def fingerprint_baseline(ctx: ScanContext) -> Baseline:
    sizes: list[int] = []
    statuses: list[int] = []
    hashes: list[str] = []
    ctypes: list[str] = []
    titles: list[str] = []
    for _ in range(2):
        rand_path = f"__nonexistent_{secrets.token_hex(8)}_audit_check/"
        url = urljoin(ctx.base_url, rand_path)
        resp = ctx.get(url)
        if resp is None:
            continue
        statuses.append(resp.status_code)
        sizes.append(len(resp.content))
        ctype = resp.headers.get("Content-Type", "")
        ctypes.append(ctype)
        if "text" in ctype:
            hashes.append(_hash_body(resp.text))
            titles.append(_extract_title(resp.text))
        else:
            hashes.append("")
            titles.append("")

    if not sizes:
        return Baseline()

    most_common = Counter(statuses).most_common(1)[0][0]
    idx = statuses.index(most_common)
    return Baseline(
        status=most_common,
        body_size=sizes[idx],
        body_hash=hashes[idx] if hashes else "",
        content_type=ctypes[idx] if ctypes else "",
        title=titles[idx] if titles else "",
        samples=sizes,
    )


def matches_baseline(resp: requests.Response, baseline: Baseline) -> bool:
    if baseline.body_size == 0 and baseline.body_hash == "":
        return False
    if resp.status_code != baseline.status:
        return False
    ctype = resp.headers.get("Content-Type", "")
    if baseline.body_hash and "text" in ctype:
        if _hash_body(resp.text) == baseline.body_hash:
            return True
    if baseline.body_size > 0:
        diff = abs(len(resp.content) - baseline.body_size) / baseline.body_size
        if diff < 0.05:
            if baseline.title and "text" in ctype:
                return _extract_title(resp.text) == baseline.title
            return True
    return False


# =============================================================================
# Constants — payloads, signatures, paths
# =============================================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": ("high",
        "HSTS header missing — browsers won't enforce HTTPS",
        "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' over HTTPS only."),
    "Content-Security-Policy": ("medium",
        "CSP header missing — no defense against XSS injection",
        "Define a CSP policy. Start with report-only, tighten gradually."),
    "X-Frame-Options": ("medium",
        "X-Frame-Options missing — site can be framed (clickjacking)",
        "Add 'X-Frame-Options: SAMEORIGIN' or use CSP frame-ancestors."),
    "X-Content-Type-Options": ("low",
        "X-Content-Type-Options missing — MIME-type sniffing possible",
        "Add 'X-Content-Type-Options: nosniff'."),
    "Referrer-Policy": ("low",
        "Referrer-Policy missing — full URLs leaked to external sites",
        "Add 'Referrer-Policy: strict-origin-when-cross-origin'."),
    "Permissions-Policy": ("info",
        "Permissions-Policy missing — no restriction on browser features",
        "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'."),
}

SENSITIVE_PATHS = [
    (".env", "high", "Environment file with secrets",
     ["=", "APP_", "DB_", "SECRET", "KEY"]),
    (".env.backup", "high", "Backup of environment file",
     ["=", "APP_", "DB_", "SECRET", "KEY"]),
    (".env.local", "high", "Local environment file",
     ["=", "APP_", "DB_", "SECRET", "KEY"]),
    (".git/config", "critical", "Git repo metadata exposed — source code may be downloadable",
     ["[core]", "repositoryformatversion"]),
    (".git/HEAD", "critical", "Git repo metadata exposed",
     ["ref: refs/", "refs/heads"]),
    (".svn/entries", "high", "SVN metadata exposed", ["svn:"]),
    (".DS_Store", "low", "macOS metadata leaks directory structure", []),
    ("config.php.bak", "critical", "Backup config may contain DB credentials",
     ["<?php", "DB_", "password", "DATABASE"]),
    ("wp-config.php.bak", "critical", "WordPress config backup",
     ["<?php", "DB_NAME", "DB_PASSWORD", "AUTH_KEY"]),
    ("wp-config.php~", "critical", "WordPress config editor backup",
     ["<?php", "DB_NAME", "DB_PASSWORD"]),
    ("wp-config.old", "critical", "WordPress old config backup",
     ["<?php", "DB_NAME", "DB_PASSWORD"]),
    ("backup.sql", "critical", "Database backup",
     ["INSERT INTO", "CREATE TABLE", "-- MySQL"]),
    ("dump.sql", "critical", "Database dump",
     ["INSERT INTO", "CREATE TABLE", "-- MySQL"]),
    ("database.sql", "critical", "Database file",
     ["INSERT INTO", "CREATE TABLE"]),
    (".htpasswd", "critical", "HTTP basic auth credentials", [":$"]),
    ("phpinfo.php", "high", "PHP info disclosure",
     ["phpinfo()", "PHP Version"]),
    ("info.php", "high", "Possible PHP info disclosure",
     ["phpinfo()", "PHP Version"]),
    ("server-status", "medium", "Apache server status page",
     ["Apache Server Status", "Server Version"]),
    ("server-info", "medium", "Apache server info page",
     ["Apache Server Information", "Server Settings"]),
]

PRIVATE_KEY_PATHS = [
    ("id_rsa", "critical", "Private SSH RSA key",
     ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"]),
    ("id_dsa", "critical", "Private SSH DSA key",
     ["BEGIN DSA PRIVATE KEY"]),
    ("id_ecdsa", "critical", "Private SSH ECDSA key",
     ["BEGIN EC PRIVATE KEY"]),
    ("id_ed25519", "critical", "Private SSH Ed25519 key",
     ["BEGIN OPENSSH PRIVATE KEY"]),
    (".ssh/id_rsa", "critical", "Private SSH key in .ssh/",
     ["BEGIN RSA PRIVATE KEY", "BEGIN OPENSSH PRIVATE KEY"]),
    (".ssh/authorized_keys", "high", "SSH authorized_keys",
     ["ssh-rsa ", "ssh-ed25519 ", "ecdsa-sha2"]),
    ("server.key", "critical", "TLS/SSL private key",
     ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY", "BEGIN EC PRIVATE KEY"]),
    ("private.key", "critical", "Private key file",
     ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"]),
    ("ssl/private.pem", "critical", "PEM private key",
     ["BEGIN PRIVATE KEY", "BEGIN RSA PRIVATE KEY"]),
    (".aws/credentials", "critical", "AWS credentials",
     ["aws_access_key_id", "aws_secret_access_key"]),
    (".npmrc", "high", "npm token",
     ["//registry.npmjs.org", "_authToken"]),
    (".docker/config.json", "high", "Docker registry auth",
     ['"auths"', '"auth"']),
    ("credentials.json", "high", "Credentials JSON",
     ['"client_secret"', '"private_key"', '"api_key"']),
]

WORDPRESS_PATHS = [
    ("readme.html", "low", "WordPress version disclosure",
     ["WordPress", "Version"]),
    ("license.txt", "low", "WordPress license (version disclosure)",
     ["WordPress", "GNU GENERAL PUBLIC LICENSE"]),
    ("wp-login.php", "info", "WordPress login page accessible",
     ["loginform", "wp-submit", "user_login"]),
    ("wp-admin/install.php", "high", "WordPress installer accessible",
     ["WordPress &rsaquo; Installation", "wp-install"]),
    ("wp-admin/upgrade.php", "medium", "WordPress upgrade page accessible",
     ["WordPress &rsaquo; Update", "Database Update"]),
    ("wp-json/wp/v2/users", "medium", "WordPress user enumeration via REST",
     ['"id":', '"slug":', '"name":']),
    ("?author=1", "medium", "WordPress author enumeration via query param",
     ["author/", "rel=\"author\""]),
]

DIRECTORY_PATHS = [
    "/wp-content/uploads/", "/uploads/", "/backup/", "/backups/",
    "/files/", "/admin/", "/private/", "/.git/",
]

ADMIN_PANEL_PATHS = [
    "admin/", "administrator/", "admin.php", "admin/index.php",
    "wp-admin/", "phpmyadmin/", "pma/", "adminer.php", "adminer/",
    "manager/html", "console/", "dashboard/", "panel/",
    "cpanel/", "webmail/", "control-panel/", "siteadmin/",
    "moderator/", "controlpanel/", "system/", "backend/",
]

ADMIN_PAGE_HINTS = [
    "<title>admin", "<title>login", "<title>dashboard",
    "control panel", "phpmyadmin", "administrator login",
    "sign in to admin", "admin panel", "manage site",
]
LOGIN_FORM_HINTS = ["password", "login", "sign in", "username", "user_login"]

CSRF_TOKEN_INDICATORS = [
    "csrf", "_token", "authenticity_token", "anti-forgery",
    "_csrf", "xsrf", "nonce", "__requestverificationtoken",
]

ERROR_DISCLOSURE_PATTERNS = [
    (re.compile(r"<b>Fatal error</b>:.*?\.php", re.I | re.S), "high",
     "PHP fatal error with file path"),
    (re.compile(r"<b>(Warning|Notice|Parse error)</b>:.*?\.php", re.I | re.S), "medium",
     "PHP warning/notice"),
    (re.compile(r"Stack trace:\s*\n", re.I), "medium", "Stack trace exposed"),
    (re.compile(r"Traceback \(most recent call last\)", re.I), "medium",
     "Python traceback exposed"),
    (re.compile(r"\bat (java|com|org|sun)\.\w+\.\w+\(", re.I), "medium",
     "Java stack trace exposed"),
    (re.compile(r"<title>\s*Whoops\!", re.I), "medium", "Laravel debug page (Whoops)"),
    (re.compile(r"<title>\s*Werkzeug Debugger", re.I), "high",
     "Flask/Werkzeug interactive debugger exposed"),
    (re.compile(r"DEBUG\s*=\s*True", re.I), "medium", "Debug mode hint in response"),
    (re.compile(r"Symfony\\Component\\Debug", re.I), "medium",
     "Symfony debug component exposed"),
    (re.compile(r"<title>.*?Rails\b.*?Error", re.I), "medium",
     "Ruby on Rails error page"),
    (re.compile(r"Microsoft\s+OLE\s+DB\s+Provider|System\.Data\.SqlClient", re.I), "high",
     ".NET SQL exception leaked"),
    (re.compile(r"NullPointerException|IllegalStateException", re.I), "low",
     "Java exception leaked"),
]

# --- Active payloads ---

_XSS_MARKER = "qXAuD1tXsScNrY"
XSS_PAYLOADS = [
    f'"><svg/onload=z="{_XSS_MARKER}">',
    f"<img src=x onerror=`{_XSS_MARKER}`>",
    f"</textarea><{_XSS_MARKER}>",
    f"';{_XSS_MARKER}//",  # JS context break
]
# Patterns proving payload broke into HTML / JS context
_XSS_HTML_CONTEXT = re.compile(
    rf'<svg[^>]*{re.escape(_XSS_MARKER)}|<img[^>]*{re.escape(_XSS_MARKER)}|<{re.escape(_XSS_MARKER)}',
    re.I,
)
_XSS_JS_CONTEXT = re.compile(rf"';{re.escape(_XSS_MARKER)}//")

SQLI_PAYLOADS = ["'", "\"", "')", "';", "\\'"]
SQL_ERROR_PATTERNS = [
    re.compile(r"you have an error in your sql syntax", re.I),
    re.compile(r"warning.*?\bmysql_", re.I),
    re.compile(r"unclosed quotation mark after the character string", re.I),
    re.compile(r"quoted string not properly terminated", re.I),
    re.compile(r"\bORA-\d{5}\b", re.I),
    re.compile(r"PostgreSQL.*?ERROR", re.I),
    re.compile(r"sqlite_(error|exception)", re.I),
    re.compile(r"SQLSTATE\[\w+\]", re.I),
    re.compile(r"Microsoft.*?ODBC.*?SQL Server", re.I),
    re.compile(r"PDOException", re.I),
    re.compile(r"mysqli_(num_rows|fetch|query|real_escape)", re.I),
    re.compile(r"valid MySQL result", re.I),
    re.compile(r"Npgsql\.\w+", re.I),
]

SSTI_FACTOR_A, SSTI_FACTOR_B = 1337, 7919
SSTI_PRODUCT = str(SSTI_FACTOR_A * SSTI_FACTOR_B)
SSTI_PAYLOADS = [
    # Multi-engine combo (Spring/Mako, Jinja2/Twig, ERB, Ruby/JSP-EL)
    (f"${{{SSTI_FACTOR_A}*{SSTI_FACTOR_B}}}"
     f"{{{{{SSTI_FACTOR_A}*{SSTI_FACTOR_B}}}}}"
     f"<%={SSTI_FACTOR_A}*{SSTI_FACTOR_B}%>"
     f"#{{{SSTI_FACTOR_A}*{SSTI_FACTOR_B}}}", "multi-engine"),
    # Smarty-specific
    (f"{{{SSTI_FACTOR_A}*{SSTI_FACTOR_B}}}", "smarty"),
    # Velocity
    (f"#set($x={SSTI_FACTOR_A}*{SSTI_FACTOR_B})$x", "velocity"),
]

LFI_PAYLOADS = [
    "../../../../../../../../etc/passwd",
    "....//....//....//....//etc/passwd",
    "/etc/passwd",
    "..%2f..%2f..%2f..%2fetc/passwd",
    "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    "/proc/self/environ",
    # PHP filter wrapper — base64-encodes the file content
    "php://filter/convert.base64-encode/resource=index.php",
]
LFI_UNIX_PASSWD = re.compile(r"root:[x*!]?:0:0:")
LFI_WIN_INI = re.compile(r"\[(?:fonts|extensions|mci\s+extensions)\]", re.I)
LFI_PROC_ENVIRON = re.compile(r"PATH=[/\w:.-]+", re.I)
# Heuristic: long base64 chunk in response (PHP filter wrapper exfil)
LFI_PHP_B64_LEAK = re.compile(r"[A-Za-z0-9+/=]{200,}")

REDIRECT_PARAM_NAMES = {
    "url", "redirect", "redirecturl", "redirect_url", "redir",
    "next", "return", "returnurl", "return_url", "returnto",
    "goto", "destination", "to", "link", "target", "out",
    "continue", "view",
}
SSRF_PARAM_NAMES = {
    "url", "uri", "image", "imageurl", "src", "source", "fetch",
    "remote", "callback", "load", "open", "proxy", "dest",
    "feed", "host", "site", "page", "preview", "endpoint",
}

REDIRECT_PROBE_HOST = "audit-redirect-test.example.com"
REDIRECT_PAYLOADS = [
    f"https://{REDIRECT_PROBE_HOST}/",
    f"//{REDIRECT_PROBE_HOST}/",          # protocol-relative
    f"/\\/{REDIRECT_PROBE_HOST}/",        # backslash bypass
    f"https:{REDIRECT_PROBE_HOST}",       # missing slashes
]

SSRF_PROBE_URL = "http://example.com/audit-ssrf-probe"
SSRF_PROBE_SIGNATURE = re.compile(r"example domain", re.I)

JSONP_CALLBACK_PARAMS = {"callback", "jsonp", "cb", "jsoncallback", "json_callback"}
_JSONP_MARKER = "jsonpAuditMarker"
JSONP_PAYLOAD = _JSONP_MARKER
_JSONP_REFLECTION = re.compile(rf"\b{re.escape(_JSONP_MARKER)}\s*\(", re.I)

# JWT detection: base64url-encoded header.payload.signature
_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")

# --- Command injection ---
CMDI_PAYLOADS: list[str] = [
    ";id", "||id", "|id", "&id", "&&id", ";id;", "|id|",
    ";whoami", "&&whoami", "\nid\n", "%0aid", "`id`",
    ";ls", "||ls", ";cat /etc/passwd",
]
CMDI_HIT_PATTERNS = [
    re.compile(r"uid=\d+\(\w+\)\s+gid=\d+", re.I),
    re.compile(r"root:[x*!]?:0:0:"),
    re.compile(r"(?:^|\s)www-data(?:\s|$)", re.I),
    re.compile(r"(?:total \d+\n|drwx)", re.M),   # ls output
]

# --- Directory traversal ---
TRAVERSAL_PAYLOADS: list[str] = [
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2fetc/passwd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "....//....//....//etc/passwd",
    "..%252f..%252f..%252fetc/passwd",
    "/etc/passwd",
    "C:/windows/win.ini",
]
TRAVERSAL_HIT_PATTERNS = [
    re.compile(r"root:[x*!]?:0:0:"),
    re.compile(r"\[(?:fonts|extensions|mci\s+extensions)\]", re.I),
    re.compile(r"daemon:[x*]?:\d+:\d+:"),
]


# =============================================================================
# PASSIVE CHECKS
# =============================================================================

def check_https_redirect(ctx: ScanContext) -> List[Finding]:
    out: list[Finding] = []
    parsed = urlparse(ctx.base_url)
    if parsed.scheme != "https":
        out.append(Finding(
            severity="high", category="TLS",
            title="Site accessed over HTTP, not HTTPS",
            detail=f"Base URL uses {parsed.scheme}://",
            recommendation="Force HTTPS. All modern browsers warn on HTTP forms.",
            url=ctx.base_url, cwe="CWE-319",
        ))
        return out

    http_url = "http://" + parsed.netloc + "/"
    resp = ctx.get(http_url, allow_redirects=False)
    if resp is None:
        out.append(Finding(
            severity="info", category="TLS",
            title="HTTP port unreachable",
            detail="Could not connect to plain HTTP — likely closed (good).",
            recommendation="No action needed.", url=http_url,
        ))
    elif 300 <= resp.status_code < 400:
        loc = resp.headers.get("Location", "")
        if loc.startswith("https://"):
            out.append(Finding(
                severity="info", category="TLS",
                title="HTTP -> HTTPS redirect OK",
                detail=f"HTTP request redirects to {loc}",
                recommendation="No action needed.", url=http_url,
            ))
        else:
            out.append(Finding(
                severity="high", category="TLS",
                title="HTTP redirect not pointing to HTTPS",
                detail=f"HTTP redirects to: {loc}",
                recommendation="Configure redirect to https://",
                url=http_url, cwe="CWE-319",
            ))
    else:
        out.append(Finding(
            severity="high", category="TLS",
            title="HTTP serves content directly",
            detail=f"HTTP returned status {resp.status_code} without redirect to HTTPS",
            recommendation="Add 301 redirect from HTTP to HTTPS at server level.",
            url=http_url, cwe="CWE-319",
        ))
    return out


def check_security_headers(resp: requests.Response, base_url: str) -> List[Finding]:
    out: list[Finding] = []
    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, (sev, missing_msg, recommendation) in SECURITY_HEADERS.items():
        if header.lower() not in headers_lower:
            out.append(Finding(
                severity=sev, category="Headers",
                title=f"Missing: {header}",
                detail=missing_msg, recommendation=recommendation,
                url=base_url, cwe="CWE-693",
            ))

    hsts = headers_lower.get("strict-transport-security", "")
    if hsts:
        if "max-age=" in hsts:
            try:
                max_age = int(hsts.split("max-age=")[1].split(";")[0].strip().strip('"'))
                if max_age < 15768000:
                    out.append(Finding(
                        severity="medium", category="Headers",
                        title="HSTS max-age too short",
                        detail=f"max-age={max_age} (less than 6 months)",
                        recommendation="Set max-age=31536000 (1 year) once you're confident.",
                        url=base_url,
                    ))
            except (ValueError, IndexError):
                pass
        if "includesubdomains" not in hsts.lower():
            out.append(Finding(
                severity="low", category="Headers",
                title="HSTS missing includeSubDomains",
                detail="Subdomains are not covered by the HSTS policy.",
                recommendation="Add 'includeSubDomains' once all subdomains serve HTTPS.",
                url=base_url,
            ))

    csp = headers_lower.get("content-security-policy", "")
    if csp:
        if "unsafe-inline" in csp:
            out.append(Finding(
                severity="medium", category="Headers",
                title="CSP allows 'unsafe-inline'",
                detail="Inline scripts/styles allowed — defeats most XSS protection.",
                recommendation="Use nonces/hashes; remove 'unsafe-inline'.",
                url=base_url, cwe="CWE-79",
            ))
        if "unsafe-eval" in csp:
            out.append(Finding(
                severity="medium", category="Headers",
                title="CSP allows 'unsafe-eval'",
                detail="eval() and Function() constructor allowed.",
                recommendation="Avoid eval-based libraries; remove unsafe-eval.",
                url=base_url, cwe="CWE-95",
            ))

    return out


def check_server_fingerprint(resp: requests.Response, base_url: str) -> List[Finding]:
    out: list[Finding] = []
    server = resp.headers.get("Server", "")
    powered_by = resp.headers.get("X-Powered-By", "")
    aspnet = resp.headers.get("X-AspNet-Version", "")

    if server and any(c.isdigit() for c in server):
        out.append(Finding(
            severity="low", category="Disclosure",
            title="Server header reveals version",
            detail=f"Server: {server}",
            recommendation="Apache 'ServerTokens Prod', nginx 'server_tokens off;'.",
            url=base_url, cwe="CWE-200",
        ))
    if powered_by:
        out.append(Finding(
            severity="low", category="Disclosure",
            title="X-Powered-By header present",
            detail=f"X-Powered-By: {powered_by}",
            recommendation="Hide via PHP 'expose_php = Off' or web server config.",
            url=base_url, cwe="CWE-200",
        ))
    if aspnet:
        out.append(Finding(
            severity="low", category="Disclosure",
            title="X-AspNet-Version header present",
            detail=f"X-AspNet-Version: {aspnet}",
            recommendation="Set 'enableVersionHeader=false' in web.config.",
            url=base_url, cwe="CWE-200",
        ))

    if "<meta name=\"generator\" content=\"WordPress" in resp.text:
        gen_idx = resp.text.find("<meta name=\"generator\"")
        snippet = resp.text[gen_idx:gen_idx + 120]
        out.append(Finding(
            severity="low", category="Disclosure",
            title="WordPress version in HTML meta",
            detail=snippet.split('>')[0] + ">",
            recommendation="remove_action('wp_head', 'wp_generator') in functions.php.",
            url=base_url, cwe="CWE-200",
        ))
    return out


def check_cookie_flags(resp: requests.Response, base_url: str) -> List[Finding]:
    out: list[Finding] = []
    try:
        raw_cookies = resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        raw_cookies = [v for k, v in resp.raw.headers.items()
                       if k.lower() == "set-cookie"]
    if not raw_cookies:
        single = resp.headers.get("Set-Cookie", "")
        raw_cookies = [single] if single else []

    for cookie_str in raw_cookies:
        if not cookie_str:
            continue
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()
        is_https = base_url.startswith("https://")

        if is_https and "secure" not in lower:
            out.append(Finding(
                severity="medium", category="Cookies",
                title=f"Cookie '{name}' missing Secure flag",
                detail="Cookie may be sent over HTTP if site is ever accessed insecurely.",
                recommendation="Add Secure flag to all cookies on HTTPS sites.",
                url=base_url, cwe="CWE-614",
            ))
        if "httponly" not in lower:
            out.append(Finding(
                severity="medium", category="Cookies",
                title=f"Cookie '{name}' missing HttpOnly flag",
                detail="Cookie accessible from JavaScript — XSS can steal it.",
                recommendation="Add HttpOnly to session/auth cookies.",
                url=base_url, cwe="CWE-1004",
            ))
        if "samesite" not in lower:
            out.append(Finding(
                severity="low", category="Cookies",
                title=f"Cookie '{name}' missing SameSite attribute",
                detail="No CSRF mitigation from SameSite.",
                recommendation="Set SameSite=Lax (Strict for auth cookies).",
                url=base_url, cwe="CWE-352",
            ))

        # JWT detection in cookie value
        if _JWT_PATTERN.search(cookie_str):
            out.append(Finding(
                severity="info", category="Cookies",
                title=f"Cookie '{name}' looks like a JWT",
                detail="Verify the JWT uses a strong algorithm (not 'none' / 'HS256' with weak secret) "
                       "and validates signature server-side.",
                recommendation="Audit JWT validation logic. Reject 'alg: none' explicitly.",
                url=base_url, cwe="CWE-347",
                evidence=f"cookie={name}",
            ))
    return out


def check_cors(ctx: ScanContext) -> List[Finding]:
    out: list[Finding] = []
    resp = ctx.get(ctx.base_url, headers={"Origin": "https://evil.example.com"})
    if resp is None:
        return out
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao == "*":
        sev = "high" if acac == "true" else "low"
        out.append(Finding(
            severity=sev, category="CORS",
            title="Access-Control-Allow-Origin: *",
            detail=f"Wildcard CORS{' WITH credentials (critical)' if acac == 'true' else ''}",
            recommendation="Whitelist specific origins; never combine '*' with credentials.",
            url=ctx.base_url, cwe="CWE-942",
        ))
    elif acao == "https://evil.example.com":
        out.append(Finding(
            severity="high", category="CORS",
            title="CORS reflects arbitrary Origin",
            detail="Server echoes back any Origin header — bypasses same-origin protection.",
            recommendation="Use a strict whitelist of allowed origins.",
            url=ctx.base_url, cwe="CWE-942",
            evidence="sent Origin: https://evil.example.com → reflected",
        ))

    null_resp = ctx.get(ctx.base_url, headers={"Origin": "null"})
    if null_resp is not None and null_resp.headers.get("Access-Control-Allow-Origin", "") == "null":
        out.append(Finding(
            severity="high", category="CORS",
            title="CORS reflects null origin",
            detail="Server accepts 'null' as a valid origin — exploitable via sandboxed iframes.",
            recommendation="Reject null origin; only whitelist specific https:// origins.",
            url=ctx.base_url, cwe="CWE-942",
            evidence="sent Origin: null → reflected",
        ))
    return out


def check_robots_sitemap(ctx: ScanContext) -> List[Finding]:
    out: list[Finding] = []
    for path in ["robots.txt", "sitemap.xml", "sitemap_index.xml"]:
        url = urljoin(ctx.base_url, path)
        resp = ctx.get(url)
        if resp and resp.status_code == 200:
            out.append(Finding(
                severity="info", category="Recon",
                title=f"{path} accessible",
                detail=f"Size: {len(resp.content)} bytes",
                recommendation="Review for unintentionally listed admin paths.",
                url=url,
            ))
    return out


def check_http_methods(ctx: ScanContext) -> List[Finding]:
    """Check OPTIONS / TRACE / PUT / DELETE on the base URL."""
    out: list[Finding] = []
    opt = ctx.request("OPTIONS", ctx.base_url)
    if opt is not None:
        allow = opt.headers.get("Allow") or opt.headers.get("Access-Control-Allow-Methods", "")
        risky = {"PUT", "DELETE", "TRACE", "PATCH", "CONNECT"} & {
            m.strip().upper() for m in allow.split(",")
        }
        if risky:
            out.append(Finding(
                severity="medium", category="HTTP Methods",
                title=f"Risky HTTP methods advertised: {', '.join(sorted(risky))}",
                detail=f"OPTIONS Allow header: {allow}",
                recommendation="Disable unused methods at the server/WAF level.",
                url=ctx.base_url, cwe="CWE-650",
                evidence=f"Allow: {allow}",
            ))

    trace = ctx.request("TRACE", ctx.base_url)
    if trace is not None and trace.status_code == 200 and "TRACE" in trace.text.upper():
        out.append(Finding(
            severity="medium", category="HTTP Methods",
            title="HTTP TRACE method enabled (XST risk)",
            detail="TRACE echoes request — combined with XSS, can steal HttpOnly cookies.",
            recommendation="Disable TRACE: Apache 'TraceEnable Off', nginx blocks by default.",
            url=ctx.base_url, cwe="CWE-693",
        ))

    # PUT probe — to a random path; 405/403/401 expected, 200/201/204 means writable
    rand = f"/__audit_put_probe_{secrets.token_hex(4)}.txt"
    put = ctx.request("PUT", urljoin(ctx.base_url, rand), data=b"")
    if put is not None and put.status_code in (200, 201, 204):
        out.append(Finding(
            severity="critical", category="HTTP Methods",
            title="PUT method accepts file upload to random path",
            detail=f"PUT {rand} returned {put.status_code} — server may accept arbitrary files.",
            recommendation="Disable PUT, or restrict to authenticated/authorized paths only.",
            url=urljoin(ctx.base_url, rand), cwe="CWE-434",
            evidence=f"PUT {rand} → {put.status_code}",
        ))
    return out


def check_host_header_injection(ctx: ScanContext) -> List[Finding]:
    """Try to poison the Host header — many apps echo it into links / cache keys."""
    out: list[Finding] = []
    poison_host = "audit-host-poison.example.com"
    resp = ctx.get(ctx.base_url, headers={"Host": poison_host},
                   allow_redirects=False)
    if resp is None:
        return out

    # Reflected in body (link generation)
    if poison_host in resp.text:
        out.append(Finding(
            severity="medium", category="Host Header",
            title="Host header reflected in response body",
            detail=f"Server echoes Host: {poison_host} into links/markup — "
                   f"may enable cache poisoning or password-reset hijacking.",
            recommendation="Validate Host against an allowlist; configure web server to "
                           "reject unknown hosts.",
            url=ctx.base_url, cwe="CWE-444",
            evidence=f"Host: {poison_host} → reflected in body",
        ))

    # Reflected in redirect Location
    loc = resp.headers.get("Location", "")
    if poison_host in loc:
        out.append(Finding(
            severity="high", category="Host Header",
            title="Host header reflected in Location redirect",
            detail=f"Server redirects to attacker-controlled host: {loc}",
            recommendation="Build redirect URLs from a configured canonical host, "
                           "not the request Host header.",
            url=ctx.base_url, cwe="CWE-601",
            evidence=f"Host: {poison_host} → Location: {loc}",
        ))
    return out


def check_admin_panels(ctx: ScanContext, baseline: Baseline) -> List[Finding]:
    out: list[Finding] = []
    for path in ADMIN_PANEL_PATHS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.get(url)
        if resp is None or resp.status_code != 200:
            continue
        if matches_baseline(resp, baseline):
            continue
        ctype = resp.headers.get("Content-Type", "")
        if "text" not in ctype:
            continue

        body_lower = resp.text[:8192].lower()
        is_admin_page = any(h in body_lower for h in ADMIN_PAGE_HINTS)
        has_login = any(h in body_lower for h in LOGIN_FORM_HINTS)
        has_password = bool(re.search(r'<input[^>]+type\s*=\s*["\']?password',
                                      resp.text, re.I))
        if not is_admin_page:
            continue

        if has_password or has_login:
            out.append(Finding(
                severity="medium", category="Admin Panel",
                title=f"Admin panel exposed: /{path}",
                detail="Admin/management interface reachable; login form visible.",
                recommendation="Restrict by IP/VPN, rename default URLs, enforce 2FA.",
                url=url, cwe="CWE-284",
            ))
        else:
            out.append(Finding(
                severity="high", category="Admin Panel",
                title=f"Admin panel without login challenge: /{path}",
                detail="Admin interface returns HTTP 200 with no password prompt — "
                       "may be entirely unauthenticated.",
                recommendation="Add authentication immediately. Verify access controls.",
                url=url, cwe="CWE-306",
            ))
    return out


def check_error_disclosure(ctx: ScanContext) -> List[Finding]:
    out: list[Finding] = []
    seen: set[str] = set()
    probes = [
        urljoin(ctx.base_url, f"?id={_XSS_MARKER}'\""),
        urljoin(ctx.base_url, f"?file=../../{_XSS_MARKER}"),
        urljoin(ctx.base_url, "?debug=1&trace=1"),
        urljoin(ctx.base_url, f"_audit_invalid_route_{secrets.token_hex(4)}/{_XSS_MARKER}"),
    ]
    for url in probes:
        resp = ctx.get(url)
        if resp is None or "text" not in resp.headers.get("Content-Type", ""):
            continue
        body = resp.text[:32768]
        for pattern, sev, desc in ERROR_DISCLOSURE_PATTERNS:
            m = pattern.search(body)
            if m and desc not in seen:
                seen.add(desc)
                out.append(Finding(
                    severity=sev, category="Info Disclosure",
                    title=desc,
                    detail="Error/debug info leaked to public clients.",
                    recommendation="Disable verbose errors in production. Log details server-side.",
                    url=url, cwe="CWE-209",
                    evidence=_trim(m.group(0)),
                ))
    return out


def check_csrf_forms(ctx: ScanContext, max_pages: int) -> List[Finding]:
    if not HAS_BS4:
        return [Finding(
            severity="info", category="CSRF",
            title="CSRF form check skipped",
            detail="beautifulsoup4 not installed.",
            recommendation="pip install beautifulsoup4",
            url=ctx.base_url,
        )]
    from bs4 import BeautifulSoup as _BS

    out: list[Finding] = []
    base_netloc = urlparse(ctx.base_url).netloc
    visited: set[str] = set()
    queue: deque[str] = deque([ctx.base_url])
    # Key: (frozenset of input names, action path) — same template across pages = 1 finding
    flagged: set[tuple] = set()

    while queue and len(visited) < max_pages:
        page_url = queue.popleft()
        if page_url in visited:
            continue
        visited.add(page_url)
        resp = ctx.get(page_url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        soup = _BS(resp.text, "html.parser")
        for form in soup.find_all("form"):
            method = _attr_str(form, "method", "get").upper()
            if method != "POST":
                continue
            action = _attr_str(form, "action")
            form_id = urljoin(page_url, action) if action else page_url
            input_names = [
                _attr_str(inp, "name").lower()
                for inp in form.find_all(["input", "textarea", "select"])
                if _attr_str(inp, "name")
            ]
            has_token = any(
                any(tok in n for tok in CSRF_TOKEN_INDICATORS) for n in input_names
            )
            if has_token:
                continue
            # Deduplicate by form structure + action path (same template on N pages = 1 finding)
            form_key = (frozenset(input_names), urlparse(form_id).path)
            if form_key in flagged:
                continue
            flagged.add(form_key)
            out.append(Finding(
                severity="medium", category="CSRF",
                title="POST form without CSRF token",
                detail=f"Form action='{action or '(self)'}' — "
                       f"no anti-CSRF token field detected.",
                recommendation="Add a per-session CSRF token; validate server-side; "
                               "use SameSite=Lax cookies.",
                url=form_id, cwe="CWE-352",
                evidence=f"inputs={','.join(input_names[:5]) or '(none)'}",
            ))

        for link in soup.find_all("a", href=True):
            href = _attr_str(link, "href")
            if not href:
                continue
            link_parsed = urlparse(urljoin(page_url, href))
            if link_parsed.netloc != base_netloc:
                continue
            normalized = link_parsed._replace(fragment="").geturl()
            if normalized not in visited and len(visited) + len(queue) < max_pages * 3:
                queue.append(normalized)
    return out


def check_sensitive_files(ctx: ScanContext, paths, category: str,
                          baseline: Baseline) -> List[Finding]:
    out: list[Finding] = []
    for entry in paths:
        path, severity, desc, expected_signals = entry
        url = urljoin(ctx.base_url, path)
        resp = ctx.get(url)
        if resp is None or resp.status_code != 200 or len(resp.content) == 0:
            continue
        ctype = resp.headers.get("Content-Type", "")
        body_lower = resp.text[:2000].lower() if "text" in ctype else ""
        if any(x in body_lower for x in ["404", "not found", "page not found"]):
            continue
        if matches_baseline(resp, baseline):
            continue
        if expected_signals:
            full = resp.text[:8192].lower() if "text" in ctype else ""
            if not any(sig.lower() in full for sig in expected_signals):
                continue
        out.append(Finding(
            severity=severity, category=category,
            title=f"Accessible: /{path}",
            detail=f"{desc} (HTTP 200, {len(resp.content)} bytes, {ctype})",
            recommendation="Block via web server config, delete file, or move out of webroot.",
            url=url, cwe="CWE-538",
        ))
    return out


def check_directory_listing(ctx: ScanContext, baseline: Baseline) -> List[Finding]:
    out: list[Finding] = []
    indicators = ["Index of /", "<title>Index of", "Parent Directory</a>"]
    for path in DIRECTORY_PATHS:
        url = urljoin(ctx.base_url, path)
        resp = ctx.get(url)
        if resp is None or resp.status_code != 200:
            continue
        if matches_baseline(resp, baseline):
            continue
        if any(ind in resp.text for ind in indicators):
            out.append(Finding(
                severity="medium", category="Disclosure",
                title=f"Directory listing enabled: {path}",
                detail="Auto-generated directory index served.",
                recommendation="Apache 'Options -Indexes', nginx 'autoindex off;'.",
                url=url, cwe="CWE-548",
            ))
    return out


# =============================================================================
# ACTIVE SCANNING — input discovery + parallel probes
# =============================================================================

def discover_inputs(ctx: ScanContext, max_pages: int) -> List[InputPoint]:
    if not HAS_BS4:
        logger.warning("beautifulsoup4 not installed — skipping input discovery.")
        return []
    from bs4 import BeautifulSoup as _BS

    base_netloc = urlparse(ctx.base_url).netloc
    visited: set[str] = set()
    queue: deque[str] = deque([ctx.base_url])
    inputs: list[InputPoint] = []
    seen: set[tuple] = set()

    def _add(ip: InputPoint):
        sig = ip.signature()
        if sig not in seen:
            seen.add(sig)
            inputs.append(ip)

    logger.info("Crawling up to %d pages for input parameters...", max_pages)
    while queue and len(visited) < max_pages:
        page_url = queue.popleft()
        if page_url in visited:
            continue
        visited.add(page_url)
        resp = ctx.get(page_url)
        if not resp or "text/html" not in resp.headers.get("Content-Type", ""):
            continue

        parsed = urlparse(page_url)
        if parsed.query:
            qs = parse_qs(parsed.query, keep_blank_values=True)
            params = {k: (v[0] if v else "") for k, v in qs.items()}
            base = parsed._replace(query="", fragment="").geturl()
            for p in params:
                _add(InputPoint(base, "GET", params.copy(), p, page_url))

        soup = _BS(resp.text, "html.parser")
        for form in soup.find_all("form"):
            action = _attr_str(form, "action")
            method = _attr_str(form, "method", "get").upper()
            form_url = urljoin(page_url, action) if action else page_url
            form_url = urlparse(form_url)._replace(fragment="").geturl()
            if urlparse(form_url).netloc and urlparse(form_url).netloc != base_netloc:
                continue
            params: dict[str, str] = {}
            for inp in form.find_all(["input", "textarea", "select"]):
                name = _attr_str(inp, "name")
                if not name:
                    continue
                inp_type = _attr_str(inp, "type").lower()
                if inp_type in ("submit", "button", "image", "reset", "file"):
                    continue
                params[name] = _attr_str(inp, "value") or "test"
            for p in params:
                _add(InputPoint(form_url, method, params.copy(), p, page_url))

        for link in soup.find_all("a", href=True):
            href = _attr_str(link, "href")
            if not href:
                continue
            link_parsed = urlparse(urljoin(page_url, href))
            if link_parsed.netloc != base_netloc:
                continue
            base_link = link_parsed._replace(query="", fragment="").geturl()
            if link_parsed.query:
                qs = parse_qs(link_parsed.query, keep_blank_values=True)
                params = {k: (v[0] if v else "") for k, v in qs.items()}
                for p in params:
                    _add(InputPoint(base_link, "GET", params.copy(), p, page_url))
            if base_link not in visited and len(queue) < max_pages * 3:
                queue.append(base_link)

    logger.info("Discovered %d unique injection point(s) across %d page(s).",
                len(inputs), len(visited))
    return inputs


def _probe(ctx: ScanContext, ip: InputPoint, payload: str,
           allow_redirects: bool = True) -> Optional[requests.Response]:
    params = {**ip.params, ip.fuzz_param: payload}
    if ip.method == "POST":
        return ctx.post(ip.url, data=params, allow_redirects=allow_redirects)
    return ctx.get(ip.url, params=params, allow_redirects=allow_redirects)


def _dedup(inputs: Sequence[InputPoint]) -> list[InputPoint]:
    seen: set[tuple] = set()
    out: list[InputPoint] = []
    for ip in inputs:
        if ip.signature() not in seen:
            seen.add(ip.signature())
            out.append(ip)
    return out


def _run_parallel(ctx: ScanContext, inputs: Sequence[InputPoint],
                  worker: Callable[[InputPoint], List[Finding]]) -> List[Finding]:
    """Run `worker` for each input across ctx.threads workers; aggregate findings."""
    inputs = _dedup(inputs)
    if not inputs:
        return []
    results: list[Finding] = []
    if ctx.threads <= 1:
        for ip in inputs:
            results.extend(worker(ip))
        return results
    with ThreadPoolExecutor(max_workers=ctx.threads) as ex:
        futures = [ex.submit(worker, ip) for ip in inputs]
        for fut in as_completed(futures):
            try:
                results.extend(fut.result())
            except Exception as e:
                logger.debug("worker raised: %s", e)
    return results


async def _run_active_async(ctx: ScanContext, inputs: List[InputPoint],
                            active_checks: set) -> None:
    """Run all active check categories concurrently via asyncio + thread executor."""
    check_map: dict[str, Callable] = {
        "xss":       check_xss,
        "sqli":      check_sqli,
        "ssti":      check_ssti,
        "lfi":       check_lfi,
        "cmdi":      check_cmdi,
        "traversal": check_traversal,
        "redirect":  check_open_redirect,
        "ssrf":      check_ssrf,
        "jsonp":     check_jsonp,
    }
    to_run = [(cid, fn) for cid, fn in check_map.items()
              if cid in active_checks and ctx.should_run(cid)]
    if not to_run:
        return

    loop = asyncio.get_running_loop()

    async def _one(cid: str, fn: Callable) -> tuple:
        logger.info("  [ASYNC:%s] started", cid.upper())
        findings: List[Finding] = await loop.run_in_executor(None, fn, ctx, inputs)
        return cid, findings

    tasks = [asyncio.ensure_future(_one(cid, fn)) for cid, fn in to_run]
    logger.info("Running %d active check(s) asynchronously...", len(tasks))
    for coro in asyncio.as_completed(tasks):
        cid, findings = await coro
        if findings:
            ctx.add(*findings)
            logger.info("  [ASYNC:%s] %d finding(s)", cid.upper(), len(findings))
        else:
            logger.info("  [ASYNC:%s] clean", cid.upper())


# --- XSS ---

def check_xss(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        for payload in XSS_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            body = resp.text
            if _XSS_HTML_CONTEXT.search(body) or _XSS_JS_CONTEXT.search(body):
                return [Finding(
                    severity="high", category="XSS",
                    title=f"Reflected XSS via parameter '{ip.fuzz_param}'",
                    detail=f"{ip.method} {ip.url} reflects payload into an executable context.",
                    recommendation="HTML-encode user input. Use auto-escaping templates "
                                   "and a strict CSP without 'unsafe-inline'.",
                    url=ip.url, cwe="CWE-79",
                    evidence=f"payload={_trim(payload, 80)}",
                )]
        return []
    return _run_parallel(ctx, inputs, worker)


# --- SQL injection (error-based + boolean differential) ---

def check_sqli(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        # Establish a baseline body for differential comparison
        baseline_value = ip.params.get(ip.fuzz_param) or "1"
        baseline_resp = _probe(ctx, ip, baseline_value)
        baseline_body = baseline_resp.text if baseline_resp else ""

        # 1) Error-based — look for DB error strings on quote injection
        for payload in SQLI_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None:
                continue
            for pat in SQL_ERROR_PATTERNS:
                m = pat.search(resp.text)
                if m and not pat.search(baseline_body):
                    return [Finding(
                        severity="critical", category="SQLi",
                        title=f"SQL injection (error-based) via '{ip.fuzz_param}'",
                        detail=f"{ip.method} {ip.url} returns DB error on payload {payload!r}.",
                        recommendation="Use parameterized queries / prepared statements. "
                                       "Never concatenate user input into SQL.",
                        url=ip.url, cwe="CWE-89",
                        evidence=f"payload={payload!r} matched={_trim(m.group(0), 60)}",
                    )]

        # 2) Boolean differential — `value AND 1=1` vs `value AND 1=2`
        true_payload = f"{baseline_value}' AND '1'='1"
        false_payload = f"{baseline_value}' AND '1'='2"
        true_resp = _probe(ctx, ip, true_payload)
        false_resp = _probe(ctx, ip, false_payload)
        if true_resp and false_resp:
            t_hash = _hash_body(true_resp.text)
            f_hash = _hash_body(false_resp.text)
            b_hash = _hash_body(baseline_body)
            # Strong signal: TRUE matches baseline closely, FALSE diverges noticeably
            if t_hash == b_hash and f_hash != b_hash and len(false_resp.text) != len(true_resp.text):
                return [Finding(
                    severity="critical", category="SQLi",
                    title=f"SQL injection (boolean) via '{ip.fuzz_param}'",
                    detail="TRUE/FALSE payloads produce different responses while TRUE matches "
                           "the original — the parameter is reaching a SQL clause unsanitized.",
                    recommendation="Use parameterized queries / prepared statements.",
                    url=ip.url, cwe="CWE-89",
                    evidence=f"len(true)={len(true_resp.text)} len(false)={len(false_resp.text)}",
                )]
        return []
    return _run_parallel(ctx, inputs, worker)


# --- SSTI ---

def check_ssti(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        for payload, engine in SSTI_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None or SSTI_PRODUCT not in resp.text:
                continue
            # Confirm with a different multiplier so the digits aren't coincidence
            confirm_b = 2027
            confirm = SSTI_PAYLOADS[0][0].replace(str(SSTI_FACTOR_B), str(confirm_b))
            confirm_value = str(SSTI_FACTOR_A * confirm_b)
            confirm_resp = _probe(ctx, ip, confirm)
            if confirm_resp and confirm_value in confirm_resp.text:
                return [Finding(
                    severity="critical", category="SSTI",
                    title=f"Server-Side Template Injection via '{ip.fuzz_param}'",
                    detail=f"Template engine ({engine}) evaluated arithmetic — "
                           f"RCE is typically possible from this primitive.",
                    recommendation="Never pass user input to a template render function. "
                                   "Use sandboxed rendering and strict input filtering.",
                    url=ip.url, cwe="CWE-1336",
                    evidence=f"engine={engine} produced={SSTI_PRODUCT}",
                )]
        return []
    return _run_parallel(ctx, inputs, worker)


# --- LFI / Path Traversal ---

def check_lfi(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        for payload in LFI_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None:
                continue
            body = resp.text
            indicator = None
            if LFI_UNIX_PASSWD.search(body):
                indicator = "/etc/passwd contents (root:x:0:0:)"
            elif LFI_WIN_INI.search(body):
                indicator = "Windows win.ini contents"
            elif "/proc/self/environ" in payload and LFI_PROC_ENVIRON.search(body):
                indicator = "/proc/self/environ contents"
            elif payload.startswith("php://filter") and LFI_PHP_B64_LEAK.search(body):
                # Heuristic only — could false-positive on legit base64 content
                if "<?php" not in body and resp.headers.get("Content-Type", "").startswith("text"):
                    indicator = "Suspected base64-encoded PHP source via filter wrapper"
            if indicator:
                return [Finding(
                    severity="critical", category="LFI",
                    title=f"Local File Inclusion via '{ip.fuzz_param}'",
                    detail=f"Response contains {indicator}.",
                    recommendation="Validate file paths against an allowlist. "
                                   "Never concatenate user input into file system calls.",
                    url=ip.url, cwe="CWE-22",
                    evidence=f"payload={_trim(payload, 80)} → {indicator}",
                )]
        return []
    return _run_parallel(ctx, inputs, worker)


# --- Open redirect ---

def check_open_redirect(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    candidates = [ip for ip in _dedup(inputs)
                  if ip.fuzz_param.lower() in REDIRECT_PARAM_NAMES]
    def worker(ip: InputPoint) -> list[Finding]:
        for payload in REDIRECT_PAYLOADS:
            resp = _probe(ctx, ip, payload, allow_redirects=False)
            if resp is None:
                continue
            if 300 <= resp.status_code < 400:
                loc = resp.headers.get("Location", "")
                if REDIRECT_PROBE_HOST in loc:
                    return [Finding(
                        severity="medium", category="Open Redirect",
                        title=f"Open redirect via '{ip.fuzz_param}'",
                        detail=f"Redirects to attacker-controlled URL: {loc}",
                        recommendation="Validate redirect targets against an allowlist of "
                                       "trusted internal domains.",
                        url=ip.url, cwe="CWE-601",
                        evidence=f"payload={_trim(payload, 60)} → {_trim(loc, 60)}",
                    )]
        return []
    return _run_parallel(ctx, candidates, worker)


# --- SSRF (basic) ---

def check_ssrf(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    candidates = [ip for ip in _dedup(inputs)
                  if ip.fuzz_param.lower() in SSRF_PARAM_NAMES]
    def worker(ip: InputPoint) -> list[Finding]:
        resp = _probe(ctx, ip, SSRF_PROBE_URL)
        if resp is None:
            return []
        if "text" in resp.headers.get("Content-Type", "") and \
           SSRF_PROBE_SIGNATURE.search(resp.text):
            return [Finding(
                severity="high", category="SSRF",
                title=f"SSRF: server fetches user-controlled URL via '{ip.fuzz_param}'",
                detail=f"Server returned content of {SSRF_PROBE_URL}. Could be pivoted to "
                       f"internal services (cloud metadata, intranet, localhost).",
                recommendation="Validate target URLs against an allowlist. Block private IP "
                               "ranges (RFC1918, link-local, 169.254.169.254). Disable HTTP "
                               "redirects in server-side fetches.",
                url=ip.url, cwe="CWE-918",
                evidence=f"probed {SSRF_PROBE_URL} → 'Example Domain' string in response",
            )]
        return []
    return _run_parallel(ctx, candidates, worker)


# --- JSONP callback reflection ---

def check_jsonp(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    candidates = [ip for ip in _dedup(inputs)
                  if ip.fuzz_param.lower() in JSONP_CALLBACK_PARAMS]
    def worker(ip: InputPoint) -> list[Finding]:
        resp = _probe(ctx, ip, JSONP_PAYLOAD)
        if resp is None:
            return []
        ctype = resp.headers.get("Content-Type", "")
        if "json" not in ctype and "javascript" not in ctype:
            return []
        if _JSONP_REFLECTION.search(resp.text):
            return [Finding(
                severity="medium", category="JSONP",
                title=f"JSONP callback reflects unfiltered input via '{ip.fuzz_param}'",
                detail="Server emits JavaScript wrapping user-controlled callback name — "
                       "can be abused to leak data via cross-site script include or to inject JS.",
                recommendation="Validate callback against [a-zA-Z0-9_$]+ regex; or migrate "
                               "from JSONP to CORS for cross-origin reads.",
                url=ip.url, cwe="CWE-79",
                evidence=f"callback={_JSONP_MARKER} reflected as function call",
            )]
        return []
    return _run_parallel(ctx, candidates, worker)


# --- Command injection ---

def check_cmdi(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        baseline_resp = _probe(ctx, ip, ip.params.get(ip.fuzz_param) or "test")
        baseline_text = baseline_resp.text if baseline_resp else ""
        for payload in CMDI_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None:
                continue
            for pat in CMDI_HIT_PATTERNS:
                m = pat.search(resp.text)
                if m and not pat.search(baseline_text):
                    return [Finding(
                        severity="critical", category="Command Injection",
                        title=f"OS command injection via '{ip.fuzz_param}'",
                        detail=f"{ip.method} {ip.url} executes OS commands unsanitized.",
                        recommendation="Never pass user input to shell commands. "
                                       "Use language-native APIs; validate with strict allowlists.",
                        url=ip.url, cwe="CWE-78",
                        evidence=f"payload={_trim(payload, 60)} → {_trim(m.group(0), 60)}",
                    )]
        return []
    return _run_parallel(ctx, inputs, worker)


# --- Directory traversal ---

def check_traversal(ctx: ScanContext, inputs: Sequence[InputPoint]) -> List[Finding]:
    def worker(ip: InputPoint) -> list[Finding]:
        baseline_resp = _probe(ctx, ip, ip.params.get(ip.fuzz_param) or "test")
        baseline_text = baseline_resp.text if baseline_resp else ""
        for payload in TRAVERSAL_PAYLOADS:
            resp = _probe(ctx, ip, payload)
            if resp is None:
                continue
            for pat in TRAVERSAL_HIT_PATTERNS:
                m = pat.search(resp.text)
                if m and not pat.search(baseline_text):
                    return [Finding(
                        severity="critical", category="Path Traversal",
                        title=f"Directory traversal via '{ip.fuzz_param}'",
                        detail=f"Parameter allows reading arbitrary files outside webroot.",
                        recommendation="Validate file paths against an allowlist. "
                                       "Use realpath() and verify path stays within webroot.",
                        url=ip.url, cwe="CWE-22",
                        evidence=f"payload={_trim(payload, 60)} → {_trim(m.group(0), 40)}",
                    )]
        return []
    return _run_parallel(ctx, inputs, worker)


# =============================================================================
# Orchestration
# =============================================================================

def run_audit(ctx: ScanContext, deep: bool, active_checks: set,
              max_crawl_pages: int, concurrent: bool = False) -> None:
    """
    active_checks: set of check IDs to run (subset of ACTIVE_CHECKS).
                   Empty set = no active scanning.
    concurrent:    if True, run all active checks in parallel via asyncio.
    """
    active = bool(active_checks)
    step = 0

    def step_log(label: str) -> None:
        nonlocal step
        step += 1
        logger.info("[%d] %s", step, label)

    # Standard passive
    if ctx.should_run("tls"):
        step_log("HTTPS redirect")
        ctx.add(*check_https_redirect(ctx))

    base_resp: Optional[requests.Response] = None
    if any(ctx.should_run(c) for c in ("headers", "fingerprint", "cookies")):
        step_log("Fetching base URL (headers / fingerprint / cookies)")
        base_resp = ctx.get(ctx.base_url)
        if base_resp is None:
            ctx.add(Finding(
                severity="high", category="Connectivity",
                title="Cannot fetch base URL",
                detail="Connection failed — header/cookie checks skipped.",
                recommendation="Verify the server is reachable.",
                url=ctx.base_url,
            ))
        else:
            if ctx.should_run("headers"):
                ctx.add(*check_security_headers(base_resp, ctx.base_url))
            if ctx.should_run("fingerprint"):
                ctx.add(*check_server_fingerprint(base_resp, ctx.base_url))
            if ctx.should_run("cookies"):
                ctx.add(*check_cookie_flags(base_resp, ctx.base_url))

    if ctx.should_run("cors"):
        step_log("CORS configuration")
        ctx.add(*check_cors(ctx))

    if ctx.should_run("recon"):
        step_log("robots.txt / sitemap")
        ctx.add(*check_robots_sitemap(ctx))

    if ctx.should_run("methods"):
        step_log("HTTP methods (OPTIONS / TRACE / PUT)")
        ctx.add(*check_http_methods(ctx))

    if ctx.should_run("host"):
        step_log("Host header injection")
        ctx.add(*check_host_header_injection(ctx))

    if ctx.should_run("errors"):
        step_log("Error / debug page disclosure")
        ctx.add(*check_error_disclosure(ctx))

    if ctx.should_run("csrf"):
        step_log(f"Crawling up to {max_crawl_pages} pages for CSRF-less forms")
        ctx.add(*check_csrf_forms(ctx, max_crawl_pages))

    # Baseline (needed for admin-panel & deep checks)
    baseline = Baseline()
    if ctx.should_run("admin") or deep:
        step_log("Fingerprinting server's not-found behavior")
        baseline = fingerprint_baseline(ctx)
        if baseline.body_size and baseline.status == 200:
            logger.info("      Catch-all detected: HTTP 200 + %dB body. Filtering matches.",
                        baseline.body_size)
        elif baseline.status:
            logger.info("      Server returns HTTP %d for unknown URLs (good).",
                        baseline.status)

    if ctx.should_run("admin"):
        step_log("Unauthenticated admin panels")
        ctx.add(*check_admin_panels(ctx, baseline))

    # Deep
    if deep:
        if ctx.should_run("files"):
            step_log("Sensitive files")
            ctx.add(*check_sensitive_files(ctx, SENSITIVE_PATHS, "Exposed File", baseline))
        if ctx.should_run("keys"):
            step_log("Private keys")
            ctx.add(*check_sensitive_files(ctx, PRIVATE_KEY_PATHS, "Private Key", baseline))
        if ctx.should_run("wordpress"):
            step_log("WordPress paths")
            ctx.add(*check_sensitive_files(ctx, WORDPRESS_PATHS, "WordPress", baseline))
        if ctx.should_run("dirs"):
            step_log("Directory listings")
            ctx.add(*check_directory_listing(ctx, baseline))
    else:
        logger.info("[deep] Skipped sensitive file & directory scan (use --deep)")

    # Active
    if active:
        step_log(f"Discovering input parameters (up to {max_crawl_pages} pages)")
        inputs = discover_inputs(ctx, max_crawl_pages)
        n = len(_dedup(inputs))

        if inputs:
            if concurrent:
                step_log(f"Running {len(active_checks)} active check(s) ASYNC "
                         f"({n} input[s], {ctx.threads} thread[s])")
                asyncio.run(_run_active_async(ctx, inputs, active_checks))
            else:
                check_map: list[tuple[str, str, Callable]] = [
                    ("xss",       "Reflected XSS",                  check_xss),
                    ("sqli",      "SQL injection (error + boolean)", check_sqli),
                    ("ssti",      "Server-Side Template Injection",  check_ssti),
                    ("lfi",       "Local File Inclusion",            check_lfi),
                    ("cmdi",      "Command Injection",               check_cmdi),
                    ("traversal", "Directory Traversal",             check_traversal),
                    ("redirect",  "Open redirect",                   check_open_redirect),
                    ("ssrf",      "Server-Side Request Forgery",     check_ssrf),
                    ("jsonp",     "JSONP callback reflection",       check_jsonp),
                ]
                for cid, label, fn in check_map:
                    if cid not in active_checks or not ctx.should_run(cid):
                        continue
                    step_log(f"{label} ({n} input[s], {ctx.threads} thread[s])")
                    ctx.add(*fn(ctx, inputs))

        ctx.add(Finding(
            severity="info", category="Manual Review",
            title="Vulnerability classes not auto-tested",
            detail="The following require specialized testing: "
                   "RCE (too dangerous to run unattended), XXE (needs XML endpoints "
                   "with custom payloads), IDOR / access control (requires comparison "
                   "across roles), Authentication bypass (requires session manipulation).",
            recommendation="Use Burp Suite / OWASP ZAP with multiple test accounts for "
                           "IDOR/auth. Audit server code for exec(), eval(), XML parsers.",
            url=ctx.base_url,
        ))
    else:
        logger.info("[active] Skipped active scanning — use individual flags or --all-active")


# =============================================================================
# Reporting
# =============================================================================

def print_report(findings: List[Finding]) -> None:
    if not findings:
        print("\nNo issues found.")
        return
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 99), f.category, f.title))
    print("\n" + "=" * 80)
    print(f"AUDIT REPORT — {len(findings)} findings")
    print("=" * 80)

    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    summary = "  ".join(f"{SEVERITY_TAG[k].strip()}: {by_sev[k]}"
                        for k in SEVERITY_ORDER if k in by_sev)
    print(f"Summary: {summary}\n")

    for f in findings:
        tag = SEVERITY_TAG.get(f.severity, "????")
        cwe = f" [{f.cwe}]" if f.cwe else ""
        print(f"[{tag}] {f.category}{cwe}: {f.title}")
        print(f"    Detail:   {f.detail}")
        if f.evidence:
            print(f"    Evidence: {f.evidence}")
        if f.url:
            print(f"    URL:      {f.url}")
        print(f"    Fix:      {f.recommendation}")
        print()


def write_csv(findings: List[Finding], path: str) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["severity", "category", "title", "detail",
                         "url", "evidence", "cwe", "recommendation"])
        for finding in findings:
            writer.writerow([finding.severity, finding.category, finding.title,
                             finding.detail, finding.url, finding.evidence,
                             finding.cwe, finding.recommendation])


def write_json(findings: List[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump([asdict(x) for x in findings], f, indent=2, ensure_ascii=False)


# =============================================================================
# CLI
# =============================================================================

def _parse_filter(raw: Optional[str]) -> set:
    if not raw:
        return set()
    items = {x.strip().lower() for x in raw.split(",") if x.strip()}
    unknown = items - ALL_CHECKS
    if unknown:
        logger.warning("Unknown check IDs ignored: %s", ", ".join(sorted(unknown)))
    return items & ALL_CHECKS


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Web vulnerability audit — XSS / SQLi / SSTI / LFI / SSRF / "
                    "Open-Redirect / JSONP / CSRF / admin panels / info disclosure / "
                    "private keys / HTTP methods / host header / misconfig.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("url", nargs="?", default="",
                        help="Base URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (s)")
    parser.add_argument("--delay", type=float, default=0.1,
                        help="Delay between requests (s)")
    parser.add_argument("--threads", type=int, default=8,
                        help="Parallel workers for active scans")
    parser.add_argument("--max-requests", type=int, default=2000,
                        help="Global cap on total HTTP requests (safety net)")
    parser.add_argument("--max-crawl-pages", type=int, default=15,
                        help="Pages to crawl for CSRF / admin / input discovery")
    parser.add_argument("--deep", action="store_true",
                        help="Probe sensitive files, private keys, dir listings")
    parser.add_argument("--active", action="store_true",
                        help="Run ALL active checks sequentially (XSS/SQLi/SSTI/LFI/CMDi/"
                             "Traversal/SSRF/Redirect/JSONP). USE ONLY WITH PERMISSION.")
    parser.add_argument("--all-active", action="store_true",
                        help="Run ALL active checks concurrently (async). "
                             "Same as --active but parallel. USE ONLY WITH PERMISSION.")

    # Individual active check flags
    _active_flags = [
        ("--xss",       "Run XSS (Cross-Site Scripting) check"),
        ("--sqli",      "Run SQL injection check"),
        ("--ssti",      "Run Server-Side Template Injection check"),
        ("--lfi",       "Run Local File Inclusion check"),
        ("--cmdi",      "Run OS Command Injection check"),
        ("--traversal", "Run Directory Traversal check"),
        ("--redirect",  "Run Open Redirect check"),
        ("--ssrf",      "Run Server-Side Request Forgery check"),
        ("--jsonp",     "Run JSONP callback reflection check"),
    ]
    for flag, help_text in _active_flags:
        parser.add_argument(flag, action="store_true", help=help_text)

    parser.add_argument("--payload-dir", default="payload",
                        help="Directory containing payload wordlists (default: payload/)")
    parser.add_argument("--cookie", action="append", default=[], metavar="NAME=VALUE",
                        help="Add cookie (repeatable). Useful for auth'd scanning.")
    parser.add_argument("--header", action="append", default=[], metavar="NAME: VALUE",
                        help="Add HTTP header (repeatable).")
    parser.add_argument("--bearer", help="Bearer token for Authorization header")
    parser.add_argument("--proxy", metavar="URL",
                        help="Proxy URL for all requests, e.g. http://127.0.0.1:8080 "
                             "or socks5://127.0.0.1:1080. "
                             "Useful for inspecting which IP your server logs.")
    parser.add_argument("--skip", help="Comma list of check IDs to skip "
                                       "(e.g. 'xss,sqli,methods')")
    parser.add_argument("--only", help="Comma list of check IDs to run "
                                       "(takes precedence over --skip)")
    parser.add_argument("--output", default="output/security_audit.csv", help="CSV report path")
    parser.add_argument("--json", help="Optional JSON report path")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose logging")
    parser.add_argument("--list-checks", action="store_true",
                        help="Print all check IDs and exit")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(message)s",
    )

    if args.list_checks:
        print("Passive: " + ", ".join(sorted(PASSIVE_CHECKS)))
        print("Deep:    " + ", ".join(sorted(DEEP_CHECKS)))
        print("Active:  " + ", ".join(sorted(ACTIVE_CHECKS)))
        return 0

    if not urlparse(args.url).scheme:
        print("URL must include scheme (http:// or https://)", file=sys.stderr)
        return 1
    if not args.url.endswith("/"):
        args.url += "/"

    skip = _parse_filter(args.skip)
    only = _parse_filter(args.only) if args.only else None
    if only is not None and not only:
        print("--only resolved to empty set — nothing to run", file=sys.stderr)
        return 1

    # Determine active checks to run
    _individual = {"xss", "sqli", "ssti", "lfi", "cmdi", "traversal",
                   "redirect", "ssrf", "jsonp"}
    enabled_by_flag = {c for c in _individual if getattr(args, c, False)}
    concurrent = getattr(args, "all_active", False)
    if args.active or concurrent:
        active_checks = _individual.copy()
    else:
        active_checks = enabled_by_flag
    # Apply --skip / --only on top of active_checks
    if only is not None:
        active_checks &= only
    else:
        active_checks -= skip

    # Load payloads from directory
    payload_base = Path(args.payload_dir)
    if payload_base.is_dir():
        init_payloads(payload_base)
        logger.info("Payloads loaded from: %s", payload_base.resolve())
    else:
        logger.info("Payload directory not found (%s) — using built-in payloads", args.payload_dir)

    session = build_session(args.cookie, args.header, args.bearer, args.proxy)
    ctx = ScanContext(
        session=session, base_url=args.url,
        timeout=args.timeout, delay=args.delay,
        max_requests=args.max_requests, threads=args.threads,
        skip=skip, only=only,
    )

    modes = []
    if args.deep:
        modes.append("DEEP")
    if active_checks:
        tag = "ASYNC" if concurrent else "ACTIVE"
        modes.append(f"{tag}[{','.join(sorted(active_checks))}]")
    print(f"Auditing: {args.url}")
    print(f"Mode: {' + '.join(modes) if modes else 'STANDARD'} | "
          f"threads={args.threads} delay={args.delay} budget={args.max_requests}")
    if args.proxy:
        print(f"Proxy  : {_normalize_proxy(args.proxy)}  "
              f"(server logs will show this IP, not yours)")
    if active_checks:
        print("\n!! ACTIVE mode sends probe payloads. Use only with permission. !!\n")

    interrupted = False
    try:
        run_audit(ctx, args.deep, active_checks, args.max_crawl_pages, concurrent)
    except KeyboardInterrupt:
        interrupted = True
        print("\n[INTERRUPTED] Saving findings collected so far...", file=sys.stderr)
    finally:
        session.close()

    print_report(ctx.findings)
    write_csv(ctx.findings, args.output)
    print(f"\nCSV report : {args.output}")
    if args.json:
        write_json(ctx.findings, args.json)
        print(f"JSON report: {args.json}")
    print(f"Requests   : {ctx.request_count} / {args.max_requests}")
    if interrupted:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
