"""
API Key Leak Scanner — defensive recon for leaked employee API keys / tokens.

What this script does
---------------------
1. Crawls a target site (same-origin, configurable depth) and harvests HTML +
   inline / external JS responses.
2. Scans every harvested response with a curated regex library covering 40+
   API key / token formats (AWS, GCP, Azure, Stripe, Slack, Telegram, GitHub,
   private keys, JWTs, etc.). Pattern names match the conventions used by
   `mazen160/secrets-patterns-db` and the README in this folder.
3. Detects ASP.NET `__VIEWSTATE` blobs and, when enabled (`--machinekey`),
   tries every (validationKey, decryptionKey) pair from
   `Files/MachineKeys.txt` to identify a known/leaked IIS machine key (the
   `Blacklist3r` workflow described in IIS-Machine-Keys.md).
4. Optionally validates a small set of high-impact tokens with read-only API
   calls (`--validate`) — currently Telegram bot tokens, GitHub PATs, Slack
   tokens, SendGrid keys. All other tokens are reported but not validated.
5. Writes findings to stdout, CSV, and JSON.

USE ONLY ON SYSTEMS YOU OWN OR HAVE WRITTEN AUTHORIZATION TO TEST.

Examples
--------
  python api_key_leak_scanner.py https://my.example.com
  python api_key_leak_scanner.py https://my.example.com --depth 2 --machinekey
  python api_key_leak_scanner.py https://my.example.com --validate --json out.json
  python api_key_leak_scanner.py - --file dump.html      # scan a local file
"""

from __future__ import annotations

import argparse
import base64
import csv
import hmac
import hashlib
import json
import logging
import re
import sys
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from html.parser import HTMLParser
from pathlib import Path
from threading import Lock
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger("apikey-leak")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36 ApiKeyLeakScanner/1.0"
)

DEFAULT_MACHINEKEYS = Path(__file__).parent / "Files" / "MachineKeys.txt"


# =============================================================================
# Regex pattern library
# =============================================================================
# `confidence`: high = format is unambiguous, medium = needs context check,
# low = generic format that produces noise on real sites.
# `severity`: how bad it is when valid.
# `validator`: optional name pointing to a function in VALIDATORS below.

PATTERNS: list[dict] = [
    # --- Cloud providers --------------------------------------------------
    {"name": "AWS Access Key ID",            "regex": r"\b(AKIA|ASIA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA|ACCA)[0-9A-Z]{16}\b",
     "confidence": "high",   "severity": "critical"},
    {"name": "AWS Secret Access Key",        "regex": r"(?i)aws(.{0,20})?(secret|key)[\"' :=]{0,5}([A-Za-z0-9/+=]{40})",
     "confidence": "medium", "severity": "critical", "group": 3},
    {"name": "AWS MWS Auth Token",           "regex": r"amzn\.mws\.[0-9a-f-]{36}",
     "confidence": "high",   "severity": "high"},
    {"name": "Google API Key",               "regex": r"\bAIza[0-9A-Za-z\-_]{35}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Google OAuth Access Token",    "regex": r"\bya29\.[0-9A-Za-z\-_]{20,}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Google Cloud Service Account", "regex": r"\"type\"\s*:\s*\"service_account\"",
     "confidence": "high",   "severity": "critical"},
    {"name": "Azure Subscription Key",       "regex": r"(?i)(azure|ocp-apim)[-_]?subscription[-_]?key[\"' :=]{0,5}([0-9a-f]{32})",
     "confidence": "medium", "severity": "high",     "group": 2},
    {"name": "Azure Storage Account Key",    "regex": r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;AccountKey=[A-Za-z0-9+/=]{88}",
     "confidence": "high",   "severity": "critical"},
    {"name": "Azure Shared Access Signature","regex": r"[?&]sig=[A-Za-z0-9%]{43,}%3D",
     "confidence": "medium", "severity": "high"},
    {"name": "Heroku API Key",               "regex": r"(?i)heroku[a-z0-9_ \.\-]{0,20}[\"' :=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
     "confidence": "medium", "severity": "high",     "group": 1},

    # --- Source control / CI ---------------------------------------------
    {"name": "GitHub Personal Access Token", "regex": r"\bghp_[0-9A-Za-z]{36,}\b",
     "confidence": "high",   "severity": "critical", "validator": "github"},
    {"name": "GitHub OAuth Token",           "regex": r"\bgho_[0-9A-Za-z]{36,}\b",
     "confidence": "high",   "severity": "critical", "validator": "github"},
    {"name": "GitHub App Token",             "regex": r"\b(ghu|ghs)_[0-9A-Za-z]{36,}\b",
     "confidence": "high",   "severity": "high",     "validator": "github"},
    {"name": "GitHub Refresh Token",         "regex": r"\bghr_[0-9A-Za-z]{36,}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "GitHub Fine-Grained PAT",      "regex": r"\bgithub_pat_[0-9A-Za-z_]{82}\b",
     "confidence": "high",   "severity": "critical", "validator": "github"},
    {"name": "GitLab Personal Token",        "regex": r"\bglpat-[0-9A-Za-z\-_]{20,}\b",
     "confidence": "high",   "severity": "critical"},
    {"name": "Bitbucket Client Secret",      "regex": r"(?i)bitbucket(.{0,20})?[\"' :=]{0,5}([0-9a-zA-Z=]{32,})",
     "confidence": "low",    "severity": "high",     "group": 2},
    {"name": "NPM Access Token",             "regex": r"\bnpm_[0-9A-Za-z]{36}\b",
     "confidence": "high",   "severity": "high"},

    # --- Payment / messaging / mail --------------------------------------
    {"name": "Stripe Live Secret Key",       "regex": r"\bsk_live_[0-9a-zA-Z]{24,}\b",
     "confidence": "high",   "severity": "critical"},
    {"name": "Stripe Restricted Key",        "regex": r"\brk_live_[0-9a-zA-Z]{24,}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Stripe Publishable Key",       "regex": r"\bpk_live_[0-9a-zA-Z]{24,}\b",
     "confidence": "high",   "severity": "info"},
    {"name": "Square Access Token",          "regex": r"\bsq0atp-[0-9A-Za-z\-_]{22}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Square OAuth Secret",          "regex": r"\bsq0csp-[0-9A-Za-z\-_]{43}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "PayPal Braintree Token",       "regex": r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b",
     "confidence": "high",   "severity": "critical"},
    {"name": "Slack Token",                  "regex": r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b",
     "confidence": "high",   "severity": "high",     "validator": "slack"},
    {"name": "Slack Webhook URL",            "regex": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
     "confidence": "high",   "severity": "medium"},
    {"name": "Telegram Bot Token",           "regex": r"\b[0-9]{8,10}:AA[0-9A-Za-z\-_]{32,35}\b",
     "confidence": "high",   "severity": "high",     "validator": "telegram"},
    {"name": "Discord Webhook URL",          "regex": r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+",
     "confidence": "high",   "severity": "medium"},
    {"name": "Discord Bot Token",            "regex": r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b",
     "confidence": "medium", "severity": "high"},
    {"name": "SendGrid API Key",             "regex": r"\bSG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}\b",
     "confidence": "high",   "severity": "high",     "validator": "sendgrid"},
    {"name": "Mailgun API Key",              "regex": r"\bkey-[0-9a-zA-Z]{32}\b",
     "confidence": "medium", "severity": "high"},
    {"name": "Mailchimp API Key",            "regex": r"\b[0-9a-f]{32}-us[0-9]{1,2}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Twilio API Key",               "regex": r"\bSK[0-9a-fA-F]{32}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Twilio Account SID",           "regex": r"\bAC[0-9a-fA-F]{32}\b",
     "confidence": "high",   "severity": "medium"},
    {"name": "Postman API Key",              "regex": r"\bPMAK-[0-9a-fA-F]{24}-[0-9a-fA-F]{34}\b",
     "confidence": "high",   "severity": "high"},

    # --- Generic / structural --------------------------------------------
    {"name": "JSON Web Token (JWT)",         "regex": r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b",
     "confidence": "high",   "severity": "medium"},
    {"name": "RSA Private Key",              "regex": r"-----BEGIN RSA PRIVATE KEY-----",
     "confidence": "high",   "severity": "critical"},
    {"name": "OpenSSH Private Key",          "regex": r"-----BEGIN OPENSSH PRIVATE KEY-----",
     "confidence": "high",   "severity": "critical"},
    {"name": "PGP Private Key",              "regex": r"-----BEGIN PGP PRIVATE KEY BLOCK-----",
     "confidence": "high",   "severity": "critical"},
    {"name": "Generic API Key Assignment",   "regex": r"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)[\"' :=]{1,5}([A-Za-z0-9_\-]{24,})",
     "confidence": "low",    "severity": "medium",   "group": 2},
    {"name": "Hardcoded Password Assignment","regex": r"(?i)(password|passwd|pwd)[\"' :=]{1,5}([A-Za-z0-9_\-!@#$%^&*]{8,})[\"']",
     "confidence": "low",    "severity": "medium",   "group": 2},
    {"name": "Basic Auth Credentials in URL","regex": r"https?://[A-Za-z0-9._%+-]+:[^/@\s]{4,}@[A-Za-z0-9.-]+",
     "confidence": "high",   "severity": "high"},

    # --- Misc service tokens ---------------------------------------------
    {"name": "Cloudinary URL",               "regex": r"cloudinary://[0-9]+:[A-Za-z0-9_\-]+@[A-Za-z0-9_\-]+",
     "confidence": "high",   "severity": "high"},
    {"name": "Firebase Cloud Messaging Key", "regex": r"\bAAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Datadog API Key",              "regex": r"(?i)dd[_-]?api[_-]?key[\"' :=]{1,5}([0-9a-f]{32})",
     "confidence": "medium", "severity": "high",     "group": 1},
    {"name": "New Relic License Key",        "regex": r"(?i)new[_-]?relic[_-]?(license|api)[_-]?key[\"' :=]{1,5}([A-Za-z0-9]{40,})",
     "confidence": "medium", "severity": "high",     "group": 2},
    {"name": "Shopify Access Token",         "regex": r"\bshpat_[a-fA-F0-9]{32}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Shopify Shared Secret",        "regex": r"\bshpss_[a-fA-F0-9]{32}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Algolia Admin API Key",        "regex": r"(?i)algolia(.{0,20})?admin[\"' :=]{1,5}([0-9a-f]{32})",
     "confidence": "medium", "severity": "high",     "group": 2},
    {"name": "OpenAI API Key",               "regex": r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Anthropic API Key",            "regex": r"\bsk-ant-[a-z0-9\-]{32,}\b",
     "confidence": "high",   "severity": "high"},
    {"name": "Hugging Face Token",           "regex": r"\bhf_[A-Za-z]{34,}\b",
     "confidence": "high",   "severity": "medium"},
]

# Pre-compile patterns for speed
for _p in PATTERNS:
    _p["compiled"] = re.compile(_p["regex"])


# =============================================================================
# Data classes
# =============================================================================

@dataclass
class Finding:
    severity: str
    pattern: str
    confidence: str
    secret: str       # the matched token (redacted in console; full in JSON)
    source_url: str
    context: str      # ~80 chars surrounding the hit
    validated: Optional[str] = None  # "valid" / "invalid" / None when not tested

    def redacted(self) -> str:
        s = self.secret
        if len(s) <= 12:
            return s[:4] + "***"
        return f"{s[:6]}…{s[-4:]} (len={len(s)})"


@dataclass
class ScanState:
    findings: list[Finding] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)
    seen_secrets: set[tuple] = field(default_factory=set)  # dedupe (pattern, secret)
    request_count: int = 0
    lock: Lock = field(default_factory=Lock)

    def add(self, f: Finding) -> bool:
        key = (f.pattern, f.secret)
        with self.lock:
            if key in self.seen_secrets:
                return False
            self.seen_secrets.add(key)
            self.findings.append(f)
            return True


# =============================================================================
# HTTP session
# =============================================================================

def build_session(timeout: int, proxy: Optional[str], headers: list[str],
                  cookies: list[str], insecure: bool = False) -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = USER_AGENT
    for h in headers:
        if ":" in h:
            name, _, val = h.partition(":")
            s.headers[name.strip()] = val.strip()
    for c in cookies:
        if "=" in c:
            name, _, val = c.partition("=")
            s.cookies.set(name.strip(), val.strip())
    if proxy:
        # Accepts http://, https://, socks5:// (socks needs `pip install requests[socks]`).
        # Authenticated proxies: http://user:pass@host:port
        if "://" not in proxy:
            proxy = "http://" + proxy
        s.proxies.update({"http": proxy, "https": proxy})
    if insecure:
        s.verify = False
        # Burp/ZAP self-signed cert produces a flood of warnings — quiet them.
        try:
            from urllib3.exceptions import InsecureRequestWarning
            import urllib3
            urllib3.disable_warnings(InsecureRequestWarning)
        except Exception:
            pass
    retry = Retry(total=2, backoff_factor=0.3,
                  status_forcelist=[500, 502, 503, 504],
                  allowed_methods=["GET", "HEAD"], raise_on_status=False)
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    return s


# =============================================================================
# Crawler — HTML parser that yields same-origin links + script srcs
# =============================================================================

class _LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []

    def handle_starttag(self, tag, attrs):
        d = dict(attrs)
        if tag == "a" and d.get("href"):
            self.links.append(d["href"])
        elif tag == "script" and d.get("src"):
            self.scripts.append(d["src"])
        elif tag == "link" and d.get("href"):
            self.links.append(d["href"])


def _same_origin(a: str, b: str) -> bool:
    pa, pb = urlparse(a), urlparse(b)
    return (pa.scheme, pa.netloc) == (pb.scheme, pb.netloc)


def crawl(start_url: str, session: requests.Session, depth: int,
          max_pages: int, timeout: int, state: ScanState) -> Iterable[tuple[str, str]]:
    """
    BFS crawl from start_url, yielding (url, body_text) for each fetched page.
    Stays same-origin; honours --depth and --max-pages.
    """
    queue: deque[tuple[str, int]] = deque([(start_url, 0)])
    while queue and len(state.visited) < max_pages:
        url, d = queue.popleft()
        if url in state.visited:
            continue
        state.visited.add(url)
        try:
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as e:
            logger.debug("fetch failed %s: %s", url, e)
            continue
        with state.lock:
            state.request_count += 1
        ct = resp.headers.get("Content-Type", "")
        if not any(t in ct for t in ("text/html", "application/javascript",
                                     "text/javascript", "application/json",
                                     "text/plain", "application/xml")):
            continue
        body = resp.text
        yield url, body

        if d >= depth or "html" not in ct:
            continue
        parser = _LinkExtractor()
        try:
            parser.feed(body)
        except Exception:
            continue
        for href in parser.links + parser.scripts:
            absolute = urljoin(url, href.split("#", 1)[0])
            if not absolute.startswith(("http://", "https://")):
                continue
            if not _same_origin(start_url, absolute):
                continue
            if absolute not in state.visited:
                queue.append((absolute, d + 1))


# =============================================================================
# Pattern scan
# =============================================================================

def _context_window(text: str, start: int, end: int, pad: int = 40) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    snippet = text[a:b].replace("\n", " ").replace("\r", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def scan_text(text: str, source: str, state: ScanState) -> int:
    """Apply every pattern to `text`. Returns number of new (deduped) hits."""
    new_hits = 0
    for p in PATTERNS:
        for m in p["compiled"].finditer(text):
            group_idx = p.get("group", 0)
            try:
                secret = m.group(group_idx)
            except IndexError:
                secret = m.group(0)
            if not secret or len(secret) < 8:
                continue
            f = Finding(
                severity=p["severity"],
                pattern=p["name"],
                confidence=p["confidence"],
                secret=secret,
                source_url=source,
                context=_context_window(text, m.start(), m.end()),
            )
            if state.add(f):
                new_hits += 1
    return new_hits


# =============================================================================
# ASP.NET ViewState + IIS MachineKey identification
# =============================================================================
# Implements the workflow from IIS-Machine-Keys.md:
#   1. find __VIEWSTATE + __VIEWSTATEGENERATOR
#   2. for each (validationKey, decryptionKey) pair, compute HMAC-SHA1 of
#      (data_without_signature || generator_bytes_le) and compare against the
#      trailing 20 bytes of the decoded viewstate.
#   3. report a match as critical.

VIEWSTATE_RE = re.compile(
    r"name=[\"']__VIEWSTATE[\"'][^>]*value=[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
VSGEN_RE = re.compile(
    r"name=[\"']__VIEWSTATEGENERATOR[\"'][^>]*value=[\"']([0-9A-Fa-f]+)[\"']",
    re.IGNORECASE,
)


def find_viewstate(html: str) -> Optional[tuple[str, Optional[str]]]:
    m = VIEWSTATE_RE.search(html)
    if not m:
        return None
    vs = m.group(1)
    g = VSGEN_RE.search(html)
    return vs, g.group(1) if g else None


def _hmac_match(data: bytes, sig: bytes, key: bytes, modifier: bytes,
                algo) -> bool:
    h = hmac.new(key, data + modifier, algo).digest()
    return hmac.compare_digest(h, sig)


def load_machinekeys(path: Path) -> list[tuple[bytes, bytes]]:
    """Load (validationKey, decryptionKey) pairs from MachineKeys.txt."""
    pairs: list[tuple[bytes, bytes]] = []
    if not path.exists():
        logger.warning("MachineKeys file not found: %s", path)
        return pairs
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or "," not in line:
                continue
            v, _, d = line.partition(",")
            try:
                vb = bytes.fromhex(v.strip())
                db = bytes.fromhex(d.strip())
            except ValueError:
                continue
            if vb:
                pairs.append((vb, db))
    return pairs


def try_identify_machinekey(viewstate_b64: str, generator_hex: Optional[str],
                            keys: list[tuple[bytes, bytes]]
                            ) -> Optional[dict]:
    """
    Returns matched key dict on success, else None.
    Tries SHA1 (20-byte sig) first — the historical default — then HMACSHA256
    (32-byte sig) for newer ASP.NET 4.5+ deployments.
    """
    try:
        raw = base64.b64decode(viewstate_b64, validate=False)
    except Exception:
        return None
    if len(raw) <= 20:
        return None

    if generator_hex:
        try:
            # __VIEWSTATEGENERATOR is little-endian uint32 hex
            gen_int = int(generator_hex, 16)
            modifier = gen_int.to_bytes(4, byteorder="little", signed=False)
        except ValueError:
            modifier = b""
    else:
        modifier = b""

    candidates = [
        ("SHA1",       hashlib.sha1,   20),
        ("HMACSHA256", hashlib.sha256, 32),
        ("HMACSHA384", hashlib.sha384, 48),
        ("HMACSHA512", hashlib.sha512, 64),
        ("MD5",        hashlib.md5,    16),
    ]
    for algo_name, algo, sig_len in candidates:
        if len(raw) <= sig_len:
            continue
        data, sig = raw[:-sig_len], raw[-sig_len:]
        for vk, dk in keys:
            if _hmac_match(data, sig, vk, modifier, algo):
                return {
                    "algorithm": algo_name,
                    "validation_key": vk.hex().upper(),
                    "decryption_key": dk.hex().upper(),
                    "generator": generator_hex or "",
                }
    return None


# =============================================================================
# Optional active validation (read-only API calls)
# =============================================================================

def _validate_telegram(token: str, session: requests.Session) -> Optional[bool]:
    try:
        r = session.get(f"https://api.telegram.org/bot{token}/getMe", timeout=10)
        if r.status_code == 200 and r.json().get("ok"):
            return True
        if r.status_code in (401, 404):
            return False
    except requests.RequestException:
        pass
    return None


def _validate_github(token: str, session: requests.Session) -> Optional[bool]:
    try:
        r = session.get("https://api.github.com/user",
                        headers={"Authorization": f"token {token}"}, timeout=10)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
    except requests.RequestException:
        pass
    return None


def _validate_slack(token: str, session: requests.Session) -> Optional[bool]:
    try:
        r = session.post("https://slack.com/api/auth.test",
                         data={"token": token}, timeout=10)
        if r.status_code == 200:
            return bool(r.json().get("ok"))
    except requests.RequestException:
        pass
    return None


def _validate_sendgrid(token: str, session: requests.Session) -> Optional[bool]:
    try:
        r = session.get("https://api.sendgrid.com/v3/scopes",
                        headers={"Authorization": f"Bearer {token}"}, timeout=10)
        if r.status_code == 200:
            return True
        if r.status_code == 401:
            return False
    except requests.RequestException:
        pass
    return None


VALIDATORS = {
    "telegram": _validate_telegram,
    "github":   _validate_github,
    "slack":    _validate_slack,
    "sendgrid": _validate_sendgrid,
}


def validate_findings(findings: list[Finding], session: requests.Session,
                      threads: int) -> None:
    """Mutates findings in place — sets .validated to 'valid' / 'invalid' / None."""
    pattern_to_validator = {p["name"]: p.get("validator") for p in PATTERNS
                            if p.get("validator")}

    def _check(f: Finding) -> None:
        v = pattern_to_validator.get(f.pattern)
        if not v:
            return
        fn = VALIDATORS[v]
        result = fn(f.secret, session)
        if result is True:
            f.validated = "valid"
        elif result is False:
            f.validated = "invalid"

    with ThreadPoolExecutor(max_workers=threads) as pool:
        list(pool.map(_check, findings))


# =============================================================================
# Output
# =============================================================================

SEV_TAG = {"critical": "CRIT", "high": "HIGH", "medium": "MED ", "low": "LOW ",
           "info": "INFO"}
SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def print_findings(findings: list[Finding], machine_key_hit: Optional[dict]) -> None:
    if machine_key_hit:
        print()
        print("=" * 70)
        print("[!! CRITICAL] Known IIS MachineKey identified — full ViewState RCE")
        print("=" * 70)
        print(f"  algorithm     : {machine_key_hit['algorithm']}")
        print(f"  generator     : {machine_key_hit['generator']}")
        print(f"  validationKey : {machine_key_hit['validation_key']}")
        print(f"  decryptionKey : {machine_key_hit['decryption_key']}")
        print("  next step     : forge ViewState with ysoserial.net (see "
              "IIS-Machine-Keys.md)")
        print()

    if not findings:
        print("[*] No API key / token leaks detected.")
        return

    findings.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.pattern))
    print(f"\n[*] {len(findings)} finding(s):\n")
    for f in findings:
        tag = SEV_TAG.get(f.severity, "????")
        valid = f" [{f.validated.upper()}]" if f.validated else ""
        print(f"  [{tag}] {f.pattern}{valid}")
        print(f"         secret : {f.redacted()}")
        print(f"         source : {f.source_url}")
        print(f"         context: {f.context[:120]}")
        print()


def write_csv(findings: list[Finding], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["severity", "pattern", "confidence", "validated",
                    "secret", "source_url", "context"])
        for x in findings:
            w.writerow([x.severity, x.pattern, x.confidence,
                        x.validated or "", x.secret, x.source_url, x.context])


def write_json(findings: list[Finding], machine_key_hit: Optional[dict],
               path: Path, target: str) -> None:
    payload = {
        "target": target,
        "scanned_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "machine_key_hit": machine_key_hit,
        "findings": [asdict(f) for f in findings],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


# =============================================================================
# CLI
# =============================================================================

def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Scan a website for leaked API keys, tokens, and weak IIS "
                    "machine keys (defensive use only).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("target", help="URL to scan (or '-' to read stdin / use --file)")
    ap.add_argument("--file", help="Scan a local file instead of crawling")
    ap.add_argument("--depth", type=int, default=1,
                    help="Crawl depth from the start URL (default: 1)")
    ap.add_argument("--max-pages", type=int, default=50,
                    help="Hard cap on pages fetched (default: 50)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--header", action="append", default=[],
                    help="Extra HTTP header, e.g. --header 'X-Auth: token'")
    ap.add_argument("--cookie", action="append", default=[],
                    help="Cookie 'name=value' (repeatable)")
    ap.add_argument("--proxy",
                    help="Proxy URL — http://, https://, or socks5:// (the last "
                         "needs `pip install requests[socks]`). Supports auth: "
                         "http://user:pass@host:8080. Common: http://127.0.0.1:8080 "
                         "for Burp Suite, http://127.0.0.1:8081 for OWASP ZAP")
    ap.add_argument("--insecure", "-k", action="store_true",
                    help="Skip TLS certificate verification (use with --proxy when "
                         "intercepting via Burp / ZAP self-signed CA)")
    ap.add_argument("--machinekey", action="store_true",
                    help="Detect __VIEWSTATE and try to identify a known IIS "
                         "machine key from Files/MachineKeys.txt")
    ap.add_argument("--machinekey-file", default=str(DEFAULT_MACHINEKEYS),
                    help=f"Path to MachineKeys.txt (default: {DEFAULT_MACHINEKEYS})")
    ap.add_argument("--validate", action="store_true",
                    help="Actively call the issuing API (Telegram, GitHub, Slack, "
                         "SendGrid) to test if the leaked token is still valid")
    ap.add_argument("--csv", help="Write findings to this CSV file")
    ap.add_argument("--json", help="Write findings to this JSON file")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )

    state = ScanState()
    machine_key_hit: Optional[dict] = None

    # ---- local-file mode ------------------------------------------------
    if args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[-] file not found: {path}", file=sys.stderr)
            return 2
        body = path.read_text(encoding="utf-8", errors="ignore")
        scan_text(body, str(path), state)
        if args.machinekey:
            vs = find_viewstate(body)
            if vs:
                keys = load_machinekeys(Path(args.machinekey_file))
                machine_key_hit = try_identify_machinekey(vs[0], vs[1], keys)
        print_findings(state.findings, machine_key_hit)
        if args.csv:
            write_csv(state.findings, Path(args.csv))
        if args.json:
            write_json(state.findings, machine_key_hit, Path(args.json), str(path))
        return 0

    # ---- crawl mode -----------------------------------------------------
    target = args.target
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    session = build_session(args.timeout, args.proxy, args.header, args.cookie,
                            insecure=args.insecure)
    if args.proxy:
        print(f"[*] Routing requests through proxy: {args.proxy}"
              f"{' (TLS verify disabled)' if args.insecure else ''}")

    print(f"[*] Crawling {target} (depth={args.depth}, max={args.max_pages})")
    machinekeys = load_machinekeys(Path(args.machinekey_file)) if args.machinekey else []
    if args.machinekey:
        print(f"[*] Loaded {len(machinekeys)} machine-key pairs")

    pages_with_viewstate: list[tuple[str, str, Optional[str]]] = []
    for url, body in crawl(target, session, args.depth, args.max_pages,
                           args.timeout, state):
        hits = scan_text(body, url, state)
        if hits:
            logger.info("[+] %d new hit(s) at %s", hits, url)
        if args.machinekey:
            vs = find_viewstate(body)
            if vs:
                pages_with_viewstate.append((url, vs[0], vs[1]))

    print(f"[*] Crawled {len(state.visited)} URL(s); {state.request_count} request(s)")

    # Try to identify a known machine key. First match wins — same key is
    # reused across pages on a given app pool.
    if args.machinekey and pages_with_viewstate and machinekeys:
        print(f"[*] Found __VIEWSTATE on {len(pages_with_viewstate)} page(s); "
              f"testing against {len(machinekeys)} known keys…")
        for url, vs, gen in pages_with_viewstate:
            hit = try_identify_machinekey(vs, gen, machinekeys)
            if hit:
                hit["found_at"] = url
                machine_key_hit = hit
                break

    if args.validate and state.findings:
        print(f"[*] Validating {sum(1 for f in state.findings if any(p['name'] == f.pattern and p.get('validator') for p in PATTERNS))} token(s) against issuer APIs…")
        validate_findings(state.findings, session, args.threads)

    print_findings(state.findings, machine_key_hit)

    if args.csv:
        write_csv(state.findings, Path(args.csv))
        print(f"[*] CSV written → {args.csv}")
    if args.json:
        write_json(state.findings, machine_key_hit, Path(args.json), target)
        print(f"[*] JSON written → {args.json}")

    # Exit-code semantics: 1 if any critical/high finding, else 0
    has_serious = any(f.severity in ("critical", "high") for f in state.findings) \
                  or machine_key_hit is not None
    return 1 if has_serious else 0


if __name__ == "__main__":
    sys.exit(main())
