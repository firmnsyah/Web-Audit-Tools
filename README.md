# Web Audit Tools

Two standalone Python scripts for auditing your own website: one checks for broken links, the other performs a passive and active security scan.

> **Both tools are for websites you own or have explicit permission to test.**

---

## Getting Started

### Clone the repository

```bash
git clone https://github.com/frmnsyah/web-audit-tools.git
cd web-audit-tools
```

### Install dependencies

```bash
# Minimal (broken link checker + security audit)
pip install requests beautifulsoup4 tldextract

# Full (includes Playwright for SPA/JS sites)
pip install playwright && playwright install chromium
```

Or install all at once via requirements.txt:

```bash
pip install -r requirements.txt
```

### Create the output folder

```bash
mkdir output
```

Reports are written to `output/` by default. The folder must exist before running either script.

---

## Notes

- The `output/` folder must exist before running (it is not created automatically).
- The security auditor uses a catch-all baseline fingerprint in deep mode to suppress false positives from SPA/catch-all servers that return HTTP 200 for all unknown paths.
- `tldextract` is optional for the broken link checker but recommended for accurate subdomain detection on multi-part TLDs (e.g. `.ac.id`, `.co.uk`).
- Active checks (`--active`) make real HTTP requests with payloads. Only use against systems you own or have written permission to test.

## Proxy usage

Both scripts accept `--proxy URL`. This routes every HTTP request (and Playwright browser traffic in `--spa` mode) through the proxy, so your real IP is not exposed to the target server.

```bash
# HTTP proxy — mitmproxy, Burp Suite, Charles, Fiddler
--proxy http://127.0.0.1:8080

# SOCKS5 — Tor, SSH tunnel, VPN gateway
--proxy socks5://127.0.0.1:1080

# With credentials
--proxy http://user:pass@proxy.example.com:3128

# Bare host:port — http:// is added automatically
--proxy 127.0.0.1:8080
```

When a proxy is active, the script prints a reminder line:

```
Proxy  : http://127.0.0.1:8080  (server logs will show this IP, not yours)
```

**Learning tip:** run a scan without `--proxy` first, then again with `--proxy`, and compare your server's access log — you will see your real IP replaced by the proxy's egress IP. This is the clearest way to understand what a server actually records about each visitor.

---

## broken_link_checker.py

Crawls a website and reports every broken or suspicious link.

**Features:**

- Browser-like headers to reduce false positives from bot-protection
- HEAD → Range GET → full GET fallback chain
- Concurrent link checking per page (`ThreadPoolExecutor`)
- Status categorization: `BROKEN` / `SUSPICIOUS` / `OK`
- Subdomain-aware scope detection via Public Suffix List (`tldextract`)
- Optional Playwright rendering for JavaScript/SPA sites
- Optional browser-based re-verification of suspicious links

### Installation

```bash
pip install requests beautifulsoup4 tldextract
# For SPA/JS sites:
pip install playwright && playwright install chromium
```

### Usage

```bash
# Standard crawl
python broken_link_checker.py https://example.com

# Limit pages and increase concurrency
python broken_link_checker.py https://example.com --max-pages 500 --concurrency 16

# JavaScript/SPA site
python broken_link_checker.py https://example.com --spa

# Include subdomains in crawl + re-verify suspicious links via browser
python broken_link_checker.py https://example.com --spa --include-subdomains --verify-suspicious

# Custom output path
python broken_link_checker.py https://example.com --output results.csv

# Route through a local proxy (e.g. mitmproxy, Burp Suite)
python broken_link_checker.py https://example.com --proxy http://127.0.0.1:8080

# Route through SOCKS5 (e.g. Tor, SSH tunnel)
python broken_link_checker.py https://example.com --proxy socks5://127.0.0.1:1080
```

### Options

| Flag                   | Default                       | Description                                                                             |
| ---------------------- | ----------------------------- | --------------------------------------------------------------------------------------- |
| `--timeout`            | `15`                          | HTTP request timeout in seconds                                                         |
| `--delay`              | `0.2`                         | Delay between page crawls (seconds)                                                     |
| `--max-pages`          | `1000`                        | Maximum pages to crawl                                                                  |
| `--concurrency`        | `8`                           | Concurrent link checks per page                                                         |
| `--output`             | `output/broken_links.csv`     | Main CSV report path                                                                    |
| `--spa`                | off                           | Use Playwright for JS-rendered pages                                                    |
| `--wait-until`         | `domcontentloaded`            | Playwright wait condition (`load`, `domcontentloaded`, `networkidle`, `commit`)         |
| `--page-timeout`       | `30`                          | Playwright page load timeout in seconds                                                 |
| `--verify-suspicious`  | off                           | Re-check 401/403/429 links via browser (requires `--spa`)                               |
| `--include-subdomains` | off                           | Also crawl pages on subdomains of the root domain                                       |
| `--subdomain-output`   | `output/subdomain_health.csv` | CSV path for per-subdomain health summary                                               |
| `--proxy URL`          | —                             | Proxy for all requests (`http://`, `https://`, `socks5://`). Applies to Playwright too. |

### Output

Reports are written to the `output/` folder by default.

**`output/broken_links.csv`** — all non-OK links:

| Column     | Description                                                              |
| ---------- | ------------------------------------------------------------------------ |
| `scope`    | `same-host`, `subdomain`, or `external`                                  |
| `category` | `broken` or `suspicious`                                                 |
| `status`   | HTTP status code                                                         |
| `url`      | The link URL                                                             |
| `method`   | Which method returned the result (`HEAD`, `GET-Range`, `GET`, `BROWSER`) |
| `error`    | Connection error message (if any)                                        |
| `found_on` | Semicolon-separated list of pages where this link appears                |

**`output/subdomain_health.csv`** — one row per unique subdomain host with the worst status seen.

---

## security_audit.py

Security audit tool for your own website. Runs in three cumulative modes:

- **Default** — passive checks: headers, TLS, cookies, CORS, CSRF, admin panels, error disclosure, HTTP methods, host header injection, robots.txt
- **`--deep`** — also probes sensitive files, private keys, WordPress paths, and directory listings
- **`--active`** — sends active canary payloads for XSS, SQLi, SSTI, LFI, Open Redirect, SSRF, and JSONP. **Use only with permission.**

**What it checks:**

| Mode       | Check                                                                                                     |
| ---------- | --------------------------------------------------------------------------------------------------------- |
| Default    | HTTPS redirect + TLS configuration                                                                        |
| Default    | Security headers: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| Default    | CSP weaknesses (`unsafe-inline`, `unsafe-eval`)                                                           |
| Default    | Cookie flags: `Secure`, `HttpOnly`, `SameSite`; JWT detection                                             |
| Default    | CORS misconfiguration (`Access-Control-Allow-Origin: *`)                                                  |
| Default    | Server fingerprinting: `Server`, `X-Powered-By`, WordPress generator meta                                 |
| Default    | CSRF — missing tokens on state-changing forms                                                             |
| Default    | Exposed admin panels (login-free access)                                                                  |
| Default    | Error/stack trace disclosure                                                                              |
| Default    | Dangerous HTTP methods (TRACE/XST, PUT file upload)                                                       |
| Default    | Host header injection (body reflection, redirect hijack)                                                  |
| Default    | `robots.txt` and `sitemap.xml` inspection                                                                 |
| `--deep`   | Sensitive file exposure: `.env`, `.git/config`, SQL dumps, PHP backups, etc.                              |
| `--deep`   | Private key / credential file exposure                                                                    |
| `--deep`   | WordPress: version disclosure, user enumeration, exposed installer                                        |
| `--deep`   | Directory listing detection                                                                               |
| `--active` | Cross-Site Scripting (XSS) — HTML and JS context                                                          |
| `--active` | SQL Injection — error-based + boolean differential                                                        |
| `--active` | Server-Side Template Injection (SSTI) — Jinja2, Twig, Smarty, Velocity                                    |
| `--active` | Local File Inclusion (LFI) — PHP filter wrappers, URL-encoded variants                                    |
| `--active` | Open Redirect — 4 bypass variants                                                                         |
| `--active` | Server-Side Request Forgery (SSRF)                                                                        |
| `--active` | JSONP callback reflection                                                                                 |

> RCE, XXE, IDOR, and Auth Bypass are **not** auto-tested — they require manual work or are too dangerous to run unattended.

### Installation

```bash
pip install requests
# For enhanced HTML parsing (admin panel / CSRF / input discovery):
pip install beautifulsoup4
```

### Usage

```bash
# Passive scan (headers, TLS, cookies, CORS, etc.)
python security_audit.py https://example.com

# Deep scan (also probes sensitive paths)
python security_audit.py https://example.com --deep

# Active scan (sends payloads — use only with permission)
python security_audit.py https://example.com --active

# Full scan with auth
python security_audit.py https://example.com --deep --active \
  --cookie "session=abc123" --bearer "eyJ..."

# Run only specific checks
python security_audit.py https://example.com --active --only xss,sqli

# Skip specific checks
python security_audit.py https://example.com --skip methods,host

# List all available check IDs
python security_audit.py https://example.com --list-checks

# JSON output in addition to CSV
python security_audit.py https://example.com --deep --active --json output/report.json

# Route through a local proxy (see which IP your server logs)
python security_audit.py https://example.com --proxy http://127.0.0.1:8080

# Route through SOCKS5 (e.g. Tor)
python security_audit.py https://example.com --proxy socks5://127.0.0.1:1080
```

### Options

| Flag                     | Default                     | Description                                                  |
| ------------------------ | --------------------------- | ------------------------------------------------------------ |
| `--timeout`              | `10`                        | Request timeout in seconds                                   |
| `--delay`                | `0.1`                       | Delay between requests (seconds)                             |
| `--threads`              | `8`                         | Parallel workers for active scans                            |
| `--max-requests`         | `2000`                      | Global HTTP request budget (safety cap)                      |
| `--max-crawl-pages`      | `15`                        | Pages to crawl for CSRF/admin/input discovery                |
| `--deep`                 | off                         | Probe sensitive files, private keys, dir listings            |
| `--active`               | off                         | Send active payloads (XSS/SQLi/SSTI/LFI/SSRF/redirect/JSONP) |
| `--cookie NAME=VALUE`    | —                           | Add a cookie (repeatable)                                    |
| `--header "Name: Value"` | —                           | Add an HTTP header (repeatable)                              |
| `--bearer TOKEN`         | —                           | Set `Authorization: Bearer` header                           |
| `--proxy URL`            | —                           | Proxy for all requests (`http://`, `https://`, `socks5://`)  |
| `--skip IDs`             | —                           | Comma-separated check IDs to skip                            |
| `--only IDs`             | —                           | Comma-separated check IDs to run (overrides `--skip`)        |
| `--output`               | `output/security_audit.csv` | CSV report path                                              |
| `--json`                 | —                           | Optional JSON report path                                    |
| `-v / --verbose`         | off                         | Verbose logging                                              |
| `--list-checks`          | —                           | Print all check IDs and exit                                 |

### Check IDs

Use these with `--skip` or `--only`:

| ID            | Mode    | Description                           |
| ------------- | ------- | ------------------------------------- |
| `tls`         | passive | HTTPS redirect + TLS                  |
| `headers`     | passive | Security response headers             |
| `cookies`     | passive | Cookie security flags + JWT detection |
| `cors`        | passive | CORS misconfiguration                 |
| `recon`       | passive | robots.txt + sitemap.xml              |
| `fingerprint` | passive | Server/version header disclosure      |
| `csrf`        | passive | Missing CSRF tokens on forms          |
| `admin`       | passive | Exposed admin panels                  |
| `errors`      | passive | Error / stack trace disclosure        |
| `methods`     | passive | Dangerous HTTP methods                |
| `host`        | passive | Host header injection                 |
| `files`       | deep    | Sensitive file exposure               |
| `keys`        | deep    | Private key / credential exposure     |
| `wordpress`   | deep    | WordPress info disclosure             |
| `dirs`        | deep    | Directory listing                     |
| `xss`         | active  | Cross-Site Scripting                  |
| `sqli`        | active  | SQL Injection                         |
| `ssti`        | active  | Server-Side Template Injection        |
| `lfi`         | active  | Local File Inclusion                  |
| `redirect`    | active  | Open Redirect                         |
| `ssrf`        | active  | Server-Side Request Forgery           |
| `jsonp`       | active  | JSONP callback reflection             |

### Output

Console report grouped by severity, plus files written to the `output/` folder.

**`output/security_audit.csv`**:

| Column           | Description                                                        |
| ---------------- | ------------------------------------------------------------------ |
| `severity`       | `critical`, `high`, `medium`, `low`, or `info`                     |
| `category`       | Finding category (e.g. `Headers`, `TLS`, `Cookies`, `CORS`, `XSS`) |
| `title`          | Short finding title                                                |
| `detail`         | Specific detail about the issue                                    |
| `url`            | URL where the issue was found                                      |
| `evidence`       | Payload and matched signature (active checks)                      |
| `cwe`            | CWE reference (e.g. `CWE-79`)                                      |
| `recommendation` | How to fix it                                                      |

**`--json` path** (optional): same findings as structured JSON.

### Severity levels

| Level      | Meaning                                                                              |
| ---------- | ------------------------------------------------------------------------------------ |
| `critical` | Immediate risk — credentials or source code exposed                                  |
| `high`     | Significant attack surface (missing HSTS, confirmed injection, HTTP serving content) |
| `medium`   | Should be fixed (missing CSP, weak cookie flags, dangerous methods)                  |
| `low`      | Minor hardening improvements                                                         |
| `info`     | Informational — review but no immediate action required                              |
