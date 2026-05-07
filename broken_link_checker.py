"""
Broken Link Checker — advanced edition
- Browser-like headers to avoid false-positive bot blocks
- Retry with backoff for transient errors
- Concurrent link checking (ThreadPoolExecutor)
- Status categorization: BROKEN / SUSPICIOUS / OK
- HEAD -> Range GET -> full GET fallback chain
- Subdomain-aware: detects registrable domain (eTLD+1) via Public Suffix List
- Optional Playwright rendering for JS-heavy SPA sites
- Optional browser-based verification of suspicious links (--verify-suspicious)
"""

import argparse
import csv
import sys
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from threading import Lock
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:
    import tldextract
    _tld_extract = tldextract.TLDExtract(suffix_list_urls=())  # offline, use cached PSL
    HAS_TLDEXTRACT = True
except ImportError:
    HAS_TLDEXTRACT = False

BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9,id;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Cache-Control": "max-age=0",
}

LINK_ATTRS = {
    "a": "href",
    "link": "href",
    "img": "src",
    "script": "src",
    "iframe": "src",
    "source": "src",
    "video": "src",
    "audio": "src",
}

SKIP_PREFIXES = (
    "mailto:", "tel:", "javascript:", "#",
    "about:", "data:", "blob:", "file:", "ftp:",
    "ws:", "wss:", "chrome:", "chrome-extension:",
)

# Status code semantics
BROKEN_CODES = {404, 410, 500, 502, 503, 504, 521, 522, 523, 524}
SUSPICIOUS_CODES = {401, 403, 429, 999}  # may be bot-protection, not actual broken

_SCOPE_PRIORITY: dict[str, int] = {"broken": 0, "suspicious": 1, "ok": 2}


@dataclass
class LinkResult:
    url: str
    status: Optional[int] = None
    error: Optional[str] = None
    method: str = ""
    category: str = "ok"  # ok | broken | suspicious
    scope: str = "external"  # same-host | subdomain | external
    sources: set = field(default_factory=set)


@dataclass
class CrawlConfig:
    url: str
    timeout: int = 15
    delay: float = 0.2
    max_pages: int = 1000
    concurrency: int = 8
    output: str = "broken_links.csv"
    spa: bool = False
    wait_until: str = "domcontentloaded"
    page_timeout: int = 30
    verify_suspicious: bool = False
    include_subdomains: bool = False
    subdomain_output: str = "subdomain_health.csv"
    proxy: Optional[str] = None


def get_registrable_domain(netloc: str) -> str:
    """Return the registrable domain (eTLD+1) from a netloc.
    e.g. 'dti.unhas.ac.id' -> 'unhas.ac.id'
         'www.example.co.uk' -> 'example.co.uk'
    Falls back to last-2-parts heuristic if tldextract is not installed.
    """
    host = netloc.split(":")[0].lower()
    if HAS_TLDEXTRACT:
        ext = _tld_extract(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
        return host
    # Fallback: handle common 2-part TLDs like .co.uk, .ac.id, .go.id
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_part_suffixes = {
        "co.uk", "co.id", "ac.id", "go.id", "or.id", "sch.id", "web.id",
        "co.jp", "ac.jp", "com.au", "com.sg", "com.my",
    }
    last_two = ".".join(parts[-2:])
    if last_two in two_part_suffixes and len(parts) >= 3:
        return ".".join(parts[-3:])
    return last_two


def get_scope(url: str, root_netloc: str, root_registrable: str) -> str:
    """Categorize a URL relative to the crawl origin."""
    netloc = urlparse(url).netloc.lower()
    if netloc == root_netloc.lower():
        return "same-host"
    if get_registrable_domain(netloc) == root_registrable:
        return "subdomain"
    return "external"


def normalize(url: str) -> str:
    parsed = urlparse(url)
    return parsed._replace(fragment="").geturl()


def categorize(status: Optional[int], error: Optional[str]) -> str:
    if error is not None:
        return "broken"
    if status is None:
        return "broken"
    if status in BROKEN_CODES:
        return "broken"
    if status in SUSPICIOUS_CODES:
        return "suspicious"
    if status >= 400:
        return "broken"
    return "ok"


def extract_links(html: str, base_url: str) -> set[str]:
    soup = BeautifulSoup(html, "html.parser")
    found: set[str] = set()
    for tag, attr in LINK_ATTRS.items():
        for el in soup.find_all(tag):
            value = el.get(attr)
            if not value:
                continue
            value = value.strip()
            if not value or value.lower().startswith(SKIP_PREFIXES):
                continue
            absolute = urljoin(base_url, value)
            if not absolute.lower().startswith(("http://", "https://")):
                continue
            found.add(normalize(absolute))
    return found


def _normalize_proxy(proxy: Optional[str]) -> Optional[str]:
    if proxy and "://" not in proxy:
        return f"http://{proxy}"
    return proxy


def build_session(proxy: Optional[str] = None) -> requests.Session:
    """Session with browser-like headers and retry logic for transient errors."""
    session = requests.Session()
    session.headers.update(BROWSER_HEADERS)
    proxy = _normalize_proxy(proxy)
    if proxy:
        session.proxies.update({"http": proxy, "https": proxy})
    retry = Retry(
        total=2,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=20, pool_maxsize=20)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def check_link(session: requests.Session, url: str, timeout: int):
    """
    HEAD -> small Range GET -> full GET fallback.
    Returns (status, error, method).
    """
    referer = f"{urlparse(url).scheme}://{urlparse(url).netloc}/"
    headers_with_referer = {"Referer": referer}

    # 1. HEAD
    try:
        resp = session.head(url, allow_redirects=True, timeout=timeout,
                            headers=headers_with_referer)
        if resp.status_code < 400:
            return resp.status_code, None, "HEAD"
        if resp.status_code not in (405, 403, 429, 501):
            return resp.status_code, None, "HEAD"
    except requests.RequestException:
        pass

    # 2. Range GET (only fetch first 1KB — saves bandwidth)
    try:
        range_headers = {**headers_with_referer, "Range": "bytes=0-1023"}
        resp = session.get(url, allow_redirects=True, timeout=timeout,
                           headers=range_headers, stream=True)
        resp.close()
        if resp.status_code < 400 or resp.status_code == 206:
            return resp.status_code, None, "GET-Range"
        if resp.status_code not in (403, 429, 416):
            return resp.status_code, None, "GET-Range"
    except requests.RequestException:
        pass

    # 3. Full GET (last resort)
    try:
        resp = session.get(url, allow_redirects=True, timeout=timeout,
                           headers=headers_with_referer, stream=True)
        resp.close()
        return resp.status_code, None, "GET"
    except requests.RequestException as e:
        return None, str(e), "GET"


class StaticFetcher:
    def __init__(self, timeout: int, proxy: Optional[str] = None):
        self.timeout = timeout
        self.session = build_session(proxy)

    def fetch(self, url: str):
        try:
            resp = self.session.get(url, timeout=self.timeout)
        except requests.RequestException as e:
            return None, str(e)
        if resp.status_code >= 400:
            return None, f"HTTP {resp.status_code}"
        if "text/html" not in resp.headers.get("Content-Type", ""):
            return None, None
        return resp.text, None

    def close(self):
        self.session.close()


class PlaywrightFetcher:
    def __init__(self, page_timeout: int, wait_until: str = "domcontentloaded",
                 proxy: Optional[str] = None):
        from playwright.sync_api import sync_playwright

        self.timeout_ms = page_timeout * 1000
        self.wait_until = wait_until
        self._pw = sync_playwright().start()
        launch_kwargs: dict = {"headless": True}
        proxy = _normalize_proxy(proxy)
        if proxy:
            launch_kwargs["proxy"] = {"server": proxy}
        self.browser = self._pw.chromium.launch(**launch_kwargs)
        self.context = self.browser.new_context(
            user_agent=BROWSER_HEADERS["User-Agent"],
            extra_http_headers={k: v for k, v in BROWSER_HEADERS.items()
                                if k.lower() != "user-agent"},
        )

    def fetch(self, url: str):
        page = self.context.new_page()
        try:
            resp = page.goto(url, timeout=self.timeout_ms, wait_until=self.wait_until)
            if resp is None:
                return None, "no response"
            if resp.status >= 400:
                return None, f"HTTP {resp.status}"
            ctype = (resp.headers or {}).get("content-type", "")
            if "text/html" not in ctype:
                return None, None
            html = page.content()
            return html, None
        except Exception as e:
            return None, str(e)
        finally:
            page.close()

    def verify_link(self, url: str, timeout_ms: Optional[int] = None):
        """Use the headless browser to verify a suspicious link."""
        page = self.context.new_page()
        try:
            resp = page.goto(url, timeout=timeout_ms or self.timeout_ms,
                             wait_until="domcontentloaded")
            if resp is None:
                return None, "no response"
            return resp.status, None
        except Exception as e:
            return None, str(e)
        finally:
            page.close()

    def close(self):
        self.context.close()
        self.browser.close()
        self._pw.stop()


def _verify_suspicious_links(
    fetcher: PlaywrightFetcher,
    results: dict[str, LinkResult],
) -> None:
    suspicious = [r for r in results.values() if r.category == "suspicious"]
    if not suspicious:
        return
    print(f"\n[VERIFY] Re-checking {len(suspicious)} suspicious links via browser...",
          flush=True)
    for r in suspicious:
        status, err = fetcher.verify_link(r.url)
        new_cat = categorize(status, err)
        if new_cat == "ok":
            print(f"  [RECOVERED] {r.url} -> {status}", flush=True)
            r.status = status
            r.error = None
            r.category = "ok"
            r.method = "BROWSER"
        else:
            print(f"  [STILL-{new_cat.upper()}] {r.url} -> {status or err}", flush=True)


def crawl(config: CrawlConfig) -> dict[str, LinkResult]:
    root_netloc = urlparse(config.url).netloc
    root_registrable = get_registrable_domain(root_netloc)
    print(f"Root domain: {root_netloc}  |  Registrable: {root_registrable}", flush=True)
    if config.include_subdomains:
        print("Subdomain crawl: ENABLED — pages on subdomains will also be crawled.",
              flush=True)

    fetcher = (
        PlaywrightFetcher(config.page_timeout, config.wait_until, config.proxy)
        if config.spa else StaticFetcher(config.timeout, config.proxy)
    )
    link_session = build_session(config.proxy)

    visited_pages: set[str] = set()
    results: dict[str, LinkResult] = {}
    results_lock = Lock()
    queue: deque[str] = deque([config.url])

    def in_crawl_scope(link: str) -> bool:
        scope = get_scope(link, root_netloc, root_registrable)
        if scope == "same-host":
            return True
        if scope == "subdomain" and config.include_subdomains:
            return True
        return False

    def check_one(link: str, source_page: str) -> LinkResult:
        status, error, method = check_link(link_session, link, config.timeout)
        category = categorize(status, error)
        scope = get_scope(link, root_netloc, root_registrable)
        with results_lock:
            if link in results:
                results[link].sources.add(source_page)
                return results[link]
            r = LinkResult(url=link, status=status, error=error,
                           method=method, category=category,
                           scope=scope, sources={source_page})
            results[link] = r
            return r

    try:
        while queue and len(visited_pages) < config.max_pages:
            page_url = normalize(queue.popleft())
            if page_url in visited_pages:
                continue
            visited_pages.add(page_url)

            print(f"[CRAWL {len(visited_pages)}/{config.max_pages}] {page_url}",
                  flush=True)
            html, error = fetcher.fetch(page_url)
            if error:
                print(f"  [PAGE-ERROR] {error}", flush=True)
                with results_lock:
                    if page_url not in results:
                        results[page_url] = LinkResult(
                            url=page_url, error=error,
                            category="broken", sources={page_url})
                continue
            if html is None:
                continue

            links = extract_links(html, page_url)
            new_links: list[str] = []
            with results_lock:
                for link in links:
                    if link in results:
                        results[link].sources.add(page_url)
                    else:
                        new_links.append(link)

            with ThreadPoolExecutor(max_workers=config.concurrency) as ex:
                futures = {ex.submit(check_one, link, page_url): link
                           for link in new_links}
                for fut in as_completed(futures):
                    r = fut.result()
                    tag = {"ok": "OK", "broken": "BROKEN", "suspicious": "SUSP"}[r.category]
                    print(f"  [{tag:5}] {r.status or 'ERR':>3} {r.method:9} {r.url}",
                          flush=True)

            time.sleep(config.delay)

            with results_lock:
                for link in links:
                    if (in_crawl_scope(link)
                            and link not in visited_pages
                            and results.get(link)
                            and results[link].category == "ok"):
                        queue.append(link)

    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Saving partial results...", flush=True)
    finally:
        if config.spa and config.verify_suspicious and isinstance(fetcher, PlaywrightFetcher):
            _verify_suspicious_links(fetcher, results)
        fetcher.close()
        link_session.close()

    return results


def write_report(results: dict[str, LinkResult], output_path: str) -> list[LinkResult]:
    issues = [r for r in results.values() if r.category != "ok"]
    scope_order = {"same-host": 0, "subdomain": 1, "external": 2}
    issues.sort(key=lambda r: (scope_order.get(r.scope, 99), r.category, r.url))
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["scope", "category", "status", "url", "method", "error", "found_on"])
        for r in issues:
            writer.writerow([r.scope, r.category, r.status or "", r.url, r.method,
                             r.error or "", "; ".join(sorted(r.sources))])
    return issues


def write_subdomain_report(
    results: dict[str, LinkResult], output_path: str
) -> list[dict]:
    """Aggregate subdomain health: each unique subdomain host with worst status seen."""
    by_host: dict[str, list[LinkResult]] = defaultdict(list)
    for r in results.values():
        if r.scope == "subdomain":
            host = urlparse(r.url).netloc
            by_host[host].append(r)
    if not by_host:
        return []

    rows = []
    for host, items in by_host.items():
        worst = min(items, key=lambda r: _SCOPE_PRIORITY.get(r.category, 99))
        rows.append({
            "host": host,
            "category": worst.category,
            "status": worst.status,
            "error": worst.error,
            "url_sample": worst.url,
            "link_count": len(items),
        })
    rows.sort(key=lambda r: (_SCOPE_PRIORITY.get(r["category"], 99), r["host"]))
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["host", "category", "status", "error", "url_sample", "link_count"])
        for r in rows:
            writer.writerow([r["host"], r["category"], r["status"] or "",
                             r["error"] or "", r["url_sample"], r["link_count"]])
    return rows


def main():
    parser = argparse.ArgumentParser(description="Find broken links on a website (advanced).")
    parser.add_argument("url", help="Starting URL (e.g. https://example.com)")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP request timeout (s)")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="Delay between page crawls (s)")
    parser.add_argument("--max-pages", type=int, default=1000, help="Max pages to crawl")
    parser.add_argument("--concurrency", type=int, default=8,
                        help="Concurrent link checks per page")
    parser.add_argument("--output", default="output/broken_links.csv", help="CSV output path")
    parser.add_argument("--spa", action="store_true",
                        help="Render pages with Playwright (for JS/SPA sites)")
    parser.add_argument("--wait-until",
                        choices=["load", "domcontentloaded", "networkidle", "commit"],
                        default="domcontentloaded",
                        help="Playwright wait condition")
    parser.add_argument("--page-timeout", type=int, default=30,
                        help="Playwright page load timeout (s)")
    parser.add_argument("--verify-suspicious", action="store_true",
                        help="Re-check 401/403/429 links via real browser "
                             "(requires --spa). Reduces false positives from bot detection.")
    parser.add_argument("--include-subdomains", action="store_true",
                        help="Also crawl pages on subdomains of the registrable domain. "
                             "Subdomain links are always health-checked; this flag enables "
                             "crawling them too.")
    parser.add_argument("--subdomain-output", default="output/subdomain_health.csv",
                        help="CSV path for per-subdomain health summary")
    parser.add_argument("--proxy", metavar="URL",
                        help="Proxy URL for all requests, e.g. http://127.0.0.1:8080 "
                             "or socks5://127.0.0.1:1080. "
                             "Useful for inspecting which IP your server logs.")
    args = parser.parse_args()

    if not urlparse(args.url).scheme:
        print("URL must include scheme (http:// or https://)", file=sys.stderr)
        sys.exit(1)

    if args.verify_suspicious and not args.spa:
        print("--verify-suspicious requires --spa", file=sys.stderr)
        sys.exit(1)

    config = CrawlConfig(
        url=args.url,
        timeout=args.timeout,
        delay=args.delay,
        max_pages=args.max_pages,
        concurrency=args.concurrency,
        output=args.output,
        spa=args.spa,
        wait_until=args.wait_until,
        page_timeout=args.page_timeout,
        verify_suspicious=args.verify_suspicious,
        include_subdomains=args.include_subdomains,
        subdomain_output=args.subdomain_output,
        proxy=_normalize_proxy(args.proxy),
    )
    if config.proxy:
        print(f"Proxy  : {config.proxy}  (server logs will show this IP, not yours)",
              flush=True)

    results = crawl(config)
    issues = write_report(results, config.output)
    subdomain_rows = write_subdomain_report(results, config.subdomain_output)

    total = len(results)
    n_broken = sum(1 for r in issues if r.category == "broken")
    n_susp = sum(1 for r in issues if r.category == "suspicious")

    scope_counts: dict[str, int] = {"same-host": 0, "subdomain": 0, "external": 0}
    scope_issues: dict[str, int] = {"same-host": 0, "subdomain": 0, "external": 0}
    for r in results.values():
        scope_counts[r.scope] += 1
        if r.category != "ok":
            scope_issues[r.scope] += 1

    print(f"\nDone. Checked {total} unique links.")
    print(f"  BROKEN     : {n_broken} (404, 410, 5xx, connection errors)")
    print(f"  SUSPICIOUS : {n_susp} (401/403/429 — likely bot-protection)")
    print()
    print("By scope:")
    for scope in ["same-host", "subdomain", "external"]:
        c = scope_counts[scope]
        b = scope_issues[scope]
        print(f"  {scope:11}: {c:4} links  ({b} not-OK)")
    print(f"\nReport             : {config.output}")
    if subdomain_rows:
        unique_subs = len(subdomain_rows)
        broken_subs = sum(1 for r in subdomain_rows if r["category"] == "broken")
        print(f"Subdomain summary  : {config.subdomain_output} "
              f"({unique_subs} unique subdomains, {broken_subs} broken)")


if __name__ == "__main__":
    main()
