# API Key Leak Scanner

> Defensive recon tool to hunt for leaked employee API keys, tokens, private keys, and weak IIS machine keys on a target you own or are authorized to test. Implements the workflows described in [`README.md`](./README.md) and [`IIS-Machine-Keys.md`](./IIS-Machine-Keys.md).

## Summary

- [Authorization](#authorization)
- [Requirements](#requirements)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Usage Examples](#usage-examples)
    - [Basic crawl](#basic-crawl)
    - [Deep crawl with IIS MachineKey identification](#deep-crawl-with-iis-machinekey-identification)
    - [Live token validation](#live-token-validation)
    - [Behind Burp Suite / OWASP ZAP](#behind-burp-suite--owasp-zap)
    - [Authenticated session](#authenticated-session)
    - [Scanning a local file or HAR dump](#scanning-a-local-file-or-har-dump)
    - [CI / pipeline integration](#ci--pipeline-integration)
- [Detected Patterns](#detected-patterns)
- [IIS MachineKey Workflow](#iis-machinekey-workflow)
- [Output Formats](#output-formats)
- [Exit Codes](#exit-codes)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [References](#references)

## Authorization

**Use only on systems you own or have written authorization to test.** This script crawls a target site, sends it identifiable requests, and — when `--validate` is enabled — calls third-party APIs (GitHub, Telegram, Slack, SendGrid) with any token it finds. Activity is logged on every endpoint hit. Treat each finding as actionable signal, not as a confirmation that the key is in active use.

## Requirements

- Python 3.10+
- `pip install requests`
- Optional: `pip install requests[socks]` to use `socks5://` proxies

The script has zero dependencies on Burp / ZAP / nuclei / trufflehog — those are referenced in [`README.md`](./README.md) for ecosystem context but are not invoked.

## Quick Start

```powershell
# minimal scan (depth 1, default 50 pages)
python api_key_leak_scanner.py https://my-site.example.com

# add IIS MachineKey identification + JSON report
python api_key_leak_scanner.py https://my-site.example.com `
    --depth 2 --machinekey --json output/api_keys.json
```

## CLI Reference

| Flag | Default | Description |
| --- | --- | --- |
| `target` | — | URL to scan. Pass `-` together with `--file` to scan a local file. |
| `--file PATH` | — | Scan a local HTML / JS / log file instead of crawling. |
| `--depth N` | `1` | BFS crawl depth from the start URL. `0` = only the start page. |
| `--max-pages N` | `50` | Hard cap on fetched pages. |
| `--timeout N` | `15` | Per-request timeout (seconds). |
| `--threads N` | `8` | Worker pool used during `--validate`. |
| `--header H` | — | Extra HTTP header. Repeatable: `--header "Authorization: Bearer …"`. |
| `--cookie C` | — | Cookie `name=value`. Repeatable. |
| `--proxy URL` | — | `http://`, `https://`, or `socks5://` proxy. Supports `http://user:pass@host:port`. |
| `--insecure`, `-k` | off | Skip TLS certificate verification. Use with `--proxy` for Burp/ZAP. |
| `--machinekey` | off | Detect `__VIEWSTATE` and try to identify the IIS machine key. |
| `--machinekey-file PATH` | `Files/MachineKeys.txt` | Custom keylist (one `validation,decryption` hex pair per line). |
| `--validate` | off | Probe issuer APIs to test if found tokens are still valid (Telegram, GitHub, Slack, SendGrid). |
| `--csv PATH` | — | Write findings to CSV. |
| `--json PATH` | — | Write findings + machine-key result to JSON. |
| `-v`, `--verbose` | off | Debug logging. |

## Usage Examples

### Basic crawl

Walks the start page + every same-origin link / `<script src>` one hop deep, scans every response with the regex library:

```powershell
python api_key_leak_scanner.py https://my-site.example.com
```

### Deep crawl with IIS MachineKey identification

Combines the README pattern hunt with the [IIS-Machine-Keys.md](./IIS-Machine-Keys.md) Blacklist3r workflow. Whenever a `__VIEWSTATE` field is found, every pair from `Files/MachineKeys.txt` is tested using HMAC-SHA1 / SHA256 / SHA384 / SHA512 / MD5 with the `__VIEWSTATEGENERATOR` modifier:

```powershell
python api_key_leak_scanner.py https://my-site.example.com `
    --depth 3 --max-pages 200 --machinekey
```

If a match is found, the output looks like:

```text
======================================================================
[!! CRITICAL] Known IIS MachineKey identified — full ViewState RCE
======================================================================
  algorithm     : SHA1
  generator     : CA0B0334
  validationKey : C551753B0325187D1759B4FB055B44F7C5077B016C02AF67…
  decryptionKey : F6722806843145965513817CEBDECBB1F94808E4A6C0B2F2
  next step     : forge ViewState with ysoserial.net (see IIS-Machine-Keys.md)
```

Follow up with `ysoserial.net` exactly as shown in [IIS-Machine-Keys.md → Generate ViewState For RCE](./IIS-Machine-Keys.md#generate-viewstate-for-rce).

### Live token validation

After collecting findings, send a read-only API call to the issuer for each supported token type. The script never POSTs / writes; it only checks `getMe` / `/user` / `auth.test` / `/v3/scopes`:

```powershell
python api_key_leak_scanner.py https://my-site.example.com --validate
```

Findings then carry a `[VALID]` / `[INVALID]` tag in console output and a `validated` field in CSV / JSON.

### Behind Burp Suite / OWASP ZAP

Pipe every request through an intercepting proxy so you can replay or modify them. The `--insecure` flag is required because Burp/ZAP present a self-signed certificate:

```powershell
# Burp Suite (default 8080)
python api_key_leak_scanner.py https://my-site.example.com `
    --proxy http://127.0.0.1:8080 --insecure

# OWASP ZAP (default 8081)
python api_key_leak_scanner.py https://my-site.example.com `
    --proxy http://127.0.0.1:8081 --insecure
```

For corporate / authenticated proxies:

```powershell
python api_key_leak_scanner.py https://my-site.example.com `
    --proxy http://alice:p4ss@proxy.corp.local:3128
```

For SOCKS5 (e.g. via SSH tunnel `ssh -D 1080 jumpbox`):

```powershell
pip install requests[socks]
python api_key_leak_scanner.py https://my-site.example.com `
    --proxy socks5://127.0.0.1:1080
```

### Authenticated session

Many leaks live behind login walls. Pass session cookies and / or bearer tokens:

```powershell
python api_key_leak_scanner.py https://intranet.example.com `
    --cookie "sessionid=abc123" `
    --cookie "csrftoken=xyz789" `
    --header "Authorization: Bearer eyJhbGciOi…" `
    --depth 2
```

### Scanning a local file or HAR dump

Useful for offline triage of leaked archives, S3 dumps, or pasted JS bundles:

```powershell
python api_key_leak_scanner.py - --file ./suspicious_bundle.js
python api_key_leak_scanner.py - --file ./old_leak.html --machinekey
```

### CI / pipeline integration

Combine `--json` with the exit-code semantics described below. The example below fails a GitHub Action when any `critical` / `high` finding (or a known machine key) is found:

```yaml
- name: API key leak scan
  run: |
    python "payload/API Key Leaks/api_key_leak_scanner.py" \
        https://staging.example.com \
        --depth 2 --machinekey --validate \
        --json artifacts/api_keys.json
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: api-keys-report
    path: artifacts/api_keys.json
```

## Detected Patterns

40+ patterns covering the categories from [`README.md → Common Causes of Leaks`](./README.md#common-causes-of-leaks):

| Category | Examples |
| --- | --- |
| Cloud providers | AWS Access Key ID / Secret / MWS, Google API key, Google OAuth, GCP Service Account JSON, Azure Subscription Key, Azure Storage Account Key, Azure SAS, Heroku |
| Source control / CI | GitHub PAT (classic + fine-grained), GitHub OAuth / App / refresh tokens, GitLab PAT, Bitbucket secret, NPM access token |
| Payment | Stripe live secret / restricted / publishable, Square access + OAuth secret, PayPal Braintree |
| Messaging / mail | Slack token (xoxa/b/p/r/s), Slack webhook, Telegram bot token, Discord webhook + bot token, SendGrid, Mailgun, Mailchimp, Twilio key + SID, Postman |
| Generic / structural | JWT, RSA / OpenSSH / PGP private key, hardcoded `apiKey=` / `password=` assignments, basic-auth credentials embedded in URLs |
| Misc service tokens | Cloudinary URL, Firebase Cloud Messaging, Datadog, New Relic, Shopify access + shared secret, Algolia admin, OpenAI, Anthropic, Hugging Face |

Each pattern is tagged with `severity` (`critical` / `high` / `medium` / `low` / `info`) and `confidence` (`high` / `medium` / `low`). Low-confidence patterns are deliberately included to catch generic `apiKey=…` style assignments — review them manually before acting.

## IIS MachineKey Workflow

Implements the Blacklist3r-style identification described in [IIS-Machine-Keys.md → Identify Known Machine Key](./IIS-Machine-Keys.md#identify-known-machine-key):

1. The crawler grabs every `__VIEWSTATE` and `__VIEWSTATEGENERATOR` it finds.
2. The viewstate is base64-decoded into `data || signature`. Signature length depends on the algorithm: 16 (MD5), 20 (SHA1, the historical default), 32 (HMACSHA256, the .NET 4.5+ default), 48 (SHA384), or 64 (SHA512).
3. For each algorithm and each `(validationKey, decryptionKey)` pair from `Files/MachineKeys.txt`, the tool computes `HMAC(validationKey, data || generator_le_uint32)` and compares against the trailing signature. The first match wins — IIS reuses the same machine key across the whole app pool.
4. On match, the script reports algorithm + both keys + the page where it was found, plus a pointer to the ViewState RCE generation steps in [IIS-Machine-Keys.md → Generate ViewState For RCE](./IIS-Machine-Keys.md#generate-viewstate-for-rce).

`Files/MachineKeys.txt` ships with 3 570 known leaked / sample / weak keys collated from public sources. You can swap in your own list with `--machinekey-file path/to/keys.txt`.

## Output Formats

### Console

Findings are sorted by severity, then by pattern. Secrets are redacted (`AKIAIO…MPLE (len=20)`) so the terminal stays paste-safe. Add `-v` for debug logging.

### CSV (`--csv path`)

Columns: `severity, pattern, confidence, validated, secret, source_url, context`. Secrets are written **in full** so you can pivot through with Excel / `csvkit` — handle the file as sensitive.

### JSON (`--json path`)

```jsonc
{
  "target": "https://my-site.example.com",
  "scanned_at": "2026-05-09T14:32:01",
  "machine_key_hit": {
    "algorithm": "SHA1",
    "generator": "CA0B0334",
    "validation_key": "C551753B…",
    "decryption_key": "F6722806…",
    "found_at": "https://my-site.example.com/Default.aspx"
  },
  "findings": [
    {
      "severity": "critical",
      "pattern": "AWS Access Key ID",
      "confidence": "high",
      "secret": "AKIA…",
      "source_url": "https://my-site.example.com/static/app.js",
      "context": "AWS_ACCESS_KEY=AKIA… ; …",
      "validated": null
    }
  ]
}
```

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | No `critical` / `high` findings, no machine-key hit. |
| `1` | At least one `critical` / `high` finding **or** a known IIS machine key was identified. |
| `2` | Bad input (e.g. `--file` does not exist). |

This is meant for non-zero-on-failure CI pipelines. Adjust the threshold by post-processing the JSON if you need different policy.

## Limitations

- Same-origin only. Subdomains and CDN-hosted JS are not followed.
- No JavaScript execution — content rendered after page load (SPA bundles fetched dynamically) is missed unless that bundle URL is in the initial HTML.
- The validator set is intentionally small and read-only. Other tokens (AWS, Stripe, etc.) are reported but not test-called, because the validation endpoints either mutate state or carry billing impact. Use the `keyhacks` references from [`README.md → Validate The API Key`](./README.md#validate-the-api-key) for manual verification.
- Generic patterns (`apiKey=…`) produce false positives on minified bundles. Filter by `confidence=high` in the JSON / CSV when triaging at scale.
- ViewState identification only handles the **standard** ASP.NET HMAC scheme. Custom `compatibilityMode="Framework45"` deployments with explicit `IVType=None` are out of scope — fall back to `viewgen` / `ysoserial.net` per the markdown.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `SSLError: certificate verify failed` while using Burp/ZAP | Add `--insecure`. |
| `MissingDependency: SOCKS support is not installed` | `pip install requests[socks]`. |
| Crawler stops after one page | Increase `--depth` and `--max-pages`. The default is conservative. |
| Lots of low-quality `Generic API Key Assignment` hits | Filter to `confidence=high` — that pattern catches `apiKey=…` lookalikes by design. |
| `__VIEWSTATE` found but no key match | Site may use a non-leaked custom key, or `compatibilityMode="Framework45"`. Try `viewgen --guess` and the keys from the badsecrets / viewstalker projects in [IIS-Machine-Keys.md](./IIS-Machine-Keys.md#identify-known-machine-key). |
| `403` on every page | Provide a session via `--cookie` / `--header`, or run the scan from a network the WAF allows. |

## References

- [`README.md`](./README.md) — methodology + tool ecosystem (trufflehog, badsecrets, keyhacks, …).
- [`IIS-Machine-Keys.md`](./IIS-Machine-Keys.md) — full ViewState RCE chain.
- [mazen160/secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db) — pattern names align with this database.
- [streaak/keyhacks](https://github.com/streaak/keyhacks) — manual validation cheat-sheet for the tokens this script does not validate automatically.
