# php2shell Scanner

**Detection only — no exploitation performed.**

A lightweight Python scanner that checks if a PHP server is affected by the php2shell vulnerabilities (CVE-2026-109618 / CVE-2026-109619) — unauthenticated RCE in PHP's `session.upload_progress` handler.

## Vulnerabilities

| CVE | Title | CWE | CVSS 4.0 |
|---|---|---|---|
| CVE-2026-109618 | Out-of-Bounds Memory Corruption | CWE-787 | 9.2 CRITICAL |
| CVE-2026-109619 | Use-After-Free | CWE-416 | 9.2 CRITICAL |

**Affected:** PHP 5.4.0 through all unpatched versions  
**Fixed in:** PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12  
**No fix available:** PHP 5.4 — 8.1 (end of life)  
**All SAPIs affected:** mod_php, PHP-FPM, CGI, LiteSpeed, FrankenPHP

## How It Works

The scanner uses **two detection methods**:

### 1. Version Detection
Detects PHP version from HTTP response headers (`X-Powered-By`, `Server`), `phpinfo()` page content, or the local PHP binary (`--local` mode).

### 2. Upload Progress Probe (the key feature)

Many production servers **hide the PHP version** (`expose_php = Off`). This scanner can still detect vulnerability by probing `session.upload_progress`:

- Sends a **normal** multipart POST with a `PHP_SESSION_UPLOAD_PROGRESS` field
- If the feature is enabled, PHP automatically starts a session and returns `Set-Cookie: PHPSESSID=...`
- A server with active `session.upload_progress` is **likely vulnerable** unless patched

**This is NOT exploitation.** It uses [documented PHP behavior](https://www.php.net/manual/en/session.upload-progress.php). No memory corruption, no crafted payloads, no malicious data.

## Risk Assessment

The scanner assesses risk level based on:

| Factor | Risk Impact |
|---|---|
| mod_php or LiteSpeed | CRITICAL — unauthenticated, pre-application |
| PHP-FPM / CGI | HIGH — exploitable via stale state (CVE-2026-109619) |
| upload_progress = On | Attack vector is active |
| upload_progress = Off | Partial mitigation only (other paths exist) |
| PHP 5.4 — 8.1 | No fix available — must upgrade |

## Dependencies

| Library | Purpose |
|---|---|
| [requests](https://pypi.org/project/requests/) | HTTP requests handling |
| [colorama](https://pypi.org/project/colorama/) | Cross-platform colored terminal output |

Both libraries are optional — the scanner falls back to Python standard library if not installed.

## Installation

```bash
git clone https://github.com/mspiq/php2shell_scanner.git
cd php2shell_scanner
pip install -r requirements.txt
chmod +x php2shell_scanner.py
```

## Usage

### Scan a remote target (version + probe)

```bash
python3 php2shell_scanner.py https://example.com
```

### Scan with version check only (no probe)

```bash
python3 php2shell_scanner.py https://example.com --no-probe
```

### Scan the local system

```bash
python3 php2shell_scanner.py --local
```

### Scan multiple targets

```bash
python3 php2shell_scanner.py -f targets.txt
```

### JSON output

```bash
python3 php2shell_scanner.py https://example.com --json
```

## Example Output

```
        _         ___      _          _ _
  _ __ | |__  _ _|__ \___| |__   ___| | |
 | '_ \| '_ \| '_ \ __) / __| '_ \ / _ \ | |
 | |_) | | | | |_) / __/\__ \ | | |  __/ | |
 | .__/|_| |_| .__/_____|___/_| |_|\___|_|_|
 |_|         |_|
  Scanner v1.1.0
  Author: Mohammed Salah
  CVE-2026-109618 / CVE-2026-109619
  Detection only — no exploitation performed

  Scanning https://example.com ...

  Target:  https://example.com
  Server:  Apache/2.4.62
  PHP:     Detected
  Version: Hidden/Unknown
  Method:  upload_progress probe
  session.upload_progress: On

  [!!] PHP unknown version is VULNERABLE to php2shell (CVE-2026-109618 / CVE-2026-109619)
  [!!] Risk Level: HIGH

  [*] PHP version unknown — but session.upload_progress is active
  [*] Server is LIKELY vulnerable unless running a patched version
  [*] session.upload_progress.enabled = On — attack vector is active
```

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | All targets are not vulnerable |
| 1 | Connection error(s) occurred |
| 2 | One or more targets are vulnerable |

## Remediation

**Update PHP** to the latest patched version:

| Branch | Patched Version |
|---|---|
| PHP 8.2 | 8.2.35 |
| PHP 8.3 | 8.3.36 |
| PHP 8.4 | 8.4.27 |
| PHP 8.5 | 8.5.12 |

PHP 5.4 — 8.1 will **not** receive patches. Upgrade to PHP 8.2+.

**Temporary mitigation** (partial — does NOT fully protect):

```ini
; php.ini
session.upload_progress.enabled = 0
```

Then restart your web server. Note: [Datadog's analysis](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/) warns this does not protect against all attack paths.

## References

- [CVE-2026-109618 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109618)
- [CVE-2026-109619 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-109619)
- [JFrog — PHP2Shell Analysis](https://research.jfrog.com/post/php2shell-all-you-need-to-know-about-cve-2026-109618-and-cve-2026-109619/)
- [Rapid7 — Critical RCE in PHP](https://www.rapid7.com/blog/post/etr-cve-2026-109618-and-cve-2026-109619-critical-unauthenticated-remote-code-execution-in-php/)
- [Datadog — PHP2Shell Detection](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [PHP Session Upload Progress (docs)](https://www.php.net/manual/en/session.upload-progress.php)

## Disclaimer

This tool is provided for **authorized security testing and system administration only**. Only scan systems you own or have explicit permission to test. The author is not responsible for misuse.

## Author

**Mohammed Salah**  
Independent Security Researcher  
GitHub: [@mspiq](https://github.com/mspiq)

## License

MIT License
