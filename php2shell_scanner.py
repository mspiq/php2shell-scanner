#!/usr/bin/env python3

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    import http.client
    import ssl
    import urllib.parse
    import urllib.request
    import urllib.error
    HAS_REQUESTS = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    CYAN = Fore.CYAN
    BOLD = Style.BRIGHT
    RESET = Style.RESET_ALL
except ImportError:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


VERSION = "1.1.0"
TOOL_NAME = "php2shell Scanner"

FIXED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

VULNERABILITIES = [
    {
        "cve": "CVE-2026-109618",
        "title": "Out-of-Bounds Memory Corruption in Session Upload Progress",
        "cwe": "CWE-787",
        "severity": "CRITICAL",
        "cvss": "9.2",
        "description": (
            "A flaw in PHP's session.upload_progress handler causes an "
            "out-of-bounds write when a memory allocation fails during "
            "multipart request parsing. The longjmp-based OOM bailout "
            "leaves internal state inconsistent, leading to memory "
            "corruption. On mod_php, exploitation occurs before "
            "application code runs (unauthenticated RCE)."
        ),
        "affected": "PHP 5.4.0 through unpatched versions",
        "fixed_in": "PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-109618",
    },
    {
        "cve": "CVE-2026-109619",
        "title": "Use-After-Free in Session Upload Progress",
        "cwe": "CWE-416",
        "severity": "CRITICAL",
        "cvss": "9.2",
        "description": (
            "A PHP worker can reuse stale state from a previous request. "
            "A later request on the same worker accesses freed memory "
            "through the session.upload_progress handler before normal "
            "initialization clears it. Affects mod_php and PHP-FPM."
        ),
        "affected": "PHP 5.4.0 through unpatched versions",
        "fixed_in": "PHP 8.2.35, 8.3.36, 8.4.27, 8.5.12",
        "reference": "https://nvd.nist.gov/vuln/detail/CVE-2026-109619",
    },
]


def parse_php_version(version_str):
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    return None


def is_vulnerable(version_tuple):
    if not version_tuple:
        return False
    major, minor, patch = version_tuple
    if major < 5 or (major == 5 and minor < 4):
        return False
    if major < 8:
        return True
    if major == 8 and minor < 2:
        return True
    branch = (major, minor)
    fixed = FIXED_VERSIONS.get(branch)
    if fixed:
        return version_tuple < fixed
    return False


def get_fix_version(version_tuple):
    if not version_tuple:
        return None
    major, minor, _ = version_tuple
    if major < 8 or (major == 8 and minor < 2):
        return "No fix available — upgrade to PHP 8.2.35+ or 8.3.36+ or 8.4.27+"
    branch = (major, minor)
    fixed = FIXED_VERSIONS.get(branch)
    if fixed:
        return f"{fixed[0]}.{fixed[1]}.{fixed[2]}"
    return None


def build_upload_progress_probe():
    boundary = "----php2shellScannerBoundary9f8e7d"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"\r\n'
        f"\r\n"
        f"scanner_test\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test.txt"\r\n'
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"scanner probe\r\n"
        f"--{boundary}--\r\n"
    )
    content_type = f"multipart/form-data; boundary={boundary}"
    return body.encode("utf-8"), content_type


def probe_upload_progress(url, timeout=10):
    result = {
        "enabled": None,
        "session_cookie": None,
        "php_detected": False,
        "php_version": None,
        "server_header": None,
        "status_code": None,
        "error": None,
    }

    body, content_type = build_upload_progress_probe()

    if HAS_REQUESTS:
        try:
            resp = requests.post(
                url,
                data=body,
                headers={
                    "Content-Type": content_type,
                    "User-Agent": f"php2shell-scanner/{VERSION}",
                    "Cookie": "PHPSESSID=php2shell_scanner_test",
                },
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )

            result["status_code"] = resp.status_code
            result["server_header"] = resp.headers.get("Server", "")

            xpb = resp.headers.get("X-Powered-By", "")
            if "PHP" in xpb:
                result["php_detected"] = True
                m = re.search(r"PHP/([\d.]+)", xpb)
                if m:
                    result["php_version"] = m.group(1)

            set_cookies = resp.headers.get("Set-Cookie", "")
            if "PHPSESSID" in set_cookies:
                result["php_detected"] = True
                result["enabled"] = True
                m = re.search(r"PHPSESSID=([^;]+)", set_cookies)
                if m:
                    result["session_cookie"] = m.group(1)

            if result["php_detected"] and result["enabled"] is None:
                result["enabled"] = False

            if not result["php_detected"]:
                if "PHPSESSID" in resp.text or "PHP" in (xpb or ""):
                    result["php_detected"] = True

        except Exception as e:
            result["error"] = str(e)
    else:
        parsed = urllib.parse.urlparse(url)
        use_ssl = parsed.scheme == "https"
        host = parsed.hostname
        port = parsed.port or (443 if use_ssl else 80)
        path = parsed.path or "/"

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)

            headers = {
                "Content-Type": content_type,
                "User-Agent": f"php2shell-scanner/{VERSION}",
                "Cookie": "PHPSESSID=php2shell_scanner_test",
            }

            conn.request("POST", path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read().decode("utf-8", errors="replace")

            result["status_code"] = resp.status
            result["server_header"] = resp.getheader("Server", "")

            xpb = resp.getheader("X-Powered-By", "")
            if "PHP" in xpb:
                result["php_detected"] = True
                m = re.search(r"PHP/([\d.]+)", xpb)
                if m:
                    result["php_version"] = m.group(1)

            set_cookies = []
            for header, value in resp.getheaders():
                if header.lower() == "set-cookie":
                    set_cookies.append(value)

            for cookie in set_cookies:
                if "PHPSESSID" in cookie:
                    result["php_detected"] = True
                    result["enabled"] = True
                    m = re.search(r"PHPSESSID=([^;]+)", cookie)
                    if m:
                        result["session_cookie"] = m.group(1)
                    break

            if result["php_detected"] and result["enabled"] is None:
                result["enabled"] = False

            if not result["php_detected"]:
                if "PHPSESSID" in resp_body or "PHP" in (xpb or ""):
                    result["php_detected"] = True

            conn.close()

        except Exception as e:
            result["error"] = str(e)

    return result


def detect_php_remote(url, timeout=10):
    result = {
        "url": url,
        "php_detected": False,
        "php_version": None,
        "version_tuple": None,
        "server_header": None,
        "powered_by": None,
        "detection_method": None,
        "sapi": None,
        "session_upload_progress": None,
        "error": None,
    }

    if HAS_REQUESTS:
        try:
            resp = requests.get(
                url,
                headers={"User-Agent": f"php2shell-scanner/{VERSION}"},
                timeout=timeout,
                verify=False,
                allow_redirects=True,
            )
            headers = resp.headers
            body = resp.text

            result["server_header"] = headers.get("Server", "")
            result["powered_by"] = headers.get("X-Powered-By", "")

            xpb = headers.get("X-Powered-By", "")
            if "PHP" in xpb:
                result["php_detected"] = True
                result["detection_method"] = "X-Powered-By header"
                m = re.search(r"PHP/([\d.]+)", xpb)
                if m:
                    result["php_version"] = m.group(1)
                    result["version_tuple"] = parse_php_version(m.group(1))

            if not result["php_version"]:
                server = headers.get("Server", "")
                if "PHP" in server:
                    result["php_detected"] = True
                    result["detection_method"] = "Server header"
                    m = re.search(r"PHP/([\d.]+)", server)
                    if m:
                        result["php_version"] = m.group(1)
                        result["version_tuple"] = parse_php_version(m.group(1))

            if "PHP Version" in body:
                result["php_detected"] = True
                m = re.search(r"PHP Version\s*</td><td[^>]*>([\d.]+)", body)
                if not m:
                    m = re.search(r"PHP Version\s+([\d.]+)", body)
                if m:
                    result["php_version"] = m.group(1)
                    result["version_tuple"] = parse_php_version(m.group(1))
                    result["detection_method"] = "phpinfo() page"

                m_sapi = re.search(r"Server API\s*</td><td[^>]*>([^<]+)", body)
                if m_sapi:
                    result["sapi"] = m_sapi.group(1).strip()

                m_sup = re.search(
                    r"session\.upload_progress\.enabled\s*</td><td[^>]*>([^<]+)",
                    body,
                )
                if m_sup:
                    result["session_upload_progress"] = m_sup.group(1).strip()

            if not result["php_detected"]:
                set_cookie = headers.get("Set-Cookie", "")
                if "PHPSESSID" in set_cookie:
                    result["php_detected"] = True
                    result["detection_method"] = "PHPSESSID cookie"

        except requests.exceptions.HTTPError as e:
            if e.response is not None:
                xpb = e.response.headers.get("X-Powered-By", "")
                result["server_header"] = e.response.headers.get("Server", "")
                result["powered_by"] = xpb
                if "PHP" in xpb:
                    result["php_detected"] = True
                    result["detection_method"] = "X-Powered-By header (error page)"
                    m = re.search(r"PHP/([\d.]+)", xpb)
                    if m:
                        result["php_version"] = m.group(1)
                        result["version_tuple"] = parse_php_version(m.group(1))
        except Exception as e:
            result["error"] = str(e)
    else:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"php2shell-scanner/{VERSION}"},
            )
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener = urllib.request.build_opener(handler)
            resp = opener.open(req, timeout=timeout)
            resp_headers = resp.headers
            body = resp.read().decode("utf-8", errors="replace")

            result["server_header"] = resp_headers.get("Server", "")
            result["powered_by"] = resp_headers.get("X-Powered-By", "")

            xpb = resp_headers.get("X-Powered-By", "")
            if "PHP" in xpb:
                result["php_detected"] = True
                result["detection_method"] = "X-Powered-By header"
                m = re.search(r"PHP/([\d.]+)", xpb)
                if m:
                    result["php_version"] = m.group(1)
                    result["version_tuple"] = parse_php_version(m.group(1))

            if not result["php_version"]:
                server = resp_headers.get("Server", "")
                if "PHP" in server:
                    result["php_detected"] = True
                    result["detection_method"] = "Server header"
                    m = re.search(r"PHP/([\d.]+)", server)
                    if m:
                        result["php_version"] = m.group(1)
                        result["version_tuple"] = parse_php_version(m.group(1))

            if "PHP Version" in body:
                result["php_detected"] = True
                m = re.search(r"PHP Version\s*</td><td[^>]*>([\d.]+)", body)
                if not m:
                    m = re.search(r"PHP Version\s+([\d.]+)", body)
                if m:
                    result["php_version"] = m.group(1)
                    result["version_tuple"] = parse_php_version(m.group(1))
                    result["detection_method"] = "phpinfo() page"

                m_sapi = re.search(r"Server API\s*</td><td[^>]*>([^<]+)", body)
                if m_sapi:
                    result["sapi"] = m_sapi.group(1).strip()

                m_sup = re.search(
                    r"session\.upload_progress\.enabled\s*</td><td[^>]*>([^<]+)",
                    body,
                )
                if m_sup:
                    result["session_upload_progress"] = m_sup.group(1).strip()

            if not result["php_detected"]:
                set_cookie = resp_headers.get("Set-Cookie", "")
                if "PHPSESSID" in set_cookie:
                    result["php_detected"] = True
                    result["detection_method"] = "PHPSESSID cookie"

        except urllib.error.HTTPError as e:
            xpb = e.headers.get("X-Powered-By", "")
            result["server_header"] = e.headers.get("Server", "")
            result["powered_by"] = xpb
            if "PHP" in xpb:
                result["php_detected"] = True
                result["detection_method"] = "X-Powered-By header (error page)"
                m = re.search(r"PHP/([\d.]+)", xpb)
                if m:
                    result["php_version"] = m.group(1)
                    result["version_tuple"] = parse_php_version(m.group(1))
        except urllib.error.URLError as e:
            result["error"] = str(e.reason)
        except Exception as e:
            result["error"] = str(e)

    return result


def detect_php_local():
    result = {
        "url": "localhost",
        "php_detected": False,
        "php_version": None,
        "version_tuple": None,
        "sapi": None,
        "session_upload_progress": None,
        "detection_method": "local CLI",
        "mod_php_installed": False,
        "apache_running": False,
        "error": None,
    }

    try:
        out = subprocess.run(
            ["php", "-v"], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            result["php_detected"] = True
            m = re.search(r"PHP ([\d.]+)", out.stdout)
            if m:
                result["php_version"] = m.group(1)
                result["version_tuple"] = parse_php_version(m.group(1))
    except FileNotFoundError:
        result["error"] = "PHP is not installed on this system."
        return result
    except Exception as e:
        result["error"] = str(e)
        return result

    try:
        out = subprocess.run(
            ["php", "-r", "echo ini_get('session.upload_progress.enabled');"],
            capture_output=True, text=True, timeout=5,
        )
        val = out.stdout.strip()
        result["session_upload_progress"] = "On" if val in ("1", "On") else "Off"
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["php", "-r", "echo php_sapi_name();"],
            capture_output=True, text=True, timeout=5,
        )
        result["sapi"] = out.stdout.strip()
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["find", "/usr/lib", "-name", "libphp*", "-o", "-name", "mod_php*"],
            capture_output=True, text=True, timeout=5,
        )
        if out.stdout.strip():
            result["mod_php_installed"] = True
    except Exception:
        pass

    try:
        out = subprocess.run(
            ["pgrep", "-x", "apache2"], capture_output=True, text=True, timeout=5
        )
        if out.returncode == 0:
            result["apache_running"] = True
    except Exception:
        pass

    return result


def assess_risk(detection, probe_result=None):
    risk = {
        "vulnerable": False,
        "risk_level": "NONE",
        "factors": [],
        "fix_version": None,
    }

    has_version = detection.get("version_tuple") is not None
    version_vulnerable = has_version and is_vulnerable(detection["version_tuple"])
    upload_progress_on = False

    if probe_result and probe_result.get("enabled"):
        upload_progress_on = True

    sup = (detection.get("session_upload_progress") or "").lower()
    if sup in ("on", "1"):
        upload_progress_on = True

    if version_vulnerable:
        risk["vulnerable"] = True
        risk["risk_level"] = "HIGH"
        risk["fix_version"] = get_fix_version(detection["version_tuple"])
        risk["factors"].append(
            f"PHP {detection['php_version']} is in the affected range"
        )

    elif not has_version and upload_progress_on:
        risk["vulnerable"] = True
        risk["risk_level"] = "HIGH"
        risk["factors"].append(
            "PHP version unknown — but session.upload_progress is active"
        )
        risk["factors"].append(
            "Server is LIKELY vulnerable unless running a patched version"
        )

    elif has_version and not version_vulnerable:
        return risk

    else:
        return risk

    sapi = (detection.get("sapi") or "").lower()
    if "apache" in sapi or "mod_php" in sapi:
        risk["risk_level"] = "CRITICAL"
        risk["factors"].append(
            "Apache mod_php detected — highest risk: exploit fires before "
            "application code runs (unauthenticated)"
        )
    elif "fpm" in sapi or "cgi" in sapi:
        risk["factors"].append(
            f"SAPI: {detection['sapi']} — exploitable via CVE-2026-109619 "
            f"(stale state reuse)"
        )
    elif "litespeed" in sapi or "lsapi" in sapi:
        risk["risk_level"] = "CRITICAL"
        risk["factors"].append(
            "LiteSpeed SAPI detected — confirmed exploitable"
        )

    if upload_progress_on:
        risk["factors"].append(
            "session.upload_progress.enabled = On — attack vector is active"
        )
    elif sup in ("off", "0"):
        if risk["risk_level"] == "CRITICAL":
            risk["risk_level"] = "HIGH"
        risk["factors"].append(
            "session.upload_progress.enabled = Off — primary attack vector "
            "disabled (but other paths may exist, patching is required)"
        )

    if detection.get("mod_php_installed"):
        risk["factors"].append("mod_php is installed on this system")
    if detection.get("apache_running"):
        risk["factors"].append("Apache is currently running")

    return risk


def scan_target(url, timeout=10, local=False, probe=True):
    scan_result = {
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "scanner": f"{TOOL_NAME} v{VERSION}",
        "author": "Mohammed Salah",
    }

    if local:
        detection = detect_php_local()
        probe_result = None
    else:
        url = url.strip().rstrip("/")
        if not url.startswith("http"):
            url = "https://" + url
        detection = detect_php_remote(url, timeout)

        probe_result = None
        if probe and not detection.get("error"):
            probe_result = probe_upload_progress(url, timeout)
            if probe_result.get("php_detected") and not detection["php_detected"]:
                detection["php_detected"] = True
                detection["detection_method"] = "upload_progress probe"
            if probe_result.get("php_version") and not detection["php_version"]:
                detection["php_version"] = probe_result["php_version"]
                detection["version_tuple"] = parse_php_version(
                    probe_result["php_version"]
                )
            if probe_result.get("enabled") is not None:
                detection["session_upload_progress"] = (
                    "On" if probe_result["enabled"] else "Off"
                )

    scan_result["detection"] = detection
    risk = assess_risk(detection, probe_result if not local else None)
    scan_result["risk"] = risk

    if detection.get("error"):
        scan_result["status"] = "error"
        scan_result["message"] = f"Error: {detection['error']}"
        scan_result["vulnerabilities"] = []

    elif not detection["php_detected"]:
        scan_result["status"] = "no_php"
        scan_result["message"] = "PHP was not detected on the target."
        scan_result["vulnerabilities"] = []

    elif risk["vulnerable"]:
        version_str = detection.get("php_version") or "unknown version"
        scan_result["status"] = "vulnerable"
        scan_result["message"] = (
            f"PHP {version_str} is VULNERABLE to php2shell "
            f"(CVE-2026-109618 / CVE-2026-109619)"
        )
        scan_result["vulnerabilities"] = VULNERABILITIES

    elif detection.get("php_version") and not is_vulnerable(
        detection.get("version_tuple")
    ):
        scan_result["status"] = "not_vulnerable"
        scan_result["message"] = (
            f"PHP {detection['php_version']} is NOT affected by php2shell."
        )
        scan_result["vulnerabilities"] = []

    else:
        scan_result["status"] = "unknown"
        scan_result["message"] = (
            "PHP detected but could not determine vulnerability status. "
            "Manual verification recommended."
        )
        scan_result["vulnerabilities"] = []

    return scan_result


def print_banner():
    print(
        f"""
{CYAN}        _         ___      _          _ _
  _ __ | |__  _ _|__ \\___| |__   ___| | |
 | '_ \\| '_ \\| '_ \\ __) / __| '_ \\ / _ \\ | |
 | |_) | | | | |_) / __/\\__ \\ | | |  __/ | |
 | .__/|_| |_| .__/_____|___/_| |_|\\___|_|_|
 |_|         |_|{RESET}
  {BOLD}Scanner v{VERSION}{RESET}
  Author: Mohammed Salah
  CVE-2026-109618 / CVE-2026-109619
  Detection only — no exploitation performed
"""
    )


def print_result(result):
    det = result["detection"]

    if det.get("url") == "localhost":
        print(f"  {BOLD}Mode:{RESET}    Local system scan")
    else:
        print(f"  {BOLD}Target:{RESET}  {det.get('url', 'N/A')}")

    if det.get("server_header"):
        print(f"  {BOLD}Server:{RESET}  {det['server_header']}")
    if det.get("powered_by"):
        print(f"  {BOLD}X-Powered-By:{RESET} {det['powered_by']}")

    print(f"  {BOLD}PHP:{RESET}     {'Detected' if det['php_detected'] else 'Not detected'}")
    print(f"  {BOLD}Version:{RESET} {det.get('php_version') or 'Hidden/Unknown'}")

    if det.get("detection_method"):
        print(f"  {BOLD}Method:{RESET}  {det['detection_method']}")
    if det.get("sapi"):
        print(f"  {BOLD}SAPI:{RESET}    {det['sapi']}")
    if det.get("session_upload_progress"):
        print(f"  {BOLD}session.upload_progress:{RESET} {det['session_upload_progress']}")
    if det.get("mod_php_installed") is not None and det["url"] == "localhost":
        print(f"  {BOLD}mod_php:{RESET} {'Installed' if det['mod_php_installed'] else 'Not found'}")
    if det.get("apache_running") is not None and det["url"] == "localhost":
        print(f"  {BOLD}Apache:{RESET}  {'Running' if det['apache_running'] else 'Not running'}")

    print()

    if result["status"] == "error":
        print(f"  {RED}[!] {result['message']}{RESET}")
        return

    if result["status"] == "no_php":
        print(f"  {YELLOW}[-] {result['message']}{RESET}")
        return

    if result["status"] == "unknown":
        print(f"  {YELLOW}[?] {result['message']}{RESET}")
        return

    if result["status"] == "not_vulnerable":
        print(f"  {GREEN}[OK] {result['message']}{RESET}")
        return

    risk = result["risk"]

    print(f"  {RED}{BOLD}[!!] {result['message']}{RESET}")
    print(f"  {RED}{BOLD}[!!] Risk Level: {risk['risk_level']}{RESET}")
    print()

    for factor in risk["factors"]:
        print(f"  {YELLOW}[*]{RESET} {factor}")

    if risk.get("fix_version"):
        print(f"  {YELLOW}[*]{RESET} Fix: Update to PHP {risk['fix_version']}")
    print()

    for v in result.get("vulnerabilities", []):
        print(f"  {BOLD}--- {v['cve']} ---{RESET}")
        print(f"  Title:    {v['title']}")
        print(f"  CWE:      {v['cwe']}")
        print(f"  CVSS:     {v['cvss']} {v['severity']}")
        print(f"  Affected: {v['affected']}")
        print(f"  Fixed in: {v['fixed_in']}")
        print(f"  Ref:      {v['reference']}")
        print()

    print(f"  {BOLD}Remediation:{RESET}")
    print("    1. Update PHP to the latest patched version:")
    print("       PHP 8.2 → 8.2.35 | PHP 8.3 → 8.3.36")
    print("       PHP 8.4 → 8.4.27 | PHP 8.5 → 8.5.12")
    print("    2. PHP 5.4 — 8.1: No fix available. Upgrade to 8.2+")
    print("    3. Temporary mitigation (partial — does NOT fully protect):")
    print("       session.upload_progress.enabled = 0 in php.ini")
    print("       Then restart Apache/PHP-FPM")
    print()


def main():
    parser = argparse.ArgumentParser(
        description=(
            "php2shell Scanner — checks for CVE-2026-109618 / CVE-2026-109619. "
            "Detection only, no exploitation."
        ),
    )
    parser.add_argument(
        "target",
        nargs="?",
        help="Target URL (e.g., https://example.com)",
    )
    parser.add_argument(
        "-f", "--file",
        help="File containing target URLs (one per line)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Scan the local system instead of a remote target",
    )
    parser.add_argument(
        "--no-probe",
        action="store_true",
        help="Skip the upload_progress probe (version check only)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output results as JSON",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Connection timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"{TOOL_NAME} v{VERSION}",
    )

    args = parser.parse_args()

    if not args.target and not args.file and not args.local:
        parser.print_help()
        sys.exit(1)

    if not args.json:
        print_banner()

    all_results = []

    if args.local:
        if not args.json:
            print("  Scanning local system ...")
            print()
        result = scan_target("localhost", local=True)
        all_results.append(result)
        if not args.json:
            print_result(result)
    else:
        targets = []
        if args.file:
            try:
                with open(args.file) as f:
                    targets = [
                        line.strip()
                        for line in f
                        if line.strip() and not line.startswith("#")
                    ]
            except FileNotFoundError:
                print(f"Error: File '{args.file}' not found.", file=sys.stderr)
                sys.exit(1)
        elif args.target:
            targets = [args.target]

        for target in targets:
            if not args.json:
                print(f"  Scanning {target} ...")
                print()
            result = scan_target(
                target, args.timeout, probe=not args.no_probe
            )
            all_results.append(result)
            if not args.json:
                print_result(result)
                if len(targets) > 1:
                    print("  " + "=" * 60)
                    print()

    if args.json:
        for r in all_results:
            if "detection" in r and "version_tuple" in r["detection"]:
                vt = r["detection"]["version_tuple"]
                r["detection"]["version_tuple"] = list(vt) if vt else None
        print(json.dumps(all_results, indent=2, ensure_ascii=False))

    if not args.json and len(all_results) > 1:
        vuln_count = sum(1 for r in all_results if r["status"] == "vulnerable")
        safe_count = sum(1 for r in all_results if r["status"] == "not_vulnerable")
        err_count = sum(
            1 for r in all_results
            if r["status"] in ("error", "no_php", "unknown")
        )
        print(f"  {BOLD}Summary:{RESET} {len(all_results)} targets scanned")
        print(f"    Vulnerable:     {vuln_count}")
        print(f"    Not vulnerable: {safe_count}")
        print(f"    Errors/Other:   {err_count}")
        print()

    if any(r["status"] == "vulnerable" for r in all_results):
        sys.exit(2)
    if any(r["status"] == "error" for r in all_results):
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
