"""
Core logic for the Web-App Vulnerability Scan tool.

IMPORTANT: This tool performs only passive, non-destructive checks --
it reads HTTP response headers, cookies, and TLS certificate metadata,
and checks whether a small list of commonly-known paths respond. It
never sends injection payloads (no SQLi/XSS strings), never attempts
authentication bypass, and never modifies anything on the target.

Only ever scan systems you own or have explicit written permission to
test. Scanning third-party systems without authorization is illegal
in most jurisdictions (e.g. under the U.S. Computer Fraud and Abuse
Act or the UK Computer Misuse Act), regardless of how "light" the
scan is.
"""
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlparse, urljoin


@dataclass
class Finding:
    category: str          # "Headers" | "Cookies" | "TLS" | "Disclosure" | "Exposed Path"
    severity: str           # "info" | "low" | "medium" | "high"
    title: str
    detail: str


@dataclass
class WebScanResult:
    target: str
    final_url: Optional[str] = None
    status_code: Optional[int] = None
    findings: List[Finding] = field(default_factory=list)
    error: Optional[str] = None


SECURITY_HEADERS = {
    "Strict-Transport-Security": ("medium", "HSTS not set — browsers won't force HTTPS on repeat visits."),
    "Content-Security-Policy": ("medium", "No CSP — reduces defense-in-depth against XSS/data-injection."),
    "X-Content-Type-Options": ("low", "Missing 'nosniff' — browsers may MIME-sniff responses."),
    "X-Frame-Options": ("medium", "No clickjacking protection via X-Frame-Options (check CSP frame-ancestors too)."),
    "Referrer-Policy": ("low", "No Referrer-Policy — full URLs may leak to third parties via the Referer header."),
    "Permissions-Policy": ("low", "No Permissions-Policy — browser features aren't explicitly restricted."),
}

# Small, well-known list of commonly-exposed sensitive paths.
SENSITIVE_PATHS = [
    "/.git/config", "/.env", "/.DS_Store", "/wp-admin/", "/admin/",
    "/backup.zip", "/.well-known/security.txt", "/server-status", "/phpinfo.php",
]

TIMEOUT = 8


def _check_headers(headers, is_https: bool) -> List[Finding]:
    findings = []
    lower_headers = {k.lower(): v for k, v in headers.items()}

    for header, (severity, detail) in SECURITY_HEADERS.items():
        if header == "Strict-Transport-Security" and not is_https:
            continue  # HSTS is meaningless over plain HTTP
        if header.lower() not in lower_headers:
            findings.append(Finding("Headers", severity, f"Missing header: {header}", detail))

    server = lower_headers.get("server")
    if server:
        findings.append(Finding(
            "Disclosure", "low", f"Server header reveals: {server}",
            "Consider suppressing or genericizing this to reduce fingerprinting.",
        ))
    powered_by = lower_headers.get("x-powered-by")
    if powered_by:
        findings.append(Finding(
            "Disclosure", "low", f"X-Powered-By reveals: {powered_by}",
            "Consider removing this header to reduce fingerprinting.",
        ))

    cors = lower_headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append(Finding(
            "Headers", "medium", "CORS allows any origin (Access-Control-Allow-Origin: *)",
            "Fine for public APIs; risky if this endpoint returns sensitive/authenticated data.",
        ))

    return findings


def _check_cookies(response) -> List[Finding]:
    findings = []
    try:
        raw_cookies = response.raw.headers.getlist("Set-Cookie")
    except Exception:
        raw_cookies = []

    for cookie_str in raw_cookies:
        name = cookie_str.split("=", 1)[0].strip()
        lower = cookie_str.lower()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            findings.append(Finding(
                "Cookies", "medium", f"Cookie '{name}' missing: {', '.join(missing)}",
                "Cookies without these flags are more exposed to theft via XSS or network snooping.",
            ))
    return findings


def _check_tls(hostname: str) -> List[Finding]:
    findings = []
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
        days_left = (not_after - datetime.utcnow()).days
        if days_left < 0:
            findings.append(Finding("TLS", "high", "TLS certificate has expired",
                                     f"Expired {abs(days_left)} day(s) ago on {not_after.date()}."))
        elif days_left < 30:
            findings.append(Finding("TLS", "medium", f"TLS certificate expires soon ({days_left} days)",
                                     f"Expires on {not_after.date()}. Plan renewal now."))
        else:
            findings.append(Finding("TLS", "info", f"TLS certificate valid for {days_left} more days",
                                     f"Expires on {not_after.date()}."))
    except ssl.SSLCertVerificationError as e:
        findings.append(Finding("TLS", "high", "TLS certificate verification failed", str(e)))
    except Exception as e:
        findings.append(Finding("TLS", "low", "Could not verify TLS certificate", str(e)))
    return findings


def _check_exposed_paths(session, base_url: str) -> List[Finding]:
    """
    Checks a small list of commonly-sensitive paths. First establishes a
    baseline by requesting a random, definitely-nonexistent path -- some
    servers ("soft 404s") return HTTP 200 for everything instead of a
    real 404, which would otherwise make every path look "exposed".
    Only paths that behave differently from that baseline are flagged.
    """
    import secrets

    findings = []
    random_path = f"/rupux-baseline-check-{secrets.token_hex(8)}"
    try:
        baseline_resp = session.get(urljoin(base_url, random_path), timeout=TIMEOUT, allow_redirects=False)
        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.content)
    except Exception:
        baseline_status, baseline_len = None, None

    soft_404 = baseline_status == 200

    for path in SENSITIVE_PATHS:
        url = urljoin(base_url, path)
        try:
            resp = session.get(url, timeout=TIMEOUT, allow_redirects=False)
        except Exception:
            continue  # unreachable path is not itself a finding

        if resp.status_code != 200 or len(resp.content) == 0:
            continue

        if soft_404:
            # Only flag if meaningfully different from the site's generic "not found" response
            if baseline_len and abs(len(resp.content) - baseline_len) < max(50, baseline_len * 0.05):
                continue  # looks like the same soft-404 page, not real content
            findings.append(Finding(
                "Exposed Path", "medium", f"Possibly exposed: {path} (HTTP 200, differs from baseline)",
                "Site returns 200 for unknown paths (soft-404), but this response differs "
                "from that baseline in size — worth checking manually.",
            ))
        else:
            findings.append(Finding(
                "Exposed Path", "high", f"Possibly exposed: {path} (HTTP 200)",
                "Verify manually to confirm this is real, sensitive content.",
            ))

    return findings


def scan_target(url: str, progress_callback=None) -> WebScanResult:
    import requests

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        return WebScanResult(target=url, error="Could not parse a valid hostname from that URL.")

    session = requests.Session()
    session.headers.update({"User-Agent": "Rupux-WebAppScanner/1.0 (authorized-testing-only)"})

    if progress_callback:
        progress_callback(f"Connecting to {hostname}...")

    try:
        resp = session.get(url, timeout=TIMEOUT, allow_redirects=True)
    except requests.exceptions.SSLError as e:
        return WebScanResult(target=url, error=f"TLS/SSL error connecting: {e}")
    except requests.exceptions.ConnectionError as e:
        return WebScanResult(target=url, error=f"Could not connect: {e}")
    except requests.exceptions.Timeout:
        return WebScanResult(target=url, error="Connection timed out.")
    except Exception as e:
        return WebScanResult(target=url, error=f"Request failed: {e}")

    result = WebScanResult(target=url, final_url=resp.url, status_code=resp.status_code)
    is_https = resp.url.startswith("https://")

    if progress_callback:
        progress_callback("Checking security headers...")
    result.findings += _check_headers(resp.headers, is_https)

    if progress_callback:
        progress_callback("Checking cookie flags...")
    result.findings += _check_cookies(resp)

    if is_https:
        if progress_callback:
            progress_callback("Checking TLS certificate...")
        result.findings += _check_tls(hostname)

    if progress_callback:
        progress_callback(f"Checking {len(SENSITIVE_PATHS)} common sensitive paths...")
    netloc = hostname if not parsed.port else f"{hostname}:{parsed.port}"
    result.findings += _check_exposed_paths(session, f"{parsed.scheme}://{netloc}")

    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    result.findings.sort(key=lambda f: severity_rank.get(f.severity, 4))

    return result
