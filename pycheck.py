"""WebShield scan engine.

run_checks(url) fetches the target once (following redirects by hand so every hop is
validated), then evaluates a list of checks. Each check returns a dict:
    {key, name, status: pass|warn|fail|na, points, max, evidence, fix}
"""
import ipaddress
import re
import socket
import ssl
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit

import requests
import urllib3
from bs4 import BeautifulSoup

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

MAX_REDIRECTS = 5
MAX_BODY_BYTES = 256 * 1024
SCAN_DEADLINE_SECONDS = 15
ALLOWED_PORTS = (80, 443)
HSTS_MIN_SECONDS = 15552000  # 180 days
REFUSED_STATUSES = (401, 403, 429)
# Headers bot-protection systems add to the challenge page they serve instead of the real site.
CHALLENGE_HEADERS = {"x-amzn-waf-action": "challenge", "cf-mitigated": "challenge"}

HOSTNAME_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
SESSIONISH_COOKIE_RE = re.compile(r"sess|sid|auth|token|login|jwt|csrf|user", re.I)
ANALYTICS_COOKIE_RE = re.compile(r"(_ga(_.+)?|_gid|_gat.*|_gcl_.+|_fbp|_fbc|__utm[a-z]|_pk_.+)")
TECH_HEADERS = ("x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-runtime", "x-version", "x-generator")
VERSION_RE = re.compile(r"(/\d+)|(\d+\.\d+)")


class ScanError(Exception):
    """The target is invalid, forbidden, or could not be scanned. Message is user-safe."""


@dataclass
class FetchResult:
    final_url: str
    status: int = 200
    headers: dict = field(default_factory=dict)      # lower-cased names
    cookies: list = field(default_factory=list)      # raw Set-Cookie values from every hop
    body: str = ""
    tls_error: bool = False                          # certificate verification failed during fetch
    hops: int = 0


# ----------------------------------------------------------------------------- input / SSRF

def normalize_url(url):
    """Trim the input, default to https://, and canonicalise so one site is always stored one way.

    The scheme and host are lower-cased, a trailing dot on the host, the fragment and a bare "/" path are
    dropped. A non-web scheme (ftp://) is left alone for validate_target to reject with a clear message.
    """
    url = (url or "").strip()
    if re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I) and not re.match(r"^https?://", url, re.I):
        return url
    if not re.match(r"^https?://", url, re.I):
        url = f"https://{url}"
    try:
        parts = urlsplit(url)
    except ValueError:
        return url
    netloc = parts.netloc.lower()
    if netloc.endswith("."):
        netloc = netloc[:-1]
    path = "" if parts.path == "/" else parts.path
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def validate_target(url):
    """Raise ScanError unless url points at a public host on port 80/443."""
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError:
        raise ScanError("That doesn't look like a valid URL.")
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        if parsed.scheme not in ("http", "https") and parsed.scheme:
            raise ScanError("Only http:// and https:// addresses can be scanned.")
        raise ScanError("Enter a website address such as example.com.")
    if parsed.username or parsed.password:
        raise ScanError("URLs with embedded credentials are not allowed.")
    host = parsed.hostname
    is_ip = True
    try:
        ipaddress.ip_address(host)
    except ValueError:
        is_ip = False
    if not is_ip and not HOSTNAME_RE.match(host):
        raise ScanError("That doesn't look like a valid domain name.")
    if port not in (None,) + ALLOWED_PORTS:
        raise ScanError("Only the standard web ports (80 and 443) can be scanned.")
    try:
        infos = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ScanError(f"Could not find a server named '{host}'.")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if getattr(ip, "ipv4_mapped", None):
            ip = ip.ipv4_mapped
        if not ip.is_global:
            raise ScanError("Scanning private, local or reserved addresses is not allowed.")


# ----------------------------------------------------------------------------- network

def check_response_is_real_site(resp):
    """Refuse to score an error page or a bot-protection challenge: its headers say nothing about the site."""
    challenged = any(resp.headers.get(name, "").lower() == value for name, value in CHALLENGE_HEADERS.items())
    if challenged or resp.status_code in REFUSED_STATUSES:
        resp.close()
        raise ScanError(f"The site refused the scan (status {resp.status_code}), usually because it blocks "
                        "automated visitors. Its real security headers could not be read, so no score was given.")
    if resp.status_code >= 500:
        resp.close()
        raise ScanError(f"The site returned a server error (status {resp.status_code}), "
                        "so it cannot be assessed right now. Try again later.")


def fetch(url, deadline):
    """GET url following up to MAX_REDIRECTS redirects, validating every hop."""
    verify = True
    tls_error = False
    cookies = []
    hops = 0
    current = url
    while True:
        validate_target(current)
        if time.monotonic() > deadline:
            raise ScanError("The scan took too long and was stopped.")
        try:
            resp = requests.get(current, headers=HEADERS, timeout=(3, 5), allow_redirects=False,
                                verify=verify, stream=True)
        except requests.exceptions.SSLError:
            if not verify:
                raise ScanError("Could not establish a TLS connection to the site.")
            verify, tls_error = False, True        # retry this hop to still read its headers
            continue
        except requests.exceptions.RequestException:
            raise ScanError("Could not connect to the site (timeout or connection refused).")

        raw = getattr(resp.raw, "headers", None)
        if raw is not None and hasattr(raw, "getlist"):
            cookies.extend(raw.getlist("Set-Cookie"))

        if resp.is_redirect and resp.headers.get("Location"):
            resp.close()
            hops += 1
            if hops > MAX_REDIRECTS:
                raise ScanError("The site redirected too many times.")
            current = urljoin(current, resp.headers["Location"])
            continue

        check_response_is_real_site(resp)

        body = ""
        if "html" in resp.headers.get("Content-Type", "").lower():
            data = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
            body = data.decode(resp.encoding or "utf-8", errors="replace")
        resp.close()
        return FetchResult(
            final_url=resp.url, status=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            cookies=cookies, body=body, tls_error=tls_error, hops=hops,
        )


def probe_tls(host, port=443):
    """Handshake with full verification. Returns a dict describing the certificate."""
    info = {"valid": False, "error": None, "expires": None, "days_left": None,
            "issuer": None, "version": None}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                info["valid"] = bool(cert)
                info["version"] = tls.version()
                expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                info["expires"] = expires.date().isoformat()
                info["days_left"] = (expires - datetime.now(timezone.utc)).days
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
    except ssl.SSLCertVerificationError as e:
        info["error"] = e.verify_message or "certificate verification failed"
    except (OSError, ssl.SSLError):
        info["error"] = "could not complete a TLS handshake on port 443"
    return info


def probe_http_redirect(host):
    """Request http://host/ and follow up to 3 redirects (e.g. http://x -> http://www.x -> https://www.x).

    Returns 'redirects' if the chain reaches https://, 'plain' if it ends on plain HTTP, 'closed' if
    nothing answers on port 80.
    """
    current = f"http://{host}/"
    try:
        for _ in range(4):
            validate_target(current)
            r = requests.get(current, headers=HEADERS, timeout=(3, 4), allow_redirects=False, stream=True)
            location = r.headers.get("Location", "")
            is_redirect = r.is_redirect
            r.close()
            if not is_redirect or not location:
                return "plain"
            current = urljoin(current, location)
            if current.lower().startswith("https://"):
                return "redirects"
        return "plain"
    except (ScanError, requests.exceptions.RequestException):
        return "closed"


# ----------------------------------------------------------------------------- checks

def _res(key, name, status, max_pts, evidence, fix=""):
    points = {"pass": max_pts, "warn": max_pts // 2}.get(status, 0)
    if status == "na":
        max_pts = 0
    return {"key": key, "name": name, "status": status, "points": points,
            "max": max_pts, "evidence": evidence, "fix": fix}


def check_https(f):
    if f.final_url.startswith("https://") and not f.tls_error:
        return _res("https", "HTTPS", "pass", 15, "Site is served over HTTPS.")
    if f.final_url.startswith("https://"):
        return _res("https", "HTTPS", "fail", 15, "Site uses HTTPS but its certificate failed verification.",
                    "Install a valid certificate (see the Certificate check).")
    return _res("https", "HTTPS", "fail", 15, f"Final page was served over plain HTTP ({f.final_url}).",
                "Serve the whole site over HTTPS and redirect all HTTP traffic to it. Free certificates: Let's Encrypt.")


def check_certificate(tls):
    fix = "Install a certificate from a trusted CA (Let's Encrypt is free) that matches your domain, and renew it before it expires."
    if not tls["valid"]:
        return _res("certificate", "TLS Certificate", "fail", 15, f"Certificate rejected: {tls['error']}.", fix)
    ev = f"Issued by {tls['issuer'] or 'unknown CA'}, expires {tls['expires']} ({tls['days_left']} days), {tls['version']}."
    if tls["days_left"] < 0:
        return _res("certificate", "TLS Certificate", "fail", 15, ev, fix)
    if tls["days_left"] < 14 or tls["version"] in ("TLSv1", "TLSv1.1"):
        return _res("certificate", "TLS Certificate", "warn", 15, ev, "Renew the certificate soon and disable TLS 1.0/1.1.")
    return _res("certificate", "TLS Certificate", "pass", 15, ev)


def check_http_redirect(outcome):
    if outcome == "redirects":
        return _res("http_redirect", "HTTP → HTTPS Redirect", "pass", 5, "http:// requests are redirected to https://.")
    if outcome == "plain":
        return _res("http_redirect", "HTTP → HTTPS Redirect", "fail", 5, "http:// serves content without redirecting to HTTPS.",
                    "nginx: server { listen 80; return 301 https://$host$request_uri; }")
    return _res("http_redirect", "HTTP → HTTPS Redirect", "na", 5, "Port 80 is not reachable, so no plain-HTTP exposure.")


def check_hsts(f):
    fix = "Add the header: Strict-Transport-Security: max-age=31536000; includeSubDomains\nnginx: add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;"
    value = f.headers.get("strict-transport-security")
    if not f.final_url.startswith("https://"):
        return _res("hsts", "HSTS", "fail", 15, "HSTS only works over HTTPS.", fix)
    if not value:
        return _res("hsts", "HSTS", "fail", 15, "Strict-Transport-Security header is missing.", fix)
    m = re.search(r"max-age\s*=\s*\"?(\d+)", value, re.I)
    age = int(m.group(1)) if m else 0
    if age == 0:
        return _res("hsts", "HSTS", "fail", 15, f"max-age is 0, which disables HSTS ({value}).", fix)
    if age < HSTS_MIN_SECONDS:
        return _res("hsts", "HSTS", "warn", 15, f"max-age={age} is under 180 days ({value}).", fix)
    return _res("hsts", "HSTS", "pass", 15, value)


def check_csp(f):
    fix = "Start with: Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'\nthen allow only the sources your pages need. Avoid 'unsafe-inline' and 'unsafe-eval'."
    value = f.headers.get("content-security-policy")
    if not value:
        if f.headers.get("content-security-policy-report-only"):
            return _res("csp", "Content-Security-Policy", "warn", 15,
                        "Only a report-only policy is sent (Content-Security-Policy-Report-Only). It reports violations but blocks nothing.",
                        "When the reports look clean, send the same policy as Content-Security-Policy so the browser enforces it.")
        return _res("csp", "Content-Security-Policy", "fail", 15, "Content-Security-Policy header is missing.", fix)
    problems = []
    directives = {}
    for part in value.split(";"):
        tokens = part.split()
        if tokens:
            directives[tokens[0].lower()] = [t.lower() for t in tokens[1:]]
    for name in ("default-src", "script-src"):
        sources = directives.get(name, [])
        if "'unsafe-inline'" in sources and not any(s.startswith(("'nonce-", "'sha")) for s in sources):
            problems.append(f"{name} allows 'unsafe-inline'")
        if "'unsafe-eval'" in sources:
            problems.append(f"{name} allows 'unsafe-eval'")
        if "*" in sources:
            problems.append(f"{name} allows any source (*)")
    if problems:
        return _res("csp", "Content-Security-Policy", "warn", 15, "Present but weak: " + "; ".join(problems) + ".", fix)
    return _res("csp", "Content-Security-Policy", "pass", 15, value[:160] + ("…" if len(value) > 160 else ""))


def check_frame(f):
    fix = "Add X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive."
    xfo = f.headers.get("x-frame-options", "").strip().upper()
    csp = f.headers.get("content-security-policy", "")
    if re.search(r"frame-ancestors\s+[^;]+", csp, re.I):
        return _res("frame", "Clickjacking Protection", "pass", 5, "CSP frame-ancestors is set.")
    if xfo in ("DENY", "SAMEORIGIN"):
        return _res("frame", "Clickjacking Protection", "pass", 5, f"X-Frame-Options: {xfo}")
    if xfo:
        return _res("frame", "Clickjacking Protection", "fail", 5, f"X-Frame-Options value '{xfo}' does not block framing.", fix)
    return _res("frame", "Clickjacking Protection", "fail", 5, "Neither X-Frame-Options nor CSP frame-ancestors is set.", fix)


def check_nosniff(f):
    value = f.headers.get("x-content-type-options", "").strip().lower()
    if value == "nosniff":
        return _res("nosniff", "MIME Sniffing Protection", "pass", 5, "X-Content-Type-Options: nosniff")
    ev = f"Invalid value '{value}'; it must be exactly nosniff." if value else "X-Content-Type-Options header is missing."
    return _res("nosniff", "MIME Sniffing Protection", "fail", 5, ev, "Add the header: X-Content-Type-Options: nosniff")


def check_referrer(f):
    fix = "Add the header: Referrer-Policy: strict-origin-when-cross-origin"
    value = f.headers.get("referrer-policy", "").strip().lower()
    if not value:
        return _res("referrer", "Referrer-Policy", "fail", 5, "Referrer-Policy header is missing.", fix)
    last = value.split(",")[-1].strip()
    if last in ("unsafe-url", "no-referrer-when-downgrade", ""):
        return _res("referrer", "Referrer-Policy", "warn", 5, f"'{last}' can leak full URLs to other sites.", fix)
    return _res("referrer", "Referrer-Policy", "pass", 5, value)


def check_permissions_policy(f):
    value = f.headers.get("permissions-policy")
    if value:
        return _res("permissions", "Permissions-Policy", "pass", 0, value[:120])
    return _res("permissions", "Permissions-Policy", "warn", 0, "Not set (informational, not scored).",
                "Add Permissions-Policy: camera=(), microphone=(), geolocation=()")


def check_cookies(f):
    fix = "Set cookies with: Secure; HttpOnly; SameSite=Lax\nFlask: SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax'"
    seen, problems, minor, no_samesite, total = set(), [], [], [], 0
    for raw in f.cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0].strip()
        if not name or name in seen or ANALYTICS_COOKIE_RE.fullmatch(name):
            continue
        seen.add(name)
        total += 1
        attrs = {p.split("=", 1)[0].strip().lower(): p.partition("=")[2].strip().lower() for p in parts[1:]}
        missing = [label for key, label in (("secure", "Secure"), ("httponly", "HttpOnly")) if key not in attrs]
        # HttpOnly only protects against script theft of session-like cookies, so a missing HttpOnly on a
        # cookie that does not look like a session/auth cookie is a weakness, not a failure.
        if "Secure" in missing or ("HttpOnly" in missing and SESSIONISH_COOKIE_RE.search(name)):
            problems.append(f"{name} (missing {', '.join(missing)})")
        elif missing:
            minor.append(f"{name} (missing {', '.join(missing)})")
        if "samesite" not in attrs:
            no_samesite.append(name)
    if total == 0:
        return _res("cookies", "Cookie Security", "na", 10, "No first-party cookies were set on this page.")
    if problems:
        return _res("cookies", "Cookie Security", "fail", 10, "Insecure cookies: " + "; ".join(problems) + ".", fix)
    if minor:
        return _res("cookies", "Cookie Security", "warn", 10, "Cookies lacking HttpOnly: " + "; ".join(minor) + ".", fix)
    if no_samesite:
        return _res("cookies", "Cookie Security", "warn", 10, f"{total} cookie(s) secure, but no SameSite on: {', '.join(no_samesite)}.", fix)
    return _res("cookies", "Cookie Security", "pass", 10, f"{total} cookie(s) set with Secure, HttpOnly and SameSite.")


def check_server_leakage(f):
    fix = "nginx: server_tokens off;   Apache: ServerTokens Prod and ServerSignature Off   Remove X-Powered-By in your framework or proxy."
    leaked = [f"{h}: {f.headers[h]}" for h in TECH_HEADERS if h in f.headers]
    server = f.headers.get("server", "").strip()
    if server and VERSION_RE.search(server):
        leaked.append(f"Server: {server}")
    if leaked:
        return _res("server_leakage", "Server Information Leakage", "fail", 10, "Reveals software details: " + "; ".join(leaked) + ".", fix)
    return _res("server_leakage", "Server Information Leakage", "pass", 10,
                f"Server: {server}" if server else "No server or technology headers exposed.")


def check_mixed_content(f):
    if not f.final_url.startswith("https://") or not f.body:
        return _res("mixed_content", "Mixed Content", "na", 5, "Not applicable (page is not HTML served over HTTPS).")
    soup = BeautifulSoup(f.body, "html.parser")
    found = []
    for tag, attr in (("script", "src"), ("link", "href"), ("img", "src"), ("iframe", "src"), ("audio", "src"), ("video", "src"), ("source", "src")):
        for el in soup.find_all(tag):
            val = (el.get(attr) or "").strip()
            if val.lower().startswith("http://"):
                found.append(val)
    if found:
        return _res("mixed_content", "Mixed Content", "fail", 5,
                    f"{len(found)} resource(s) load over HTTP, e.g. {found[0][:80]}.",
                    "Change http:// resource URLs to https:// (or protocol-relative paths).")
    return _res("mixed_content", "Mixed Content", "pass", 5, "No insecure resources found in the page HTML.")


# ----------------------------------------------------------------------------- orchestration

def run_checks(url):
    """Scan url and return the list of check results. Raises ScanError if it can't be scanned."""
    url = normalize_url(url)
    validate_target(url)
    host = urlparse(url).hostname
    deadline = time.monotonic() + SCAN_DEADLINE_SECONDS

    with ThreadPoolExecutor(max_workers=3) as pool:
        main = pool.submit(fetch, url, deadline)
        tls = pool.submit(probe_tls, host)
        redirect = pool.submit(probe_http_redirect, host)
        fetched = main.result()          # ScanError propagates
        tls_info, redirect_outcome = tls.result(), redirect.result()

    return [
        check_https(fetched),
        check_certificate(tls_info),
        check_http_redirect(redirect_outcome),
        check_hsts(fetched),
        check_csp(fetched),
        check_frame(fetched),
        check_nosniff(fetched),
        check_referrer(fetched),
        check_cookies(fetched),
        check_server_leakage(fetched),
        check_mixed_content(fetched),
        check_permissions_policy(fetched),
    ]
