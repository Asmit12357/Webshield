"""Each check is tested against fabricated responses: no network needed."""
import socket

import pytest

import pycheck
from pycheck import (FetchResult, ScanError, check_certificate, check_cookies, check_csp, check_frame,
                     check_hsts, check_http_redirect, check_https, check_mixed_content, check_nosniff,
                     check_referrer, check_server_leakage, validate_target)


def page(headers=None, cookies=None, url="https://example.com/", body="", tls_error=False):
    return FetchResult(final_url=url, headers={k.lower(): v for k, v in (headers or {}).items()},
                       cookies=cookies or [], body=body, tls_error=tls_error)


def status(check_fn, **kw):
    return check_fn(page(**kw))["status"]


# --- HTTPS / certificate (bugs 1, 2, 6) --------------------------------------------------------
def test_https_requires_final_https():
    assert status(check_https) == "pass"
    assert status(check_https, url="http://example.com/") == "fail"


def test_https_fails_when_certificate_was_rejected():
    assert status(check_https, tls_error=True) == "fail"


BAD_TLS = {"valid": False, "error": "certificate has expired", "expires": None, "days_left": None, "issuer": None, "version": None}
GOOD_TLS = {"valid": True, "error": None, "expires": "2027-01-01", "days_left": 90, "issuer": "Lets Encrypt", "version": "TLSv1.3"}


def test_certificate_states():
    assert check_certificate(BAD_TLS)["status"] == "fail"
    assert check_certificate(GOOD_TLS)["status"] == "pass"
    assert check_certificate({**GOOD_TLS, "days_left": 5})["status"] == "warn"
    assert check_certificate({**GOOD_TLS, "days_left": -1})["status"] == "fail"
    assert check_certificate({**GOOD_TLS, "version": "TLSv1"})["status"] == "warn"


def test_http_redirect_follows_www_hop(monkeypatch):
    """http://x -> http://www.x -> https://www.x counts as a redirect to HTTPS."""
    monkeypatch.setattr(pycheck, "validate_target", lambda url: None)

    class R:
        def __init__(self, loc): self.headers = {"Location": loc} if loc else {}; self.is_redirect = bool(loc)
        def close(self): pass

    chain = iter([R("http://www.example.com/"), R("https://www.example.com/")])
    monkeypatch.setattr(pycheck.requests, "get", lambda *a, **k: next(chain))
    assert pycheck.probe_http_redirect("example.com") == "redirects"
    monkeypatch.setattr(pycheck.requests, "get", lambda *a, **k: R(None))
    assert pycheck.probe_http_redirect("example.com") == "plain"


def test_http_redirect_outcomes():
    assert check_http_redirect("redirects")["status"] == "pass"
    assert check_http_redirect("plain")["status"] == "fail"
    assert check_http_redirect("closed")["max"] == 0   # excluded from the score


# --- header values, not just presence (bug 3) --------------------------------------------------
@pytest.mark.parametrize("value,expected", [
    ("max-age=31536000; includeSubDomains", "pass"),
    ("max-age=3600", "warn"),
    ("max-age=0", "fail"),
    ("garbage", "fail"),
])
def test_hsts_values(value, expected):
    assert status(check_hsts, headers={"Strict-Transport-Security": value}) == expected


def test_hsts_missing_or_over_http_fails():
    assert status(check_hsts) == "fail"
    assert status(check_hsts, url="http://x.com/", headers={"Strict-Transport-Security": "max-age=31536000"}) == "fail"


@pytest.mark.parametrize("value,expected", [
    ("default-src 'self'; object-src 'none'", "pass"),
    ("default-src * 'unsafe-inline' 'unsafe-eval'", "warn"),
    ("script-src 'self' 'unsafe-inline'", "warn"),
    ("script-src 'self' 'nonce-abc' 'unsafe-inline'", "pass"),   # nonce makes unsafe-inline ignored
    ("script-src *", "warn"),
])
def test_csp_values(value, expected):
    assert status(check_csp, headers={"Content-Security-Policy": value}) == expected


def test_csp_missing():
    assert status(check_csp) == "fail"


def test_frame_protection():
    assert status(check_frame, headers={"X-Frame-Options": "DENY"}) == "pass"
    assert status(check_frame, headers={"X-Frame-Options": "ALLOWALL"}) == "fail"
    assert status(check_frame, headers={"Content-Security-Policy": "frame-ancestors 'none'"}) == "pass"
    assert status(check_frame) == "fail"


def test_nosniff_must_be_exact():
    assert status(check_nosniff, headers={"X-Content-Type-Options": "nosniff"}) == "pass"
    assert status(check_nosniff, headers={"X-Content-Type-Options": "whatever"}) == "fail"
    assert status(check_nosniff) == "fail"


def test_referrer_policy():
    assert status(check_referrer, headers={"Referrer-Policy": "strict-origin-when-cross-origin"}) == "pass"
    assert status(check_referrer, headers={"Referrer-Policy": "unsafe-url"}) == "warn"
    assert status(check_referrer) == "fail"


# --- cookies (bugs 4, 5) -----------------------------------------------------------------------
@pytest.mark.parametrize("name", ["legacy_auth", "organization_session", "language_session", "pagination_token"])
def test_cookie_names_containing_ga_are_not_exempt(name):
    assert status(check_cookies, cookies=[f"{name}=abc; Path=/"]) == "fail"


def test_real_analytics_cookies_are_exempt():
    assert status(check_cookies, cookies=["_ga=1; Path=/", "_gid=2; Path=/", "_ga_ABC123=3; Path=/"]) == "na"


def test_cookies_from_redirect_hops_are_included():
    # fetch() accumulates Set-Cookie across hops; the check sees them all
    assert status(check_cookies, cookies=["sessionid=abc; Path=/"]) == "fail"


def test_cookie_secure_httponly_samesite():
    assert status(check_cookies, cookies=["sid=a; Secure; HttpOnly; SameSite=Lax"]) == "pass"
    assert status(check_cookies, cookies=["sid=a; Secure; HttpOnly"]) == "warn"
    assert status(check_cookies, cookies=["sid=a; Secure; SameSite=None"]) == "fail"   # no HttpOnly
    assert status(check_cookies, cookies=["sid=a; HttpOnly; SameSite=Lax"]) == "fail"  # no Secure


def test_missing_httponly_on_non_session_cookie_is_only_a_warning():
    assert status(check_cookies, cookies=["_octo=1; Secure; SameSite=Lax"]) == "warn"
    assert status(check_cookies, cookies=["prefs=1; SameSite=Lax"]) == "fail"          # no Secure


def test_no_cookies_is_not_a_free_pass():
    result = check_cookies(page())
    assert result["status"] == "na" and result["max"] == 0


# --- information leakage -----------------------------------------------------------------------
@pytest.mark.parametrize("server,expected", [
    ("nginx/1.10.3 (Ubuntu)", "fail"), ("Apache/2.4.41", "fail"), ("gunicorn/19.9.0", "fail"),
    ("cloudflare", "pass"), ("gws", "pass"), ("github.com", "pass"), ("", "pass"),
])
def test_server_header(server, expected):
    assert status(check_server_leakage, headers={"Server": server} if server else {}) == expected


def test_x_powered_by_leaks():
    assert status(check_server_leakage, headers={"X-Powered-By": "Express"}) == "fail"


# --- mixed content -----------------------------------------------------------------------------
def test_mixed_content():
    html = '<html><img src="http://cdn.example.com/a.png"><script src="https://ok.com/a.js"></script></html>'
    assert status(check_mixed_content, body=html) == "fail"
    assert status(check_mixed_content, body='<img src="https://ok.com/a.png">') == "pass"
    assert status(check_mixed_content, body="") == "na"


# --- SSRF guard / input validation -------------------------------------------------------------
def fake_dns(ip):
    def _getaddrinfo(host, port, **kw):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]
    return _getaddrinfo


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.169.254", "100.64.0.1", "0.0.0.0"])
def test_private_addresses_rejected(monkeypatch, ip):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns(ip))
    with pytest.raises(ScanError):
        validate_target("https://example.com")


@pytest.mark.parametrize("target", ["http://127.0.0.1/", "http://[::1]/", "http://169.254.169.254/latest/meta-data/", "http://localhost/"])
def test_ip_literals_and_localhost_rejected(target):
    with pytest.raises(ScanError):
        validate_target(target)


@pytest.mark.parametrize("target", ["https://example.com:8080", "https://example.com:22", "https://user:pw@example.com",
                                    "https://", "ftp://example.com", "https://not a host", "https://nodot"])
def test_bad_targets_rejected(monkeypatch, target):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns("93.184.216.34"))
    with pytest.raises(ScanError):
        validate_target(target)


def test_public_address_accepted(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", fake_dns("93.184.216.34"))
    validate_target("https://example.com")
    validate_target("http://example.com:80/path")


def test_unresolvable_host_rejected(monkeypatch):
    def boom(*a, **k):
        raise socket.gaierror
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(ScanError):
        validate_target("https://nonexistent-domain.example")


def test_normalize_url():
    assert pycheck.normalize_url("  example.com ") == "https://example.com"
    assert pycheck.normalize_url("http://example.com") == "http://example.com"
