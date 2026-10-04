"""Scripted Network adapter: the second adapter behind the network seam (the first is network.RealNetwork).

Describe a site by its DNS answers, the responses it gives per URL and its certificate; the scan engine
then runs end to end with no sockets. Every call is recorded so tests can assert what the engine did.
"""
from network import Hop, NameNotFound, NetworkError

PUBLIC_IP = "93.184.216.34"
GOOD_TLS = {"valid": True, "error": None, "expires": "2099-01-01", "days_left": 900, "issuer": "Test CA", "version": "TLSv1.3"}
BAD_TLS = {"valid": False, "error": "certificate has expired", "expires": None, "days_left": None, "issuer": None, "version": None}

SECURE_HEADERS = {
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
    "content-type": "text/html",
}


def hop(status=200, headers=None, cookies=None, body="<html></html>", location=None):
    merged = {k.lower(): v for k, v in (headers or {}).items()}
    if location:
        merged["location"] = location
    return Hop(status=status, headers=merged, cookies=cookies or [], body=body)


def redirect(location, cookies=None, status=301):
    return hop(status=status, location=location, cookies=cookies, body="")


class ScriptedNetwork:
    """dns: host -> addresses (or a list of address lists, consumed one per lookup).
    pages: url -> Hop, or an Exception to raise, or a list of those consumed one per request.
    tls: host -> certificate dict."""

    def __init__(self, dns=None, pages=None, tls=None):
        self.dns = dns or {}
        self.pages = pages or {}
        self.tls = tls or {}
        self.lookups, self.requests, self.handshakes = [], [], []

    def resolve(self, host, port):
        self.lookups.append((host, port))
        answer = self.dns.get(host)
        if answer is None:
            raise NameNotFound(host)
        if answer and isinstance(answer[0], list):          # one answer per lookup, last one repeats
            answer = answer.pop(0) if len(answer) > 1 else answer[0]
        return list(answer)

    def get(self, url, ips, verify=True):
        self.requests.append({"url": url, "ips": list(ips), "verify": verify})
        page = self.pages.get(url)
        if page is None:
            raise NetworkError(f"connection refused: {url}")
        if isinstance(page, list):
            page = page.pop(0) if len(page) > 1 else page[0]
        if isinstance(page, Exception):
            raise page
        return page

    def handshake(self, host, port, ips):
        self.handshakes.append({"host": host, "port": port, "ips": list(ips)})
        return dict(self.tls.get(host, BAD_TLS))


def site(host="example.com", headers=None, cookies=None, body="<html></html>", tls=GOOD_TLS, http_redirects=True):
    """A well-behaved HTTPS site: https://host/ answers 200, http://host/ redirects to it."""
    pages = {f"https://{host}": hop(headers=headers if headers is not None else SECURE_HEADERS, cookies=cookies, body=body)}
    if http_redirects:
        pages[f"http://{host}/"] = redirect(f"https://{host}/")
    return ScriptedNetwork(dns={host: [PUBLIC_IP]}, pages=pages, tls={host: tls})
