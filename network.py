"""The scan engine's only contact with the outside world.

A Network offers three operations; the engine (pycheck.py) uses nothing else:

    resolve(host, port)          -> list of IP address strings
    get(url, ips, verify)        -> Hop, one HTTP request with no redirect following
    handshake(host, port, ips)   -> dict describing the TLS certificate

`get` and `handshake` connect only to the addresses they are given, which the engine has already
checked are public, so a DNS answer cannot change between the check and the connection (DNS rebinding).
The hostname is still used for the Host header, SNI and certificate matching.

RealNetwork is the production adapter. tests/fake_network.py holds the scripted adapter used in tests.
"""
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

import requests
import urllib3
from requests.adapters import HTTPAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

MAX_BODY_BYTES = 256 * 1024
MAX_ADDRESSES_TRIED = 2        # a dead first address should not eat the whole scan deadline
REDIRECT_STATUSES = (301, 302, 303, 307, 308)


class NetworkError(Exception):
    """The connection failed (refused, timed out, reset)."""


class TlsFailure(NetworkError):
    """The server's certificate was rejected, or the TLS handshake failed."""


class NameNotFound(NetworkError):
    """DNS has no address for the host."""


@dataclass
class Hop:
    """One HTTP response. Header names are lower-cased; cookies are the raw Set-Cookie values."""
    status: int
    headers: dict = field(default_factory=dict)
    cookies: list = field(default_factory=list)
    body: str = ""

    @property
    def location(self):
        return self.headers.get("location", "")

    @property
    def is_redirect(self):
        return self.status in REDIRECT_STATUSES and bool(self.location)


def _ipv4_first(addresses):
    return sorted(addresses, key=lambda a: ":" in a)


class _PinnedAdapter(HTTPAdapter):
    """Opens HTTPS connections to an IP address while verifying the certificate against `hostname`."""

    def __init__(self, hostname, **kwargs):
        self._hostname = hostname
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["server_hostname"] = self._hostname
        kwargs["assert_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)


class RealNetwork:
    def resolve(self, host, port):
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror:
            raise NameNotFound(host)
        return _ipv4_first(list(dict.fromkeys(info[4][0] for info in infos)))

    def get(self, url, ips, verify=True):
        parts = urlsplit(url)
        last_error = NetworkError("no address to connect to")
        for ip in _ipv4_first(ips)[:MAX_ADDRESSES_TRIED]:
            host_part = f"[{ip}]" if ":" in ip else ip
            netloc = f"{host_part}:{parts.port}" if parts.port else host_part
            pinned = urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))
            headers = {**HEADERS, "Host": parts.netloc.rpartition("@")[2]}
            session = requests.Session()
            session.mount("https://", _PinnedAdapter(parts.hostname))
            try:
                resp = session.get(pinned, headers=headers, timeout=(3, 5), allow_redirects=False,
                                   verify=verify, stream=True)
            except requests.exceptions.SSLError as exc:
                session.close()
                raise TlsFailure(str(exc))
            except requests.exceptions.RequestException as exc:
                session.close()
                last_error = NetworkError(str(exc))
                continue
            try:
                return self._read(resp)
            finally:
                resp.close()
                session.close()
        raise last_error

    @staticmethod
    def _read(resp):
        raw = getattr(resp.raw, "headers", None)
        cookies = raw.getlist("Set-Cookie") if raw is not None and hasattr(raw, "getlist") else []
        headers = {k.lower(): v for k, v in resp.headers.items()}
        hop = Hop(status=resp.status_code, headers=headers, cookies=cookies)
        if not hop.is_redirect and "html" in headers.get("content-type", "").lower():
            data = resp.raw.read(MAX_BODY_BYTES, decode_content=True)
            hop.body = data.decode(resp.encoding or "utf-8", errors="replace")
        return hop

    def handshake(self, host, port, ips):
        info = {"valid": False, "error": None, "expires": None, "days_left": None, "issuer": None, "version": None}
        context = ssl.create_default_context()
        error = "could not complete a TLS handshake on port 443"
        for ip in _ipv4_first(ips)[:MAX_ADDRESSES_TRIED]:
            try:
                with socket.create_connection((ip, port), timeout=4) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        info["valid"] = bool(cert)
                        info["version"] = tls.version()
                        expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                        info["expires"] = expires.date().isoformat()
                        info["days_left"] = (expires - datetime.now(timezone.utc)).days
                        issuer = dict(x[0] for x in cert.get("issuer", ()))
                        info["issuer"] = issuer.get("organizationName") or issuer.get("commonName")
                        return info
            except ssl.SSLCertVerificationError as exc:
                info["error"] = exc.verify_message or "certificate verification failed"
                return info
            except (OSError, ssl.SSLError):
                continue
        info["error"] = error
        return info
