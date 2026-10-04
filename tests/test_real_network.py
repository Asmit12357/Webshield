"""RealNetwork against a throwaway local HTTP server: pinning, no redirect following, cookies, body, errors."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from network import NameNotFound, NetworkError, RealNetwork

seen = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        seen.append({"path": self.path, "host": self.headers.get("Host"), "agent": self.headers.get("User-Agent")})
        if self.path == "/moved":
            self.send_response(301)
            self.send_header("Location", "/elsewhere")
            self.end_headers()
        elif self.path == "/json":
            body = b'{"a": 1}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            body = b"<html>hello</html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "a=1; Secure")
            self.send_header("Set-Cookie", "b=2; HttpOnly")
            self.send_header("X-Test", "Yes")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield httpd.server_address[1]
    httpd.shutdown()


def test_connects_to_the_given_address_but_sends_the_hostname(server):
    seen.clear()
    hop = RealNetwork().get(f"http://example.test:{server}/page", ["127.0.0.1"])      # example.test does not resolve
    assert hop.status == 200 and hop.body == "<html>hello</html>"
    assert seen[0]["host"] == f"example.test:{server}" and seen[0]["path"] == "/page"
    assert "Mozilla" in seen[0]["agent"]


def test_reads_every_set_cookie_and_lower_cases_header_names(server):
    hop = RealNetwork().get(f"http://example.test:{server}/", ["127.0.0.1"])
    assert hop.cookies == ["a=1; Secure", "b=2; HttpOnly"]
    assert hop.headers["x-test"] == "Yes"


def test_redirects_are_reported_not_followed(server):
    seen.clear()
    hop = RealNetwork().get(f"http://example.test:{server}/moved", ["127.0.0.1"])
    assert hop.status == 301 and hop.is_redirect and hop.location == "/elsewhere"
    assert [s["path"] for s in seen] == ["/moved"]


def test_non_html_bodies_are_not_read(server):
    assert RealNetwork().get(f"http://example.test:{server}/json", ["127.0.0.1"]).body == ""


def test_connection_refused_raises_network_error():
    with pytest.raises(NetworkError):
        RealNetwork().get("http://example.test:9/", ["127.0.0.1"])


def test_no_addresses_raises_network_error():
    with pytest.raises(NetworkError):
        RealNetwork().get("http://example.test/", [])


def test_unresolvable_name_raises_name_not_found():
    with pytest.raises(NameNotFound):
        RealNetwork().resolve("no-such-host.invalid", 443)


def test_resolve_returns_ipv4_first():
    assert RealNetwork().resolve("127.0.0.1", 80) == ["127.0.0.1"]
