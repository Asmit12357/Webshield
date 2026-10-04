"""The scan engine run end to end against a scripted site: redirects, cookies, deadline, TLS and address pinning."""
import pytest

import pycheck
from network import NetworkError, TlsFailure
from pycheck import ScanError, probe_http_redirect, run_checks
from score import calculate_score
from tests.fake_network import (BAD_TLS, GOOD_TLS, PUBLIC_IP, ScriptedNetwork, hop, redirect, site)


def by_key(checks):
    return {c["key"]: c for c in checks}


# --- the whole scan ------------------------------------------------------------------------------
def test_well_configured_site_scores_full_marks():
    checks = by_key(run_checks("example.com", site()))
    assert {c["status"] for c in checks.values() if c["max"]} == {"pass"}
    assert checks["cookies"]["status"] == "na"
    assert calculate_score(list(checks.values())) == 100


def test_bad_site_is_marked_down_check_by_check():
    network = site(headers={"content-type": "text/html", "server": "nginx/1.10.3"}, tls=BAD_TLS, http_redirects=False)
    network.pages["http://example.com/"] = hop()                  # plain HTTP, no redirect
    checks = by_key(run_checks("example.com", network))
    assert checks["certificate"]["status"] == "fail"
    assert checks["http_redirect"]["status"] == "fail"
    assert checks["hsts"]["status"] == "fail" and checks["csp"]["status"] == "fail"
    assert checks["server_leakage"]["status"] == "fail"
    assert calculate_score(list(checks.values())) <= 50            # rejected certificate caps the score


def test_scan_input_is_normalised_before_requests_are_made():
    network = site()
    run_checks("  Example.COM/  ", network)
    assert any(r["url"] == "https://example.com" for r in network.requests)
    assert ("example.com", 443) in network.lookups


# --- redirects and cookies -----------------------------------------------------------------------
def test_cookies_from_every_redirect_hop_reach_the_cookie_check():
    network = site()
    network.dns["www.example.com"] = [PUBLIC_IP]
    network.pages["https://example.com"] = redirect("https://www.example.com/", cookies=["sessionid=abc; Path=/"])
    network.pages["https://www.example.com/"] = hop(headers={"content-type": "text/html"}, cookies=["other=1; Secure; HttpOnly; SameSite=Lax"])
    cookies = by_key(run_checks("example.com", network))["cookies"]
    assert cookies["status"] == "fail" and "sessionid" in cookies["evidence"]


def test_final_url_after_redirects_decides_the_https_check():
    network = site()
    network.dns["other.example.org"] = [PUBLIC_IP]
    network.pages["https://example.com"] = redirect("http://other.example.org/")
    network.pages["http://other.example.org/"] = hop()
    assert by_key(run_checks("example.com", network))["https"]["status"] == "fail"


def test_too_many_redirects_is_an_error():
    network = site()
    network.pages["https://example.com"] = redirect("https://example.com/")
    network.pages["https://example.com/"] = redirect("https://example.com")
    with pytest.raises(ScanError, match="redirected too many times"):
        pycheck.fetch("https://example.com", float("inf"), network)


def test_redirect_to_a_private_host_is_blocked_at_that_hop():
    network = site()
    network.dns["internal.example.org"] = ["10.0.0.7"]
    network.pages["https://example.com"] = redirect("https://internal.example.org/admin")
    with pytest.raises(ScanError, match="private, local or reserved"):
        run_checks("example.com", network)
    assert all("internal" not in r["url"] for r in network.requests)     # never even requested


def test_http_redirect_probe_follows_a_www_hop():
    """http://x -> http://www.x -> https://www.x counts as a redirect to HTTPS."""
    network = site(http_redirects=False)
    network.dns["www.example.com"] = [PUBLIC_IP]
    network.pages["http://example.com/"] = redirect("http://www.example.com/")
    network.pages["http://www.example.com/"] = redirect("https://www.example.com/")
    assert probe_http_redirect("example.com", network) == "redirects"
    network.pages["http://www.example.com/"] = hop()
    assert probe_http_redirect("example.com", network) == "plain"


def test_http_redirect_probe_reports_closed_port():
    network = site(http_redirects=False)                              # nothing answers http://
    assert probe_http_redirect("example.com", network) == "closed"
    assert by_key(run_checks("example.com", network))["http_redirect"]["status"] == "na"


# --- deadline, errors, TLS -------------------------------------------------------------------------
def test_scan_stops_when_the_deadline_has_passed(monkeypatch):
    monkeypatch.setattr(pycheck, "SCAN_DEADLINE_SECONDS", -1)
    with pytest.raises(ScanError, match="took too long"):
        run_checks("example.com", site())


def test_unreachable_site_is_an_error_not_a_score():
    network = site()
    network.pages["https://example.com"] = NetworkError("timed out")
    with pytest.raises(ScanError, match="Could not connect"):
        run_checks("example.com", network)


def test_unknown_host_is_an_error():
    with pytest.raises(ScanError, match="Could not find a server"):
        run_checks("nowhere.example.org", ScriptedNetwork())


def test_challenge_page_is_refused_not_scored():
    network = site()
    network.pages["https://example.com"] = hop(status=202, headers={"x-amzn-waf-action": "challenge"})
    with pytest.raises(ScanError, match="refused the scan"):
        run_checks("example.com", network)


def test_rejected_certificate_still_reads_headers_but_fails_https():
    """A TLS failure on the first try retries without verification so the headers can still be assessed."""
    network = site(tls=BAD_TLS)
    network.pages["https://example.com"] = [TlsFailure("bad cert"), hop(headers={"content-type": "text/html"})]
    checks = by_key(run_checks("example.com", network))
    main = [r for r in network.requests if r["url"] == "https://example.com"]
    assert [r["verify"] for r in main] == [True, False]
    assert checks["https"]["status"] == "fail" and "certificate" in checks["https"]["evidence"]
    assert checks["hsts"]["status"] == "fail"                          # headers were still read


def test_second_tls_failure_is_an_error():
    network = site()
    network.pages["https://example.com"] = TlsFailure("handshake failed")
    with pytest.raises(ScanError, match="TLS connection"):
        run_checks("example.com", network)


# --- address pinning (DNS rebinding) -----------------------------------------------------------------
def test_connections_use_exactly_the_addresses_that_were_validated():
    network = site()
    run_checks("example.com", network)
    assert network.requests and all(r["ips"] == [PUBLIC_IP] for r in network.requests)
    assert network.handshakes == [{"host": "example.com", "port": 443, "ips": [PUBLIC_IP]}]


def test_a_dns_answer_that_changes_after_validation_is_never_used():
    """Rebinding attack: DNS answers with a public address when checked, then a private one afterwards.

    Each hop resolves once, validates, and connects to those very addresses, so the later answer is never
    consulted for that connection.
    """
    network = site(http_redirects=False)
    network.dns["example.com"] = [[PUBLIC_IP], ["127.0.0.1"], ["127.0.0.1"], ["127.0.0.1"]]
    fetched = pycheck.fetch("https://example.com", float("inf"), network)
    assert fetched.status == 200
    assert network.requests[0]["ips"] == [PUBLIC_IP]
    assert "127.0.0.1" not in [ip for r in network.requests for ip in r["ips"]]


def test_a_host_that_resolves_to_a_private_address_on_the_first_lookup_is_refused():
    network = site()
    network.dns["example.com"] = [["127.0.0.1"]]
    with pytest.raises(ScanError, match="private, local or reserved"):
        run_checks("example.com", network)
    assert network.requests == []
