import sqlite3

import pytest

import app as app_module
from pycheck import ScanError

CHECKS = [{"key": "https", "name": "HTTPS", "status": "pass", "points": 15, "max": 15, "evidence": "ok", "fix": ""},
          {"key": "hsts", "name": "HSTS", "status": "fail", "points": 0, "max": 15, "evidence": "missing", "fix": "add header X"}]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(app_module, "_db_path", lambda: str(tmp_path / "t.db"))
    app_module._hits.clear()
    app_module.app.config["TESTING"] = True
    return app_module.app.test_client()


@pytest.fixture
def fake_scan(monkeypatch):
    calls = []
    monkeypatch.setattr(app_module, "run_checks", lambda url: calls.append(url) or CHECKS)
    return calls


def test_pages_load(client):
    assert client.get("/").status_code == 200
    assert client.get("/history").status_code == 200
    assert client.get("/api/index.py/history").status_code == 200   # Vercel prefix


def test_scan_saves_and_redirects_to_detail_page(client, fake_scan):
    r = client.post("/", data={"url": "example.com"})
    assert r.status_code == 303 and r.headers["Location"].endswith("/scan/1")
    assert fake_scan == ["https://example.com"]
    page = client.get("/scan/1").get_data(as_text=True)
    assert "HSTS" in page and "add header X" in page and "50" in page
    assert "https://example.com" in client.get("/history").get_data(as_text=True)


@pytest.mark.parametrize("value", ["", "   "])
def test_empty_input_rejected_and_not_saved(client, fake_scan, value):
    assert client.post("/", data={"url": value}).status_code == 400
    assert client.post("/", data={}).status_code == 400
    assert fake_scan == []
    assert "0 scans saved" in client.get("/history").get_data(as_text=True)


def test_scan_error_shown_and_not_saved(client, monkeypatch):
    def boom(url):
        raise ScanError("Could not find a server named 'x.com'.")
    monkeypatch.setattr(app_module, "run_checks", boom)
    r = client.post("/", data={"url": "x.com"})
    assert r.status_code == 422 and "Could not find a server" in r.get_data(as_text=True)
    assert "0 scans saved" in client.get("/history").get_data(as_text=True)


@pytest.mark.parametrize("target", ["http://127.0.0.1/", "http://127.0.0.1:8000/", "http://169.254.169.254/", "localhost"])
def test_private_target_blocked_end_to_end(client, target):
    r = client.post("/", data={"url": target})
    assert r.status_code == 422
    assert "0 scans saved" in client.get("/history").get_data(as_text=True)


def test_html_in_url_is_escaped(client, fake_scan):
    client.post("/", data={"url": "<script>alert(1)</script>.com"})
    html = client.get("/scan/1").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html


def test_rate_limit(client, fake_scan):
    for _ in range(app_module.RATE_LIMIT_SCANS):
        assert client.post("/", data={"url": "example.com"}).status_code == 303
    assert client.post("/", data={"url": "example.com"}).status_code == 429


def test_missing_scan_404(client):
    assert client.get("/scan/999").status_code == 404


def test_legacy_rows_still_display(client):
    with app_module.app.app_context():
        db = app_module.get_db()
        db.execute("INSERT INTO scans(url, score) VALUES ('https://old.example', 85)")
        db.commit()
    page = client.get("/scan/1").get_data(as_text=True)
    assert "older version" in page
    assert "old.example" in client.get("/history").get_data(as_text=True)


def test_migration_adds_columns_to_old_database(tmp_path):
    conn = sqlite3.connect(tmp_path / "old.db")
    conn.execute("CREATE TABLE scans(id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, score INTEGER NOT NULL, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.execute("INSERT INTO scans(url, score) VALUES ('https://a.com', 70)")
    app_module.init_db(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(scans)")}
    assert {"grade", "details", "score_version"} <= cols
    assert conn.execute("SELECT score_version FROM scans").fetchone()[0] == 1


def test_result_page_shows_ledger_and_groups_findings(client, fake_scan):
    client.post("/", data={"url": "example.com"})
    page = client.get("/scan/1").get_data(as_text=True)
    assert page.count('class="seg ') == 2                      # one ledger block per scored check
    assert 'href="#check-hsts"' in page and 'id="check-hsts"' in page
    assert '<details class="fix" open>' in page                # failures show their fix straight away
    assert "Needs attention" in page and "Passing" in page


def test_unknown_page_renders_404_template(client):
    r = client.get("/no/such/page")
    assert r.status_code == 404 and "Page not found" in r.get_data(as_text=True)


def test_history_shows_change_since_previous_scan(client, monkeypatch):
    scores = iter([[{**CHECKS[0]}], CHECKS])                    # 100, then 50
    monkeypatch.setattr(app_module, "run_checks", lambda url: next(scores))
    client.post("/", data={"url": "example.com"})
    client.post("/", data={"url": "example.com"})
    page = client.get("/history").get_data(as_text=True)
    assert "−50" in page and "First scan" in page


def test_history_filter(client, fake_scan):
    client.post("/", data={"url": "alpha.com"})
    client.post("/", data={"url": "beta.com"})
    page = client.get("/history?q=alpha").get_data(as_text=True)
    assert "alpha.com" in page and "beta.com" not in page and "1 of 2 scans match" in page
    assert "No scans match" in client.get("/history?q=zzz").get_data(as_text=True)
    assert client.get("/history?q=%25").status_code == 200      # LIKE wildcards are escaped


def test_static_assets_are_served_from_the_single_public_folder(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_pages_have_no_inline_scripts_or_styles_blocks(client, fake_scan):
    client.post("/", data={"url": "example.com"})
    for path in ("/", "/history", "/scan/1", "/no/such/page"):
        html = client.get(path).get_data(as_text=True)
        assert "<script>" not in html and "<style" not in html, path
        assert 'src="/static/app.js"' in html and 'href="/static/style.css"' in html


def test_status_classes_use_one_tone_mechanism(client, fake_scan):
    client.post("/", data={"url": "example.com"})
    page = client.get("/scan/1").get_data(as_text=True)
    assert 'class="finding tone-fail"' in page and 'class="seg tone-pass"' in page
    assert 'class="line tone-pass"' in page
    assert 'data-copy="#fix-hsts"' in page and 'id="fix-hsts"' in page


def test_home_console_hooks_for_progress_script(client):
    html = client.get("/").get_data(as_text=True)
    for hook in ("data-scan-form", "data-scan-button", "data-console-log", "data-scan-status", "data-fill="):
        assert hook in html
