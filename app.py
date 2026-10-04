import json
import os
import shutil
import sqlite3
import tempfile
import threading
import time
from collections import defaultdict, deque

from flask import Flask, abort, g, redirect, render_template, request, url_for

from pycheck import ScanError, normalize_url, run_checks
from score import calculate_score, grade_for

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
# One copy of the assets: Vercel serves public/ from its CDN, and Flask serves the same folder locally.
STATIC_DIR = os.path.join(BASE_DIR, "public", "static")

RATE_LIMIT_SCANS = 10      # scans allowed per client...
RATE_LIMIT_WINDOW = 60     # ...per this many seconds
MAX_URL_LENGTH = 2048

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR
)

# Vercel serverless functions sometimes receive the rewritten path (e.g. /api/index.py or /api)
# PrefixMiddleware strips this prefix so Flask routing functions identically both locally and on Vercel
class PrefixMiddleware:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path_info = environ.get("PATH_INFO", "")
        for prefix in ["/api/index.py", "/api/index", "/api"]:
            if path_info.startswith(prefix):
                environ["PATH_INFO"] = path_info[len(prefix):] or "/"
                break
        return self.wsgi_app(environ, start_response)

app.wsgi_app = PrefixMiddleware(app.wsgi_app)


# ----------------------------------------------------------------------------- database

def _db_path():
    if os.environ.get("VERCEL"):
        # On Vercel the bundle is read-only; copy the seed database to /tmp (lost on cold start)
        db_path = os.path.join(tempfile.gettempdir(), "data.db")
        src_db = os.path.join(BASE_DIR, "data.db")
        if not os.path.exists(db_path) and os.path.exists(src_db):
            shutil.copy2(src_db, db_path)
        return db_path
    return os.path.join(BASE_DIR, "data.db")


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Older databases lack these columns. score_version=1 marks the legacy presence-only scoring.
    existing = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    for column, ddl in (("grade", "TEXT"), ("details", "TEXT"), ("score_version", "INTEGER NOT NULL DEFAULT 1")):
        if column not in existing:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {ddl}")
    conn.commit()


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(_db_path())
        g.db.row_factory = sqlite3.Row
        init_db(g.db)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def score_tone(score):
    """Color family for a score: pass (75+), warn (40-74) or fail (below 40)."""
    return "pass" if score >= 75 else "warn" if score >= 40 else "fail"


@app.context_processor
def inject_globals():
    return {"ephemeral_history": bool(os.environ.get("VERCEL")), "tone": score_tone}


# ----------------------------------------------------------------------------- rate limiting
# In-memory and per-process: enough to stop casual abuse, not a distributed limiter.

_hits = defaultdict(deque)
_hits_lock = threading.Lock()


def client_id():
    if os.environ.get("VERCEL"):
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limited(client):
    now = time.monotonic()
    with _hits_lock:
        window = _hits[client]
        while window and now - window[0] > RATE_LIMIT_WINDOW:
            window.popleft()
        if len(window) >= RATE_LIMIT_SCANS:
            return True
        window.append(now)
        return False


# ----------------------------------------------------------------------------- routes

def recent_scans(db, limit=5):
    return db.execute("SELECT id, url, score, grade, timestamp FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def index_with_error(message, status):
    return render_template("index.html", recent_scans=recent_scans(get_db()), error=message), status


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", recent_scans=recent_scans(get_db()))

    raw_url = request.form.get("url", "").strip()
    if not raw_url:
        return index_with_error("Please enter a website address.", 400)
    if len(raw_url) > MAX_URL_LENGTH:
        return index_with_error("That URL is too long.", 400)
    if rate_limited(client_id()):
        return index_with_error("Too many scans. Please wait a minute and try again.", 429)

    url = normalize_url(raw_url)
    try:
        checks = run_checks(url)
    except ScanError as e:
        return index_with_error(str(e), 422)

    score = calculate_score(checks)
    grade = grade_for(score)
    db = get_db()
    cur = db.execute(
        "INSERT INTO scans(url, score, grade, details, score_version) VALUES (?, ?, ?, ?, 2)",
        (url, score, grade, json.dumps(checks)),
    )
    db.commit()
    return redirect(url_for("scan", scan_id=cur.lastrowid), code=303)


@app.route("/scan/<int:scan_id>")
def scan(scan_id):
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        abort(404)
    checks = json.loads(row["details"]) if row["details"] else None
    return render_template(
        "result.html", url=row["url"], score=row["score"], grade=row["grade"] or grade_for(row["score"]),
        checks=checks, scanned_at=row["timestamp"], last_scans=recent_scans(db),
    )


def escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


@app.route("/history")
def history():
    query = request.args.get("q", "").strip()[:100]
    db = get_db()
    # prev_score: the previous scan of the same URL, so the table can show the change.
    # Only version-2 scans are comparable; version 1 used a different scoring scheme.
    sql = ("SELECT s.id, s.url, s.score, s.grade, s.timestamp, s.score_version, "
           "(SELECT p.score FROM scans p WHERE p.url = s.url AND p.id < s.id AND p.score_version = 2 "
           "ORDER BY p.id DESC LIMIT 1) AS prev_score FROM scans s ")
    if query:
        rows = db.execute(sql + "WHERE s.url LIKE ? ESCAPE '\\' ORDER BY s.id DESC",
                          (f"%{escape_like(query)}%",)).fetchall()
    else:
        rows = db.execute(sql + "ORDER BY s.id DESC").fetchall()
    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return render_template("history.html", rows=rows, query=query, total=total)


@app.errorhandler(404)
def not_found(_error):
    return render_template("404.html"), 404


if __name__ == "__main__":
    app.run(debug=True)
