import os
import shutil
import sqlite3
import tempfile
from flask import Flask, render_template, request
from pycheck import run_checks
from score import calculate_score

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")

app = Flask(
    __name__,
    template_folder=TEMPLATES_DIR,
    static_folder=STATIC_DIR
)

def get_db():
    if os.environ.get("VERCEL"):
        # On Vercel (Linux serverless), tempfile.gettempdir() resolves to /tmp
        # Cross-platform support ensures tests also pass on Windows
        temp_dir = tempfile.gettempdir()
        db_path = os.path.join(temp_dir, "data.db")
        if not os.path.exists(db_path):
            src_db = os.path.join(BASE_DIR, "data.db")
            if os.path.exists(src_db):
                shutil.copy2(src_db, db_path)
    else:
        db_path = os.path.join(BASE_DIR, "data.db")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            score INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );
    """)
    conn.commit()
    return conn

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        scan_results = run_checks(url)
        score = calculate_score(scan_results)
        conn = get_db()
        conn.execute("INSERT INTO scans(url, score) VALUES (?, ?)", (url, score))
        conn.commit()

        last_scans = conn.execute("SELECT url, score, timestamp FROM scans ORDER BY id DESC LIMIT 5").fetchall()

        return render_template("result.html", url=url, score=score, results=scan_results, last_scans=last_scans)
    return render_template("index.html")

@app.route("/history")
def history():
    conn = get_db()
    rows = conn.execute("SELECT * FROM scans ORDER BY id DESC").fetchall()
    return render_template("history.html", rows=rows)

if __name__ == "__main__":
    app.run(debug=True)
