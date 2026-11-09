import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from flask import Flask, jsonify, render_template, request, send_file, abort
from scanner import scan_url
from analyzer import analyze_headers, calculate_score
from reporter import save_json_report, save_text_report

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
REPORT_DIR = ROOT / "reports"
DB_PATH = DATA_DIR / "webshield.db"
DATA_DIR.mkdir(exist_ok=True)
REPORT_DIR.mkdir(exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                final_url TEXT NOT NULL,
                checked_at TEXT NOT NULL,
                http_status INTEGER,
                score INTEGER NOT NULL,
                rating TEXT NOT NULL,
                result_json TEXT NOT NULL
            )
        """)

init_db()

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    return jsonify({"ok": True, "name": "WebShield"})

@app.get("/api/history")
def history():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, target, final_url, checked_at, http_status, score, rating FROM scans ORDER BY id DESC LIMIT 30"
        ).fetchall()
    return jsonify([dict(row) for row in rows])

@app.get("/api/history/<int:scan_id>")
def history_detail(scan_id):
    with db() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        return jsonify({"error": "Scan not found."}), 404
    item = dict(row)
    item["result"] = json.loads(item.pop("result_json"))
    return jsonify(item)

@app.post("/api/scan")
def scan():
    payload = request.get_json(silent=True) or {}
    target = str(payload.get("url", "")).strip()
    if not target:
        return jsonify({"error": "Enter a website URL to scan."}), 400

    try:
        timeout = int(payload.get("timeout", 10))
        if not 1 <= timeout <= 60:
            return jsonify({"error": "Timeout must be between 1 and 60 seconds."}), 400
        response = scan_url(target, timeout)
        checks = analyze_headers(response["headers"], response["final_url"])
        score = calculate_score(checks)
    except (ValueError, RuntimeError) as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception:
        app.logger.exception("Unexpected scan error")
        return jsonify({"error": "An unexpected error occurred while scanning."}), 500

    result = {
        "tool": "WebShield",
        "version": "1.1.0",
        "requested_url": response["requested_url"],
        "final_url": response["final_url"],
        "status_code": response["status_code"],
        "is_https": response["is_https"],
        "checked_at": response["checked_at"],
        "score": score,
        "checks": checks,
        "disclaimer": "A limited HTTP security-header configuration review, not a penetration test. A missing header does not by itself prove exploitability."
    }
    with db() as conn:
        cur = conn.execute(
            """INSERT INTO scans (target, final_url, checked_at, http_status, score, rating, result_json)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (response["requested_url"], response["final_url"], response["checked_at"],
             response["status_code"], score["score"], score["rating"], json.dumps(result))
        )
        scan_id = cur.lastrowid
    result["scan_id"] = scan_id
    return jsonify(result)

@app.get("/api/report/<int:scan_id>/<kind>")
def download_report(scan_id, kind):
    if kind not in ("json", "txt"):
        abort(404)
    with db() as conn:
        row = conn.execute("SELECT result_json FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if not row:
        abort(404)
    result = json.loads(row["result_json"])
    # Adapt the saved dashboard result to the existing reporter's input contract.
    response = {
        "requested_url": result["requested_url"],
        "final_url": result["final_url"],
        "status_code": result["status_code"],
        "is_https": result["is_https"],
        "checked_at": result["checked_at"]
    }
    score = result["score"]
    checks = result["checks"]
    path = REPORT_DIR / f"webshield_scan_{scan_id}.{kind}"
    if kind == "json":
        save_json_report(response, checks, score, path)
        mimetype = "application/json"
    else:
        save_text_report(response, checks, score, path)
        mimetype = "text/plain"
    return send_file(path, as_attachment=True, download_name=path.name, mimetype=mimetype)

if __name__ == "__main__":
    # Local-only dashboard. Do not expose the development server to the public internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
