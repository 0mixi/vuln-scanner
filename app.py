"""
Web-Based Vulnerability Assessment Tool
Author: Om Awachar
Automates scanning for XSS, SQLi, sensitive data exposure, and server misconfigurations.
"""

from flask import Flask, render_template, request, jsonify, send_file
from utils.scanner import Scanner
from utils.report_gen import generate_html_report
import json, os, uuid
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.urandom(24)
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/scan", methods=["POST"])
def scan():
    data    = request.get_json()
    target  = data.get("url", "").strip()
    options = data.get("options", {})

    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "Invalid URL. Must start with http:// or https://"}), 400

    scan_id = str(uuid.uuid4())[:8]
    scanner = Scanner(target, options)
    results = scanner.run()

    report_path = generate_html_report(results, REPORTS_DIR, scan_id)
    results["report_id"] = scan_id
    results["report_path"] = report_path

    return jsonify(results)

@app.route("/report/<scan_id>")
def view_report(scan_id):
    path = os.path.join(REPORTS_DIR, f"report_{scan_id}.html")
    if os.path.exists(path):
        return send_file(path)
    return "Report not found", 404

if __name__ == "__main__":
    app.run(debug=True, port=5000)
