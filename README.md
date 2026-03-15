# 🔍 Web Vulnerability Assessment Tool

> Python (Flask) powered web application security scanner — detects XSS, SQL Injection, sensitive data exposure, and server misconfigurations. Generates severity-rated HTML reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-2.2+-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Overview

A lightweight but powerful security scanning tool with a clean dark-themed web UI. Point it at a target URL and get a structured vulnerability report with severity ratings and remediation guidance — no manual testing overhead.

**Built by:** Om Awachar — Security Analyst with 1+ year of professional pentesting across 15+ banking and brokerage clients.

---

## 🎯 What It Detects

| Check | Description |
|---|---|
| **XSS** | Reflected XSS via URL parameters using 5 payloads |
| **SQL Injection** | Error-based SQLi detection via 7 payloads |
| **Sensitive Paths** | Checks 15+ common exposed files (.env, .git, phpinfo, etc.) |
| **Security Headers** | Checks for 6 critical HTTP security headers |
| **Info Disclosure** | Server version leakage detection |

---

## 🚀 Quick Start

```bash
git clone https://github.com/om-awachar/vuln-scanner.git
cd vuln-scanner
pip install -r requirements.txt
python app.py
# Open http://localhost:5000
```

---

## 🖥️ Screenshots

The tool provides:
- Clean dark-themed UI for entering target URL
- Scan options (toggle individual check types)
- Real-time results with severity badges (CRITICAL / HIGH / MEDIUM / LOW)
- Downloadable HTML report per scan

---

## 📁 Project Structure

```
vuln-scanner/
├── app.py                  # Flask app + routes
├── requirements.txt
├── utils/
│   ├── scanner.py          # Core scanning engine
│   └── report_gen.py       # HTML report generator
├── templates/
│   └── index.html          # Web UI
└── reports/                # Auto-created, stores HTML reports
```

---

## ⚠️ Disclaimer

For **authorized security testing only**. Only scan systems you own or have explicit written permission to test.

---

## 👤 Author

**Om Awachar** — Security Analyst  
