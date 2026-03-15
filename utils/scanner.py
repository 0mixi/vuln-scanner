"""
Scanner — core scanning engine.
Runs XSS, SQLi, sensitive data, and misconfiguration checks.
"""

import requests
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
from datetime import datetime
import re

HEADERS = {"User-Agent": "VulnScanner/1.0 (Security Research — Authorized Testing Only)"}

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    'javascript:alert(1)',
]

SQLI_PAYLOADS = [
    "'", '"', "' OR '1'='1", "' OR 1=1--",
    "1; DROP TABLE users--", "' UNION SELECT NULL--",
    "1' AND SLEEP(3)--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ora-0", "pg_query",
    "sqlite", "odbc driver", "unclosed quotation", "syntax error",
    "warning: mysql", "valid mysql result",
]

SENSITIVE_PATHS = [
    ".env", ".git/config", "config.php", "wp-config.php",
    "phpinfo.php", "server-status", "robots.txt",
    "sitemap.xml", ".htaccess", "backup.zip",
    "admin/", "api/v1/users", "debug",
]

SECURITY_HEADERS = [
    "X-Frame-Options", "X-Content-Type-Options",
    "Content-Security-Policy", "Strict-Transport-Security",
    "Referrer-Policy", "Permissions-Policy",
]


class Scanner:
    def __init__(self, target: str, options: dict):
        self.target  = target.rstrip("/")
        self.options = options
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.session.verify = False
        self.findings = []
        self.start_time = datetime.now()

    def _add(self, category, name, severity, detail, evidence=""):
        self.findings.append({
            "category": category, "name": name,
            "severity": severity, "detail": detail, "evidence": evidence[:300]
        })

    def check_headers(self):
        try:
            r = self.session.get(self.target, timeout=10)
            missing = [h for h in SECURITY_HEADERS if h not in r.headers]
            for h in missing:
                self._add("Misconfiguration", f"Missing header: {h}", "MEDIUM",
                          f"The response does not include the {h} security header.")
            server = r.headers.get("Server", "")
            if server:
                self._add("Information Disclosure", "Server version exposed", "LOW",
                          f"Server header reveals: {server}", server)
        except Exception as e:
            self._add("Error", "Header check failed", "INFO", str(e))

    def check_sensitive_paths(self):
        for path in SENSITIVE_PATHS:
            url = urljoin(self.target + "/", path)
            try:
                r = self.session.get(url, timeout=8, allow_redirects=False)
                if r.status_code == 200 and len(r.text) > 10:
                    self._add("Sensitive Data Exposure", f"Accessible: /{path}", "HIGH",
                              f"Path returned HTTP 200 with {len(r.text)} bytes.", url)
            except Exception:
                pass

    def check_xss(self):
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in XSS_PAYLOADS:
                new_params = {k: (payload if k == param else v[0]) for k, v in params.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                try:
                    r = self.session.get(test_url, timeout=10)
                    if payload in r.text:
                        self._add("XSS", f"Reflected XSS in param: {param}", "HIGH",
                                  f"Payload reflected in response.", f"Payload: {payload}")
                        break
                except Exception:
                    pass

    def check_sqli(self):
        parsed = urlparse(self.target)
        params = parse_qs(parsed.query)
        if not params:
            return
        for param in params:
            for payload in SQLI_PAYLOADS:
                new_params = {k: (payload if k == param else v[0]) for k, v in params.items()}
                test_url = urlunparse(parsed._replace(query=urlencode(new_params)))
                try:
                    r = self.session.get(test_url, timeout=10)
                    body_lower = r.text.lower()
                    hit = next((e for e in SQLI_ERRORS if e in body_lower), None)
                    if hit:
                        self._add("SQL Injection", f"Possible SQLi in param: {param}", "CRITICAL",
                                  f"Error pattern '{hit}' detected.", f"Payload: {payload}")
                        break
                except Exception:
                    pass

    def run(self) -> dict:
        if self.options.get("headers", True):   self.check_headers()
        if self.options.get("paths",   True):   self.check_sensitive_paths()
        if self.options.get("xss",     True):   self.check_xss()
        if self.options.get("sqli",    True):   self.check_sqli()

        duration = (datetime.now() - self.start_time).total_seconds()
        counts = {}
        for f in self.findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1

        return {
            "target":    self.target,
            "timestamp": self.start_time.isoformat(),
            "duration":  round(duration, 2),
            "total":     len(self.findings),
            "counts":    counts,
            "findings":  self.findings,
        }
