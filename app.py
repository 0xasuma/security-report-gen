#!/usr/bin/env python3
"""
AI-Powered Security Audit Report Generator
Generates professional security audit reports from raw scan data using MiMo AI.
"""

import os
import json
import time
import hashlib
from datetime import datetime
from flask import Flask, render_template, request, jsonify, send_file
import requests
import io
import re

app = Flask(__name__)
app.secret_key = os.urandom(24)

# MiMo API config (via 9router proxy)
MIMO_API_KEY = os.environ.get("MIMO_API_KEY", "sk-WaGKTcDXJcvYhJDAdekwqzxlz7etoWCCiigwcp7tbA")
MIMO_API_BASE = os.environ.get("MIMO_API_BASE", "http://43.134.12.202:20128/v1")
MIMO_MODEL = "mimo-v2.5-pro"

# Sample scan data for demo
SAMPLE_SCANS = {
    "nmap_scan": """Starting Nmap 7.94 ( https://nmap.org ) at 2026-05-24 10:00 WIB
Nmap scan report for 192.168.1.100
Host is up (0.0023s latency).

PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
80/tcp   open  http        Apache httpd 2.4.41
443/tcp  open  ssl/http    Apache httpd 2.4.41
3306/tcp open  mysql       MySQL 5.7.38-0ubuntu0.18.04.1
8080/tcp open  http-proxy  Squid http proxy 4.10
8443/tcp open  ssl/http    Apache Tomcat 9.0.65

Service detection performed. Please report any incorrect results.
Nmap done: 1 IP address (1 host up) scanned in 12.34 seconds""",

    "nikto_scan": """- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.100
+ Target Hostname:    192.168.1.100
+ Target Port:        80
+ Start Time:         2026-05-24 10:05:00 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: Uncommon header 'x-content-type-options' found, with contents: nosniff
+ /: Directory indexing found.
+ /admin/: Admin directory found.
+ /phpmyadmin/: phpMyAdmin directory found.
+ /server-status/: Apache server-status accessible.
+ /icons/README: Apache default file found. See: https://www.rapid7.com/db/vulnerabilities/http-apache-readme/
+ /wordpress/: WordPress installation found.
+ 8080: Server leaks info via "Server" header: "Apache-Coyote/1.1"
+ /wp-login.php: WordPress login page found.
+ /.htaccess: .htaccess file found. This may contain sensitive configuration.
+ /backup/: Backup directory found.
+ /cgi-bin/: CGI directory found, may be scriptable.
---------------------------------------------------------------------------
+ End Time:           2026-05-24 10:15:00 (GMT0)
---------------------------------------------------------------------------
+ 1 host(s) tested""",

    "ssl_scan": """SSL/TLS Configuration Analysis for 192.168.1.100:443
================================================================

Certificate:
  Subject: CN=example.local
  Issuer: CN=Let's Encrypt Authority X3
  Not Before: 2026-01-15
  Not After: 2026-04-15  *** EXPIRED ***
  Key Size: 2048-bit RSA
  Signature Algorithm: SHA256withRSA

Protocols:
  SSLv3:   DISABLED ✓
  TLSv1.0: ENABLED  ✗ (INSECURE)
  TLSv1.1: ENABLED  ✗ (INSECURE)
  TLSv1.2: ENABLED  ✓
  TLSv1.3: ENABLED  ✓

Cipher Suites (TLSv1.2):
  TLS_RSA_WITH_AES_128_CBC_SHA        (WEAK)
  TLS_RSA_WITH_AES_256_CBC_SHA        (WEAK)
  TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  (STRONG)
  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384  (STRONG)

Vulnerabilities:
  POODLE:   VULNERABLE (SSLv3 enabled)
  BEAST:    VULNERABLE (TLSv1.0 enabled)
  CRIME:    NOT VULNERABLE
  HEARTBLEED: NOT VULNERABLE

Grade: C""",

    "headers_check": """HTTP Security Headers Analysis for https://192.168.1.100
================================================================

Headers Present:
  X-Content-Type-Options: nosniff ✓
  X-XSS-Protection: 1; mode=block ✓

Headers Missing:
  Content-Security-Policy: MISSING ✗
  X-Frame-Options: MISSING ✗
  Strict-Transport-Security: MISSING ✗
  Referrer-Policy: MISSING ✗
  Permissions-Policy: MISSING ✗

Risk: HIGH — Missing headers allow clickjacking, MIME sniffing attacks, and no HSTS enforcement."""
}


def call_mimo_api(prompt, system_msg="You are a senior cybersecurity auditor."):
    """Call MiMo API for AI analysis."""
    if not MIMO_API_KEY:
        return None, "API key not configured"

    headers = {
        "Authorization": f"Bearer {MIMO_API_KEY}",
        "Content-Type": "application/json"
    }

    data = {
        "model": MIMO_MODEL,
        "messages": [
            {"role": "system", "content": system_msg},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.3,
        "max_tokens": 4000,
        "stream": False
    }

    try:
        resp = requests.post(
            f"{MIMO_API_BASE}/chat/completions",
            headers=headers,
            json=data,
            timeout=120
        )
        if resp.status_code == 200:
            result = resp.json()
            content = result["choices"][0]["message"]["content"]
            usage = result.get("usage", {})
            return content, usage
        else:
            return None, f"API error {resp.status_code}: {resp.text[:200]}"
    except Exception as e:
        return None, str(e)


@app.route("/")
def index():
    return render_template("index.html", samples=SAMPLE_SCANS)


@app.route("/analyze", methods=["POST"])
def analyze():
    """Analyze scan data and generate report."""
    scan_data = request.form.get("scan_data", "").strip()
    scan_type = request.form.get("scan_type", "auto")
    target_name = request.form.get("target_name", "Target System")
    include_remediation = request.form.get("include_remediation", "on") == "on"
    include_executive = request.form.get("include_executive", "on") == "on"

    if not scan_data:
        return jsonify({"error": "No scan data provided"}), 400

    start_time = time.time()

    # Build analysis prompt
    prompt = f"""Analyze the following security scan data and generate a professional security audit report.

TARGET: {target_name}
SCAN TYPE: {scan_type}
INCLUDE REMEDIATION: {include_remediation}
INCLUDE EXECUTIVE SUMMARY: {include_executive}

SCAN DATA:
```
{scan_data}
```

Generate a report with these sections:

1. EXECUTIVE SUMMARY (if requested): Brief overview for non-technical stakeholders, risk level (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL), key findings count.

2. FINDINGS: For each finding:
   - Title
   - Severity (CRITICAL/HIGH/MEDIUM/LOW/INFORMATIONAL)
   - CVSS Score (0.0-10.0)
   - Description
   - Impact
   - Evidence/Proof
   - Remediation (if requested)
   - References (CWE, OWASP, etc.)

3. RISK MATRIX: Summary table of findings by severity.

4. RECOMMENDATIONS: Prioritized list of actions.

Format the output as structured JSON with these exact keys:
{{
  "executive_summary": "...",
  "risk_level": "CRITICAL|HIGH|MEDIUM|LOW",
  "findings": [
    {{
      "id": "VULN-001",
      "title": "...",
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "cvss_score": 8.5,
      "cvss_vector": "CVSS:3.1/...",
      "description": "...",
      "impact": "...",
      "evidence": "...",
      "remediation": "...",
      "references": ["CWE-xxx", "OWASP-xxx"]
    }}
  ],
  "risk_matrix": {{
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0
  }},
  "recommendations": ["..."]
}}

Be thorough and accurate. Base all findings on actual evidence in the scan data."""

    system_msg = """You are a senior cybersecurity auditor with 15+ years of experience.
You generate professional security audit reports following industry standards (OWASP, NIST, CIS).
You are thorough, accurate, and provide actionable remediation steps.
You calculate CVSS scores precisely using CVSS v3.1 metrics.
You never fabricate findings — everything must be based on actual scan evidence.
You format output as clean, valid JSON."""

    analysis, usage_or_error = call_mimo_api(prompt, system_msg)
    elapsed = round(time.time() - start_time, 2)

    if analysis is None:
        return jsonify({"error": f"AI analysis failed: {usage_or_error}"}), 500

    # Try to parse JSON from response
    try:
        # Extract JSON from markdown code blocks if present
        json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', analysis, re.DOTALL)
        if json_match:
            json_str = json_match.group(1)
        else:
            json_str = analysis

        report_data = json.loads(json_str)
    except json.JSONDecodeError:
        # If JSON parsing fails, wrap raw text
        report_data = {
            "executive_summary": analysis[:500],
            "risk_level": "HIGH",
            "findings": [],
            "risk_matrix": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            "recommendations": [analysis],
            "raw_analysis": analysis
        }

    # Add metadata
    report_data["metadata"] = {
        "target": target_name,
        "scan_type": scan_type,
        "generated_at": datetime.now().isoformat(),
        "analysis_time": elapsed,
        "model": MIMO_MODEL,
        "tokens_used": usage_or_error if isinstance(usage_or_error, dict) else {}
    }

    return jsonify(report_data)


@app.route("/samples/<sample_name>")
def get_sample(sample_name):
    """Get sample scan data."""
    if sample_name in SAMPLE_SCANS:
        return jsonify({"data": SAMPLE_SCANS[sample_name]})
    return jsonify({"error": "Sample not found"}), 404


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({
        "status": "ok",
        "service": "AI Security Report Generator",
        "model": MIMO_MODEL,
        "api_configured": bool(MIMO_API_KEY)
    })


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5005))
    print(f"Starting AI Security Report Generator on port {port}")
    app.run(host="0.0.0.0", port=port, debug=False)
