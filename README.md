# 🛡️ AI Security Audit Report Generator

An AI-powered tool that generates professional security audit reports from raw scan data using MiMo v2.5-pro. Takes output from Nmap, Nikto, SSL scanners, and other security tools, then produces structured reports with CVSS scores, remediation steps, and executive summaries.

## Features

- **Multi-Scanner Support**: Accepts output from Nmap, Nikto, SSL/TLS scanners, HTTP header analyzers, and more
- **AI-Powered Analysis**: Uses MiMo v2.5-pro to analyze scan data and generate professional reports
- **CVSS v3.1 Scoring**: Each vulnerability gets a precise CVSS score and vector
- **Executive Summary**: Non-technical overview for stakeholders
- **Risk Matrix**: Visual breakdown of findings by severity (Critical/High/Medium/Low/Info)
- **Remediation Steps**: Actionable fix recommendations for each finding
- **Industry Standards**: References CWE, OWASP, NIST, and CIS benchmarks
- **Dark Theme UI**: Professional, accessible interface

## How It Works

1. **Paste** raw scan output from any security tool
2. **Configure** target name, scan type, and report options
3. **Generate** — AI analyzes the data and produces a structured audit report
4. **Review** findings with expandable details, CVSS scores, and remediation

## Supported Scan Types

| Scanner | What It Detects |
|---------|----------------|
| **Nmap** | Open ports, running services, OS detection |
| **Nikto** | Web server vulnerabilities, misconfigurations |
| **SSL/TLS** | Certificate issues, weak protocols, cipher suites |
| **HTTP Headers** | Missing security headers, clickjacking, HSTS |
| **Combined** | Multi-scan correlation for comprehensive reports |

## Quick Start

```bash
# Clone
git clone https://github.com/0xasuma/security-report-gen.git
cd security-report-gen

# Install
pip install -r requirements.txt

# Set API key
export MIMO_API_KEY="your-mimo-api-key"

# Run
python app.py
```

Open `http://localhost:5005` in your browser.

## API Usage

```bash
# Analyze scan data via API
curl -X POST http://localhost:5005/analyze \
  -F "scan_data=@nmap_output.txt" \
  -F "scan_type=nmap" \
  -F "target_name=Production Server"
```

## Tech Stack

- **Backend**: Flask (Python)
- **AI Model**: MiMo v2.5-pro (Xiaomi)
- **Frontend**: Vanilla HTML/CSS/JS (no dependencies)
- **Standards**: OWASP, NIST, CIS, CVSS v3.1

## Example Output

The tool generates structured JSON reports with:
- Executive summary with overall risk level
- Individual findings with CVSS scores, descriptions, impact, evidence, and remediation
- Risk matrix showing severity distribution
- Prioritized recommendations

## License

MIT
