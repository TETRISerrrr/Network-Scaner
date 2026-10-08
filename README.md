# Network-Scaner
A lightweight web security scanner written in Python.

This project is a cybersecurity pet project designed to perform basic security checks on web applications and detect common security misconfigurations.

Features
HTTPS detection
Security headers analysis
Cookie security checks
HTTP status code analysis
robots.txt analysis
HTML form analysis
Website crawling
Reflected input detection
Potential Open Redirect detection
Technology detection
Risk score calculation
JSON report generation
CLI interface
Project Structure
web-security-scanner/
│
├── main.py
├── scanner.py
├── checks.py
├── report.py
├── requirements.txt
├── README.md
└── .gitignore
Usage

Scan a website:

python main.py https://example.com

Scan multiple pages:

python main.py https://example.com --max-pages 20

Save the scan results to JSON:

python main.py https://example.com --output report.json
Example Output
============================================================
                 Web Security Scanner
============================================================

Target: https://example.com
Max pages: 10

[+] Checking: https://example.com/robots.txt
[+] Scanning: https://example.com

============================================================
                     SCAN REPORT
============================================================

Target: https://example.com
Pages scanned: 1
Findings: 6
Risk score: 19
Risk level: MEDIUM

Technologies detected:
  - Cloudflare

Severity summary:
  HIGH:   0
  MEDIUM: 3
  LOW:    2
  INFO:   1
Risk Levels
Level	Score	Description
NONE	0	No detected issues
LOW	1–9	Low-risk findings
MEDIUM	10–19	Potential security weaknesses
HIGH	20+	More serious findings
Detected Technologies

The scanner can identify some technologies using HTTP headers and page content:

Cloudflare
Nginx
Apache
PHP
Express
WordPress
React
jQuery

Technology detection is basic and may produce false positives.

Limitations

This is an educational project and not a replacement for professional security scanners.

Some findings require manual verification and may result in false positives.

The scanner performs basic security checks and does not attempt to exploit vulnerabilities.

Disclaimer

This project is intended for educational purposes and authorized security testing only.

Only scan websites and systems that you own or have explicit permission to test.

The author is not responsible for any misuse of this software.
