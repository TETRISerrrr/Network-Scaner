# Python Web Security Scanner

A lightweight web security scanner written in Python for cybersecurity learning and authorized security testing.

## Features

* HTTPS security checks
* Security headers analysis
* Cookie security checks
* HTTP status code analysis
* `robots.txt` analysis
* HTML form analysis
* Website crawling
* Reflected input detection
* Open redirect detection
* Technology detection
* Risk score calculation
* Severity classification
* JSON export
* Configurable maximum pages

## Project Structure

```text
web-security-scanner/
├── main.py
├── scanner.py
├── checks.py
├── report.py
├── requirements.txt
└── README.md
```

## Usage

### Scan a website

```bash
python main.py https://example.com
```

By default, up to `10` pages are scanned.

### Change maximum number of pages

```bash
python main.py https://example.com --max-pages 20
```

### Export results to JSON

```bash
python main.py https://example.com --output report.json
```

### Scan and export results

```bash
python main.py https://example.com --max-pages 20 --output report.json
```

## Example Output

```text
============================================================
                 Web Security Scanner
============================================================
Target: https://example.com
Max pages: 10
============================================================
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

Findings:

[MEDIUM] Missing Content-Security-Policy header
    Type: security_header
    URL: https://example.com
    The Content-Security-Policy security header is not present.

[MEDIUM] Missing Strict-Transport-Security header
    Type: security_header
    URL: https://example.com
    The Strict-Transport-Security security header is not present.
```

## How It Works

The scanner sends HTTP requests to the target website and analyzes the returned responses.

For each page:

1. The HTTP response is received.
2. HTTPS configuration is checked.
3. Security headers are analyzed.
4. Cookies are checked for security flags.
5. HTTP status codes are analyzed.
6. HTML forms are inspected.
7. URL parameters are tested for reflected input.
8. Redirect parameters are checked.
9. Website technologies are detected.
10. Links from the same domain are added to the scan queue.

The scanner continues until the configured maximum number of pages is reached.

## Technologies

* Python
* HTTP/HTTPS
* Requests
* BeautifulSoup
* HTML Parsing
* Web Crawling
* JSON

## Security Notice

This project is intended for educational purposes and authorized security testing.

Only scan websites that you own or systems for which you have explicit permission to perform security testing.

The author is not responsible for misuse of this software.
