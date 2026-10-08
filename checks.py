from urllib.parse import (
    urlparse,
    parse_qsl
)

from bs4 import BeautifulSoup


SECURITY_HEADERS = {
    "Content-Security-Policy": "MEDIUM",
    "Strict-Transport-Security": "MEDIUM",
    "X-Content-Type-Options": "LOW",
    "X-Frame-Options": "MEDIUM",
    "Referrer-Policy": "LOW",
}


def create_finding(
    severity,
    title,
    url,
    description,
    finding_type="security"
):
    return {
        "type": finding_type,
        "severity": severity,
        "title": title,
        "url": url,
        "description": description
    }


# --------------------------------
# HTTPS
# --------------------------------

def check_https(url):
    findings = []

    parsed = urlparse(url)

    if parsed.scheme != "https":

        findings.append(
            create_finding(
                "HIGH",
                "HTTPS is not used",
                url,
                "The page is accessed over HTTP instead of HTTPS.",
                "transport_security"
            )
        )

    return findings


# --------------------------------
# HTTP status
# --------------------------------

def check_status_code(url, response):
    findings = []

    if response.status_code >= 500:

        findings.append(
            create_finding(
                "INFO",
                f"Server returned HTTP {response.status_code}",
                url,
                "The server returned a 5xx status code.",
                "http_status"
            )
        )

    elif response.status_code >= 400:

        findings.append(
            create_finding(
                "INFO",
                f"Page returned HTTP {response.status_code}",
                url,
                "The page returned a client error.",
                "http_status"
            )
        )

    return findings


# --------------------------------
# Security headers
# --------------------------------

def check_security_headers(url, headers):
    findings = []

    for header, severity in SECURITY_HEADERS.items():

        if header not in headers:

            findings.append(
                create_finding(
                    severity,
                    f"Missing {header} header",
                    url,
                    f"The {header} security header is not present.",
                    "security_header"
                )
            )

    return findings


# --------------------------------
# Server
# --------------------------------

def check_server_header(url, headers):
    findings = []

    server = headers.get("Server")

    if server:

        findings.append(
            create_finding(
                "INFO",
                "Server header exposed",
                url,
                f"The server identifies itself as: {server}",
                "information_disclosure"
            )
        )

    return findings


# --------------------------------
# Cookies
# --------------------------------

def check_cookies(url, response):
    findings = []

    for cookie in response.cookies:

        if not cookie.secure:

            findings.append(
                create_finding(
                    "MEDIUM",
                    "Cookie without Secure flag",
                    url,
                    f"Cookie '{cookie.name}' does not have the Secure flag.",
                    "cookie_security"
                )
            )

        if not cookie.has_nonstandard_attr(
            "HttpOnly"
        ):

            findings.append(
                create_finding(
                    "MEDIUM",
                    "Cookie without HttpOnly flag",
                    url,
                    f"Cookie '{cookie.name}' does not have the HttpOnly flag.",
                    "cookie_security"
                )
            )

    return findings


# --------------------------------
# Forms
# --------------------------------

def check_forms(url, html):
    findings = []

    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    forms = soup.find_all("form")

    for index, form in enumerate(
        forms,
        start=1
    ):

        method = form.get(
            "method",
            "get"
        ).lower()

        action = form.get(
            "action",
            ""
        )

        if method == "get":

            findings.append(
                create_finding(
                    "INFO",
                    "GET form detected",
                    url,
                    f"Form #{index} submits data using GET.",
                    "form_analysis"
                )
            )

        if not action:

            findings.append(
                create_finding(
                    "INFO",
                    "Form has no explicit action",
                    url,
                    f"Form #{index} does not specify an action URL.",
                    "form_analysis"
                )
            )

    return findings


# --------------------------------
# robots.txt
# --------------------------------

def check_robots(url, response):
    findings = []

    if response.status_code != 200:
        return findings

    text = response.text.lower()

    if "disallow:" in text:

        findings.append(
            create_finding(
                "INFO",
                "robots.txt contains Disallow rules",
                url,
                "The robots.txt file contains Disallow rules.",
                "robots"
            )
        )

    return findings


# --------------------------------
# Reflected XSS
# --------------------------------

def check_reflected_xss(
    session,
    test_url,
    marker
):
    findings = []

    try:

        response = session.get(
            test_url,
            timeout=10,
            allow_redirects=True
        )

    except Exception:
        return findings

    if marker in response.text:

        findings.append(
            create_finding(
                "MEDIUM",
                "Potential reflected input detected",
                test_url,
                "A unique test marker was reflected in the HTTP response. Manual verification is required to determine whether the reflection is exploitable as XSS.",
                "xss"
            )
        )

    return findings


# --------------------------------
# Open Redirect
# --------------------------------

def check_open_redirect(
    session,
    test_url
):
    findings = []

    parsed = urlparse(test_url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    redirect_names = {
        "url",
        "uri",
        "redirect",
        "redirect_url",
        "next",
        "return",
        "return_url",
        "continue",
        "destination"
    }

    for name, value in parameters:

        if name.lower() not in redirect_names:
            continue

        if not value.startswith(("http://", "https://")):
            continue

        try:

            response = session.get(
                test_url,
                timeout=10,
                allow_redirects=False
            )

        except Exception:
            continue

        location = response.headers.get(
            "Location",
            ""
        )

        if location.startswith(
            ("http://", "https://")
        ):

            target_host = urlparse(
                location
            ).netloc

            original_host = parsed.netloc

            if target_host and target_host != original_host:

                findings.append(
                    create_finding(
                        "MEDIUM",
                        "Potential open redirect",
                        test_url,
                        "The application appears to redirect to an external URL. Manual verification is required.",
                        "open_redirect"
                    )
                )

    return findings


# --------------------------------
# Technology detection
# --------------------------------

def detect_technologies(response):
    technologies = []

    headers = response.headers

    server = headers.get(
        "Server",
        ""
    ).lower()

    powered_by = headers.get(
        "X-Powered-By",
        ""
    ).lower()

    if "nginx" in server:
        technologies.append("Nginx")

    if "apache" in server:
        technologies.append("Apache")

    if "cloudflare" in server:
        technologies.append("Cloudflare")

    if "php" in powered_by:
        technologies.append("PHP")

    if "express" in powered_by:
        technologies.append("Express")

    content = response.text.lower()

    if "wp-content" in content:
        technologies.append("WordPress")

    if "react" in content:
        technologies.append("React")

    if "jquery" in content:
        technologies.append("jQuery")

    return technologies


# --------------------------------
# Main checker
# --------------------------------

def check_page(url, response):
    findings = []

    findings.extend(
        check_https(url)
    )

    findings.extend(
        check_status_code(
            url,
            response
        )
    )

    findings.extend(
        check_security_headers(
            url,
            response.headers
        )
    )

    findings.extend(
        check_server_header(
            url,
            response.headers
        )
    )

    findings.extend(
        check_cookies(
            url,
            response
        )
    )

    content_type = response.headers.get(
        "Content-Type",
        ""
    )

    if "text/html" in content_type:

        findings.extend(
            check_forms(
                url,
                response.text
            )
        )

    return findings