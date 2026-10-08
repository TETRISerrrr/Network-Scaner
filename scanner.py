from urllib.parse import (
    urljoin,
    urlparse,
    parse_qsl,
    urlencode
)

import requests
from bs4 import BeautifulSoup

from checks import (
    check_page,
    check_robots,
    check_reflected_xss,
    check_open_redirect,
    detect_technologies
)


USER_AGENT = "WebSecurityScanner/2.0"

XSS_MARKER = "WSS_XSS_TEST_12345"


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url.rstrip("/")


def get_links(url, html, base_domain):
    soup = BeautifulSoup(
        html,
        "html.parser"
    )

    links = set()

    for tag in soup.find_all("a", href=True):

        link = urljoin(
            url,
            tag["href"]
        )

        parsed = urlparse(link)

        if parsed.scheme not in ("http", "https"):
            continue

        if parsed.netloc != base_domain:
            continue

        clean_link = link.split("#")[0].rstrip("/")

        links.add(clean_link)

    return links


def get_parameter_urls(url):
    parsed = urlparse(url)

    parameters = parse_qsl(
        parsed.query,
        keep_blank_values=True
    )

    urls = []

    for index, (name, value) in enumerate(parameters):

        modified = list(parameters)

        modified[index] = (
            name,
            XSS_MARKER
        )

        new_query = urlencode(modified)

        test_url = parsed._replace(
            query=new_query
        ).geturl()

        urls.append(test_url)

    return urls


def scan(target_url, max_pages=10):
    target_url = normalize_url(target_url)

    session = requests.Session()

    session.headers.update({
        "User-Agent": USER_AGENT
    })

    parsed_target = urlparse(target_url)

    base_domain = parsed_target.netloc

    queue = [target_url]
    visited = set()

    results = {
        "target": target_url,
        "pages_scanned": 0,
        "findings": [],
        "technologies": []
    }

    # -------------------------
    # robots.txt
    # -------------------------

    robots_url = urljoin(
        target_url + "/",
        "robots.txt"
    )

    print(
        f"[+] Checking: {robots_url}"
    )

    try:
        robots_response = session.get(
            robots_url,
            timeout=10
        )

        results["findings"].extend(
            check_robots(
                robots_url,
                robots_response
            )
        )

    except requests.RequestException:
        pass

    # -------------------------
    # Crawl
    # -------------------------

    while queue and len(visited) < max_pages:

        url = queue.pop(0)

        if url in visited:
            continue

        visited.add(url)

        print(
            f"[+] Scanning: {url}"
        )

        try:
            response = session.get(
                url,
                timeout=10,
                allow_redirects=True
            )

        except requests.RequestException as error:

            print(
                f"    Request failed: {error}"
            )

            continue

        results["pages_scanned"] += 1

        # -------------------------
        # Basic checks
        # -------------------------

        results["findings"].extend(
            check_page(
                url,
                response
            )
        )

        # -------------------------
        # Technologies
        # -------------------------

        technologies = detect_technologies(
            response
        )

        for technology in technologies:

            if technology not in results["technologies"]:
                results["technologies"].append(
                    technology
                )

        # -------------------------
        # Parameter checks
        # -------------------------

        parameter_urls = get_parameter_urls(
            response.url
        )

        for parameter_url in parameter_urls:

            print(
                f"    [*] Testing parameter: "
                f"{parameter_url}"
            )

            # Reflected XSS
            results["findings"].extend(
                check_reflected_xss(
                    session,
                    parameter_url,
                    XSS_MARKER
                )
            )

            # Open redirect
            results["findings"].extend(
                check_open_redirect(
                    session,
                    parameter_url
                )
            )

        # -------------------------
        # Find HTML links
        # -------------------------

        content_type = response.headers.get(
            "Content-Type",
            ""
        )

        if "text/html" not in content_type:
            continue

        links = get_links(
            response.url,
            response.text,
            base_domain
        )

        for link in links:

            if (
                link not in visited
                and link not in queue
            ):
                queue.append(link)

    return results