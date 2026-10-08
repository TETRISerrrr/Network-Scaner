import json


SEVERITY_SYMBOLS = {
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
    "INFO": "[INFO]"
}


SEVERITY_POINTS = {
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0
}


def calculate_score(findings):
    score = 0

    for finding in findings:
        severity = finding.get(
            "severity",
            "INFO"
        )

        score += SEVERITY_POINTS.get(
            severity,
            0
        )

    return score


def get_risk_level(score):
    if score >= 20:
        return "HIGH"

    if score >= 10:
        return "MEDIUM"

    if score > 0:
        return "LOW"

    return "NONE"


def print_report(results):
    findings = results["findings"]

    print("\n")
    print("=" * 60)
    print("                     SCAN REPORT")
    print("=" * 60)

    print(
        f"\nTarget: {results['target']}"
    )

    print(
        f"Pages scanned: {results['pages_scanned']}"
    )

    print(
        f"Findings: {len(findings)}"
    )

    score = calculate_score(
        findings
    )

    risk = get_risk_level(
        score
    )

    print(
        f"Risk score: {score}"
    )

    print(
        f"Risk level: {risk}"
    )

    technologies = results.get(
        "technologies",
        []
    )

    if technologies:

        print(
            "\nTechnologies detected:"
        )

        for technology in technologies:
            print(
                f"  - {technology}"
            )

    if results["pages_scanned"] == 0:

        print(
            "\nScan failed: no pages were successfully scanned."
        )

        return

    if not findings:

        print(
            "\nNo security issues found."
        )

        return

    high = 0
    medium = 0
    low = 0
    info = 0

    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        )

        if severity == "HIGH":
            high += 1

        elif severity == "MEDIUM":
            medium += 1

        elif severity == "LOW":
            low += 1

        elif severity == "INFO":
            info += 1

    print("\nSeverity summary:")

    print(f"  HIGH:   {high}")
    print(f"  MEDIUM: {medium}")
    print(f"  LOW:    {low}")
    print(f"  INFO:   {info}")

    print("\nFindings:\n")

    for finding in findings:

        severity = finding.get(
            "severity",
            "INFO"
        )

        title = finding.get(
            "title",
            "Unknown finding"
        )

        url = finding.get(
            "url",
            "Unknown URL"
        )

        description = finding.get(
            "description",
            "No description available."
        )

        finding_type = finding.get(
            "type",
            "security"
        )

        symbol = SEVERITY_SYMBOLS.get(
            severity,
            "[UNKNOWN]"
        )

        print(
            f"{symbol} {title}"
        )

        print(
            f"    Type: {finding_type}"
        )

        print(
            f"    URL: {url}"
        )

        print(
            f"    {description}"
        )

        print()


def save_json(results, filename):

    findings = results["findings"]

    report = dict(results)

    report["risk_score"] = calculate_score(
        findings
    )

    report["risk_level"] = get_risk_level(
        report["risk_score"]
    )

    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )