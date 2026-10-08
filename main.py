import argparse

from scanner import scan
from report import print_report, save_json


def main():
    parser = argparse.ArgumentParser(
        description="Web Security Scanner"
    )

    parser.add_argument(
        "url",
        help="Target URL"
    )

    parser.add_argument(
        "--max-pages",
        type=int,
        default=10,
        help="Maximum number of pages to scan"
    )

    parser.add_argument(
        "--output",
        help="Save report to JSON"
    )

    args = parser.parse_args()

    print("=" * 60)
    print("                 Web Security Scanner")
    print("=" * 60)

    print(f"\nTarget: {args.url}")
    print(f"Max pages: {args.max_pages}\n")

    try:
        results = scan(
            args.url,
            args.max_pages
        )

        print_report(results)

        if args.output:
            save_json(
                results,
                args.output
            )

            print(
                f"\nReport saved to: {args.output}"
            )

    except KeyboardInterrupt:
        print("\nScan interrupted.")

    except Exception as error:
        print(f"\nError: {error}")


if __name__ == "__main__":
    main()