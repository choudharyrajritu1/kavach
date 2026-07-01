#!/usr/bin/env python3
"""CLI: Google search via SerpAPI.

Examples:
  export SERPAPI_API_KEY=your_key
  python scripts/google_search.py "Fresh Bagels" --location "Seattle-Tacoma, WA"
  python scripts/google_search.py --cve CVE-2025-29927
  python scripts/google_search.py "Next.js middleware bypass" --start 10 --json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from kavach.config import get_config  # noqa: E402 — loads .env
from kavach.search.google import GoogleSearchClient  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Google search via SerpAPI")
    parser.add_argument("query", nargs="?", help="Search query (omit when using --cve)")
    parser.add_argument("--cve", metavar="CVE-ID", help="CVE-focused search shortcut")
    parser.add_argument("--location", default="", help="SerpAPI location string")
    parser.add_argument("--hl", default="en")
    parser.add_argument("--gl", default="us")
    parser.add_argument("--start", type=int, default=0, help="Result offset (pagination)")
    parser.add_argument("--num", type=int, default=10, help="Number of results")
    parser.add_argument("--json", action="store_true", help="Print raw JSON organic results")
    args = parser.parse_args()

    if not args.query and not args.cve:
        parser.error("provide a query or --cve")

    cfg = get_config()
    api_key = cfg.get("serpapi_api_key") or __import__("os").environ.get("SERPAPI_API_KEY", "")
    client = GoogleSearchClient(api_key=api_key)

    if args.cve:
        results = client.search_cve(args.cve.upper())
    else:
        results = client.search(
            args.query,
            location=args.location,
            hl=args.hl,
            gl=args.gl,
            start=args.start,
            num=args.num,
        )

    if args.json:
        print(
            json.dumps(
                [r.__dict__ for r in results.organic_results],
                indent=2,
            )
        )
    else:
        print(results.as_text(max_results=args.num))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
