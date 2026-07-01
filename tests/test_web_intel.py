from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.search.google import OrganicResult  # noqa: E402
from kavach.search.intel import (  # noqa: E402
    _heuristic_extract,
    gather_web_intel,
)


class WebIntelTest(unittest.TestCase):
    def test_heuristic_extracts_paths_and_headers(self) -> None:
        organic = [
            OrganicResult(
                position=1,
                title="PoC",
                link="https://example.com/poc",
                snippet="GET /api/hello with x-middleware-subrequest: middleware:middleware",
            )
        ]
        intel = _heuristic_extract(organic, query="CVE-2025-29927")
        self.assertIn("/api/hello", intel.probe_paths)
        self.assertTrue(
            any(h.get("name", "").lower() == "x-middleware-subrequest" for h in intel.request_headers)
        )

    def test_gather_web_intel_mock_mode(self) -> None:
        mock_llm = MagicMock()
        cfg = {
            "serpapi_api_key": os.environ.get("SERPAPI_API_KEY", ""),
            "llm_mode": "mock",
        }
        if not cfg["serpapi_api_key"]:
            self.skipTest("SERPAPI_API_KEY not set")
        intel = gather_web_intel("CVE-2025-29927", "", mock_llm, cfg)
        self.assertIsNotNone(intel)
        assert intel is not None
        self.assertTrue(intel.reference_urls)


if __name__ == "__main__":
    unittest.main()
