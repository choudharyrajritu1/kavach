from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.exploit.candidates import merge_candidate_lists  # noqa: E402


class CandidateBuilderTest(unittest.TestCase):
    def test_merge_candidate_lists_deduplicates(self) -> None:
        primary = [{"method": "GET", "url": "http://lab.test/a"}]
        extra = [
            {"method": "GET", "url": "http://lab.test/a"},
            {"method": "POST", "url": "http://lab.test/b", "body": "x=1"},
        ]
        merged = merge_candidate_lists(primary, extra)
        self.assertEqual(len(merged), 2)
        self.assertEqual(merged[0]["url"], "http://lab.test/a")
        self.assertEqual(merged[1]["method"], "POST")


if __name__ == "__main__":
    unittest.main()
