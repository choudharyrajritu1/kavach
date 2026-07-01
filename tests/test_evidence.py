from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.exploit.evidence import (  # noqa: E402
    apply_triage_proof,
    assess_exploit_evidence_strength,
    is_benign_discovery_url,
    marker_is_distinctive,
    strongest_proof_from_attempts,
    strongest_proof_from_triage,
    validate_exploit_proof,
)
from kavach.exploit.base import ModuleResult  # noqa: E402
from kavach.exploit.signals import SignalEvaluator  # noqa: E402

_CANTO_README_BODY = """=== Canto ===
Contributors: foo
Stable tag: 3.0.4
License: GPLv2
Canto plugin for WordPress
"""

_PASSWD_BODY = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"


class EvidenceProofTest(unittest.TestCase):
    def test_benign_readme_url_is_discovery(self) -> None:
        url = "http://target/wp-content/plugins/canto/readme.txt"
        self.assertTrue(is_benign_discovery_url(url))
        self.assertFalse(is_benign_discovery_url(
            "http://target/wp-content/plugins/canto/includes/detail.php?wp_abspath=../../../etc/passwd"
        ))

    def test_weak_canto_marker_not_distinctive(self) -> None:
        self.assertFalse(marker_is_distinctive("Canto"))
        self.assertFalse(marker_is_distinctive("readme"))

    def test_signal_evaluator_rejects_readme_canto_false_positive(self) -> None:
        url = "http://target/wp-content/plugins/canto/readme.txt"
        ev = SignalEvaluator(
            success_signals=[
                {"type": "response_body_contains", "pattern": "Canto", "description": "LLM success_marker"},
            ],
            expect_planted_flag=False,
        )
        outcome = ev.evaluate(
            status=200,
            headers={},
            body=_CANTO_README_BODY,
            request_url=url,
        )
        self.assertFalse(outcome.success)
        self.assertFalse(outcome.captured == "Canto")

    def test_signal_evaluator_accepts_passwd_read(self) -> None:
        url = (
            "http://target/wp-content/plugins/canto/includes/detail.php"
            "?wp_abspath=../../../etc/passwd%00"
        )
        ev = SignalEvaluator(expect_planted_flag=False)
        outcome = ev.evaluate(status=200, headers={}, body=_PASSWD_BODY, request_url=url)
        self.assertTrue(outcome.success)
        self.assertIn("passwd", outcome.evidence[0].lower())

    def test_validate_rejects_directory_listing(self) -> None:
        ok, reason = validate_exploit_proof(
            evidence=["body contains 'Index' (LLM success_marker)"],
            request_url="http://target/wp-content/plugins/canto/",
            body="Index of /wp-content/plugins/canto/",
            captured="Index",
        )
        self.assertFalse(ok)
        self.assertIn("discovery", reason.lower())

    def test_assess_strength_strong_for_passwd(self) -> None:
        self.assertEqual(
            assess_exploit_evidence_strength(
                success=True,
                flag_captured=_PASSWD_BODY[:40],
                evidence=["sensitive file contents (passwd-like) in response"],
            ),
            "strong",
        )

    def test_assess_strength_weak_for_plugin_name(self) -> None:
        self.assertEqual(
            assess_exploit_evidence_strength(
                success=True,
                flag_captured="Canto",
                evidence=["body contains 'Canto' (LLM success_marker)"],
            ),
            "weak",
        )

    def test_strongest_proof_from_uid_attempt(self) -> None:
        class Att:
            def __init__(self, body: str) -> None:
                self.response_excerpt = body

        attempts = [
            Att("uid=33(www-data) gid=33(www-data) groups=33(www-data)\n/wp-admin/admin.php"),
        ]
        ok, excerpt, ev = strongest_proof_from_attempts(attempts)
        self.assertTrue(ok)
        self.assertIn("uid=", excerpt)
        self.assertTrue(ev)

    def test_signal_uid_always_counts_as_proof(self) -> None:
        body = "uid=33(www-data) gid=33(www-data) groups=33(www-data)"
        ev = SignalEvaluator(expect_planted_flag=False)
        outcome = ev.evaluate(status=500, headers={}, body=body, request_url="http://t/get.php?x=1")
        self.assertTrue(outcome.success)

    def test_strongest_proof_from_triage_uid(self) -> None:
        triage = [
            {"status": 500, "url": "http://t/get.php?x=1", "snippet": "uid=0(root) gid=0(root)"},
            {"status": 200, "url": "http://t/readme.txt", "snippet": "Index of /plugins/canto"},
        ]
        ok, excerpt, ev, rec = strongest_proof_from_triage(triage)
        self.assertTrue(ok)
        self.assertIn("uid=", excerpt)
        self.assertEqual(rec["status"], 500)

    def test_apply_triage_proof_upgrades_batch_last(self) -> None:
        mr = ModuleResult(
            success=False,
            response_excerpt="Index of /wp-content/plugins/canto/public",
            status=200,
            candidate_triage=[
                {
                    "status": 500,
                    "url": "http://t/get.php?wp_abspath=data://",
                    "snippet": "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n/wp-admin/admin.php",
                },
                {
                    "status": 200,
                    "url": "http://t/public/",
                    "snippet": "Index of /wp-content/plugins/canto/public",
                },
            ],
        )
        upgraded = apply_triage_proof(mr)
        self.assertTrue(upgraded.success)
        self.assertIn("uid=", upgraded.response_excerpt)
        self.assertEqual(upgraded.status, 500)

    def test_strongest_proof_from_attempt_with_triage(self) -> None:
        class Att:
            def __init__(self) -> None:
                self.response_excerpt = "Index of /canto"
                self.candidate_triage = [
                    {
                        "status": 500,
                        "snippet": "uid=1(daemon) gid=1(daemon) groups=1(daemon)",
                    },
                ]

        ok, excerpt, ev = strongest_proof_from_attempts([Att()])
        self.assertTrue(ok)
        self.assertIn("uid=", excerpt)


if __name__ == "__main__":
    unittest.main()
