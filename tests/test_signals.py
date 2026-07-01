from __future__ import annotations

import sys
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.exploit.callback import CallbackListener  # noqa: E402
from kavach.exploit.signals import SignalEvaluator, build_auth_headers  # noqa: E402


class SignalEvaluatorTest(unittest.TestCase):
    def test_capture_marker_success(self) -> None:
        ev = SignalEvaluator(flag="KAVACH_FLAG{x}")
        out = ev.evaluate(status=200, headers={}, body="KAVACHCAP[KAVACH_FLAG{x}]KAVACHEND")
        self.assertTrue(out.success)
        self.assertEqual(out.captured, "KAVACH_FLAG{x}")

    def test_http_status_signal(self) -> None:
        ev = SignalEvaluator(success_signals=[{"type": "http_status", "code": 500}])
        out = ev.evaluate(status=500, headers={}, body="boom")
        self.assertTrue(out.success)

    def test_header_signal(self) -> None:
        ev = SignalEvaluator(
            success_signals=[{"type": "response_header_contains", "pattern": "X-Injected"}]
        )
        out = ev.evaluate(status=200, headers={"X-Injected": "1"}, body="")
        self.assertTrue(out.success)

    def test_failure_signal_short_circuits(self) -> None:
        ev = SignalEvaluator(
            success_signals=[{"type": "response_body_contains", "pattern": "ok"}],
            failure_signals=[{"type": "http_status", "code": 400}],
        )
        out = ev.evaluate(status=400, headers={}, body="ok")
        self.assertFalse(out.success)
        self.assertIn("failure", out.failure_reason.lower())

    def test_callback_signal(self) -> None:
        ev = SignalEvaluator(success_signals=[{"type": "callback_received"}])
        out = ev.evaluate(status=200, headers={}, body="", callback_hits=1)
        self.assertTrue(out.success)
        out2 = ev.evaluate(status=200, headers={}, body="", callback_hits=0)
        self.assertFalse(out2.success)


class ExternalEvidenceTest(unittest.TestCase):
    def test_infer_flag_pattern_without_planted_flag(self) -> None:
        ev = SignalEvaluator(expect_planted_flag=False)
        out = ev.evaluate(
            status=200,
            headers={},
            body="root:x:0:0:root:/root:/bin/bash\nFLAG{abc123}",
        )
        self.assertTrue(out.success)
        self.assertIn("FLAG{abc123}", out.captured)

    def test_no_false_success_on_generic_html(self) -> None:
        ev = SignalEvaluator(expect_planted_flag=False)
        out = ev.evaluate(
            status=200,
            headers={},
            body="<!DOCTYPE html><html><body>404 Not Found</body></html>",
        )
        self.assertFalse(out.success)


class AuthHeaderTest(unittest.TestCase):
    def test_bearer(self) -> None:
        ep = {"auth_required": True, "auth_type": "bearer", "auth_credentials": {"token": "abc"}}
        self.assertEqual(build_auth_headers(ep), {"Authorization": "Bearer abc"})

    def test_basic(self) -> None:
        ep = {
            "auth_required": True,
            "auth_type": "basic",
            "auth_credentials": {"username": "u", "password": "p"},
        }
        headers = build_auth_headers(ep)
        self.assertTrue(headers["Authorization"].startswith("Basic "))

    def test_no_auth(self) -> None:
        self.assertEqual(build_auth_headers({"auth_required": False}), {})


class CallbackListenerTest(unittest.TestCase):
    def test_records_oob_hit(self) -> None:
        with CallbackListener() as cb:
            self.assertEqual(cb.hit_count(), 0)
            urllib.request.urlopen(f"{cb.url}/oob?proof=1", timeout=3).read()
            self.assertTrue(cb.wait_for_hit(timeout=2))
            self.assertGreaterEqual(cb.hit_count(), 1)
            self.assertIn("/oob", cb.hits[0].path)


if __name__ == "__main__":
    unittest.main()
