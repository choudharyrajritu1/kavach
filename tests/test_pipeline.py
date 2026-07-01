from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.config import get_config  # noqa: E402
from kavach.orchestrator import Orchestrator  # noqa: E402


def _config(tmp: str) -> dict:
    os.environ["KAVACH_LLM_MODE"] = "mock"
    os.environ["KAVACH_OFFLINE"] = "true"
    os.environ["KAVACH_SANDBOX_ENABLED"] = "false"
    cfg = get_config()
    cfg["db_path"] = str(Path(tmp) / "test.db")
    return cfg


class PipelineEndToEndTest(unittest.TestCase):
    def test_known_cve_runs_to_completion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(_config(tmp))
            state = orch.analyze("CVE-2021-44228")

            self.assertEqual(state.stage, "done")
            self.assertIsNotNone(state.cve_context)
            self.assertIsNotNone(state.research_memo)
            self.assertIsNotNone(state.verification)
            self.assertIsNotNone(state.report)
            self.assertEqual(state.report.severity, "CRITICAL")
            self.assertIn("JNDI", state.research_memo.vulnerability_class)
            self.assertEqual(state.verification.sandbox_mode, "dry-run")
            self.assertTrue(state.report.remediation)

    def test_invalid_cve_id_halts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            orch = Orchestrator(_config(tmp))
            state = orch.analyze("NOT-A-CVE")
            self.assertEqual(state.stage, "failed")
            self.assertTrue(state.errors)

    def test_run_is_persisted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg = _config(tmp)
            orch = Orchestrator(cfg)
            state = orch.analyze("CVE-2014-0160")
            loaded = orch.store.get(state.run_id)
            self.assertIsNotNone(loaded)
            self.assertEqual(loaded["cve_id"], "CVE-2014-0160")


if __name__ == "__main__":
    unittest.main()
