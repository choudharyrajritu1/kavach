from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.cve_input import (  # noqa: E402
    CVEInputValidationError,
    load_cve_input,
    parse_cve_input,
)
from kavach.config import get_config  # noqa: E402
from kavach.orchestrator import Orchestrator  # noqa: E402

EXAMPLE_JSON = Path(__file__).resolve().parents[1] / "data/examples/lab_command_injection.json"
TEMPLATE_JSON = Path(__file__).resolve().parents[1] / "data/examples/cve_exploit_input.template.json"


class CVEInputValidationTest(unittest.TestCase):
    def test_example_json_loads(self) -> None:
        spec = load_cve_input(EXAMPLE_JSON)
        self.assertEqual(spec.id, "CVE-2099-00001")
        self.assertEqual(spec.disclosure_status, "public")
        self.assertTrue(spec.serve_lab)
        self.assertEqual(spec.flag_value, "KAVACH_FLAG{json-lab-test}")
        self.assertGreater(len(spec.build_llm_context_block()), 200)

    def test_template_requires_operator_edits(self) -> None:
        data = parse_cve_input(load_cve_input(EXAMPLE_JSON).raw)
        self.assertEqual(data.id, "CVE-2099-00001")

    def test_minimal_exploit_only_json(self) -> None:
        path = Path(__file__).resolve().parents[1] / "data/examples/lab_nextjs_cve_2025_29927_basic.json"
        spec = load_cve_input(path)
        self.assertTrue(spec.exploit_only)
        self.assertEqual(spec.id, "CVE-2025-29927")
        self.assertEqual(len(spec.endpoints), 0)
        self.assertEqual(spec.success_signals, [])

    def test_minimal_command_injection_json(self) -> None:
        path = Path(__file__).resolve().parents[1] / "data/examples/lab_command_injection_basic.json"
        spec = load_cve_input(path)
        self.assertTrue(spec.exploit_only)
        self.assertEqual(spec.id, "CVE-2099-00001")
        self.assertEqual(len(spec.endpoints), 0)

    def test_empty_primitives_get_default(self) -> None:
        bad = load_cve_input(EXAMPLE_JSON).raw.copy()
        bad["vulnerability"] = dict(bad["vulnerability"])
        bad["vulnerability"]["primitives"] = []
        spec = parse_cve_input(bad)
        self.assertGreaterEqual(len(spec.primitives), 1)

    def test_rejects_bad_schema_version(self) -> None:
        bad = load_cve_input(EXAMPLE_JSON).raw.copy()
        bad["schema_version"] = "2.0"
        with self.assertRaises(CVEInputValidationError):
            parse_cve_input(bad)


class CVEJsonPipelineTest(unittest.TestCase):
    def test_cve_json_exploit_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["KAVACH_LLM_MODE"] = "mock"
            os.environ["KAVACH_OFFLINE"] = "true"
            os.environ["KAVACH_SANDBOX_ENABLED"] = "false"
            cfg = get_config()
            cfg["db_path"] = str(Path(tmp) / "test.db")
            cfg["runs_dir"] = str(Path(tmp) / "runs")

            state = Orchestrator(cfg).analyze(
                "",
                cve_json_path=str(EXAMPLE_JSON),
            )

            self.assertEqual(state.stage, "done")
            self.assertIsNotNone(state.exploit)
            self.assertTrue(state.exploit.success)
            self.assertEqual(state.exploit.flag_captured, "KAVACH_FLAG{json-lab-test}")
            self.assertIsNotNone(state.report)
            self.assertEqual(state.report.verdict, "exploited")


if __name__ == "__main__":
    unittest.main()
