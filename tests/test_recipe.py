from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from kavach.config import get_config  # noqa: E402
from kavach.cve_input import parse_cve_input  # noqa: E402
from kavach.llm_client import MockChatModel  # noqa: E402
from kavach.orchestrator import Orchestrator  # noqa: E402
from kavach.recipe import AutoRecipeGenerator  # noqa: E402
from kavach.schemas import CVEContext, Primitive, ResearchMemo  # noqa: E402


def _cfg(tmp: str) -> dict:
    os.environ["KAVACH_LLM_MODE"] = "mock"
    os.environ["KAVACH_OFFLINE"] = "true"
    os.environ["KAVACH_SANDBOX_ENABLED"] = "false"
    cfg = get_config()
    cfg["db_path"] = str(Path(tmp) / "t.db")
    cfg["runs_dir"] = str(Path(tmp) / "runs")
    return cfg


class AutoRecipeGeneratorTest(unittest.TestCase):
    def _gen(self) -> AutoRecipeGenerator:
        return AutoRecipeGenerator(MockChatModel(), {"llm_mode": "mock"})

    def test_command_injection_recipe_is_valid(self) -> None:
        ctx = CVEContext(cve_id="CVE-2099-00001", description="x" * 30, cwe_ids=["CWE-78"])
        memo = ResearchMemo(
            root_cause="shell concat sink with user input",
            vulnerability_class="OS Command Injection",
            primitives=[Primitive("sink", "shell concat")],
        )
        recipe = self._gen().generate(ctx, memo)
        spec = parse_cve_input(recipe)  # must validate
        self.assertEqual(spec.id, "CVE-2099-00001")
        self.assertTrue(spec.serve_lab)
        self.assertEqual(spec.endpoints, [])

    def test_ssrf_recipe_requires_callback(self) -> None:
        ctx = CVEContext(cve_id="CVE-2099-00002", description="y" * 30, cwe_ids=["CWE-918"])
        memo = ResearchMemo(
            root_cause="server fetches attacker url",
            vulnerability_class="Server-Side Request Forgery",
            primitives=[Primitive("fetch", "server side fetch")],
        )
        recipe = self._gen().generate(ctx, memo)
        spec = parse_cve_input(recipe)
        self.assertTrue(spec.callback.get("required"))
        self.assertTrue(any(s["type"] == "callback_received" for s in spec.success_signals))

    def test_generic_recipe_is_valid(self) -> None:
        ctx = CVEContext(cve_id="CVE-2099-00003", description="z" * 30)
        memo = ResearchMemo(root_cause="unknown sink reached", vulnerability_class="Unknown",
                            primitives=[Primitive("p", "d")])
        recipe = self._gen().generate(ctx, memo)
        parse_cve_input(recipe)  # should not raise


class AutoPipelineTest(unittest.TestCase):
    def test_auto_recipe_exploits_lab(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            state = Orchestrator(_cfg(tmp)).analyze("CVE-2099-00001", auto_recipe=True)
            self.assertEqual(state.stage, "done")
            self.assertIsNotNone(state.exploit)
            self.assertTrue(state.exploit.success)
            self.assertTrue(state.exploit.flag_captured.startswith("KAVACH_FLAG{"))
            self.assertEqual(state.report.verdict, "exploited")


if __name__ == "__main__":
    unittest.main()
