"""Auto-generate an exploit recipe (CVE JSON) from a CVE.

This closes the "front half" gap: instead of an operator hand-writing the
structured exploit JSON, the research swarm produces it from the collected CVE
context + research memo. The output is the same `cve_exploit_input` contract the
Exploiter already consumes, so the rest of the pipeline is unchanged.

Swarm roles (sequential, role-diversified research agents):
  LEAD -> CONTRARIAN -> VERIFIER

In mock/offline mode (or if the LLM output won't validate), a deterministic
heuristic recipe is built from the vulnerability class so the pipeline still
runs end-to-end (and the bundled command-injection lab is fully exploitable
offline).
"""
from __future__ import annotations

import json
import re
from typing import Any

from .cve_input import CVEInputValidationError, parse_cve_input
from .llm_client import LLM
from .prompts import load_prompt
from .schemas import CVEContext, ResearchMemo

_MARKER_PREFIX = "KAVACHCAP["
_MARKER_SUFFIX = "]KAVACHEND"


class AutoRecipeGenerator:
    """Produce a validated cve_exploit_input dict from CVE context + memo."""

    def __init__(self, llm: LLM, config: dict[str, Any]) -> None:
        self.llm = llm
        self.config = config
        self.system = load_prompt("recipe")
        self._mock = config.get("llm_mode", "mock") == "mock"

    def generate(self, ctx: CVEContext, memo: ResearchMemo) -> dict[str, Any]:
        """Return a recipe dict. Tries the LLM swarm, falls back to heuristics."""
        if not self._mock:
            recipe = self._swarm(ctx, memo)
            if recipe is not None:
                return recipe
        return self._heuristic(ctx, memo)

    def _swarm(self, ctx: CVEContext, memo: ResearchMemo) -> dict[str, Any] | None:
        base = self._context_block(ctx, memo)
        try:
            lead = self.llm.complete(self.system, f"ROLE: LEAD\n\n{base}")
            contrarian = self.llm.complete(
                self.system,
                f"ROLE: CONTRARIAN\n\n{base}\n\nLEAD draft:\n{lead}",
            )
            final = self.llm.complete(
                self.system,
                f"ROLE: VERIFIER\n\n{base}\n\nLEAD draft:\n{lead}\n\n"
                f"CONTRARIAN critique:\n{contrarian}\n\nOutput ONLY the final JSON.",
            )
        except Exception:  # noqa: BLE001 - degrade to heuristic on any LLM failure
            return None

        data = self._parse_json(final)
        if data is None:
            return None
        # Force a usable id + defaults, then validate against the real loader.
        data.setdefault("schema_version", "1.0")
        data.setdefault("identification", {}).setdefault("id", ctx.cve_id)
        try:
            parse_cve_input(data)
        except CVEInputValidationError:
            return None
        return data

    @staticmethod
    def _parse_json(raw: str) -> dict[str, Any] | None:
        text = raw.strip()
        if "```" in text:
            m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
            if m:
                text = m.group(1)
        start = text.find("{")
        if start < 0:
            return None
        depth, end = 0, start
        for i, ch in enumerate(text[start:], start):
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        try:
            data = json.loads(text[start:end])
            return data if isinstance(data, dict) else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _context_block(ctx: CVEContext, memo: ResearchMemo) -> str:
        return (
            f"CVE: {ctx.cve_id}\n"
            f"Severity: {ctx.severity}\n"
            f"CWE: {', '.join(ctx.cwe_ids)}\n"
            f"Affected: {', '.join(ctx.affected_products)}\n"
            f"Vulnerability class: {memo.vulnerability_class}\n"
            f"Root cause: {memo.root_cause}\n"
            f"Description:\n{ctx.description}\n\n"
            f"Patch diff (may be empty):\n{ctx.patch_diff[:3000]}"
        )

    # ---- Heuristic fallback -------------------------------------------------

    def _heuristic(self, ctx: CVEContext, memo: ResearchMemo) -> dict[str, Any]:
        vclass = (memo.vulnerability_class or "").lower()
        profile = self._profile_for_class(vclass)

        auth = profile["authorization"]
        planted = bool(auth.get("lab_mode") or auth.get("serve_lab"))
        flag = f"KAVACH_FLAG{{{ctx.cve_id.lower()}}}" if planted else ""
        recipe: dict[str, Any] = {
            "schema_version": "1.0",
            "identification": {
                "id": ctx.cve_id,
                "disclosure_status": "public" if ctx.source != "cve_json" else "0day",
                "severity": ctx.severity or "UNKNOWN",
                "cvss_score": ctx.cvss_score,
                "cvss_vector": ctx.cvss_vector,
                "cwe_ids": list(ctx.cwe_ids),
            },
            "vulnerability": {
                "description": ctx.description or f"{ctx.cve_id}: {memo.vulnerability_class}.",
                "root_cause": memo.root_cause or "Untrusted input reaches a sensitive sink.",
                "vulnerability_class": memo.vulnerability_class or "Unknown",
                "attack_scenario": memo.attack_scenario,
                "primitives": [
                    {"name": p.name, "description": p.description, "sink_type": profile["sink_type"]}
                    for p in (memo.primitives or [])
                ] or [{"name": "untrusted-input", "description": "attacker-controlled input reaches sink",
                       "sink_type": profile["sink_type"]}],
            },
            "affected_software": {
                "products": list(ctx.affected_products),
                "vulnerable_versions": list(ctx.affected_versions),
                "repo_url": ctx.repo_url,
            },
            "attack_surface": {
                "protocol": "http",
                "base_urls": ["http://127.0.0.1:8080"],
                "endpoints": [profile["endpoint"]] if profile.get("endpoint") else [],
                "callback": profile.get("callback", {"required": False, "type": "http"}),
            },
            "source_artifacts": {"patch_diff": ctx.patch_diff},
            "verification": {
                "flag": {
                    "format": "KAVACH_FLAG{...}",
                    "value": flag,
                    "location_type": profile["flag_location"],
                    "capture_marker": {"prefix": _MARKER_PREFIX, "suffix": _MARKER_SUFFIX},
                },
                "success_signals": profile["success_signals"],
                "failure_signals": [{"type": "http_status", "code": 400,
                                     "description": "input validation blocked payload"}],
                "patched_verification": {"required": True, "expect_blocked": True},
            },
            "authorization": profile["authorization"],
            "exploit_hints": {
                "preferred_techniques": [],
                "payload_suggestions": [],
                "avoid": ["reverse shell", "destructive commands", "rm -rf"],
                "notes": (
                    "Auto-generated recipe skeleton only. The Exploiter LLM derives "
                    "all paths, parameters, encodings, and payloads from CVE context, "
                    "recon, web intel snippets, and prior attempt evidence."
                ),
            },
            "references": list(ctx.references),
            "metadata": {"source": "auto_recipe_heuristic"},
        }
        # Validate; if our own heuristic is somehow invalid, raise loudly (a bug).
        parse_cve_input(recipe)
        return recipe

    @staticmethod
    def _profile_is_inclusion_or_plugin(vclass: str) -> bool:
        low = (vclass or "").lower()
        return any(
            k in low
            for k in (
                "inclusion",
                "include",
                "lfi",
                "rfi",
                "remote file",
                "local file",
                "file read",
                "wordpress",
                "plugin",
            )
        )

    @staticmethod
    def _profile_for_class(vclass: str) -> dict[str, Any]:
        """Minimal metadata only — no invented routes, payloads, or technique lists."""
        body_signal = [
            {
                "type": "response_body_contains",
                "pattern": _MARKER_PREFIX,
                "description": "capture marker present in response",
            }
        ]
        base = {
            "endpoint": None,
            "authorization": {"operator_confirms_authorized": False, "lab_mode": False},
            "callback": {"required": False, "type": "http"},
        }

        if "command" in vclass or "os command" in vclass or "rce" in vclass or "code injection" in vclass:
            return {
                **base,
                "sink_type": "os_command",
                "flag_location": "environment_variable",
                "success_signals": body_signal,
                "authorization": {
                    "target_url": "http://127.0.0.1:8080",
                    "operator_confirms_authorized": True,
                    "lab_mode": True,
                    "serve_lab": True,
                    "lab_fixture": "command_injection_ping",
                },
            }
        if "ssrf" in vclass or "server-side request" in vclass:
            return {
                **base,
                "sink_type": "url_fetch",
                "flag_location": "callback_proof",
                "success_signals": [
                    {
                        "type": "callback_received",
                        "description": "target made an out-of-band request",
                    }
                ],
                "callback": {"required": True, "type": "http"},
            }
        if "sql" in vclass:
            return {
                **base,
                "sink_type": "sql_query",
                "flag_location": "http_response",
                "success_signals": [
                    {
                        "type": "response_body_contains",
                        "pattern": "uid=",
                        "description": "query output in response",
                    },
                ],
            }
        if "traversal" in vclass or "path" in vclass:
            return {
                **base,
                "sink_type": "file_read",
                "flag_location": "file",
                "success_signals": [
                    {
                        "type": "response_body_contains",
                        "pattern": "root:",
                        "description": "sensitive file contents in response",
                    },
                ],
            }
        if AutoRecipeGenerator._profile_is_inclusion_or_plugin(vclass):
            return {
                **base,
                "sink_type": "file_include",
                "flag_location": "http_response",
                "success_signals": [
                    {
                        "type": "response_body_contains",
                        "pattern": "uid=",
                        "description": "shell output",
                    },
                    {
                        "type": "response_body_contains",
                        "pattern": "root:",
                        "description": "passwd-like",
                    },
                ],
            }
        return {
            **base,
            "sink_type": "generic_sink",
            "flag_location": "http_response",
            "success_signals": [
                {
                    "type": "response_body_contains",
                    "pattern": "uid=",
                    "description": "shell output",
                },
            ],
        }
