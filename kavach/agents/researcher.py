from __future__ import annotations

from ..safety import enforce
from ..schemas import Primitive, ResearchMemo, PipelineState, Stage
from .base import BaseAgent

# Heuristic mapping from CWE / keywords to a vulnerability class. This gives the
# pipeline a useful baseline even in mock mode, and seeds the live LLM prompt.
_CWE_CLASS = {
    "CWE-917": "JNDI / Lookup Injection",
    "CWE-502": "Insecure Deserialization",
    "CWE-125": "Memory Safety (Buffer Over-read)",
    "CWE-787": "Memory Safety (Buffer Over-write)",
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-site Scripting",
    "CWE-22": "Path Traversal",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-78": "OS Command Injection",
    "CWE-94": "Code Injection",
}

# When multiple CWEs are present, prefer the more specific/actionable class.
_CWE_PRIORITY = ["CWE-917", "CWE-94", "CWE-78", "CWE-89", "CWE-918", "CWE-22", "CWE-79", "CWE-502", "CWE-787", "CWE-125"]

_KEYWORD_CLASS = [
    ("deserial", "Insecure Deserialization"),
    ("jndi", "JNDI / Lookup Injection"),
    ("sql", "SQL Injection"),
    ("xss", "Cross-site Scripting"),
    ("traversal", "Path Traversal"),
    ("buffer", "Memory Safety (Buffer Over-read/write)"),
    ("over-read", "Memory Safety (Buffer Over-read)"),
    ("ssrf", "Server-Side Request Forgery"),
    ("command", "OS Command Injection"),
    ("rce", "Remote Code Execution"),
]


class ResearcherAgent(BaseAgent):
    """Analyzes root cause and maps the attack surface (defensively)."""

    name = "researcher"
    prompt_name = "researcher"

    def run(self, state: PipelineState) -> PipelineState:
        state.stage = Stage.RESEARCH.value
        if state.research_memo is not None and state.cve_context and state.cve_context.source == "cve_json":
            state.log(self.name, "skipped (CVE JSON input already loaded")
            return state

        ctx = state.cve_context
        if ctx is None:
            state.errors.append("Researcher: missing CVE context")
            state.log(self.name, "no context to analyze")
            return state

        vuln_class = self._classify(ctx.cwe_ids, ctx.description)
        analysis_text = self._invoke_llm(state)

        memo = ResearchMemo(
            summary=self._first_sentence(ctx.description),
            root_cause=self._root_cause(vuln_class, ctx.description),
            vulnerability_class=vuln_class,
            affected_modules=list(ctx.affected_products),
            primitives=self._primitives(vuln_class),
            attack_scenario=self._scenario(vuln_class, ctx),
            detection_ideas=self._detection(vuln_class),
            confidence=0.75 if ctx.patch_diff else 0.55,
        )

        # Defensive guardrail: never let analysis text smuggle weaponized payloads.
        verdict = enforce(analysis_text + "\n" + memo.attack_scenario, context="research")
        if not verdict.allowed:
            memo.attack_scenario = enforce(memo.attack_scenario, context="research").redacted_text
            state.log(self.name, "redacted weaponized content", findings=verdict.findings)

        state.research_memo = memo
        state.log(self.name, "produced research memo", vuln_class=vuln_class)
        return state

    def _invoke_llm(self, state: PipelineState) -> str:
        ctx = state.cve_context
        assert ctx is not None
        user = (
            f"CVE: {ctx.cve_id}\nSeverity: {ctx.severity}\nCWE: {', '.join(ctx.cwe_ids)}\n"
            f"Affected: {', '.join(ctx.affected_products)}\n\nDescription:\n{ctx.description}\n\n"
            f"Patch diff (may be empty):\n{ctx.patch_diff[:4000]}"
        )
        try:
            return self.ask(user)
        except Exception as exc:  # noqa: BLE001 - degrade gracefully to heuristics
            state.log(self.name, f"LLM call failed, using heuristics: {exc}")
            return ""

    @staticmethod
    def _classify(cwe_ids: list[str], description: str) -> str:
        present = [c for c in cwe_ids if c in _CWE_CLASS]
        for cwe in _CWE_PRIORITY:
            if cwe in present:
                return _CWE_CLASS[cwe]
        if present:
            return _CWE_CLASS[present[0]]
        low = description.lower()
        for kw, cls in _KEYWORD_CLASS:
            if kw in low:
                return cls
        return "Unknown"

    @staticmethod
    def _first_sentence(text: str) -> str:
        text = (text or "").strip()
        if not text:
            return "No description available."
        return text.split(". ")[0].strip().rstrip(".") + "."

    @staticmethod
    def _root_cause(vuln_class: str, description: str) -> str:
        return (
            f"The defect is best characterized as '{vuln_class}'. Untrusted input "
            "reaches a sensitive sink without adequate validation or isolation, "
            "as reflected in the advisory description."
        )

    @staticmethod
    def _primitives(vuln_class: str) -> list[Primitive]:
        catalog = {
            "Insecure Deserialization": [
                Primitive("untrusted-input", "Attacker controls serialized/lookup input"),
                Primitive("gadget-resolution", "Input resolves to a sensitive class/handler"),
                Primitive("sink-invocation", "Resolved object triggers unsafe behavior"),
            ],
            "JNDI / Lookup Injection": [
                Primitive("log-controlled-input", "Attacker controls a logged/interpolated value"),
                Primitive("lookup-expansion", "Lookup expression is evaluated"),
                Primitive("remote-fetch", "Evaluation reaches a remote resource resolver"),
            ],
            "Memory Safety (Buffer Over-read)": [
                Primitive("length-field-trust", "A length field is trusted without bounds check"),
                Primitive("oob-read", "Read extends past the allocated buffer"),
            ],
        }
        return catalog.get(
            vuln_class,
            [
                Primitive("untrusted-input", "Attacker-controlled input enters the component"),
                Primitive("missing-validation", "Input is not validated/sanitized"),
                Primitive("sensitive-sink", "Input reaches a security-sensitive operation"),
            ],
        )

    @staticmethod
    def _scenario(vuln_class: str, ctx) -> str:
        return (
            f"An attacker supplies crafted input to an affected {', '.join(ctx.affected_products) or 'component'} "
            f"endpoint. Because of the {vuln_class.lower()} defect, the input is processed "
            "unsafely, leading to the impact described in the advisory. "
            "(Conceptual description for defenders; no runnable payload is provided.)"
        )

    @staticmethod
    def _detection(vuln_class: str) -> list[str]:
        base = [
            "Add unit/integration tests asserting untrusted input is rejected at the sink.",
            "Monitor logs for anomalous input patterns reaching the affected component.",
        ]
        extra = {
            "JNDI / Lookup Injection": [
                "Alert on outbound LDAP/RMI/DNS from app servers that should not initiate them.",
                "Search logs for '${' interpolation tokens in user-controlled fields.",
            ],
            "Insecure Deserialization": [
                "Flag deserialization of types outside an explicit allowlist.",
            ],
            "Memory Safety (Buffer Over-read)": [
                "Fuzz the parser with malformed length fields under ASAN.",
            ],
        }
        return base + extra.get(vuln_class, [])
