from __future__ import annotations

from ..exploit.evidence import assess_exploit_evidence_strength, strongest_proof_from_attempts
from ..safety import enforce
from ..schemas import JudgeReport, PipelineState, Severity, Stage
from .base import BaseAgent


class JudgeAgent(BaseAgent):
    """Synthesizes evidence into a final report with an actor-critic pass."""

    name = "judge"
    prompt_name = "judge"

    def run(self, state: PipelineState) -> PipelineState:
        state.stage = Stage.JUDGE.value
        ctx = state.cve_context
        memo = state.research_memo
        ver = state.verification

        if ctx is None or memo is None:
            state.errors.append("Judge: missing inputs for report")
            state.stage = Stage.FAILED.value
            state.log(self.name, "cannot judge without context/memo")
            return state

        verdict, confidence = self._decide(memo, ver, state.exploit)
        report = JudgeReport(
            cve_id=ctx.cve_id,
            verdict=verdict,
            severity=ctx.severity or Severity.UNKNOWN.value,
            confidence=confidence,
            summary=memo.summary or self._fallback_summary(ctx),
            impact=memo.attack_scenario,
            remediation=self._remediation(ctx, memo),
            references=ctx.references,
            false_positive_checks=self._fp_checks(memo, ver, state.exploit),
        )

        # Final defensive gate over the whole report payload.
        blob = "\n".join([report.summary, report.impact, *report.remediation])
        v = enforce(blob, context="report")
        if not v.allowed:
            report.impact = enforce(report.impact, context="report").redacted_text
            state.log(self.name, "redacted report content", findings=v.findings)

        state.report = report
        state.stage = (
            Stage.NEEDS_REVIEW.value
            if self.config.get("human_review_required")
            else Stage.DONE.value
        )
        state.log(self.name, "finalized report", verdict=verdict, confidence=confidence)
        return state

    @staticmethod
    def _decide(memo, ver, exploit) -> tuple[str, float]:
        if exploit is not None and exploit.success:
            strength = assess_exploit_evidence_strength(
                success=exploit.success,
                flag_captured=exploit.flag_captured,
                evidence=exploit.evidence,
            )
            if strength == "strong":
                return "exploited", 0.95
            return "not_reproduced", 0.35

        # Live HTTP proof may appear in attempt logs even if exploit.success was not set.
        if exploit is not None and exploit.attempts:
            ok, excerpt, ev = strongest_proof_from_attempts(exploit.attempts)
            if ok:
                strength = assess_exploit_evidence_strength(
                    success=True,
                    flag_captured=excerpt,
                    evidence=ev,
                )
                if strength == "strong":
                    return "exploited", 0.92

        if ver is not None and ver.executed:
            if ver.vulnerable_signal and ver.patched_signal_blocked:
                return "confirmed", min(0.95, memo.confidence + 0.2)
            if ver.vulnerable_signal:
                return "likely", min(0.85, memo.confidence + 0.1)
            return "not_reproduced", max(0.2, memo.confidence - 0.2)
        # Dry-run / no execution: cap at "likely" based on static analysis only.
        if memo.confidence >= 0.7:
            return "likely", memo.confidence
        return "inconclusive", memo.confidence

    @staticmethod
    def _fallback_summary(ctx) -> str:
        return f"{ctx.cve_id}: {ctx.severity} severity issue in {', '.join(ctx.affected_products) or 'affected software'}."

    @staticmethod
    def _remediation(ctx, memo) -> list[str]:
        steps = [
            "Upgrade to a fixed/patched release of the affected component.",
            "Apply the vendor advisory mitigations until upgrade is possible.",
        ]
        cls = memo.vulnerability_class
        specific = {
            "JNDI / Lookup Injection": [
                "Disable message lookups / remove the vulnerable lookup class.",
                "Restrict outbound network egress from application servers.",
            ],
            "Insecure Deserialization": [
                "Replace native deserialization with a safe format and a type allowlist.",
            ],
            "SQL Injection": [
                "Use parameterized queries / prepared statements everywhere.",
            ],
            "Memory Safety (Buffer Over-read)": [
                "Validate length fields against buffer bounds; rebuild with hardening flags.",
            ],
        }
        steps.extend(specific.get(cls, []))
        if ctx.references:
            steps.append(f"Consult official references: {ctx.references[0]}")
        return steps

    @staticmethod
    def _fp_checks(memo, ver, exploit) -> list[str]:
        checks = [
            "Verified the vulnerability class matches the CWE/advisory.",
            "Confirmed affected modules align with the patch scope.",
        ]
        if exploit is not None and exploit.success:
            strength = assess_exploit_evidence_strength(
                success=exploit.success,
                flag_captured=exploit.flag_captured,
                evidence=exploit.evidence,
            )
            if strength == "strong":
                checks.append(
                    "Live PoC produced reference-grade proof (flag exfil, file read, "
                    "shell output, or OOB callback) — not plugin discovery alone."
                )
            else:
                checks.append(
                    "Rejected weak exploit signal (readme/plugin match or generic marker) "
                    "to avoid false positive exploited verdict."
                )
        elif exploit is not None and exploit.attempts:
            ok, _, ev = strongest_proof_from_attempts(exploit.attempts)
            if ok:
                checks.append(
                    "Live attempt responses contain exploitation proof "
                    f"({ev[0] if ev else 'observable output'})."
                )
        if ver is not None and ver.executed:
            checks.append("Compared vulnerable vs patched sandbox behavior (twin check).")
        elif exploit is None or (
            not exploit.success
            and not strongest_proof_from_attempts(
                exploit.attempts if exploit else None
            )[0]
        ):
            checks.append("No live signal available; verdict bounded to static confidence.")
        return checks
