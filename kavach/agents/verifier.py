from __future__ import annotations

from ..sandbox import SandboxRunner
from ..schemas import PipelineState, Stage, VerificationResult
from .base import BaseAgent


class VerifierAgent(BaseAgent):
    """Runs the benign harness in the sandbox and interprets the results.

    It runs two variants:
      - "vulnerable": expects the benign marker to be reached.
      - "patched":    expects the same marker to be blocked (twin verification).
    """

    name = "verifier"
    prompt_name = "verifier"

    def __init__(self, llm, config) -> None:  # noqa: ANN001 - mirrors BaseAgent
        super().__init__(llm, config)
        self.runner = SandboxRunner(config)

    def run(self, state: PipelineState) -> PipelineState:
        state.stage = Stage.VERIFY.value
        artifact = state.build_artifact
        if artifact is None:
            state.errors.append("Verifier: missing build artifact")
            state.log(self.name, "no artifact to verify")
            return state

        vuln = self.runner.run(artifact, variant="vulnerable")
        patched = self.runner.run(artifact, variant="patched")

        vulnerable_signal = bool(vuln.markers_hit) if vuln.executed else False
        patched_blocked = (not patched.markers_hit) if patched.executed else False

        evidence: list[str] = []
        if vuln.markers_hit:
            evidence.append(f"vulnerable variant emitted markers: {vuln.markers_hit}")
        if patched.executed and not patched.markers_hit:
            evidence.append("patched variant did not emit markers (signal blocked)")
        if not vuln.executed:
            evidence.append("sandbox ran in dry-run mode; no live execution performed")

        result = VerificationResult(
            executed=vuln.executed,
            sandbox_mode=vuln.mode,
            vulnerable_signal=vulnerable_signal,
            patched_signal_blocked=patched_blocked,
            logs=f"=== vulnerable ===\n{vuln.logs}\n\n=== patched ===\n{patched.logs}",
            exit_code=vuln.exit_code,
            duration_secs=round(vuln.duration_secs + patched.duration_secs, 3),
            evidence=evidence,
        )

        state.verification = result
        state.log(
            self.name,
            "completed verification",
            mode=result.sandbox_mode,
            vulnerable_signal=result.vulnerable_signal,
        )
        return state
