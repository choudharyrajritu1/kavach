from __future__ import annotations

import secrets

from ..safety import enforce
from ..schemas import BuildArtifact, PipelineState, Stage

# A benign sentinel. The harness only proves a code path was reached by emitting
# this marker -- never a shell, never network egress, never destructive actions.
BENIGN_MARKER = "KAVACH_MARKER_REACHED"

_HARNESS_PY = f"""\
# Benign KAVACH harness. It does NOT deliver a real exploit.
# It only emits a sentinel marker to prove a code path was reached.
import sys


def simulate_codepath() -> bool:
    # Placeholder for a benign trigger of the vulnerable code path.
    # In a real environment this would call the affected API with a harmless,
    # non-weaponized input and observe the resulting behavior.
    return True


def main() -> int:
    reached = simulate_codepath()
    if reached:
        print("{BENIGN_MARKER}")
        return 0
    print("KAVACH_MARKER_NOT_REACHED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
"""

_DOCKERFILE = """\
# Minimal, pinned sandbox image for benign verification.
FROM python:3.11-slim

WORKDIR /app
COPY harness.py /app/harness.py

# Run as a non-root user; the runtime additionally drops caps and disables net.
RUN useradd --create-home --uid 10001 kavach
USER kavach

ENTRYPOINT ["python", "/app/harness.py"]
"""

_COMPOSE = """\
version: "3.8"
services:
  vulnerable:
    build: .
    network_mode: "none"
    read_only: true
    cap_drop: ["ALL"]
    security_opt: ["no-new-privileges:true"]
"""


class BuilderAgent:
    """Builds a reproducible, sandboxed environment with a benign harness.

    Produces a "vulnerable" artifact; the Verifier also derives a "patched" twin
    to confirm the fix blocks the same benign signal.
    """

    name = "builder"
    prompt_name = "builder"

    def __init__(self, llm, config) -> None:  # noqa: ANN001 - mirrors BaseAgent
        self.llm = llm
        self.config = config

    def run(self, state: PipelineState) -> PipelineState:
        state.stage = Stage.BUILD.value
        if state.build_artifact is not None and state.cve_context and state.cve_context.source == "cve_json":
            state.log(self.name, "skipped (CVE JSON input already loaded", flag=state.build_artifact.flag)
            return state

        if state.research_memo is None:
            state.errors.append("Builder: missing research memo")
            state.log(self.name, "no research memo to build from")
            return state

        plant_flag = self._uses_bundled_lab(state)
        flag = f"KAVACH_FLAG{{{secrets.token_hex(12)}}}" if plant_flag else ""

        artifact = BuildArtifact(
            dockerfile=_DOCKERFILE,
            compose=_COMPOSE,
            harness_files={"harness.py": _HARNESS_PY},
            benign_test_markers=[BENIGN_MARKER],
            flag=flag,
            notes=(
                "Pinned slim image runs a benign harness that emits a sentinel "
                "marker. No network, non-root, all capabilities dropped."
                + (
                    " A secret flag is planted for bundled-lab exploit verification."
                    if plant_flag
                    else " External targets: no planted flag; exploitation is judged from response evidence."
                )
            ),
        )

        # Guardrail: ensure nothing weaponized slipped into generated files.
        for path, contents in artifact.harness_files.items():
            verdict = enforce(contents, context=f"harness:{path}")
            if not verdict.allowed:
                artifact.harness_files[path] = verdict.redacted_text
                state.log(self.name, "redacted harness file", path=path, findings=verdict.findings)

        state.build_artifact = artifact
        state.log(
            self.name,
            "built sandbox artifact",
            markers=artifact.benign_test_markers,
            planted_flag=bool(flag),
        )
        return state

    def _uses_bundled_lab(self, state: PipelineState) -> bool:
        """Only the bundled command-injection lab gets a planted KAVACH_FLAG secret."""
        if self.config.get("serve_lab"):
            return True
        if not (state.target or "").strip() and state.cve_id.upper() == "CVE-2099-00001":
            return True
        if state.cve_input and isinstance(state.cve_input, dict):
            auth = state.cve_input.get("authorization") or {}
            if auth.get("serve_lab") or auth.get("lab_mode"):
                return True
        return False
