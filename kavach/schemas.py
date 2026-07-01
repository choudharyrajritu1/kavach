from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id(prefix: str = "run") -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Stage(str, Enum):
    """Pipeline stages, one per agent, plus terminal states."""

    PENDING = "pending"
    COLLECT = "collect"
    RESEARCH = "research"
    BUILD = "build"
    EXPLOIT = "exploit"
    VERIFY = "verify"
    JUDGE = "judge"
    DONE = "done"
    FAILED = "failed"
    NEEDS_REVIEW = "needs_review"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class CVEContext:
    """Output of the Collector agent: public context about a CVE."""

    cve_id: str
    description: str = ""
    severity: str = Severity.UNKNOWN.value
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    affected_products: list[str] = field(default_factory=list)
    affected_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    repo_url: str = ""
    patch_diff: str = ""
    source: str = "offline"
    collected_at: str = field(default_factory=_now)


@dataclass
class Primitive:
    """A single building block in the (defensive) exploit-chain analysis."""

    name: str
    description: str
    location: str = ""  # file/function/line, when known


@dataclass
class ResearchMemo:
    """Output of the Researcher agent: root-cause analysis (no exploit code)."""

    summary: str = ""
    root_cause: str = ""
    vulnerability_class: str = ""
    affected_modules: list[str] = field(default_factory=list)
    primitives: list[Primitive] = field(default_factory=list)
    attack_scenario: str = ""  # narrative only, no weaponized payload
    detection_ideas: list[str] = field(default_factory=list)
    confidence: float = 0.0


@dataclass
class BuildArtifact:
    """Output of the Builder/Simulator agent: a sandbox repro environment."""

    dockerfile: str = ""
    compose: str = ""
    harness_files: dict[str, str] = field(default_factory=dict)  # path -> contents
    benign_test_markers: list[str] = field(default_factory=list)
    # A unique secret planted in the vulnerable environment. Capturing it proves
    # genuine exploitation (planted secret flag verification pattern).
    flag: str = ""
    notes: str = ""


@dataclass
class ExploitAttempt:
    """A single iteration of the Exploiter's generate-run-observe loop."""

    iteration: int
    request: str = ""  # the PoC request/command actually sent (sanitized for storage)
    response_excerpt: str = ""
    success: bool = False
    error: str = ""
    llm_reasoning: str = ""
    llm_raw_excerpt: str = ""
    candidate_triage: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class ExploitResult:
    """Output of the Exploiter agent: a real PoC validated against a target.

    OFFENSIVE mode only, and only against authorized targets (local lab twin or
    an explicitly authorized URL).
    """

    cve_id: str = ""
    module: str = ""
    target: str = ""
    target_kind: str = "lab"  # "lab" | "authorized_url"
    success: bool = False
    flag_captured: str = ""
    exploit_code: str = ""  # the generated PoC script (for the report/audit)
    attempts: list[ExploitAttempt] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    iterations: int = 0


@dataclass
class VerificationResult:
    """Output of the Verifier agent: results of sandboxed, benign checks."""

    executed: bool = False
    sandbox_mode: str = "dry-run"  # "dry-run" | "docker"
    vulnerable_signal: bool = False
    patched_signal_blocked: bool = False
    logs: str = ""
    exit_code: int | None = None
    duration_secs: float = 0.0
    evidence: list[str] = field(default_factory=list)


@dataclass
class JudgeReport:
    """Output of the Judge agent: the final, structured report."""

    cve_id: str = ""
    verdict: str = "inconclusive"  # confirmed | likely | inconclusive | not_reproduced
    severity: str = Severity.UNKNOWN.value
    confidence: float = 0.0
    summary: str = ""
    impact: str = ""
    remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    false_positive_checks: list[str] = field(default_factory=list)
    generated_at: str = field(default_factory=_now)


@dataclass
class PipelineState:
    """The full state passed between agents and persisted per run."""

    run_id: str = field(default_factory=lambda: new_id("run"))
    cve_id: str = ""
    repo_url: str = ""
    mode: str = "defensive"  # "defensive" | "offensive"
    target: str = ""  # authorized target URL (offensive mode), if any
    stage: str = Stage.PENDING.value
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    cve_context: CVEContext | None = None
    research_memo: ResearchMemo | None = None
    build_artifact: BuildArtifact | None = None
    exploit: ExploitResult | None = None
    verification: VerificationResult | None = None
    report: JudgeReport | None = None

    # Operator-provided JSON for 0-day / new CVE exploitation (see cve_input.py).
    cve_input: dict[str, Any] | None = None

    # One Google search + extracted paths/headers/techniques (see search/intel.py).
    web_intel: dict[str, Any] | None = None

    log_file: str = ""

    errors: list[str] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)

    def log(self, agent: str, message: str, **extra: Any) -> None:
        self.trace.append(
            {"ts": _now(), "agent": agent, "message": message, **extra}
        )
        self.updated_at = _now()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
