"""Report rendering for CLI (markdown) and run log files (plain text)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .config import get_config
from .schemas import ExploitAttempt, PipelineState

_WIDTH = 80


def _wrap(text: str, indent: int = 4, width: int = _WIDTH) -> list[str]:
    if not text:
        return []
    prefix = " " * indent
    max_len = max(20, width - indent)
    out: list[str] = []
    for paragraph in text.splitlines():
        line = paragraph.strip()
        if not line:
            out.append("")
            continue
        while len(line) > max_len:
            break_at = line.rfind(" ", 0, max_len)
            if break_at <= 0:
                break_at = max_len
            out.append(prefix + line[:break_at].rstrip())
            line = line[break_at:].lstrip()
        out.append(prefix + line)
    return out


def _log_banner(title: str, level: int = 1) -> list[str]:
    bar = "=" * _WIDTH if level == 1 else "-" * _WIDTH
    return [bar, f" {title}", bar, ""]


def _log_field(label: str, value: str, indent: int = 2) -> str:
    pad = " " * indent
    return f"{pad}{label:<14}{value}"


def render_markdown(state: PipelineState, config: dict[str, Any] | None = None) -> str:
    """Markdown report for terminal / --save output."""
    return "\n".join(_markdown_lines(state, config or get_config()))


def render_log_report(state: PipelineState, config: dict[str, Any] | None = None) -> str:
    """Plain-text report appended once to the run log (no duplicate meta sections)."""
    return "\n".join(_log_lines(state, config or get_config()))


def _markdown_lines(state: PipelineState, cfg: dict[str, Any]) -> list[str]:
    lines = [
        f"# KAVACH Report — {state.cve_id}",
        "",
        f"- Run ID: `{state.run_id}`",
        f"- Stage: **{state.stage}**",
        f"- LLM: **{cfg['provider']['name']}** / `{cfg['model']}` ({cfg['llm_mode']})",
    ]
    lines += _md_errors(state)
    lines += _md_context(state)
    lines += _md_research(state)
    lines += _md_exploit(state)
    lines += _md_run_log_ref(state, cfg)
    lines += _md_trace(state)
    lines += _md_verification(state)
    lines += _md_verdict(state)
    return lines


def _log_lines(state: PipelineState, cfg: dict[str, Any]) -> list[str]:
    lines = _log_banner(f"KAVACH REPORT — {state.cve_id}", level=1)
    lines += [
        _log_field("Run ID:", state.run_id),
        _log_field("Stage:", state.stage),
        _log_field(
            "LLM:",
            f"{cfg['provider']['name']} / {cfg['model']} ({cfg['llm_mode']})",
        ),
        "",
        "(Detailed LLM / HTTP trace is recorded above this summary.)",
        "",
    ]
    lines += _log_errors(state)
    lines += _log_context(state)
    lines += _log_research(state)
    lines += _log_exploit(state)
    lines += _log_verification(state)
    lines += _log_verdict(state)
    lines.append("")
    return lines


def _md_errors(state: PipelineState) -> list[str]:
    if not state.errors:
        return []
    return ["", "## Errors", *[f"- {e}" for e in state.errors]]


def _log_errors(state: PipelineState) -> list[str]:
    if not state.errors:
        return []
    lines = _log_banner("ERRORS", level=2)
    lines += [f"  - {e}" for e in state.errors]
    lines.append("")
    return lines


def _md_context(state: PipelineState) -> list[str]:
    if not state.cve_context:
        return []
    c = state.cve_context
    return [
        "",
        "## Collected Context",
        f"- Severity: **{c.severity}** (CVSS {c.cvss_score}) `{c.cvss_vector}`",
        f"- CWE: {', '.join(c.cwe_ids) or 'unknown'}",
        f"- Affected: {', '.join(c.affected_products) or 'unknown'} {', '.join(c.affected_versions)}",
        f"- Source: {c.source}",
        "",
        f"> {c.description}",
    ]


def _log_context(state: PipelineState) -> list[str]:
    if not state.cve_context:
        return []
    c = state.cve_context
    lines = _log_banner("COLLECTED CONTEXT", level=2)
    lines += [
        _log_field("Severity:", f"{c.severity} (CVSS {c.cvss_score})"),
        _log_field("CWE:", ", ".join(c.cwe_ids) or "unknown"),
        _log_field("Affected:", f"{', '.join(c.affected_products) or 'unknown'} {', '.join(c.affected_versions)}"),
        _log_field("Source:", c.source),
        "",
        "  Description:",
        *_wrap(c.description or "", indent=4),
        "",
    ]
    return lines


def _md_research(state: PipelineState) -> list[str]:
    if not state.research_memo:
        return []
    m = state.research_memo
    return [
        "",
        "## Analysis (Researcher)",
        f"- Class: **{m.vulnerability_class}** (confidence {m.confidence})",
        f"- Root cause: {m.root_cause}",
        "- Primitives:",
        *[f"  - `{p.name}`: {p.description}" for p in m.primitives],
        "- Detection ideas:",
        *[f"  - {d}" for d in m.detection_ideas],
    ]


def _log_research(state: PipelineState) -> list[str]:
    if not state.research_memo:
        return []
    m = state.research_memo
    lines = _log_banner("ANALYSIS (RESEARCHER)", level=2)
    lines += [
        _log_field("Class:", f"{m.vulnerability_class} (confidence {m.confidence})"),
        "",
        "  Root cause:",
        *_wrap(m.root_cause or "", indent=4),
        "",
        "  Primitives:",
    ]
    for p in m.primitives:
        lines.append(f"    - {p.name}: {p.description}")
    if m.detection_ideas:
        lines += ["", "  Detection ideas:"]
        for d in m.detection_ideas:
            lines.append(f"    - {d}")
    lines.append("")
    return lines


def _attempt_md(a: ExploitAttempt) -> list[str]:
    status = "SUCCESS" if a.success else "FAILED"
    lines = [
        "",
        f"**Attempt {a.iteration}** — {status}",
        f"- LLM reasoning: {a.llm_reasoning or 'n/a'}",
    ]
    if a.request:
        lines.append(f"- Request: `{a.request[:200]}`")
    else:
        lines.append("- Request: n/a")
    if a.error:
        lines.append(f"- Error: `{a.error}`")
    if a.response_excerpt:
        lines.append(f"- Response: `{a.response_excerpt[:300]}`")
    return lines


def _attempt_log(a: ExploitAttempt) -> list[str]:
    status = "SUCCESS" if a.success else "FAILED"
    lines = [
        f"  Attempt {a.iteration} — {status}",
        "  " + "-" * 40,
        "",
        "    Reasoning:",
        *_wrap(a.llm_reasoning or "n/a", indent=6),
        "",
    ]
    if a.request:
        lines += ["    Request:", *_wrap(a.request[:800], indent=6), ""]
    if a.error:
        lines += ["    Error:", *_wrap(a.error, indent=6), ""]
    if a.response_excerpt:
        lines += ["    Response:", *_wrap(a.response_excerpt[:600], indent=6), ""]
    lines.append("")
    return lines


def _md_exploit(state: PipelineState) -> list[str]:
    if not state.exploit:
        return []
    e = state.exploit
    lines = [
        "",
        "## Exploitation (Exploiter — LLM loop)",
        f"- Module: `{e.module or 'n/a'}` | target: {e.target} ({e.target_kind})",
        f"- **Success: {e.success}** | LLM iterations: {e.iterations}",
    ]
    if e.flag_captured:
        lines.append(f"- Flag captured: `{e.flag_captured}`")
    lines += ["- Evidence:", *[f"  - {x}" for x in e.evidence]]
    if e.attempts:
        lines += ["", "### Iteration logs (generate → run → observe)"]
        for a in e.attempts:
            lines += _attempt_md(a)
    if e.exploit_code:
        lines += ["", "### Generated PoC", "```python", e.exploit_code.rstrip(), "```"]
    return lines


def _log_exploit(state: PipelineState) -> list[str]:
    if not state.exploit:
        return []
    e = state.exploit
    lines = _log_banner("EXPLOITATION (EXPLOITER — LLM LOOP)", level=2)
    lines += [
        _log_field("Module:", e.module or "n/a"),
        _log_field("Target:", f"{e.target} ({e.target_kind})"),
        _log_field("Success:", str(e.success)),
        _log_field("Iterations:", str(e.iterations)),
    ]
    if e.flag_captured:
        lines.append(_log_field("Captured:", e.flag_captured))
    lines += ["", "  Evidence:"]
    for item in e.evidence:
        lines += _wrap(item, indent=4)
    if e.attempts:
        lines += _log_banner("ITERATION LOGS (generate → run → observe)", level=2)
        for a in e.attempts:
            lines += _attempt_log(a)
    if e.exploit_code:
        lines += ["  Generated PoC:", "  ```", *[f"  {ln}" for ln in e.exploit_code.rstrip().splitlines()], "  ```", ""]
    return lines


def _md_run_log_ref(state: PipelineState, cfg: dict[str, Any]) -> list[str]:
    run_log_path = state.log_file
    if not run_log_path:
        log_dir = Path(cfg.get("runs_dir", get_config()["runs_dir"]))
        if log_dir.is_dir():
            agent_prefix = (state.cve_id or "run").lower().replace("/", "_")
            candidates = sorted(
                log_dir.glob(f"{agent_prefix}_*.log"),
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                run_log_path = str(candidates[0])
    if not run_log_path:
        return []
    return ["", "## Run log (on disk)", f"- `{run_log_path}`"]


def _md_trace(state: PipelineState) -> list[str]:
    if not state.trace:
        return []
    return [
        "",
        "## Agent trace",
        *[
            f"- [{t.get('ts', '')}] **{t.get('agent')}**: {t.get('message')}"
            for t in state.trace[-12:]
        ],
    ]


def _md_verification(state: PipelineState) -> list[str]:
    if not state.verification or (state.cve_input or {}).get("exploit_only"):
        return []
    v = state.verification
    return [
        "",
        "## Sandbox Verification",
        f"- Mode: {v.sandbox_mode} | executed: {v.executed}",
        f"- Vulnerable signal: {v.vulnerable_signal} | patched blocked: {v.patched_signal_blocked}",
        "- Evidence:",
        *[f"  - {e}" for e in v.evidence],
    ]


def _log_verification(state: PipelineState) -> list[str]:
    if not state.verification or (state.cve_input or {}).get("exploit_only"):
        return []
    v = state.verification
    lines = _log_banner("SANDBOX VERIFICATION", level=2)
    lines += [
        _log_field("Mode:", v.sandbox_mode),
        _log_field("Executed:", str(v.executed)),
        _log_field("Vuln signal:", str(v.vulnerable_signal)),
        _log_field("Patched blocked:", str(v.patched_signal_blocked)),
        "",
        "  Evidence:",
    ]
    for e in v.evidence:
        lines.append(f"    - {e}")
    lines.append("")
    return lines


def _md_verdict(state: PipelineState) -> list[str]:
    r = state.report
    if not r:
        return []
    return [
        "",
        "## Verdict (Judge)",
        f"- **{r.verdict.upper()}** — severity {r.severity}, confidence {r.confidence}",
        f"- Summary: {r.summary}",
        f"- Impact: {r.impact}",
        "- Remediation:",
        *[f"  - {x}" for x in r.remediation],
        "- False-positive checks:",
        *[f"  - {x}" for x in r.false_positive_checks],
    ]


def _log_verdict(state: PipelineState) -> list[str]:
    r = state.report
    if not r:
        return []
    lines = _log_banner("VERDICT (JUDGE)", level=2)
    lines += [
        _log_field("Verdict:", r.verdict.upper()),
        _log_field("Severity:", r.severity),
        _log_field("Confidence:", str(r.confidence)),
        "",
        "  Summary:",
        *_wrap(r.summary or "", indent=4),
        "",
        "  Impact:",
        *_wrap(r.impact or "", indent=4),
        "",
        "  Remediation:",
    ]
    for x in r.remediation:
        lines += _wrap(x, indent=4)
    lines += ["", "  False-positive checks:"]
    for x in r.false_positive_checks:
        lines += _wrap(x, indent=4)
    lines.append("")
    return lines
