"""One Google search + LLM extraction → exploitation intel (no hardcoded CVE paths)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from ..logging_utils import log_activity
from ..prompts import load_prompt
from ..schemas import PipelineState
from .google import GoogleSearchClient, OrganicResult

_PATH_RE = re.compile(
    r"""(?:GET|POST|PUT|DELETE|curl|route|endpoint|path)\s+[`'"]?(/[a-zA-Z0-9_./%-]+)""",
    re.I,
)
_SLASH_PATH_RE = re.compile(r"""(?<![a-zA-Z0-9])(/api[a-zA-Z0-9_./-]*)""")
_PHP_PATH_RE = re.compile(
    r"""(?<![a-zA-Z0-9])(/(?:[a-zA-Z0-9_./%-]+/)?[a-zA-Z0-9_-]+\.php(?:\?[a-zA-Z0-9_=&%.-]+)?)""",
    re.I,
)
_PLUGIN_PATH_RE = re.compile(
    r"""(?<![a-zA-Z0-9])(/wp-content/plugins/[a-zA-Z0-9_./%-]+)""",
    re.I,
)
_HEADER_RE = re.compile(
    r"""(x-[a-z0-9-]+)\s*[:=]\s*[`'"]?([^`'";\s]+)""",
    re.I,
)


@dataclass
class WebIntel:
    """Structured exploitation hints mined from one Google search."""

    query: str = ""
    summary: str = ""
    vulnerability_class: str = ""
    probe_paths: list[str] = field(default_factory=list)
    request_headers: list[dict[str, str]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    success_markers: list[str] = field(default_factory=list)
    reference_urls: list[str] = field(default_factory=list)
    snippets: list[str] = field(default_factory=list)

    def format_block(self) -> str:
        lines = ["=== WEB INTEL (public search snippets — interpret yourself) ==="]
        if self.summary:
            lines.append(f"Summary: {self.summary}")
        if self.reference_urls:
            lines.append("Sources:")
            for u in self.reference_urls[:8]:
                lines.append(f"  - {u}")
        if self.snippets:
            lines.append("")
            lines.append("Raw snippets:")
            for snip in self.snippets[:10]:
                lines.append(f"  - {snip[:500]}")
        lines.append(
            "You must derive paths, parameters, techniques, and payloads from the above "
            "plus recon and prior attempts — the framework does not pre-build exploit URLs."
        )
        return "\n".join(lines)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebIntel:
        return cls(
            query=str(data.get("query") or ""),
            summary=str(data.get("summary") or ""),
            vulnerability_class=str(data.get("vulnerability_class") or ""),
            probe_paths=[str(p) for p in (data.get("probe_paths") or []) if p],
            request_headers=[
                {str(k): str(v) for k, v in h.items()}
                for h in (data.get("request_headers") or [])
                if isinstance(h, dict)
            ],
            techniques=[str(t) for t in (data.get("techniques") or []) if t],
            success_markers=[str(m) for m in (data.get("success_markers") or []) if m],
            reference_urls=[str(u) for u in (data.get("reference_urls") or []) if u],
            snippets=[str(s) for s in (data.get("snippets") or []) if s],
        )


def _heuristic_extract(
    organic: list[OrganicResult],
    *,
    query: str,
) -> WebIntel:
    snippets = [f"{r.title} {r.snippet}" for r in organic if r.snippet or r.title]
    blob = "\n".join(snippets)
    paths: set[str] = set()
    for rx in (_PATH_RE, _SLASH_PATH_RE, _PHP_PATH_RE, _PLUGIN_PATH_RE):
        for m in rx.finditer(blob):
            p = m.group(1).split("?")[0].split("#")[0]
            if p and len(p) < 120:
                paths.add(p if p.startswith("/") else f"/{p}")

    headers: list[dict[str, str]] = []
    seen_hdr: set[str] = set()
    for m in _HEADER_RE.finditer(blob):
        name, value = m.group(1), m.group(2)
        key = name.lower()
        if key in seen_hdr:
            continue
        seen_hdr.add(key)
        headers.append({"name": name, "value": value, "note": "from search snippet"})

    markers: list[str] = []
    for m in re.finditer(r"""["']([A-Za-z][A-Za-z0-9_ ]{2,30})["']""", blob):
        tok = m.group(1)
        if tok.lower() not in ("error", "unauthorized", "forbidden", "next"):
            markers.append(tok)

    return WebIntel(
        query=query,
        summary=organic[0].snippet[:400] if organic else "",
        probe_paths=sorted(paths),
        request_headers=headers,
        reference_urls=[r.link for r in organic if r.link],
        snippets=snippets[:12],
        success_markers=markers[:5],
    )


def _llm_extract(
    llm: Any,
    organic: list[OrganicResult],
    *,
    query: str,
    cve_id: str,
    mock: bool,
) -> WebIntel:
    if mock or not organic:
        return _heuristic_extract(organic, query=query)

    lines = []
    for i, r in enumerate(organic[:10], 1):
        lines.append(f"{i}. {r.title}\n   {r.link}\n   {r.snippet}")
    user = (
        f"CVE: {cve_id}\nGoogle query: {query}\n\nSearch results:\n"
        + "\n".join(lines)
    )
    system = load_prompt("web_intel_extractor")
    raw = llm.complete(system, user)
    text = raw.strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if m:
            text = m.group(1)
    start = text.find("{")
    if start < 0:
        return _heuristic_extract(organic, query=query)
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
    except json.JSONDecodeError:
        return _heuristic_extract(organic, query=query)

    intel = WebIntel.from_dict(data)
    intel.query = query
    intel.reference_urls = intel.reference_urls or [r.link for r in organic if r.link]
    intel.snippets = [f"{r.title} {r.snippet}" for r in organic[:10]]
    fallback = _heuristic_extract(organic, query=query)
    if not intel.probe_paths:
        intel.probe_paths = fallback.probe_paths
    if not intel.request_headers:
        intel.request_headers = fallback.request_headers
    if not intel.success_markers:
        intel.success_markers = fallback.success_markers
    return intel


def gather_web_intel(
    cve_id: str,
    description: str,
    llm: Any,
    config: dict[str, Any],
) -> WebIntel | None:
    """Run exactly one Google search and extract paths/headers/techniques."""
    api_key = config.get("serpapi_api_key") or ""
    if not api_key:
        return None

    # Bundled training CVE ids are not on Google; skip to avoid wrong cross-CVE intel.
    if cve_id.upper().startswith("CVE-2099-") or cve_id.upper().startswith("KAVACH-ZDAY-"):
        return None

    client = GoogleSearchClient(api_key=api_key)
    query = f"{cve_id} exploit PoC vulnerability curl"
    log_activity(config, "search", "SerpAPI query", query=query)
    t0 = time.monotonic()
    results = client.search(query, num=10)
    organic = results.organic_results
    log_activity(
        config,
        "search",
        "SerpAPI results",
        count=len(organic),
        duration_s=round(time.monotonic() - t0, 2),
    )
    mock = config.get("llm_mode", "mock") == "mock"
    return _llm_extract(llm, organic, query=query, cve_id=cve_id, mock=mock)


def enrich_state_from_web_search(
    state: PipelineState,
    llm: Any,
    config: dict[str, Any],
) -> WebIntel | None:
    """Attach web intel to pipeline state and enrich thin CVE/research context."""
    cve_id = state.cve_id.strip().upper()
    if not cve_id:
        return None

    desc = ""
    if state.cve_context:
        desc = state.cve_context.description or ""

    intel = gather_web_intel(cve_id, desc, llm, config)
    if intel is None:
        return None

    state.web_intel = asdict(intel)
    state.log(
        "web_intel",
        "google search complete",
        paths=len(intel.probe_paths),
        headers=len(intel.request_headers),
        sources=len(intel.reference_urls),
    )

    if state.cve_context:
        if intel.summary and len(state.cve_context.description) < 80:
            state.cve_context.description = intel.summary
        for url in intel.reference_urls:
            if url not in state.cve_context.references:
                state.cve_context.references.append(url)

    if state.research_memo:
        if intel.summary and not state.research_memo.attack_scenario:
            state.research_memo.attack_scenario = intel.summary
        if intel.vulnerability_class and state.research_memo.vulnerability_class in ("", "Unknown"):
            state.research_memo.vulnerability_class = intel.vulnerability_class
        if intel.techniques:
            state.research_memo.detection_ideas.extend(intel.techniques[:5])

    # CVE-number-only runs: materialize hints so the exploiter can parse signals.
    if not state.cve_input:
        from ..cve_input import CVEInputValidationError, _apply_defaults, parse_cve_input

        stub, _ = _apply_defaults(
            {
                "schema_version": "1.0",
                "identification": {"id": cve_id, "disclosure_status": "public"},
                "vulnerability": {
                    "description": (state.cve_context.description or intel.summary or "")[:500],
                    "vulnerability_class": (
                        state.research_memo.vulnerability_class
                        if state.research_memo
                        else intel.vulnerability_class or "Unknown"
                    ),
                },
                "attack_surface": {"protocol": "http", "endpoints": []},
            }
        )
        try:
            spec = parse_cve_input(stub)
            state.cve_input = spec.to_dict()
        except CVEInputValidationError:
            state.cve_input = stub

    if state.cve_input and isinstance(state.cve_input, dict):
        hints = state.cve_input.setdefault("exploit_hints", {})
        if intel.summary:
            hints["notes"] = (
                (hints.get("notes") or "") + "\nWeb intel: " + intel.summary
            ).strip()

    return intel
