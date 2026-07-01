"""Load and validate structured CVE / 0-day input for exploit generation.

Operators provide a JSON file (see schemas/cve_exploit_input.schema.json) with
everything the LLM Exploiter needs when NVD/PoCs do not exist.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .schemas import BuildArtifact, CVEContext, Primitive, ResearchMemo

SCHEMA_VERSION = "1.0"
_CVE_ID_RE = re.compile(r"^(CVE-\d{4}-\d{4,}|KAVACH-ZDAY-\d{3,}|ZDI-\d{4}-\d{3,})$", re.I)


class CVEInputValidationError(ValueError):
  def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("CVE input validation failed:\n" + "\n".join(f"  - {e}" for e in errors))


@dataclass
class CVEExploitInput:
    """Parsed operator JSON — source of truth for 0-day / new CVE exploitation."""

    raw: dict[str, Any]
    schema_version: str = SCHEMA_VERSION

    # identification
    id: str = ""
    aliases: list[str] = field(default_factory=list)
    title: str = ""
    disclosure_status: str = "public"
    severity: str = "UNKNOWN"
    cvss_score: float | None = None
    cvss_vector: str = ""
    cwe_ids: list[str] = field(default_factory=list)

    # vulnerability
    description: str = ""
    root_cause: str = ""
    vulnerability_class: str = ""
    attack_scenario: str = ""
    primitives: list[dict[str, Any]] = field(default_factory=list)

    # affected
    products: list[str] = field(default_factory=list)
    vulnerable_versions: list[str] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    repo_url: str = ""
    commit_vulnerable: str = ""
    commit_patched: str = ""

    # attack surface
    protocol: str = "http"
    base_urls: list[str] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    callback: dict[str, Any] = field(default_factory=dict)

    # source artifacts
    patch_diff: str = ""
    vulnerable_snippets: list[dict[str, Any]] = field(default_factory=list)
    patched_snippets: list[dict[str, Any]] = field(default_factory=list)
    stack_trace: str = ""
    crash_dump: str = ""

    # verification
    flag_format: str = ""
    flag_value: str = ""
    flag_location_type: str = ""
    flag_location_detail: str = ""
    capture_marker_prefix: str = "KAVACHCAP["
    capture_marker_suffix: str = "]KAVACHEND"
    success_signals: list[dict[str, Any]] = field(default_factory=list)
    failure_signals: list[dict[str, Any]] = field(default_factory=list)
    patched_verification_required: bool = True
    patched_expect_blocked: bool = True
    exploit_only: bool = False  # minimal JSON: no operator verification block; use --target

    # authorization
    target_url: str = ""
    operator_confirms_authorized: bool = False
    lab_mode: bool = False
    serve_lab: bool = False
    lab_fixture: str = ""

    # exploit hints
    preferred_techniques: list[str] = field(default_factory=list)
    payload_constraints: list[str] = field(default_factory=list)
    payload_suggestions: list[str] = field(default_factory=list)
    avoid: list[str] = field(default_factory=list)
    exploit_notes: str = ""

    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out = dict(self.raw)
        out["exploit_only"] = self.exploit_only
        return out

    def primary_endpoint(self) -> dict[str, Any] | None:
        return self.endpoints[0] if self.endpoints else None

    def controllable_parameters(self) -> list[dict[str, Any]]:
        params: list[dict[str, Any]] = []
        for ep in self.endpoints:
            for p in ep.get("parameters") or []:
                if p.get("controllable"):
                    params.append({**p, "endpoint_path": ep.get("path", "")})
        return params

    def build_llm_context_block(self) -> str:
        """Rich context for the Exploiter LLM prompt."""
        lines = [
            "=== STRUCTURED CVE / 0-DAY INPUT (operator-provided) ===",
            f"ID: {self.id} ({self.disclosure_status}) — {self.title}",
            f"Class: {self.vulnerability_class}",
            f"Root cause: {self.root_cause}",
            f"Attack scenario: {self.attack_scenario}",
            "",
            "Primitives:",
        ]
        for p in self.primitives:
            loc = p.get("location", "")
            sink = p.get("sink_type", "")
            lines.append(f"  - {p.get('name')}: {p.get('description')} [{sink} @ {loc}]")

        if self.exploit_only:
            lines.append("")
            lines.append(
                "Mode: exploit-only (no planted flag). Set success_marker to a substring "
                "you expect in the response when exploitation succeeds."
            )
        if self.endpoints:
            lines.append("")
            lines.append("Attack surface:")
            for ep in self.endpoints:
                methods = ",".join(ep.get("methods") or [])
                lines.append(f"  - {methods} {ep.get('path')}")
                for param in ep.get("parameters") or []:
                    if not param.get("controllable"):
                        continue
                    lines.append(
                        f"    * {param.get('name')} ({param.get('location')}): "
                        f"{param.get('description', '')}"
                    )
        else:
            lines.append("")
            lines.append(
                "Attack surface: use the authorized Target URL as the entry point "
                "(path/method from that URL)."
            )

        if self.vulnerable_snippets:
            lines.append("")
            lines.append("Vulnerable code:")
            for snip in self.vulnerable_snippets[:2]:
                lines.append(f"  --- {snip.get('file')} ---")
                lines.append(snip.get("content", "")[:800])

        if self.patch_diff:
            lines.append("")
            lines.append(f"Patch diff hint:\n{self.patch_diff[:600]}")

        if not self.exploit_only:
            lines.append("")
            lines.append(f"Flag: format={self.flag_format} location={self.flag_location_type}")
            lines.append(f"Flag location detail: {self.flag_location_detail}")
            lines.append(f"Capture marker: {self.capture_marker_prefix}...{self.capture_marker_suffix}")

        if self.exploit_notes:
            lines.append(f"Operator notes: {self.exploit_notes[:400]}")

        if self.callback.get("required"):
            lines.append(
                f"Callback required: type={self.callback.get('type')} "
                f"host={self.callback.get('listener_host')} port={self.callback.get('listener_port')}"
            )

        return "\n".join(lines)


def load_cve_input(path: str | Path) -> CVEExploitInput:
    """Load JSON from disk and validate required fields."""
    p = Path(path)
    if not p.is_file():
        raise CVEInputValidationError([f"file not found: {p}"])
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise CVEInputValidationError([f"invalid JSON: {exc}"]) from exc
    return parse_cve_input(data)


def _apply_defaults(data: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Fill optional sections for minimal exploit-only CVE JSON."""
    d = dict(data)
    exploit_only = "verification" not in d

    vuln = dict(d.get("vulnerability") or {})
    desc = str(vuln.get("description") or "")
    if len(desc) < 20:
        vuln["description"] = desc or "Vulnerability details not provided."
    if len(str(vuln.get("root_cause") or "")) < 10:
        vuln["root_cause"] = str(vuln.get("root_cause") or desc[:120] or "Unknown root cause")
    if not vuln.get("vulnerability_class"):
        vuln["vulnerability_class"] = "Unknown"
    if not vuln.get("primitives"):
        vuln["primitives"] = [
            {
                "name": "attack_vector",
                "description": desc or "See vulnerability description",
                "location": "HTTP",
                "sink_type": "unknown",
            }
        ]
    d["vulnerability"] = vuln

    if "attack_surface" not in d:
        d["attack_surface"] = {"protocol": "http", "endpoints": []}

    if exploit_only:
        d["verification"] = {
            "flag": {
                "format": "auto",
                "location_type": "http_response",
                "location_detail": "LLM success_marker or web-intel body match",
            },
            "success_signals": [],
            "failure_signals": [
                {"type": "http_status", "code": 401},
                {"type": "http_status", "code": 403},
                {"type": "response_body_contains", "pattern": "Unauthorized"},
                {"type": "response_body_contains", "pattern": "Forbidden"},
            ],
            "patched_verification": {"required": False},
        }

    return d, exploit_only


def parse_cve_input(data: dict[str, Any]) -> CVEExploitInput:
    data, exploit_only = _apply_defaults(data)
    errors = _validate(data)
    if errors:
        raise CVEInputValidationError(errors)

    ident = data["identification"]
    vuln = data["vulnerability"]
    surface = data["attack_surface"]
    verify = data["verification"]
    flag = verify["flag"]
    affected = data.get("affected_software") or {}
    auth = data.get("authorization") or {}
    hints = data.get("exploit_hints") or {}
    artifacts = data.get("source_artifacts") or {}
    marker = flag.get("capture_marker") or {}

    return CVEExploitInput(
        raw=data,
        schema_version=data["schema_version"],
        id=ident["id"].upper(),
        aliases=list(ident.get("aliases") or []),
        title=str(ident.get("title") or ""),
        disclosure_status=ident["disclosure_status"],
        severity=str(ident.get("severity") or "UNKNOWN"),
        cvss_score=ident.get("cvss_score"),
        cvss_vector=str(ident.get("cvss_vector") or ""),
        cwe_ids=list(ident.get("cwe_ids") or []),
        description=vuln["description"],
        root_cause=vuln["root_cause"],
        vulnerability_class=vuln["vulnerability_class"],
        attack_scenario=str(vuln.get("attack_scenario") or ""),
        primitives=list(vuln.get("primitives") or []),
        products=list(affected.get("products") or []),
        vulnerable_versions=list(affected.get("vulnerable_versions") or []),
        fixed_versions=list(affected.get("fixed_versions") or []),
        repo_url=str(affected.get("repo_url") or ""),
        commit_vulnerable=str(affected.get("commit_vulnerable") or ""),
        commit_patched=str(affected.get("commit_patched") or ""),
        protocol=surface["protocol"],
        base_urls=list(surface.get("base_urls") or []),
        endpoints=list(surface.get("endpoints") or []),
        callback=dict(surface.get("callback") or {}),
        patch_diff=str(artifacts.get("patch_diff") or ""),
        vulnerable_snippets=list(artifacts.get("vulnerable_code_snippets") or []),
        patched_snippets=list(artifacts.get("patched_code_snippets") or []),
        stack_trace=str(artifacts.get("stack_trace") or ""),
        crash_dump=str(artifacts.get("crash_dump") or ""),
        flag_format=str(flag.get("format") or ""),
        flag_value=str(flag.get("value") or ""),
        flag_location_type=flag["location_type"],
        flag_location_detail=str(flag.get("location_detail") or ""),
        capture_marker_prefix=str(marker.get("prefix") or "KAVACHCAP["),
        capture_marker_suffix=str(marker.get("suffix") or "]KAVACHEND"),
        success_signals=list(verify.get("success_signals") or []),
        failure_signals=list(verify.get("failure_signals") or []),
        patched_verification_required=bool(
            (verify.get("patched_verification") or {}).get("required", True)
        ),
        patched_expect_blocked=bool(
            (verify.get("patched_verification") or {}).get("expect_blocked", True)
        ),
        target_url=str(auth.get("target_url") or ""),
        operator_confirms_authorized=bool(auth.get("operator_confirms_authorized")),
        lab_mode=bool(auth.get("lab_mode")),
        serve_lab=bool(auth.get("serve_lab")),
        lab_fixture=str(auth.get("lab_fixture") or ""),
        preferred_techniques=list(hints.get("preferred_techniques") or []),
        payload_constraints=list(hints.get("payload_constraints") or []),
        payload_suggestions=list(hints.get("payload_suggestions") or []),
        avoid=list(hints.get("avoid") or []),
        exploit_notes=str(hints.get("notes") or ""),
        references=list(data.get("references") or []),
        metadata=dict(data.get("metadata") or {}),
        exploit_only=exploit_only,
    )


def apply_cve_input_to_state(cve_input: CVEExploitInput) -> tuple[CVEContext, ResearchMemo, BuildArtifact]:
    """Convert operator JSON into agent dataclasses (skips Collector/Researcher/Builder LLM)."""
    primitives = [
        Primitive(
            name=str(p.get("name", "primitive")),
            description=str(p.get("description", "")),
            location=str(p.get("location", "")),
        )
        for p in cve_input.primitives
    ]

    ctx = CVEContext(
        cve_id=cve_input.id,
        description=cve_input.description,
        severity=cve_input.severity,
        cvss_score=cve_input.cvss_score,
        cvss_vector=cve_input.cvss_vector,
        cwe_ids=list(cve_input.cwe_ids),
        affected_products=list(cve_input.products),
        affected_versions=list(cve_input.vulnerable_versions),
        references=list(cve_input.references),
        repo_url=cve_input.repo_url,
        patch_diff=cve_input.patch_diff,
        source="cve_json",
    )

    memo = ResearchMemo(
        summary=cve_input.title or cve_input.description[:200],
        root_cause=cve_input.root_cause,
        vulnerability_class=cve_input.vulnerability_class,
        affected_modules=list(cve_input.products),
        primitives=primitives,
        attack_scenario=cve_input.attack_scenario,
        detection_ideas=[],
        confidence=0.85 if cve_input.disclosure_status == "0day" else 0.8,
    )

    flag = ""
    auth = (cve_input.raw.get("authorization") or {}) if isinstance(cve_input.raw, dict) else {}
    if auth.get("lab_mode") or auth.get("serve_lab"):
        flag = cve_input.flag_value or ""
    artifact = BuildArtifact(
        dockerfile="",
        compose="",
        harness_files={},
        benign_test_markers=[cve_input.capture_marker_prefix],
        flag=flag,
        notes=f"Built from CVE JSON input ({cve_input.disclosure_status})",
    )

    return ctx, memo, artifact


def _validate(data: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    if not isinstance(data, dict):
        return ["root must be a JSON object"]

    if data.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be '{SCHEMA_VERSION}'")

    ident = data.get("identification")
    if not isinstance(ident, dict):
        errors.append("identification object is required")
    else:
        vid = str(ident.get("id") or "").strip()
        if not vid:
            errors.append("identification.id is required")
        elif not _CVE_ID_RE.match(vid):
            errors.append(
                f"identification.id '{vid}' must match CVE-YYYY-NNNN, KAVACH-ZDAY-NNN, or ZDI-YYYY-NNN"
            )
        status = ident.get("disclosure_status")
        if status not in ("0day", "embargoed", "public"):
            errors.append("identification.disclosure_status must be 0day|embargoed|public")

    vuln = data.get("vulnerability")
    if not isinstance(vuln, dict):
        errors.append("vulnerability object is required")
    else:
        if len(str(vuln.get("description") or "")) < 20:
            errors.append("vulnerability.description must be at least 20 characters")
        if len(str(vuln.get("root_cause") or "")) < 10:
            errors.append("vulnerability.root_cause must be at least 10 characters")
        if not vuln.get("vulnerability_class"):
            errors.append("vulnerability.vulnerability_class is required")
        prims = vuln.get("primitives")
        if not isinstance(prims, list) or len(prims) < 1:
            errors.append("vulnerability.primitives must be a non-empty array")

    surface = data.get("attack_surface")
    if not isinstance(surface, dict):
        errors.append("attack_surface object is required")
    elif surface.get("protocol"):
        eps = surface.get("endpoints")
        if eps is not None:
            if not isinstance(eps, list):
                errors.append("attack_surface.endpoints must be an array")
            else:
                for i, ep in enumerate(eps):
                    path = str(ep.get("path") or "")
                    if path and not path.startswith("/"):
                        errors.append(f"attack_surface.endpoints[{i}].path must start with /")
                    if ep.get("methods") is not None and not ep.get("methods"):
                        errors.append(f"attack_surface.endpoints[{i}].methods is required")

    verify = data.get("verification")
    if verify is not None and not isinstance(verify, dict):
        errors.append("verification must be an object when provided")
    elif isinstance(verify, dict):
        flag = verify.get("flag")
        if flag is not None:
            if not isinstance(flag, dict):
                errors.append("verification.flag object is required")
            else:
                if flag.get("format") is None and flag.get("location_type"):
                    pass
                elif flag.get("location_type"):
                    loc = flag.get("location_type")
                    valid_loc = (
                        "environment_variable",
                        "file",
                        "database",
                        "http_response",
                        "rce_output",
                        "callback_proof",
                    )
                    if loc not in valid_loc:
                        errors.append(f"verification.flag.location_type must be one of {valid_loc}")
        signals = verify.get("success_signals")
        if signals is not None and not isinstance(signals, list):
            errors.append("verification.success_signals must be an array when provided")

    auth = data.get("authorization") or {}
    if auth.get("serve_lab") or auth.get("lab_mode"):
        fixture = auth.get("lab_fixture") or "command_injection_ping"
        if fixture not in ("command_injection_ping", "custom"):
            errors.append("authorization.lab_fixture must be command_injection_ping or custom")

    return errors
