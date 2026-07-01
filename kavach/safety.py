from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Patterns that indicate weaponized/offensive content. KAVACH is defensive
# only: if generated artifacts contain these, we redact and flag for review
# instead of executing or persisting them verbatim.
_WEAPONIZED_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"reverse\s*shell",
        r"bind\s*shell",
        r"/bin/(?:ba)?sh\s+-i",
        r"nc\s+-e\b",
        r"ncat\s+-e\b",
        r"bash\s+-i\s+>&",
        r"\bmsfvenom\b",
        r"\bmeterpreter\b",
        r"powershell\s+-enc\b",
        r"curl\s+[^\n]*\|\s*(?:ba)?sh",
        r"wget\s+[^\n]*\|\s*(?:ba)?sh",
        r"rm\s+-rf\s+/(?:\s|$)",
        r":\(\)\s*\{\s*:\|:&\s*\}\s*;",  # fork bomb
    )
]

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


@dataclass
class SafetyVerdict:
    allowed: bool
    findings: list[str] = field(default_factory=list)
    redacted_text: str = ""


def validate_cve_id(cve_id: str) -> bool:
    return bool(_CVE_RE.match((cve_id or "").strip()))


def scan_for_weaponized(text: str) -> list[str]:
    """Return the names of any weaponized patterns found in ``text``."""
    if not text:
        return []
    hits: list[str] = []
    for pat in _WEAPONIZED_PATTERNS:
        if pat.search(text):
            hits.append(pat.pattern)
    return hits


def redact(text: str) -> str:
    """Replace weaponized snippets with a neutral marker."""
    if not text:
        return text
    out = text
    for pat in _WEAPONIZED_PATTERNS:
        out = pat.sub("[REDACTED: offensive payload removed by safety guardrail]", out)
    return out


_LAB_HOSTNAMES = {"localhost", "ip6-localhost", "127.0.0.1", "::1", "0.0.0.0"}


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or ip.is_private


@dataclass
class TargetAuthorization:
    allowed: bool
    kind: str  # "lab" | "authorized_url" | "denied"
    reason: str = ""


def authorize_target(
    url: str,
    *,
    allowlist: list[str] | None = None,
    explicit_authorized: str = "",
) -> TargetAuthorization:
    """Decide whether an exploit may run against ``url``.

    Policy (defense-in-depth for authorized testing only):
      - loopback / RFC1918 / *.localhost  -> allowed as "lab".
      - host in operator allowlist, or matching the explicitly authorized target
        -> allowed as "authorized_url".
      - everything else -> denied. This intentionally prevents the tool from
        being pointed at arbitrary third-party infrastructure.
    """
    allowlist = [a.lower() for a in (allowlist or [])]
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = (parsed.hostname or "").lower()
    if not host:
        return TargetAuthorization(False, "denied", "could not parse target host")

    if host in _LAB_HOSTNAMES or host.endswith(".localhost") or _is_private_ip(host):
        return TargetAuthorization(True, "lab", "loopback/private lab target")

    # Resolve to catch hostnames that point at loopback/private ranges.
    try:
        resolved = socket.gethostbyname(host)
        if _is_private_ip(resolved):
            return TargetAuthorization(True, "lab", f"{host} resolves to private {resolved}")
    except OSError:
        pass

    explicit_host = ""
    if explicit_authorized:
        ep = urlparse(explicit_authorized if "://" in explicit_authorized else f"http://{explicit_authorized}")
        explicit_host = (ep.hostname or explicit_authorized).lower()

    if host in allowlist or (explicit_host and host == explicit_host):
        return TargetAuthorization(True, "authorized_url", "host explicitly authorized by operator")

    return TargetAuthorization(
        False,
        "denied",
        f"target '{host}' is not an authorized lab or allowlisted host",
    )


def enforce(text: str, *, context: str = "artifact") -> SafetyVerdict:
    """Guardrail gate for any generated artifact before it is stored/executed.

    Defensive posture: weaponized content is never blocked silently into a
    crash; it is redacted and the run is flagged so a human can review.
    """
    findings = scan_for_weaponized(text)
    if not findings:
        return SafetyVerdict(allowed=True, findings=[], redacted_text=text)
    return SafetyVerdict(
        allowed=False,
        findings=[f"{context}: matched '{f}'" for f in findings],
        redacted_text=redact(text),
    )
