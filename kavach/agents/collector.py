from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from ..safety import validate_cve_id
from ..schemas import CVEContext, PipelineState, Stage
from .base import BaseAgent

# Offline sample data so the pipeline can demo without network access.
# These are public, historical CVEs used purely for defensive analysis demos.
_OFFLINE_CVES: dict[str, dict[str, Any]] = {
    "CVE-2021-44228": {
        "description": (
            "Apache Log4j2 JNDI features used in configuration, log messages, and "
            "parameters do not protect against attacker-controlled LDAP and other "
            "JNDI related endpoints. An attacker who can control log messages or "
            "log message parameters can execute arbitrary code (Log4Shell)."
        ),
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cwe_ids": ["CWE-502", "CWE-917"],
        "affected_products": ["Apache Log4j2"],
        "affected_versions": ["2.0-beta9 through 2.14.1"],
        "references": [
            "https://logging.apache.org/log4j/2.x/security.html",
            "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        ],
        "repo_url": "https://github.com/apache/logging-log4j2",
        "patch_diff": "",
    },
    "CVE-2099-00001": {
        "description": (
            "KAVACH built-in training lab: a demo HTTP service exposes "
            "GET /api/ping?host=<value> and concatenates the 'host' query "
            "parameter into a shell command (echo pinging <host>) executed "
            "with shell=True, enabling OS command injection. Used to validate "
            "the end-to-end exploit + flag-capture loop locally."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "cwe_ids": ["CWE-78"],
        "affected_products": ["KAVACH Demo Lab"],
        "affected_versions": ["all"],
        "references": ["local://kavach/lab/vulnerable_app.py"],
        "repo_url": "",
        "patch_diff": (
            "- cmd = f'echo pinging {host}'  # shell=True\n"
            "+ if not all(c.isalnum() or c in '.-' for c in host): abort(400)\n"
        ),
    },
    "CVE-2014-0160": {
        "description": (
            "The TLS heartbeat extension in OpenSSL 1.0.1 before 1.0.1g does not "
            "properly handle Heartbeat Extension packets, allowing remote attackers "
            "to read process memory via crafted packets that trigger a buffer "
            "over-read (Heartbleed)."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "cwe_ids": ["CWE-125"],
        "affected_products": ["OpenSSL"],
        "affected_versions": ["1.0.1 through 1.0.1f"],
        "references": [
            "https://www.openssl.org/news/secadv/20140407.txt",
            "https://nvd.nist.gov/vuln/detail/CVE-2014-0160",
        ],
        "repo_url": "https://github.com/openssl/openssl",
        "patch_diff": "",
    },
}


class CollectorAgent(BaseAgent):
    """Gathers public, factual context about a CVE."""

    name = "collector"
    prompt_name = "collector"

    def run(self, state: PipelineState) -> PipelineState:
        state.stage = Stage.COLLECT.value
        if state.cve_context is not None and state.cve_context.source == "cve_json":
            state.log(self.name, "skipped (CVE JSON input already loaded")
            return state

        cve_id = state.cve_id.strip().upper()

        if not validate_cve_id(cve_id):
            state.errors.append(f"Invalid CVE id format: {state.cve_id!r}")
            state.log(self.name, "rejected invalid CVE id")
            return state

        context = self._collect(cve_id)
        if state.repo_url and not context.repo_url:
            context.repo_url = state.repo_url

        state.cve_context = context
        state.log(
            self.name,
            "collected CVE context",
            source=context.source,
            severity=context.severity,
        )
        return state

    def _collect(self, cve_id: str) -> CVEContext:
        if not self.config.get("offline"):
            fetched = self._fetch_nvd(cve_id)
            if fetched is not None:
                return fetched

        sample = _OFFLINE_CVES.get(cve_id)
        if sample is not None:
            return CVEContext(cve_id=cve_id, source="offline-sample", **sample)

        return CVEContext(
            cve_id=cve_id,
            description="No offline data; enable KAVACH_OFFLINE=false to fetch from NVD.",
            source="unknown",
        )

    def _fetch_nvd(self, cve_id: str) -> CVEContext | None:
        base = self.config.get("nvd_api_base", "")
        if not base:
            return None
        url = f"{base}?cveId={cve_id}"
        headers = {"User-Agent": "kavach/0.1"}
        if self.config.get("nvd_api_key"):
            headers["apiKey"] = self.config["nvd_api_key"]
        try:
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return self._parse_nvd(cve_id, payload)
        except (urllib.error.URLError, KeyError, json.JSONDecodeError, TimeoutError):
            return None

    @staticmethod
    def _parse_nvd(cve_id: str, payload: dict[str, Any]) -> CVEContext | None:
        vulns = payload.get("vulnerabilities") or []
        if not vulns:
            return None
        cve = vulns[0].get("cve", {})

        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        severity, score, vector = "UNKNOWN", None, ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if entries:
                data = entries[0].get("cvssData", {})
                severity = (data.get("baseSeverity") or entries[0].get("baseSeverity") or "UNKNOWN").upper()
                score = data.get("baseScore")
                vector = data.get("vectorString", "")
                break

        cwes: list[str] = []
        for w in cve.get("weaknesses", []):
            for desc in w.get("description", []):
                val = desc.get("value", "")
                if val.startswith("CWE-"):
                    cwes.append(val)

        references = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]

        return CVEContext(
            cve_id=cve_id,
            description=description,
            severity=severity,
            cvss_score=score,
            cvss_vector=vector,
            cwe_ids=sorted(set(cwes)),
            references=references,
            source="nvd",
        )
