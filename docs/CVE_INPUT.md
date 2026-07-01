# CVE / 0-day Exploit Input JSON

KAVACH can generate and verify exploits for **new CVEs and 0-days** when you
provide structured intelligence in JSON — no NVD entry or public PoC required.

## Quick start

```bash
# Minimal CVE JSON (description only) + your lab URL
python run.py --cve-json data/examples/lab_nextjs_cve_2025_29927_basic.json \
  --target http://127.0.0.1:3100/api/hello

# Full JSON with verification signals (bundled lab example)
cp data/examples/cve_exploit_input.template.json my_cve.json
python run.py --cve-json data/examples/lab_command_injection.json
```

## Minimal exploit-only JSON

For authorized targets you already run, JSON can be **CVE intelligence only** —
no `verification`, `authorization`, or `attack_surface` blocks required.

| Field | Required |
|-------|----------|
| `identification.id` | CVE id |
| `identification.disclosure_status` | `public` / `0day` / `embargoed` |
| `vulnerability.description` | What the bug is (20+ chars) |
| `vulnerability.vulnerability_class` | e.g. Authorization Bypass |

Pass the lab URL on the CLI: `--target http://host:port/path`

Defaults applied automatically:
- Exploit iterations from `KAVACH_EXPLOIT_MAX_ITERATIONS` in `.env` (not JSON)
- Success = HTTP 200; failure = 401/403/Unauthorized (unless you add `verification`)
- Verifier/sandbox skipped (exploit-only pipeline)

```bash
# .env
KAVACH_EXPLOIT_MAX_ITERATIONS=3
```

## What you must provide

### Exploit-only (minimal)

See **Minimal exploit-only JSON** above — four fields + `--target`.

### Full JSON (lab / planted flag)

| Section | Required fields | Why the LLM needs it |
|---------|-----------------|----------------------|
| `identification` | `id`, `disclosure_status` | Track 0-day (`KAVACH-ZDAY-001`) or CVE id |
| `vulnerability` | `description`, `root_cause`, `vulnerability_class`, `primitives[]` | Root-cause reasoning for payload crafting |
| `attack_surface` | `protocol`, `endpoints[]` with path, methods, controllable `parameters` | Where to send the exploit |
| `verification` | `flag`, `success_signals[]` | How to prove exploitation (planted secret) |
| `authorization` | `target_url`, `operator_confirms_authorized` | Safety gate — authorized targets only |

**Strongly recommended** for higher success rate:

- `source_artifacts.vulnerable_code_snippets` — actual sink code
- `source_artifacts.patch_diff` — what the fix changed
- `verification.flag.value` — planted lab secret to capture

Note: `exploit_hints.payload_suggestions` is **not** sent to the Exploiter LLM.
Payloads must come from the model. Exploit iteration count is controlled by
`KAVACH_EXPLOIT_MAX_ITERATIONS` in `.env` (default 3), not the CVE JSON.
- `verification.flag.value` — planted lab secret to capture

## ID formats

- Public CVE: `CVE-2021-44228`
- Internal 0-day: `KAVACH-ZDAY-001`, `ZDI-2026-042`

## Files

| File | Purpose |
|------|---------|
| `schemas/cve_exploit_input.schema.json` | JSON Schema (draft 2020-12) |
| `data/examples/cve_exploit_input.template.json` | Blank template to copy |
| `data/examples/lab_command_injection.json` | Working example (bundled lab) |
| `kavach/cve_input.py` | Loader, validator, LLM context builder |

## Pipeline flow with JSON

```
--cve-json  →  validate  →  pre-fill Collector/Researcher/Builder
                         →  Exploiter (LLM loop against target)
                         →  Verifier (sandbox)
                         →  Judge (exploited / confirmed / …)
```

## Authorization

- `authorization.lab_mode` + `serve_lab` + `lab_fixture: command_injection_ping` → auto-starts bundled lab
- `authorization.target_url` must be loopback/RFC1918 or allowlisted
- Set `operator_confirms_authorized: true` for non-loopback allowlisted hosts

## Scope — what it can and cannot exploit

Be realistic about what "any 0-day" means here. The Exploiter is an **HTTP/HTTPS
LLM loop**, so it covers web/API vulnerability classes and proves them with
signals or out-of-band callbacks:

| Supported (HTTP-class) | Not supported |
|------------------------|---------------|
| Command injection, SQLi, SSTI, path traversal | Memory corruption (heap/stack overflow, UAF) |
| SSRF (incl. blind, via callback) | Binary / local privilege escalation |
| Deserialization over HTTP | Non-HTTP protocols (raw TCP, SMB, custom) |
| Auth/JWT/IDOR, header injection | Hardware / firmware |
| Blind RCE / JNDI (via callback URL) | Anything needing a debugger/ROP chain |

It needs the attack surface, sink, and verification criteria you would give a
human exploit developer — it does not magically reverse unknown software.

## Detection signals (how success is proven)

The Exploiter now evaluates the `verification.success_signals` /
`failure_signals` you declare — not just a body marker:

| Signal type | Proves |
|-------------|--------|
| `response_body_contains` | reflected output / captured flag |
| `response_header_contains` | injected/echoed header |
| `http_status` | crash (500), injected success (200), etc. |
| `callback_received` | **blind** SSRF/RCE/JNDI via the OOB listener |
| `shell_output` / `file_contents_match` | command/file read echoed back |

`failure_signals` (e.g. status 400 from a WAF) short-circuit an attempt.

## Authenticated endpoints

Set per-endpoint auth and it is applied automatically (lab creds only):

```json
"auth_required": true,
"auth_type": "bearer",
"auth_credentials": { "token": "lab-token" }
```

Supported `auth_type`: `basic`, `bearer`, `cookie`, `custom`.

## Multi-step exploits (LLM-driven chains)

The Exploiter is fully LLM-driven and can run **multi-step chains** in one
attempt — e.g. log in, extract a CSRF token/session, then inject. The LLM
returns a `steps` array; cookies persist across steps automatically, and values
extracted from one response feed later steps via `{{var}}` placeholders:

```json
"steps": [
  {"method": "POST", "url": "/login", "body": "user=admin&pass=admin",
   "extract": [{"name": "csrf", "from": "body", "regex": "csrf=([a-f0-9]+)"}]},
  {"method": "POST", "url": "/api/run", "body": "csrf={{csrf}}&host=; printf \"KAVACHCAP[%s]KAVACHEND\" \"$KAVACH_FLAG\""}
]
```

`extract.from` supports `body` (with `regex`), `header` (`header` name + optional
`regex`), and `json` (`json_path` like `data.token`). You don't author this — the
LLM does, given a good CVE JSON. Single-request exploits still work unchanged.

## Out-of-band (blind) classes

Declare a callback and the tool starts a loopback listener, hands the URL to the
LLM, and confirms `callback_received`:

```json
"attack_surface": { "callback": { "required": true, "type": "http" } },
"verification": { "success_signals": [ { "type": "callback_received" } ] }
```

## Auto recipe (`--auto`)

You don't have to write this JSON by hand. `python run.py CVE-XXXX --auto` runs
the **research swarm** (LEAD → CONTRARIAN → VERIFIER, in `kavach/recipe.py`)
to synthesize a validated recipe from the collected CVE context, then feeds it to
the same Exploiter. With a live LLM the swarm authors it; offline a heuristic
recipe (by vulnerability class) is used so the run still completes. A
hand-written `--cve-json` always overrides auto generation.

## Roadmap (still open)

- Auto Docker build from `source_artifacts` + `affected_software` (so `--auto`
  needs no `--target`)
- LDAP/DNS callback protocols (currently HTTP OOB)
- True multi-model swarm (different models per role)
