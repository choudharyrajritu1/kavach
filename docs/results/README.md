# Validated run results

Real KAVACH offensive runs against **authorized** targets. Each entry includes
the exact command, verdict, proof snippet, and a sanitized log excerpt so you
know what to expect after you run the tool yourself.

| CVE | Verdict | Target type | Log |
|-----|---------|-------------|-----|
| [CVE-2025-29927](CVE-2025-29927.md) | **EXPLOITED** | Local Next.js lab | [log](logs/CVE-2025-29927-success.log) |
| [CVE-2021-42013](CVE-2021-42013.md) | **EXPLOITED** | Authorized XBOW lab | [log](logs/CVE-2021-42013-success.log) |

More CVEs tested (commands in [EXAMPLE_RUNS.md](../EXAMPLE_RUNS.md)):

- CVE-2023-6553 — WordPress Backup Migration RCE
- CVE-2021-41773 — Apache path traversal
- CVE-2023-3452 — LiteSpeed Cache auth bypass

---

## What a successful run looks like

1. **Auto recipe** — research swarm builds exploit JSON from the CVE (~2–3 min live LLM)
2. **SerpAPI web intel** — Google search for public PoC hints (when `SERPAPI_API_KEY` is set)
3. **Exploiter loop** — recon → LLM plan → HTTP attempts → adaptive refinement
4. **Judge verdict** — `EXPLOITED` only when observable proof exists (not plugin discovery)

Typical terminal output ends with:

```
## Verdict (Judge)
- **EXPLOITED** — severity CRITICAL, confidence 0.95
```

Full per-run logs are also written to `data/runs/` on your machine (gitignored).
