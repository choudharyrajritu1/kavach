# Example run commands

Copy-paste commands for CVEs validated with KAVACH. See
[`results/`](results/) for success logs and proof snippets.

---

## CVE-2025-29927 — Next.js middleware bypass

**Lab setup:**

```bash
cd kavach/lab/vulnerable-nextjs-14-CVE-2025-29927
npm run dev -- -p 3300
```

**Run KAVACH:**

```bash
python run.py CVE-2025-29927 --auto \
  --target http://127.0.0.1:3300/ \
  --authorized-target

python run.py --cve-json data/examples/lab_nextjs_cve_2025_29927_basic.json \
  --target http://127.0.0.1:3300/
```

**Result:** [EXPLOITED](results/CVE-2025-29927.md)

---

## CVE-2021-42013 — Apache 2.4.50 bypass

```bash
python run.py CVE-2021-42013 --auto \
  --target http://xbow.citymutual.co.in:10260/ \
  --authorized-target

python run.py \
  --cve-json data/examples/lab_cve_2021_42013_xben026_basic.json \
  --target http://xbow.citymutual.co.in:10260/ \
  --authorized-target
```

**Result:** [EXPLOITED](results/CVE-2021-42013.md)

---

## CVE-2023-6553 — WordPress Backup Migration

```bash
python run.py CVE-2023-6553 --auto \
  --target http://xbow.citymutual.co.in:10300/ \
  --authorized-target

python run.py --cve-json data/examples/lab_cve_2023_6553_xben030_basic.json \
  --target http://xbow.citymutual.co.in:10300/ \
  --authorized-target
```

---

## CVE-2021-41773 — Apache path traversal

```bash
python run.py CVE-2021-41773 --auto \
  --target http://xbow.citymutual.co.in:10310/ \
  --authorized-target
```

---

## CVE-2023-3452 — LiteSpeed Cache

```bash
python run.py CVE-2023-3452 --auto \
  --target http://xbow.citymutual.co.in:10340/ \
  --authorized-target
```

---

## Tips

- Set `KAVACH_LLM_MODE=live` and your LLM provider key in `.env`
- Set `SERPAPI_API_KEY` for web intel enrichment before exploitation
- Use `--save report.md` to write the markdown report to disk
- Per-run flat logs land in `data/runs/` (local only, gitignored)
