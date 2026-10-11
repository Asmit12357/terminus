# Recorded fixtures (demo mode and tests)

These files are real API responses recorded with `scripts/record_fixtures.py` at the
time in `manifest.json` (`captured_at`). Demo mode serves them through the same parsing
code as live mode, and every record keeps that capture time as its `retrieved_at`.

| Path | Source | Notes |
|---|---|---|
| `nvd/CVE-*.json` | NVD CVE API 2.0 (`?cveId=`) | full responses |
| `kev.json` | CISA KEV catalog | subset limited to the demo CVE set |
| `epss.json` | FIRST EPSS API | scores as of capture date (they change daily) |
| `osv/*.json` | OSV.dev `/v1/query` | advisories with CVE aliases for 3 packages |
| `vendor/*.html` | vendor advisory pages | short text excerpts around CVE mentions only |
| `search/results.json` | **synthetic** | clearly labelled demo search results, including two adversarial prompt-injection samples used to demonstrate defences |

Values drift from live data over time. Re-record with:

```bash
uv run python scripts/record_fixtures.py
```

This product uses the NVD API but is not endorsed or certified by the NVD.
