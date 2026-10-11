"""Re-record the demo fixtures in data/fixtures from the live public APIs.

    uv run python scripts/record_fixtures.py

Fetches NVD records, the CISA KEV catalog (stored as a subset), EPSS scores
and OSV package advisories for the demo CVE set, and short text excerpts of a
few vendor advisory pages (only the text around each CVE mention is kept).
Nothing here is invented: every value comes from the API response captured at
``manifest.json:captured_at``.
"""

from __future__ import annotations

import html
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import Settings  # noqa: E402
from app.connectors.http import HttpClient, SourceUnavailable  # noqa: E402
from app.connectors.nvd import parse_response  # noqa: E402
from app.connectors.vendor import VendorAdvisoryFetcher  # noqa: E402
from app.models import utcnow  # noqa: E402
from app.storage.repository import Repository  # noqa: E402

OUT = ROOT / "data" / "fixtures"

DEMO_CVES = [
    "CVE-2021-44228",  # Apache Log4j2 (Log4Shell)
    "CVE-2021-41773",  # Apache HTTP Server 2.4.49 path traversal
    "CVE-2021-42013",  # Apache HTTP Server 2.4.49/2.4.50
    "CVE-2022-3602",  # OpenSSL 3.0.x X.509 punycode overflow
    "CVE-2014-0160",  # OpenSSL Heartbleed
    "CVE-2023-38545",  # curl SOCKS5 heap overflow
    "CVE-2023-32681",  # Python requests Proxy-Authorization leak
    "CVE-2021-23337",  # lodash template command injection
    "CVE-2024-6387",  # OpenSSH regreSSHion
    "CVE-2021-23017",  # nginx resolver off-by-one
]

OSV_PACKAGES = [
    ("PyPI", "requests"),
    ("npm", "lodash"),
    ("Maven", "org.apache.logging.log4j:log4j-core"),
]

VENDOR_PAGES = [
    "https://curl.se/docs/CVE-2023-38545.html",
    "https://logging.apache.org/log4j/2.x/security.html",
    "https://httpd.apache.org/security/vulnerabilities_24.html",
]

EXCERPT_RADIUS = 300


def main() -> int:
    settings = Settings(mode="live")
    with tempfile.TemporaryDirectory() as tmp:
        repo = Repository(Path(tmp) / "record.db")
        http = HttpClient(settings, repo)
        http.set_rate_limit("services.nvd.nist.gov", 6.5)
        (OUT / "nvd").mkdir(parents=True, exist_ok=True)
        (OUT / "osv").mkdir(parents=True, exist_ok=True)
        (OUT / "vendor").mkdir(parents=True, exist_ok=True)

        # OSV first: its CVE aliases extend the NVD list.
        cves = list(DEMO_CVES)
        for eco, name in OSV_PACKAGES:
            res = http.request(
                "POST",
                f"{settings.osv_base_url}/query",
                source="osv",
                json_body={"package": {"name": name, "ecosystem": eco}},
            )
            payload = res.json()
            vulns = [
                v
                for v in payload.get("vulns", [])
                if any(a.startswith("CVE-") for a in v.get("aliases", []))
            ]
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", name)
            (OUT / "osv" / f"{eco}__{safe}.json").write_text(
                json.dumps({"vulns": vulns}, indent=1), encoding="utf-8"
            )
            for v in vulns:
                cves += [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            print(f"OSV {eco}/{name}: {len(vulns)} advisories")

        cves = list(dict.fromkeys(cves))
        for cve_id in cves:
            try:
                res = http.request(
                    "GET",
                    settings.nvd_base_url,
                    source="nvd",
                    params={"cveId": cve_id},
                    retry_statuses=frozenset({403, 429, 500, 502, 503, 504}),
                )
            except SourceUnavailable as exc:
                print(f"NVD {cve_id}: FAILED {exc.detail}")
                continue
            payload = res.json()
            records, _, errors = parse_response(payload, res.fetched_at)
            if not records:
                print(f"NVD {cve_id}: no record ({errors})")
                continue
            (OUT / "nvd" / f"{cve_id}.json").write_text(
                json.dumps(payload, indent=1), encoding="utf-8"
            )
            print(f"NVD {cve_id}: ok ({records[0].vuln_status})")

        res = http.request("GET", settings.kev_url, source="kev")
        kev = res.json()
        subset = [v for v in kev["vulnerabilities"] if v.get("cveID") in set(cves)]
        kev_out = {k: kev[k] for k in ("title", "catalogVersion", "dateReleased") if k in kev}
        kev_out.update(
            {
                "count": len(subset),
                "vulnerabilities": subset,
                "note": "Subset of the CISA KEV catalog limited to the demo CVE set",
            }
        )
        (OUT / "kev.json").write_text(json.dumps(kev_out, indent=1), encoding="utf-8")
        print(f"KEV: {len(subset)} of {len(kev['vulnerabilities'])} entries kept")

        epss_rows = []
        for i in range(0, len(cves), 50):
            res = http.request(
                "GET",
                settings.epss_base_url,
                source="epss",
                params={"cve": ",".join(cves[i : i + 50])},
            )
            epss_rows += res.json().get("data", [])
        (OUT / "epss.json").write_text(json.dumps({"data": epss_rows}, indent=1), encoding="utf-8")
        print(f"EPSS: {len(epss_rows)} scores")

        fetcher = VendorAdvisoryFetcher(http, settings)
        index = {}
        for n, url in enumerate(VENDOR_PAGES, start=1):
            try:
                page = fetcher.fetch(url)
            except SourceUnavailable as exc:
                print(f"vendor {url}: FAILED {exc.detail}")
                continue
            excerpts = []
            for cve_id in cves:
                for m in list(re.finditer(re.escape(cve_id), page.text))[:1]:
                    lo, hi = max(0, m.start() - EXCERPT_RADIUS), m.end() + EXCERPT_RADIUS
                    excerpts.append(page.text[lo:hi])
            body = "\n<hr>\n".join(f"<p>{html.escape(e)}</p>" for e in excerpts)
            name = f"page{n}.html"
            (OUT / "vendor" / name).write_text(
                f"<!-- Excerpts recorded from {url} at {page.retrieved_at.isoformat()} -->\n{body}\n",
                encoding="utf-8",
            )
            index[url] = name
            print(f"vendor {url}: {len(excerpts)} excerpts")
        (OUT / "vendor" / "index.json").write_text(json.dumps(index, indent=1), encoding="utf-8")
        http.close()

    manifest = {
        "captured_at": utcnow().isoformat(),
        "note": "Recorded responses from NVD API 2.0, CISA KEV, FIRST EPSS and OSV.dev for demo "
        "mode. Values are as published at capture time and will drift from live data.",
        "cves": cves,
    }
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
