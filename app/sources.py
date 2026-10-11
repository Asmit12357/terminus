"""Construction of live and demo data-source bundles.

Demo mode serves recorded API responses bundled in ``app/data/fixtures`` through the same
parsing code as live mode. Every record served in demo mode keeps the capture
timestamp from the fixture manifest, and the UI and reports label it DEMO.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path
from typing import Any

from app.agent.context import SourceBundle
from app.config import Settings
from app.connectors.epss import EpssConnector, parse_epss
from app.connectors.http import HttpClient, SourceUnavailable
from app.connectors.kev import KevConnector, parse_catalog
from app.connectors.nvd import NvdConnector, parse_response
from app.connectors.osv import OsvConnector, parse_osv
from app.connectors.search import SearchResult, build_search_provider
from app.connectors.vendor import VendorAdvisoryFetcher, VendorPage, html_to_text
from app.matching.normalize import PackageId, parse_cpe
from app.models import CveRecord, EpssScore, KevEntry, OsvAdvisory
from app.paths import FIXTURES_DIR
from app.security import sanitize_untrusted
from app.storage.repository import Repository


def build_live_sources(settings: Settings, repo: Repository) -> SourceBundle:
    http = HttpClient(settings, repo)
    return SourceBundle(
        nvd=NvdConnector(http, settings),
        kev=KevConnector(http, settings),
        epss=EpssConnector(http, settings),
        osv=OsvConnector(http, settings),
        vendor=VendorAdvisoryFetcher(http, settings),
        search=build_search_provider(http, settings),
        demo=False,
        closers=[http],
    )


# ---------------------------------------------------------------------------
# Demo (recorded fixtures)
# ---------------------------------------------------------------------------


def _load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


class _Fixtures:
    def __init__(self, root: Path) -> None:
        self.root = root
        manifest = _load(root / "manifest.json")
        self.captured_at = datetime.fromisoformat(manifest["captured_at"])
        self.manifest = manifest


class DemoNvd:
    name = "nvd"

    def __init__(self, fx: _Fixtures) -> None:
        self.fx = fx
        self.errors: list[str] = []
        self._records: list[CveRecord] | None = None

    def _all(self) -> list[CveRecord]:
        if self._records is None:
            records: list[CveRecord] = []
            for path in sorted((self.fx.root / "nvd").glob("CVE-*.json")):
                recs, _, errors = parse_response(
                    _load(path), self.fx.captured_at, source="demo-fixture"
                )
                records.extend(recs)
                self.errors.extend(errors)
            self._records = records
        return self._records

    def fetch_window(
        self, start: datetime, end: datetime, field: str = "lastMod"
    ) -> Iterator[list[CveRecord]]:
        yield self._all()

    def fetch_by_product(self, vendor: str, product: str) -> Iterator[list[CveRecord]]:
        hits = []
        for rec in self._all():
            for conf in rec.configurations:
                for node in conf.nodes:
                    for m in node.matches:
                        cpe = parse_cpe(m.criteria)
                        if cpe and cpe.vendor == vendor and cpe.product == product:
                            hits.append(rec)
                            break
        yield list({r.cve_id: r for r in hits}.values())

    def fetch_cve(self, cve_id: str) -> CveRecord | None:
        return next((r for r in self._all() if r.cve_id == cve_id), None)


class DemoKev:
    name = "cisa_kev"
    stale = False

    def __init__(self, fx: _Fixtures) -> None:
        self.fx = fx
        self.errors: list[str] = []

    def fetch_catalog(self) -> list[KevEntry]:
        entries, errors = parse_catalog(_load(self.fx.root / "kev.json"), self.fx.captured_at)
        self.errors.extend(errors)
        return entries


class DemoEpss:
    name = "first_epss"

    def __init__(self, fx: _Fixtures) -> None:
        self.fx = fx
        self.errors: list[str] = []

    def fetch_scores(self, cve_ids: list[str]) -> list[EpssScore]:
        scores, errors = parse_epss(_load(self.fx.root / "epss.json"), self.fx.captured_at)
        self.errors.extend(errors)
        wanted = set(cve_ids)
        return [s for s in scores if s.cve_id in wanted]


class DemoOsv:
    name = "osv"

    def __init__(self, fx: _Fixtures) -> None:
        self.fx = fx
        self.errors: list[str] = []

    def advisories_for_package(self, pid: PackageId) -> list[OsvAdvisory]:
        if pid.ecosystem.osv_name is None:
            return []
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in pid.name)
        path = self.fx.root / "osv" / f"{pid.ecosystem.osv_name}__{safe}.json"
        if not path.is_file():
            return []
        payload = _load(path)
        return [parse_osv(v, self.fx.captured_at) for v in payload.get("vulns") or []]


class DemoVendor:
    name = "vendor_advisory"

    def __init__(self, fx: _Fixtures) -> None:
        self.fx = fx
        self.index: dict[str, str] = _load(fx.root / "vendor" / "index.json")

    def allowed(self, url: str) -> bool:
        return url in self.index

    def fetch(self, url: str) -> VendorPage:
        name = self.index.get(url)
        if name is None or "/" in name or "\\" in name or name.startswith("."):
            raise SourceUnavailable(self.name, "no recorded copy of this page")
        raw = (self.fx.root / "vendor" / name).read_text(encoding="utf-8")
        clean = sanitize_untrusted(html_to_text(raw), max_chars=200_000)
        return VendorPage(
            url=url,
            final_url=url,
            text=clean.text,
            retrieved_at=self.fx.captured_at,
            injection_flags=clean.flags,
            truncated=clean.truncated,
        )


class DemoSearch:
    """Synthetic search results (clearly labelled) used to demonstrate how
    supplementary and adversarial content is handled."""

    name = "demo-search"

    def __init__(self, fx: _Fixtures) -> None:
        self.rows = _load(fx.root / "search" / "results.json")

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        out = []
        for row in self.rows:
            if row.get("cve_id") and row["cve_id"] in query:
                snippet = sanitize_untrusted(row.get("snippet"), max_chars=1500)
                title = sanitize_untrusted(row.get("title"), max_chars=200)
                out.append(
                    SearchResult(
                        title=title.text,
                        url=row["url"],
                        snippet=snippet.text,
                        injection_flags=sorted(set(snippet.flags) | set(title.flags)),
                    )
                )
        return out[:max_results]


def build_demo_sources(fixtures_dir: Path | None = None) -> SourceBundle:
    fx = _Fixtures(fixtures_dir or FIXTURES_DIR)
    return SourceBundle(
        nvd=DemoNvd(fx),
        kev=DemoKev(fx),
        epss=DemoEpss(fx),
        osv=DemoOsv(fx),
        vendor=DemoVendor(fx),
        search=DemoSearch(fx),
        demo=True,
    )


def build_sources(settings: Settings, repo: Repository, demo: bool | None = None) -> SourceBundle:
    use_demo = settings.is_demo if demo is None else demo
    return build_demo_sources() if use_demo else build_live_sources(settings, repo)
