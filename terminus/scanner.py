"""Scan pipeline: ingest -> match -> enrich -> investigate -> score -> persist.

Modes
-----
incremental  CVEs modified since the last completed scan (or the configured
             window), all stored CVEs re-matched against the current inventory.
full         Product-targeted NVD queries for every inventory identity, OSV
             queries for every package, plus the incremental window.
Either mode runs against recorded fixtures when the source bundle is a demo
bundle; the scan is then recorded as ``demo-<mode>``.

Only one scan runs at a time (process-wide lock).
"""

from __future__ import annotations

import logging
import threading
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Literal

from terminus.agent.context import ResearchContext, SourceBundle
from terminus.agent.orchestrator import Investigation, LlmResearcher, ResearchAgent
from terminus.config import Settings
from terminus.connectors.http import SourceUnavailable
from terminus.matching.matcher import match_item
from terminus.matching.normalize import (
    _base,
    cpe_identities,
    normalize_product,
    normalize_vendor,
    package_identity,
    parse_cpe,
)
from terminus.models import (
    CveRecord,
    EpssStatus,
    Evidence,
    Finding,
    FixStatus,
    InventoryItem,
    KevStatus,
    MatchStatus,
    ScanRecord,
    SourceState,
    SourceStatus,
    TrustTier,
    utcnow,
)
from terminus.reports.recommendation import next_verification_step
from terminus.risk.scoring import RiskConfig, score_finding
from terminus.security import sanitize_untrusted
from terminus.storage.repository import Repository

log = logging.getLogger("terminus.scanner")

SCAN_LOCK = threading.Lock()
ProgressFn = Callable[[float, str], None]
ScanMode = Literal["incremental", "full"]

MAX_FULL_SCAN_PRODUCTS = 100
MAX_OSV_CVE_BACKFILL = 25
KEV_CATALOG_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"


_STATUS_TRIAGE = {
    MatchStatus.CONFIRMED_AFFECTED: 0,
    MatchStatus.POTENTIALLY_AFFECTED: 1,
    MatchStatus.UNVERIFIED: 2,
    MatchStatus.CONFIRMED_UNAFFECTED: 3,
}


class ScanAlreadyRunning(RuntimeError):
    pass


def _item_tokens(item: InventoryItem) -> set[str]:
    tokens = set(_base(item.software_name).split("_"))
    vendor = normalize_vendor(item.vendor)
    tokens |= set(normalize_product(item.software_name, vendor).split("_"))
    for cand in cpe_identities(item):
        tokens |= set(cand.product.split("_"))
    pid = package_identity(item)
    if pid:
        tokens |= set(_base(pid.name.split(":")[-1].split("/")[-1]).split("_"))
    return {t for t in tokens if t}


def _cve_tokens(cve: CveRecord) -> set[str]:
    tokens: set[str] = set()
    for conf in cve.configurations:
        for node in conf.nodes:
            for m in node.matches:
                cpe = parse_cpe(m.criteria)
                if cpe:
                    tokens |= set(cpe.product.split("_"))
    return tokens


class Scanner:
    def __init__(
        self,
        settings: Settings,
        repo: Repository,
        sources: SourceBundle,
        *,
        risk_config: RiskConfig | None = None,
        llm: LlmResearcher | None = None,
        progress: ProgressFn | None = None,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self.sources = sources
        self.risk_config = risk_config or RiskConfig()
        self.llm = llm
        self._progress = progress or (lambda f, m: None)

    def progress(self, fraction: float, message: str) -> None:
        log.info("[%3.0f%%] %s", fraction * 100, message)
        self._progress(max(0.0, min(1.0, fraction)), message)

    # ------------------------------------------------------------------
    def run(self, mode: ScanMode = "incremental") -> ScanRecord:
        if not SCAN_LOCK.acquire(blocking=False):
            raise ScanAlreadyRunning("a scan is already running")
        try:
            return self._run(mode)
        finally:
            SCAN_LOCK.release()

    def _run(self, mode: ScanMode) -> ScanRecord:
        now = utcnow()
        scan = ScanRecord(
            scan_id=uuid.uuid4().hex[:12],
            mode=f"demo-{mode}" if self.sources.demo else mode,
            status="running",
            started_at=now,
        )
        self.repo.save_scan(scan)
        try:
            self._execute(scan, mode)
            scan.status = "completed_with_errors" if scan.errors else "completed"
        except Exception as exc:
            log.exception("scan failed")
            scan.status = "failed"
            scan.errors.append(f"scan aborted: {type(exc).__name__}: {str(exc)[:300]}")
        scan.finished_at = utcnow()
        self.repo.save_scan(scan)
        self.progress(1.0, f"Scan {scan.status}")
        return scan

    def _status(
        self, scan: ScanRecord, source: str, state: SourceState, detail: str | None = None
    ) -> None:
        scan.source_status.append(
            SourceStatus(source=source, state=state, detail=detail, retrieved_at=utcnow())
        )
        if state in (SourceState.UNAVAILABLE, SourceState.ERROR):
            scan.errors.append(f"{source}: {detail}")

    def _execute(self, scan: ScanRecord, mode: ScanMode) -> None:
        items = self.repo.list_items()
        if not items:
            raise RuntimeError("no inventory imported - import an inventory before scanning")
        demo_state = SourceState.DEMO if self.sources.demo else SourceState.OK

        # 1. CVE ingestion ------------------------------------------------
        self.progress(0.02, "Fetching CVE records")
        last = self.repo.last_completed_scan([scan.mode])
        window_end = scan.started_at
        window_start = (
            last.window_end
            if last and last.window_end and mode == "incremental"
            else window_end - timedelta(days=self.settings.incremental_window_days)
        )
        scan.window_start, scan.window_end = window_start, window_end
        fetched: dict[str, CveRecord] = {}
        counts = {"inserted": 0, "updated": 0, "unchanged": 0}

        def ingest(records: list[CveRecord]) -> None:
            for rec in records:
                counts[self.repo.upsert_cve(rec)] += 1
                fetched[rec.cve_id] = rec

        nvd = self.sources.nvd
        products = sorted({(c.vendor, c.product) for i in items for c in cpe_identities(i)})
        if len(products) > MAX_FULL_SCAN_PRODUCTS:
            scan.errors.append(
                f"NVD product queries limited to {MAX_FULL_SCAN_PRODUCTS} of {len(products)} "
                "products"
            )
        products = products[:MAX_FULL_SCAN_PRODUCTS]
        try:
            # NVD can report more modified CVEs per week than the page budget allows
            # (it re-processes records in bulk). Paging through such a window would be
            # slow and still truncated, so in that case fetch what can matter to this
            # inventory instead: every newly published CVE (including ones NVD has not
            # analysed yet) plus every change to the inventory's own products.
            budget = self.settings.nvd_max_pages * self.settings.nvd_results_per_page
            modified = nvd.window_size(window_start, window_end)
            if modified <= budget:
                for page in nvd.fetch_window(window_start, window_end):
                    ingest(page)
                    self.progress(0.05, f"Fetched {len(fetched)} CVEs from the date window")
            else:
                scan.notices.append(
                    f"NVD lists {modified:,} CVEs modified in this window, more than the "
                    f"{budget:,}-record page budget (TERMINUS_NVD_MAX_PAGES). Fetched the newly "
                    f"published CVEs plus all changes to the inventory's {len(products)} "
                    "products instead; nothing that matches the inventory by CPE is skipped."
                )
                for page in nvd.fetch_window(window_start, window_end, field="pub"):
                    ingest(page)
                    self.progress(0.05, f"Fetched {len(fetched)} newly published CVEs")
                if mode == "incremental":  # full scans query each product without dates below
                    for idx, product in enumerate(products):
                        self.progress(
                            0.05 + 0.25 * idx / max(1, len(products)),
                            f"NVD changes: {product[0]}:{product[1]}",
                        )
                        for page in nvd.fetch_window(window_start, window_end, product=product):
                            ingest(page)
            if mode == "full":
                for idx, (vendor, product_name) in enumerate(products):
                    self.progress(
                        0.05 + 0.25 * idx / max(1, len(products)), f"NVD: {vendor}:{product_name}"
                    )
                    for page in nvd.fetch_by_product(vendor, product_name):
                        ingest(page)
            self._status(
                scan,
                "nvd",
                demo_state,
                f"{len(fetched)} records ({counts['inserted']} new, {counts['updated']} updated)",
            )
        except SourceUnavailable as exc:
            self._status(scan, "nvd", SourceState.UNAVAILABLE, exc.detail)
        if getattr(nvd, "errors", None):
            scan.errors.extend(f"nvd: {e}" for e in nvd.errors[:20])
            nvd.errors.clear()

        # 2. OSV package advisories (full scans) -----------------------------
        if mode == "full" and self.sources.osv is not None:
            pids = {p for p in (package_identity(i) for i in items) if p and p.ecosystem.osv_name}
            backfill: set[str] = set()
            try:
                for idx, pid in enumerate(sorted(pids, key=lambda p: (p.ecosystem.value, p.name))):
                    self.progress(0.3 + 0.1 * idx / max(1, len(pids)), f"OSV: {pid.name}")
                    for adv in self.sources.osv.advisories_for_package(pid):
                        self.repo.upsert_osv(adv)
                        backfill |= {a for a in adv.aliases if a.startswith("CVE-")}
                self._status(scan, "osv", demo_state, f"{len(pids)} packages queried")
            except SourceUnavailable as exc:
                self._status(scan, "osv", SourceState.UNAVAILABLE, exc.detail)
            missing = sorted(c for c in backfill if self.repo.get_cve(c) is None)
            for cve_id in missing[:MAX_OSV_CVE_BACKFILL]:
                try:
                    rec = nvd.fetch_cve(cve_id)
                    if rec is not None:
                        ingest([rec])
                except SourceUnavailable as exc:
                    scan.errors.append(f"nvd backfill {cve_id}: {exc.detail}")
                    break
            if len(missing) > MAX_OSV_CVE_BACKFILL:
                scan.errors.append(
                    f"{len(missing) - MAX_OSV_CVE_BACKFILL} CVEs referenced by OSV were not fetched "
                    "(backfill limit); run another full scan to continue"
                )

        # 3. Candidate matching over all stored CVEs ----------------------
        self.progress(0.42, "Matching CVEs against inventory")
        token_index = {i.item_id: _item_tokens(i) for i in items}
        candidates: dict[str, list[InventoryItem]] = {}
        best_status: dict[str, int] = {}  # preliminary, for triage only
        cve_index: dict[str, CveRecord] = {}
        all_cves = self.repo.list_cves()
        scan.cves_processed = len(fetched)
        for cve in all_cves:
            cve_tokens = _cve_tokens(cve)
            osv = self.repo.osv_for_cve(cve.cve_id)
            matched = []
            for item in items:
                if cve_tokens and not (cve_tokens & token_index[item.item_id]) and not osv:
                    continue
                result = match_item(item, cve, osv)
                if result is not None:
                    matched.append(item)
                    rank = _STATUS_TRIAGE[result.status]
                    best_status[cve.cve_id] = min(best_status.get(cve.cve_id, rank), rank)
            if matched:
                candidates[cve.cve_id] = matched
                cve_index[cve.cve_id] = cve

        # 4. Enrichment: KEV (whole catalog, also used for triage) and EPSS -----
        ctx = ResearchContext(settings=self.settings, repo=self.repo, sources=self.sources)
        self.progress(0.5, "Loading CISA KEV catalog")
        try:
            entries = self.sources.kev.fetch_catalog()
            self.repo.replace_kev(entries)
            ctx.kev_available = True
            ctx.kev_stale = bool(getattr(self.sources.kev, "stale", False))
            state = SourceState.CACHED if ctx.kev_stale else demo_state
            self._status(scan, "cisa_kev", state, f"{len(entries)} catalog entries")
        except SourceUnavailable as exc:
            previous = self.repo.kev_retrieved_at()
            ctx.kev_available = previous is not None
            ctx.kev_stale = True
            self._status(
                scan,
                "cisa_kev",
                SourceState.UNAVAILABLE,
                exc.detail
                + (
                    f"; using catalog retrieved {previous:%Y-%m-%d %H:%M} UTC"
                    if previous
                    else "; KEV status will be reported as unknown"
                ),
            )

        existing = {(f.cve_id, f.match.item_id) for f in self.repo.list_findings()}
        pending = [
            cve_id
            for cve_id, its in candidates.items()
            if mode == "full"
            or cve_id in fetched
            or any((cve_id, i.item_id) not in existing for i in its)
        ]
        # Triage before the per-scan research budget: KEV-listed first (few, and a
        # CVE newly added to KEV jumps the queue), then CVEs never researched before
        # (so repeated scans work through the whole backlog), then the strongest
        # preliminary match status, CVSS and recency. Deterministic for a database.
        kev_ids = self.repo.kev_cve_ids()

        def triage(cve_id: str) -> tuple[bool, bool, int, float, float, str]:
            cve = cve_index[cve_id]
            researched = all((cve_id, i.item_id) in existing for i in candidates[cve_id])
            score = cve.cvss.base_score if cve.cvss else 0.0
            published = cve.published.timestamp() if cve.published else 0.0
            return (
                cve_id not in kev_ids,
                researched,
                best_status[cve_id],
                -score,
                -published,
                cve_id,
            )

        to_investigate = sorted(pending, key=triage)
        cap = self.settings.agent_max_findings_per_scan
        if len(to_investigate) > cap:
            # A deliberate per-scan budget, not a failure: reported as a notice.
            scan.notices.append(
                f"Researched the {cap} highest-priority of {len(to_investigate)} candidate CVEs "
                f"(TERMINUS_AGENT_MAX_FINDINGS_PER_SCAN={cap}). The other "
                f"{len(to_investigate) - cap} keep any earlier findings and are picked up by "
                "the next scans, never-researched ones first."
            )
            to_investigate = to_investigate[:cap]

        self.progress(0.55, "Fetching EPSS scores")
        if to_investigate and self.sources.epss is not None:
            try:
                self.repo.upsert_epss(self.sources.epss.fetch_scores(to_investigate))
                self._status(
                    scan, "first_epss", demo_state, f"{len(to_investigate)} CVEs requested"
                )
            except SourceUnavailable as exc:
                ctx.epss_failed = True
                self._status(scan, "first_epss", SourceState.UNAVAILABLE, exc.detail)

        # 5. Investigation, scoring, persistence -----------------------------
        agent = ResearchAgent(ctx, self.llm)
        produced: set[str] = set()
        for idx, cve_id in enumerate(to_investigate):
            self.progress(0.6 + 0.38 * idx / max(1, len(to_investigate)), f"Investigating {cve_id}")
            inv = agent.investigate(cve_id, candidates[cve_id])
            for finding in self._findings(inv, scan.scan_id):
                self.repo.upsert_finding(finding)
                produced.add(finding.finding_id)
        # Keep findings for candidates not re-investigated this scan, plus everything
        # just produced; anything else no longer corresponds to a candidate.
        investigated = set(to_investigate)
        keep = produced | {
            Finding.make_id(item.item_id, cve_id)
            for cve_id, its in candidates.items()
            if cve_id not in investigated
            for item in its
        }
        removed = self.repo.prune_findings(keep)
        if removed:
            self.progress(0.99, f"Removed {removed} findings that no longer match")
        scan.findings_count = len(produced)

    # ------------------------------------------------------------------
    def _findings(self, inv: Investigation, scan_id: str) -> list[Finding]:
        st = inv.state
        cve = st.cve
        if cve is None:
            return []
        kev = st.kev or KevStatus(in_kev=None, source_state=SourceState.UNAVAILABLE)
        epss = st.epss or EpssStatus(score=None, source_state=SourceState.UNAVAILABLE)
        items = {i.item_id: i for i in st.items}
        official = st.advisory_list()
        summary = sanitize_untrusted(cve.description, max_chars=600)
        out = []
        for item_id, match in st.matches.items():
            item = items[item_id]
            fix = st.fixes[item_id]
            rec = st.recommendations[item_id]
            priority = score_finding(
                item=item,
                match=match,
                cvss=cve.cvss,
                kev=kev,
                epss=epss,
                fix=fix,
                config=self.risk_config,
            )
            evidence = list(match.evidence)
            pages_by_url = {p.final_url: p for p in st.vendor_pages.values()}
            for src in fix.sources:
                if src.trust_tier == TrustTier.VENDOR_ADVISORY:
                    page = pages_by_url.get(src.url or "")
                    evidence.append(
                        Evidence(
                            claim=f"Vendor advisory text mentions {cve.cve_id} and fixed "
                            f"version {src.version}",
                            source="Vendor advisory (allow-listed domain)",
                            trust_tier=TrustTier.VENDOR_ADVISORY,
                            url=src.url,
                            retrieved_at=page.retrieved_at if page else None,
                        )
                    )
            for r in st.supplementary:
                evidence.append(
                    Evidence(
                        claim=f"Supplementary search result: {r.title[:120]}",
                        source="Web search (untrusted, not used for verdicts)",
                        trust_tier=TrustTier.SUPPLEMENTARY,
                        url=r.url,
                        excerpt=r.snippet[:500],
                        flags=r.injection_flags,
                    )
                )
            supporting = [cve.nvd_url] + [a.url for a in st.osv.values()]
            supporting += [s.url for s in fix.sources if s.url]
            if kev.in_kev:
                supporting.append(KEV_CATALOG_URL)
            supporting += [r.url for r in st.supplementary]
            supporting = [u for u in dict.fromkeys(supporting) if u not in official]

            missing = list(priority.missing_data)
            if item.software_version is None:
                missing.append("installed version")
            if fix.status in (FixStatus.UNKNOWN, FixStatus.CONFLICT):
                missing.append("verified fixed version")
            if not official:
                missing.append("official vendor advisory URL")
            missing += inv.gaps.get(item_id, [])

            uncertainties: list[str] = []
            if match.status not in (
                MatchStatus.CONFIRMED_AFFECTED,
                MatchStatus.CONFIRMED_UNAFFECTED,
            ):
                uncertainties += match.reasons[1:]
            if fix.status in (FixStatus.CONFLICT, FixStatus.SINGLE_SOURCE):
                uncertainties += fix.notes
            if not cve.is_analyzed:
                uncertainties.append(f"NVD analysis status: {cve.vuln_status or 'unknown'}")
            if st.injection_flags:
                uncertainties.append(
                    "Retrieved content contained instruction-like text that was ignored: "
                    + ", ".join(sorted(st.injection_flags))
                )
            if kev.source_state in (SourceState.CACHED, SourceState.UNAVAILABLE):
                uncertainties.append(f"KEV data state: {kev.source_state.value}")

            ai = None
            if inv.ai_interpretation:
                ai = sanitize_untrusted(inv.ai_interpretation, max_chars=2000).text

            out.append(
                Finding(
                    finding_id=Finding.make_id(item_id, cve.cve_id),
                    cve_id=cve.cve_id,
                    summary=summary.text,
                    item=item,
                    match=match.model_copy(update={"evidence": evidence}),
                    cvss=cve.cvss,
                    cve_published=cve.published,
                    cve_last_modified=cve.last_modified,
                    cve_retrieved_at=cve.retrieved_at,
                    cve_source=cve.source,
                    kev=kev,
                    epss=epss,
                    priority=priority,
                    fix=fix,
                    recommendation=rec,
                    vendor_advisory_urls=official[:10],
                    supporting_urls=supporting[:20],
                    missing_information=list(dict.fromkeys(missing)),
                    uncertainties=list(dict.fromkeys(uncertainties)),
                    next_verification_step=next_verification_step(item, match, fix),
                    ai_interpretation=ai,
                    research=inv.trace,
                    scan_id=scan_id,
                )
            )
        return out
