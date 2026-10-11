"""Terminus dashboard (Streamlit).

    streamlit run app/dashboard.py

Operations available from the UI are deliberately limited to: import an
inventory, run a scan, view findings, export reports. Nothing here executes
commands or changes the systems described in the inventory.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Literal

# Allow `streamlit run app/dashboard.py` from the project root without installation.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from app.config import get_settings  # noqa: E402
from app.diagnostics import ConfigurationError  # noqa: E402
from app.inventory import InventoryFormatError, parse_inventory  # noqa: E402
from app.models import Finding, InventoryItem, MatchStatus, TrustTier  # noqa: E402
from app.paths import SAMPLE_INVENTORY_CSV, SAMPLE_INVENTORY_JSON  # noqa: E402
from app.reports.export import DISCLAIMER, export_csv, export_json  # noqa: E402
from app.reports.queue import remediation_plan  # noqa: E402
from app.risk.scoring import FORMULA, RiskConfig  # noqa: E402
from app.scanner import ScanAlreadyRunning  # noqa: E402
from app.service import get_repo, import_inventory, run_scan, summarize  # noqa: E402
from app.ui import (  # noqa: E402
    FINDING_COLUMNS,
    STATUS_META,
    TIER_COLOR,
    bar_chart,
    epss_text,
    findings_frame,
    fix_text,
    kev_text,
    md,
    safe_url,
    status_badge,
    status_label,
    tier_badge,
)

SAMPLE_JSON = SAMPLE_INVENTORY_JSON
SAMPLE_CSV = SAMPLE_INVENTORY_CSV
ACTIONABLE = [
    MatchStatus.CONFIRMED_AFFECTED,
    MatchStatus.POTENTIALLY_AFFECTED,
    MatchStatus.UNVERIFIED,
]
TIERS = ["P1", "P2", "P3", "P4", "INFO"]

settings = get_settings()
repo = get_repo(settings)


def all_findings() -> list[Finding]:
    return repo.list_findings()


def demo_banner(findings: list[Finding]) -> None:
    if any(f.cve_source == "demo-fixture" for f in findings):
        captured = min((f.cve_retrieved_at for f in findings if f.cve_retrieved_at), default=None)
        st.info(
            "**Demo data.** Findings use recorded NVD, CISA KEV, FIRST EPSS and OSV responses"
            + (f" captured {captured:%Y-%m-%d}" if captured else "")
            + ". Values may have changed since; run a live scan for current data.",
            icon=":material/science:",
        )


def run_scan_ui(mode: str, demo: bool) -> None:
    progress = st.progress(0.0, text="Starting scan")
    with st.status("Scanning", expanded=True) as status:
        log_area = st.empty()
        lines: list[str] = []

        def on_progress(fraction: float, message: str) -> None:
            progress.progress(fraction, text=message)
            lines.append(message)
            log_area.text("\n".join(lines[-8:]))

        try:
            scan = run_scan(settings, repo, mode, demo=demo, progress=on_progress)  # type: ignore[arg-type]
        except ScanAlreadyRunning:
            status.update(label="Another scan is already running", state="error")
            return
        except ConfigurationError as exc:
            status.update(label="Scan not started: configuration problem", state="error")
            for problem in exc.problems:
                st.error(problem)
            return
        state: Literal["complete", "error"] = "complete" if scan.status != "failed" else "error"
        status.update(
            label=f"Scan {scan.status}: {scan.findings_count} findings, "
            f"{scan.cves_processed} CVEs processed",
            state=state,
        )
        for issue in scan.errors[:10]:
            st.warning(issue)


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------


def page_overview() -> None:
    st.title("Overview")
    st.caption(
        "Vulnerability intelligence and remediation recommendations. "
        "Research only: Terminus never patches or changes systems."
    )
    items = repo.list_items()
    findings = all_findings()
    demo_banner(findings)

    if not items:
        st.subheader("Get started")
        st.write(
            "No inventory is loaded. Load the synthetic sample inventory and run a demo scan "
            "against recorded API data (no network or API keys needed), or import your own "
            "inventory on the Inventory page."
        )
        if st.button(
            "Load sample inventory and run demo scan", type="primary", icon=":material/play_arrow:"
        ):
            result, inventory_id = import_inventory(
                repo, SAMPLE_JSON.read_bytes(), SAMPLE_JSON.name
            )
            if inventory_id:
                run_scan_ui("full", demo=True)
                st.rerun()
            else:
                st.error(f"Sample inventory failed validation: {result.errors[:3]}")
        return

    actionable = [f for f in findings if f.match.status in ACTIONABLE]
    by_status = summarize(findings)["by_status"]
    cols = st.columns(6)
    cols[0].metric("Assets", len({i.asset_id for i in items}))
    cols[1].metric("Software items", len(items))
    cols[2].metric(
        f"{STATUS_META[MatchStatus.CONFIRMED_AFFECTED]['icon']} Confirmed affected",
        by_status.get("confirmed_affected", 0),
    )
    cols[3].metric(
        f"{STATUS_META[MatchStatus.POTENTIALLY_AFFECTED]['icon']} Potentially affected",
        by_status.get("potentially_affected", 0),
    )
    cols[4].metric(
        f"{STATUS_META[MatchStatus.UNVERIFIED]['icon']} Unverified", by_status.get("unverified", 0)
    )
    cols[5].metric(
        "KEV-listed (actionable)",
        sum(1 for f in actionable if f.kev.in_kev),
        help="Findings whose CVE is in the CISA Known Exploited Vulnerabilities catalog",
    )

    if not findings:
        st.info("No findings yet. Run a scan from the Scans page.")
        return

    left, right = st.columns(2)
    tier_df = (
        pd.DataFrame({"Tier": [f.priority.tier for f in actionable]})
        .value_counts()
        .rename("Findings")
        .reset_index()
    )
    if not tier_df.empty:
        left.altair_chart(
            bar_chart(
                tier_df,
                "Tier",
                "Findings",
                TIER_COLOR,
                TIERS,
                "Actionable findings by priority tier",
            ),
            width="stretch",
        )
    status_df = (
        pd.DataFrame({"Status": [status_label(f.match.status) for f in findings]})
        .value_counts()
        .rename("Findings")
        .reset_index()
    )
    status_colors = {status_label(k): v["color"] for k, v in STATUS_META.items()}
    right.altair_chart(
        bar_chart(
            status_df,
            "Status",
            "Findings",
            status_colors,
            [status_label(s) for s in MatchStatus],
            "All findings by match status",
        ),
        width="stretch",
    )

    st.subheader("Top priorities")
    top = findings_frame(actionable[:10])
    if top.empty:
        st.success("No actionable findings.")
    else:
        st.dataframe(
            top[
                [
                    "Tier",
                    "Score",
                    "CVE",
                    "Status",
                    "Asset",
                    "Software",
                    "Installed",
                    "KEV",
                    "EPSS",
                    "Fix",
                    "Action",
                ]
            ],
            hide_index=True,
            column_config=FINDING_COLUMNS,
        )
        st.page_link(
            PAGES["queue"], label="Open the remediation queue", icon=":material/arrow_forward:"
        )

    scans = repo.list_scans(limit=1)
    if scans:
        sc = scans[0]
        st.caption(
            f"Last scan {sc.scan_id} ({sc.mode}) {sc.status} at "
            f"{(sc.finished_at or sc.started_at):%Y-%m-%d %H:%M} UTC - "
            + ", ".join(f"{x.source}: {x.state.value}" for x in sc.source_status)
        )


def page_queue() -> None:
    st.title("Remediation queue")
    st.caption(
        "Ranked by the deterministic risk engine. Every item requires human review before "
        "any change; nothing has been patched."
    )
    findings = all_findings()
    demo_banner(findings)
    c1, c2 = st.columns(2)
    include_potential = c1.toggle("Include potentially affected", value=True)
    include_unverified = c2.toggle("Include unverified (needs verification)", value=True)
    wanted = {MatchStatus.CONFIRMED_AFFECTED}
    if include_potential:
        wanted.add(MatchStatus.POTENTIALLY_AFFECTED)
    if include_unverified:
        wanted.add(MatchStatus.UNVERIFIED)
    queue = [f for f in findings if f.match.status in wanted]
    if not queue:
        st.success("Nothing in the queue.")
        return

    st.subheader("Consolidated upgrade plan")
    st.caption(
        "One change per software installation: the highest fixed version across its open "
        "findings. Caveats show where a fix is unverified, single-source or conflicting."
    )
    plan = [
        {
            "Highest tier": row.highest_tier,
            "Max score": row.max_score,
            "Asset": row.asset_id,
            "Software": row.software,
            "Installed": row.installed_version or "unknown",
            "Open CVEs": len(row.open_cves),
            "KEV-listed": row.kev_listed,
            "Target version": row.target_version or "verify / consult advisory",
            "Caveats": "; ".join(row.caveats) or "-",
        }
        for row in remediation_plan(queue)
    ]
    plan_df = pd.DataFrame(plan)  # already ranked by tier, then score
    st.dataframe(
        plan_df,
        hide_index=True,
        column_config={
            "Max score": st.column_config.ProgressColumn(
                "Max score", min_value=0, max_value=100, format="%.1f"
            )
        },
    )

    st.subheader("All queued findings")
    df = findings_frame(queue)
    event = st.dataframe(
        df,
        hide_index=True,
        column_config=FINDING_COLUMNS,
        on_select="rerun",
        selection_mode="single-row",
        key="queue_table",
    )
    show_selected(df, event, queue, key="queue_pick")


def page_findings() -> None:
    st.title("Findings")
    findings = all_findings()
    demo_banner(findings)
    if not findings:
        st.info("No findings yet. Import an inventory and run a scan.")
        return
    c1, c2, c3 = st.columns([1, 2, 1])
    tiers = c1.multiselect("Priority", TIERS, default=[])
    statuses = c2.multiselect(
        "Match status", list(MatchStatus), default=[], format_func=status_label
    )
    assets = sorted({f.item.asset_id for f in findings})
    asset = c3.selectbox("Asset", ["All assets", *assets])
    c4, c5 = st.columns(2)
    cve_q = c4.text_input("CVE contains", max_chars=20, placeholder="e.g. 2021-44")
    product_q = c5.text_input("Product contains", max_chars=80, placeholder="e.g. log4j")

    def keep(f: Finding) -> bool:
        return (
            (not tiers or f.priority.tier in tiers)
            and (not statuses or f.match.status in statuses)
            and (asset == "All assets" or f.item.asset_id == asset)
            and (not cve_q or cve_q.strip().upper() in f.cve_id)
            and (not product_q or product_q.strip().lower() in f.item.software_name.lower())
        )

    shown = [f for f in findings if keep(f)]
    st.caption(f"{len(shown)} of {len(findings)} findings")
    df = findings_frame(shown)
    if df.empty:
        return
    event = st.dataframe(
        df,
        hide_index=True,
        column_config=FINDING_COLUMNS,
        on_select="rerun",
        selection_mode="single-row",
        key="findings_table",
    )
    show_selected(df, event, shown, key="findings_pick")


def show_selected(df: pd.DataFrame, event: object, findings: list[Finding], key: str) -> None:
    """Open the finding selected in the table, or chosen in an accessible selector."""
    rows = getattr(getattr(event, "selection", None), "rows", None) or []
    by_id = {f.finding_id: f for f in findings}
    picked = st.selectbox(
        "Inspect a finding (or select a table row)",
        options=list(by_id),
        index=None,
        format_func=lambda fid: (
            f"{by_id[fid].priority.tier} | {by_id[fid].cve_id} | "
            f"{by_id[fid].item.asset_id} | {by_id[fid].item.software_name}"
        ),
        placeholder="Choose a finding",
        key=key,
    )
    finding_id = df.iloc[rows[0]]["_id"] if rows else picked
    if finding_id:
        render_finding(repo.get_finding(str(finding_id)))


def render_finding(f: Finding | None) -> None:
    if f is None:
        st.warning("Finding not found (it may have been re-assessed).")
        return
    st.divider()
    st.subheader(
        f"{f.cve_id} on {md(f.item.asset_id)} - {md(f.item.software_name)} "
        f"{md(f.item.software_version or '(version unknown)')}"
    )
    b1, b2, b3 = st.columns([2, 2, 3])
    with b1:
        status_badge(f.match.status)
    with b2:
        tier_badge(f.priority.tier)
    b3.caption(
        f"Score {f.priority.score} / 100 - match confidence {f.match.confidence:.2f} - "
        f"last assessed {f.last_assessed:%Y-%m-%d %H:%M} UTC"
    )

    st.markdown("**Vulnerability summary** (from NVD; shown as plain text)")
    st.text(f.summary or "No description published.")

    rec = f.recommendation
    with st.container(border=True):
        st.markdown(f"**Recommendation - {md(rec.action)}**")
        st.write(rec.summary)
        for step in rec.steps:
            st.markdown(f"- {md(step)}")

    tab_facts, tab_priority, tab_evidence, tab_gaps, tab_ai, tab_trace = st.tabs(
        [
            "Verified facts",
            "Priority rationale",
            "Evidence & sources",
            "Uncertainty",
            "AI interpretation",
            "Research trace",
        ]
    )

    with tab_facts:
        c1, c2, c3 = st.columns(3)
        with c1:
            st.markdown("**Severity (CVSS)**")
            if f.cvss:
                st.write(
                    f"{f.cvss.base_score} {f.cvss.severity or ''} (v{f.cvss.version}, "
                    f"{f.cvss.score_type or 'score'} from {f.cvss.source or 'unknown'})"
                )
                st.code(f.cvss.vector or "no vector", language=None)
            else:
                st.write("Not available")
            st.caption(
                f"NVD record retrieved {f.cve_retrieved_at:%Y-%m-%d %H:%M} UTC"
                if f.cve_retrieved_at
                else ""
            )
        with c2:
            st.markdown("**CISA KEV**")
            st.write(kev_text(f) + (f" (added {f.kev.date_added})" if f.kev.date_added else ""))
            if f.kev.due_date:
                st.caption(
                    f"Federal due date {f.kev.due_date}; ransomware use: "
                    f"{f.kev.known_ransomware_use or 'unknown'}"
                )
            st.caption(
                f"Catalog state: {f.kev.source_state.value}"
                + (
                    f", retrieved {f.kev.retrieved_at:%Y-%m-%d %H:%M} UTC"
                    if f.kev.retrieved_at
                    else ""
                )
            )
        with c3:
            st.markdown("**FIRST EPSS**")
            st.write(
                epss_text(f)
                + (
                    f" (percentile {f.epss.percentile:.3f})"
                    if f.epss.percentile is not None
                    else ""
                )
            )
            st.caption(
                "Probability of exploitation activity in the next 30 days - "
                "not evidence of exploitation."
                + (f" Score date {f.epss.score_date}." if f.epss.score_date else "")
            )
        st.markdown("**Affected-version determination**")
        for reason in f.match.reasons:
            st.markdown(f"- {md(reason)}")
        if f.match.vulnerable_ranges:
            st.dataframe(
                pd.DataFrame({"Affected range (source: product range)": f.match.vulnerable_ranges}),
                hide_index=True,
            )
        st.markdown(f"**Fixed version:** {md(fix_text(f))}")
        for note in f.fix.notes:
            st.caption(note)
        st.markdown("**Asset context**")
        item: InventoryItem = f.item
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Hostname": item.hostname,
                        "OS": f"{item.os_name or ''} {item.os_version or ''}".strip(),
                        "Criticality": item.criticality.value,
                        "Exposure": {True: "internet-facing", False: "internal", None: "unknown"}[
                            item.internet_exposed
                        ],
                        "Environment": item.environment.value if item.environment else "unknown",
                        "Ecosystem": item.ecosystem.value,
                        "Identifier": item.cpe or item.purl or "-",
                    }
                ]
            ),
            hide_index=True,
        )

    with tab_priority:
        st.caption(FORMULA)
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Factor": x.name,
                        "Source value": x.raw_value,
                        "Points": x.points,
                        "Max": x.max_points,
                        "Missing": "yes" if x.missing else "",
                        "Why": x.explanation,
                    }
                    for x in f.priority.factors
                ]
            ),
            hide_index=True,
        )
        st.write(
            f"Status/confidence multiplier: {f.priority.confidence_multiplier} -> "
            f"score {f.priority.score} -> tier {f.priority.tier}"
        )
        for o in f.priority.overrides:
            st.info(o)
        if f.priority.missing_data:
            st.warning(
                "Missing inputs (placeholder values used, not zeros): "
                + ", ".join(f.priority.missing_data)
            )

    with tab_evidence:
        st.dataframe(
            pd.DataFrame(
                [
                    {
                        "Claim": e.claim,
                        "Source": e.source,
                        "Trust": e.trust_tier.value.replace("_", " "),
                        "Retrieved": e.retrieved_at.strftime("%Y-%m-%d %H:%M")
                        if e.retrieved_at
                        else "",
                        "URL": safe_url(e.url),
                        "Flags": ", ".join(e.flags),
                    }
                    for e in f.match.evidence
                ]
            ),
            hide_index=True,
            column_config={"URL": st.column_config.LinkColumn("URL")},
        )
        supplementary = [e for e in f.match.evidence if e.trust_tier == TrustTier.SUPPLEMENTARY]
        for e in supplementary:
            if e.excerpt:
                with st.expander(f"Supplementary excerpt (untrusted): {e.url}"):
                    if e.flags:
                        st.error(
                            "Instruction-like content detected and ignored: " + ", ".join(e.flags)
                        )
                    st.text(e.excerpt)
        links = [
            {"Type": "Official vendor advisory", "URL": safe_url(u)} for u in f.vendor_advisory_urls
        ] + [{"Type": "Supporting", "URL": safe_url(u)} for u in f.supporting_urls]
        if links:
            st.dataframe(
                pd.DataFrame(links),
                hide_index=True,
                column_config={"URL": st.column_config.LinkColumn("URL")},
            )
        else:
            st.warning("No official vendor advisory URL was found in structured sources.")

    with tab_gaps:
        st.markdown(f"**Next verification step:** {md(f.next_verification_step)}")
        st.markdown("**Missing information**")
        for m in f.missing_information or ["None"]:
            st.markdown(f"- {md(m)}")
        st.markdown("**Unresolved uncertainty**")
        for u in f.uncertainties or ["None recorded"]:
            st.markdown(f"- {md(u)}")

    with tab_ai:
        if f.ai_interpretation:
            st.warning(
                "AI-generated interpretation - not verified. It did not influence the status, "
                "fixed version or priority."
            )
            st.text(f.ai_interpretation)
        else:
            st.info(
                "No AI interpretation: this finding was produced by the deterministic research "
                "policy (no LLM configured)."
            )

    with tab_trace:
        if f.research:
            st.write(f"Mode: {f.research.mode} - stop reason: {f.research.stop_reason}")
            st.caption("Budget: " + ", ".join(f"{k}={v}" for k, v in f.research.budget.items()))
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Tool": c.tool,
                            "OK": "yes" if c.ok else "NO",
                            "Summary": c.summary,
                            "Error": c.error or "",
                            "ms": c.duration_ms,
                        }
                        for c in f.research.tool_calls
                    ]
                ),
                hide_index=True,
            )
            if f.research.injection_flags:
                st.error(
                    "Retrieved content contained instruction-like text; it was treated as data "
                    "and ignored: " + ", ".join(f.research.injection_flags)
                )


def page_inventory() -> None:
    st.title("Inventory")
    items = repo.list_items()
    meta = repo.latest_inventory()
    if meta:
        st.caption(
            f"Active inventory '{meta['name']}' imported {str(meta['imported_at'])[:16]} UTC "
            f"- {meta['item_count']} software items"
        )

    st.subheader("Import")
    upload = st.file_uploader("Upload a JSON or CSV inventory (max 5 MB)", type=["json", "csv"])
    if upload is not None:
        content = upload.getvalue()
        try:
            result = parse_inventory(content, upload.name)
        except InventoryFormatError as exc:
            st.error(f"Cannot read file: {exc}")
        else:
            c1, c2, c3 = st.columns(3)
            c1.metric("Valid items", len(result.items))
            c2.metric("Errors", len(result.errors))
            c3.metric("Warnings", len(result.warnings))
            if result.errors:
                st.error("Fix these errors and upload again; nothing was imported.")
                st.dataframe(pd.DataFrame([e.model_dump() for e in result.errors]), hide_index=True)
            for w in result.warnings[:30]:
                st.warning(w)
            if result.ok and st.button("Replace active inventory with this file", type="primary"):
                _, inventory_id = import_inventory(repo, content, upload.name)
                st.success(f"Imported inventory {inventory_id}. Run a scan to assess it.")
                st.rerun()

    s1, s2, s3 = st.columns(3)
    if s1.button("Load synthetic sample inventory", icon=":material/upload_file:"):
        import_inventory(repo, SAMPLE_JSON.read_bytes(), SAMPLE_JSON.name)
        st.rerun()
    s2.download_button(
        "Sample (JSON)",
        SAMPLE_JSON.read_bytes(),
        "sample_inventory.json",
        "application/json",
        icon=":material/download:",
    )
    s3.download_button(
        "Sample (CSV)",
        SAMPLE_CSV.read_bytes(),
        "sample_inventory.csv",
        "text/csv",
        icon=":material/download:",
    )

    with st.expander("Inventory schema"):
        st.dataframe(
            pd.DataFrame(
                [
                    ("asset_id", "yes", "Letters, digits, . _ : - (max 64)"),
                    ("hostname", "no", "DNS name"),
                    ("os_name / os_version", "no", "Operating system"),
                    ("software_name", "yes", "Product or package name"),
                    (
                        "software_version",
                        "no*",
                        "Installed version; missing -> findings are 'unverified'",
                    ),
                    (
                        "ecosystem",
                        "no",
                        "pypi, npm, maven, nuget, go, cargo, rubygems, deb, rpm, generic",
                    ),
                    ("vendor", "no", "Publisher; strengthens identity matching"),
                    (
                        "cpe",
                        "no",
                        "CPE 2.3 string, e.g. cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
                    ),
                    (
                        "purl",
                        "no",
                        "Package URL, e.g. pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                    ),
                    ("criticality", "no", "low, medium (default), high, critical"),
                    ("internet_exposed", "no", "true / false / empty for unknown"),
                    ("environment", "no", "production, staging, development, test"),
                    ("business_context / owner", "no", "Free text"),
                ],
                columns=["Field", "Required", "Notes"],
            ),
            hide_index=True,
        )

    st.subheader("Current inventory")
    if items:
        st.dataframe(pd.DataFrame([i.model_dump(mode="json") for i in items]), hide_index=True)
    else:
        st.info("No inventory loaded.")


def page_scans() -> None:
    st.title("Scans")
    items = repo.list_items()
    with st.container(border=True):
        st.subheader("Run a scan")
        c1, c2 = st.columns(2)
        source = c1.radio(
            "Data source",
            ["Demo fixtures (offline)", "Live public APIs"],
            index=0 if settings.is_demo else 1,
            help="Demo uses the recorded NVD/KEV/EPSS/OSV responses bundled with Terminus.",
        )
        mode = c2.radio(
            "Scope",
            ["full", "incremental"],
            format_func=lambda m: {
                "full": "Full - all inventory products + OSV packages",
                "incremental": f"Incremental - CVEs modified since last scan "
                f"(or last {settings.incremental_window_days} days)",
            }[m],
        )
        live = source.startswith("Live")
        if live:
            st.caption(
                "Live mode calls NVD, CISA KEV, FIRST EPSS, OSV.dev and allow-listed vendor sites. "
                + (
                    "NVD API key configured."
                    if settings.nvd_api_key
                    else "No NVD API key: requests are paced at ~6 s each, so full scans take minutes."
                )
                + f" Web search: {settings.search_provider}. LLM research: {settings.llm_provider}."
            )
        if st.button("Start scan", type="primary", disabled=not items, icon=":material/radar:"):
            run_scan_ui(mode, demo=not live)
        if not items:
            st.caption("Import an inventory first.")

    st.subheader("History")
    scans = repo.list_scans(limit=50)
    if not scans:
        st.info("No scans yet.")
        return
    st.dataframe(
        pd.DataFrame(
            [
                {
                    "Scan": s.scan_id,
                    "Mode": s.mode,
                    "Status": s.status,
                    "Started (UTC)": s.started_at.strftime("%Y-%m-%d %H:%M:%S"),
                    "Finished (UTC)": s.finished_at.strftime("%Y-%m-%d %H:%M:%S")
                    if s.finished_at
                    else "",
                    "CVEs processed": s.cves_processed,
                    "Findings": s.findings_count,
                    "Issues": len(s.errors),
                }
                for s in scans
            ]
        ),
        hide_index=True,
    )
    for s in scans[:5]:
        with st.expander(f"Scan {s.scan_id} - sources and issues"):
            st.dataframe(
                pd.DataFrame(
                    [
                        {
                            "Source": x.source,
                            "State": x.state.value,
                            "Detail": x.detail or "",
                            "Checked (UTC)": x.retrieved_at.strftime("%Y-%m-%d %H:%M:%S")
                            if x.retrieved_at
                            else "",
                        }
                        for x in s.source_status
                    ]
                ),
                hide_index=True,
            )
            for e in s.errors:
                st.warning(e)


def page_export() -> None:
    st.title("Export")
    findings = all_findings()
    c1, c2 = st.columns(2)
    tiers = c1.multiselect("Priority", TIERS, default=[])
    statuses = c2.multiselect(
        "Match status", list(MatchStatus), default=[], format_func=status_label
    )
    chosen = [
        f
        for f in findings
        if (not tiers or f.priority.tier in tiers) and (not statuses or f.match.status in statuses)
    ]
    st.write(f"{len(chosen)} findings selected.")
    st.caption(DISCLAIMER)
    demo = any(f.cve_source == "demo-fixture" for f in chosen)
    d1, d2 = st.columns(2)
    d1.download_button(
        "Download JSON report",
        export_json(chosen, demo=demo),
        "terminus-findings.json",
        "application/json",
        type="primary",
        disabled=not chosen,
        icon=":material/data_object:",
    )
    d2.download_button(
        "Download CSV",
        export_csv(chosen),
        "terminus-findings.csv",
        "text/csv",
        disabled=not chosen,
        icon=":material/table:",
    )
    st.caption(
        "The JSON report separates verified_facts (with retrieval timestamps) from "
        "ai_interpretation. CSV cells are protected against spreadsheet formula injection."
    )


def page_method() -> None:
    st.title("Method & sources")
    cfg = RiskConfig()
    st.subheader("Match statuses")
    st.dataframe(
        pd.DataFrame(
            [
                (
                    status_label(MatchStatus.CONFIRMED_AFFECTED),
                    "Reliable identity (CPE, package id, curated alias, vendor+product) and the installed version "
                    "is inside an affected range from a structured source, with no contradicting source.",
                ),
                (
                    status_label(MatchStatus.POTENTIALLY_AFFECTED),
                    "In range but: name-only identity, sources disagree, distribution package (backports), "
                    "unbounded NVD entry, or a platform condition that cannot be evaluated.",
                ),
                (
                    status_label(MatchStatus.UNVERIFIED),
                    "Version missing or unparseable, identity ambiguous, or source data incomplete. "
                    "Never treated as safe.",
                ),
                (
                    status_label(MatchStatus.CONFIRMED_UNAFFECTED),
                    "Reliable identity and every reliable source places the version outside affected ranges "
                    "(NVD analysis complete or ecosystem advisory present).",
                ),
            ],
            columns=["Status", "Meaning"],
        ),
        hide_index=True,
    )

    st.subheader("Priority score")
    st.code(FORMULA, language=None)
    st.dataframe(
        pd.DataFrame(
            [
                ("Severity (CVSS)", cfg.w_severity, "base score / 10"),
                ("Known exploitation (CISA KEV)", cfg.w_known_exploitation, "listed = full points"),
                ("Exploit likelihood (EPSS)", cfg.w_exploit_likelihood, "sqrt(probability)"),
                ("Internet exposure", cfg.w_exposure, "internet-facing = full points"),
                (
                    "Asset criticality",
                    cfg.w_criticality,
                    "critical 1.0, high 0.7, medium 0.4, low 0.1",
                ),
                ("Environment", cfg.w_environment, "production 1.0, staging 0.4, dev/test 0.2"),
                ("Actionability", cfg.w_actionability, "fixed version known"),
            ],
            columns=["Factor", "Weight", "Scaling"],
        ),
        hide_index=True,
    )
    st.markdown(
        f"Tiers: P1 >= {cfg.tier_thresholds['P1']}, P2 >= {cfg.tier_thresholds['P2']}, "
        f"P3 >= {cfg.tier_thresholds['P3']}, otherwise P4; confirmed unaffected = INFO. "
        "Overrides: confirmed affected + KEV is at least P2 (P1 if internet-facing); unverified "
        "findings are capped at P2. Missing CVSS/EPSS/KEV/exposure/environment use documented "
        "placeholders and are listed as missing. Weights are configurable via TERMINUS_RISK_CONFIG."
    )
    st.subheader("Fixed versions")
    st.markdown(
        "- Only structured sources propose fixed versions: NVD `versionEndExcluding` and OSV "
        "`fixed` events.\n"
        "- **Verified**: an ecosystem advisory (OSV), NVD + OSV agreement, or NVD corroborated by an "
        "allow-listed vendor advisory page that mentions the CVE and version together.\n"
        "- **Single source**: NVD only. **Conflict**: sources disagree (highest named version shown "
        "as a conservative target). **Unknown**: consult the vendor advisory.\n"
        "- Vendor page text, web search results and AI output can never introduce a fixed version."
    )
    st.subheader("Data sources and attribution")
    st.markdown(
        "- **NVD** CVE API 2.0. *This product uses the NVD API but is not endorsed or certified by "
        "the NVD.*\n"
        "- **CISA Known Exploited Vulnerabilities** catalog.\n"
        "- **FIRST EPSS** - Exploit Prediction Scoring System (Jacobs et al., FIRST.org).\n"
        "- **OSV.dev** - open source vulnerability database (GitHub Security Advisories, PyPA, ...).\n"
        "- Official vendor advisories referenced by NVD/OSV, fetched only from allow-listed domains.\n"
        "- Optional: Tavily or Exa web search (supplementary, untrusted)."
    )
    st.subheader("Limitations")
    st.markdown(
        "- Distribution packages are compared against upstream ranges, so backported fixes appear "
        "as *potentially affected* until checked against the distribution tracker.\n"
        "- CVEs awaiting NVD analysis have no CPE data; they only surface as keyword candidates.\n"
        "- Inventory accuracy bounds result accuracy; missing vendors/versions reduce confidence.\n"
        "- Recommendations are not a substitute for vendor guidance and change management."
    )


PAGES = {
    "overview": st.Page(page_overview, title="Overview", icon=":material/dashboard:", default=True),
    "queue": st.Page(
        page_queue, title="Remediation queue", icon=":material/checklist:", url_path="queue"
    ),
    "findings": st.Page(
        page_findings, title="Findings", icon=":material/manage_search:", url_path="findings"
    ),
    "inventory": st.Page(
        page_inventory, title="Inventory", icon=":material/inventory_2:", url_path="inventory"
    ),
    "scans": st.Page(page_scans, title="Scans", icon=":material/radar:", url_path="scans"),
    "export": st.Page(page_export, title="Export", icon=":material/download:", url_path="export"),
    "method": st.Page(
        page_method, title="Method & sources", icon=":material/menu_book:", url_path="method"
    ),
}


def main() -> None:
    st.set_page_config(page_title="Terminus", page_icon=":material/shield:", layout="wide")
    nav = st.navigation(
        {
            "Assess": [PAGES["overview"], PAGES["queue"], PAGES["findings"]],
            "Operate": [PAGES["inventory"], PAGES["scans"], PAGES["export"]],
            "Reference": [PAGES["method"]],
        }
    )
    with st.sidebar:
        st.markdown("### Terminus")
        st.caption("Vulnerability intelligence & remediation agent")
        scans = repo.list_scans(limit=1)
        if scans:
            sc = scans[0]
            st.caption(
                f"Last scan: {(sc.finished_at or sc.started_at):%Y-%m-%d %H:%M} UTC "
                f"({sc.mode}, {sc.status})"
            )
        st.caption(f"Default data mode: {settings.mode}")
        st.caption("Read-only research. No patches are applied.")
    nav.run()


main()
