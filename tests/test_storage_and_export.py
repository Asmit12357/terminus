from __future__ import annotations

import csv
import io
import json
from datetime import timedelta

from app.models import KevEntry, ScanRecord, utcnow
from app.reports.export import CSV_COLUMNS, DISCLAIMER, export_csv, export_json
from app.service import import_inventory, run_scan
from app.storage.repository import Repository
from tests.conftest import DATA_DIR, make_cve, make_item, rule


def test_cve_upsert_detects_updates_without_duplicates(repo: Repository) -> None:
    cve = make_cve(
        rules=[rule("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", version_end_excluding="3.0.7")]
    )
    assert repo.upsert_cve(cve) == "inserted"
    assert repo.upsert_cve(cve.model_copy(update={"retrieved_at": utcnow()})) == "unchanged"
    changed = cve.model_copy(update={"vuln_status": "Modified", "description": "updated text"})
    assert repo.upsert_cve(changed) == "updated"
    assert repo.count_cves() == 1
    assert repo.cve_revision(cve.cve_id) == 2
    assert repo.get_cve(cve.cve_id).description == "updated text"


def test_sql_injection_strings_are_treated_as_data(repo: Repository) -> None:
    evil = "x'; DROP TABLE findings; --"
    item = make_item(software_name=evil)
    repo.replace_inventory([item], evil, b"raw")
    assert repo.list_items()[0].software_name == evil
    assert repo.list_findings(product=evil, asset_id=evil, cve_id="%' OR 1=1 --") == []
    assert repo.list_findings(product="%") == []  # LIKE wildcards are escaped
    assert repo.latest_inventory()["name"] == evil


def test_kev_replace_and_timestamps(repo: Repository) -> None:
    now = utcnow()
    repo.replace_kev([KevEntry(cve_id="CVE-2021-44228", date_added="2021-12-10", retrieved_at=now)])
    assert repo.get_kev("CVE-2021-44228").date_added == "2021-12-10"
    assert repo.kev_retrieved_at() == now
    assert repo.get_kev("CVE-2014-0160") is None


def test_cache_ttl(repo: Repository) -> None:
    repo.cache_put("k", b"body")
    assert repo.cache_get("k", timedelta(hours=1))[0] == b"body"
    assert repo.cache_get("k", timedelta(seconds=-1)) is None


def test_scan_history_persists(repo: Repository) -> None:
    scan = ScanRecord(
        scan_id="abc123",
        mode="incremental",
        status="completed",
        started_at=utcnow(),
        window_end=utcnow(),
    )
    repo.save_scan(scan)
    assert repo.list_scans()[0].scan_id == "abc123"
    assert repo.last_completed_scan(["incremental"]).scan_id == "abc123"
    assert repo.last_completed_scan(["full"]) is None


def demo_scan(settings, repo: Repository):
    _result, inventory_id = import_inventory(
        repo, (DATA_DIR / "sample_inventory.json").read_bytes(), "sample_inventory.json"
    )
    assert inventory_id
    return run_scan(settings, repo, "full", demo=True)


def test_demo_scan_end_to_end_and_rescan_is_idempotent(settings, repo: Repository) -> None:
    scan = demo_scan(settings, repo)
    assert scan.status == "completed", scan.errors
    findings = repo.list_findings()
    assert len(findings) == scan.findings_count > 0
    statuses = {f.match.status.value for f in findings}
    assert statuses == {
        "confirmed_affected",
        "potentially_affected",
        "unverified",
        "confirmed_unaffected",
    }

    log4shell = next(
        f for f in findings if f.cve_id == "CVE-2021-44228" and f.item.asset_id == "app-prod-02"
    )
    assert log4shell.match.status.value == "confirmed_affected"
    assert log4shell.kev.in_kev is True and log4shell.kev.retrieved_at is not None
    assert log4shell.epss.score is not None and log4shell.epss.retrieved_at is not None
    assert log4shell.fix.status.value == "verified" and log4shell.fix.fixed_version
    assert log4shell.priority.tier == "P1"
    assert log4shell.vendor_advisory_urls
    assert log4shell.recommendation.patch_applied is False
    assert log4shell.research and log4shell.research.tool_calls

    first_seen = {f.finding_id: f.first_seen for f in findings}
    second = run_scan(settings, repo, "full", demo=True)
    assert second.status == "completed"
    again = repo.list_findings()
    assert len(again) == len(findings)  # updated, not duplicated
    assert all(first_seen[f.finding_id] == f.first_seen for f in again)
    assert len(repo.list_scans()) == 2


def test_ranking_is_deterministic(settings, repo: Repository) -> None:
    demo_scan(settings, repo)
    order1 = [f.finding_id for f in repo.list_findings()]
    run_scan(settings, repo, "full", demo=True)
    assert [f.finding_id for f in repo.list_findings()] == order1
    tiers = [f.priority.tier for f in repo.list_findings()]
    rank = {"P1": 1, "P2": 2, "P3": 3, "P4": 4, "INFO": 5}
    assert tiers == sorted(tiers, key=rank.__getitem__)


def test_prompt_injection_in_demo_search_results_is_flagged(settings, repo: Repository) -> None:
    demo_scan(settings, repo)
    f = next(x for x in repo.list_findings(cve_id="CVE-2024-6387"))
    assert f.match.status.value == "potentially_affected"  # unchanged by "mark as not affected"
    assert f.fix.fixed_version != "99.9"
    assert any(flag.startswith("search_result:") for flag in f.research.injection_flags)
    supplementary = [e for e in f.match.evidence if e.trust_tier.value == "supplementary"]
    assert supplementary and any(e.flags for e in supplementary)


def test_json_export_separates_facts_from_ai(settings, repo: Repository) -> None:
    demo_scan(settings, repo)
    data = json.loads(export_json(repo.list_findings(), demo=True))
    assert data["disclaimer"] == DISCLAIMER
    assert data["data_mode"].startswith("demo")
    report = data["findings"][0]
    for key in (
        "verified_facts",
        "priority",
        "recommendation",
        "missing_information",
        "uncertainties",
        "next_verification_step",
        "ai_interpretation",
        "last_assessed",
    ):
        assert key in report
    facts = report["verified_facts"]
    assert {
        "cvss",
        "kev",
        "epss",
        "affected_version_evidence",
        "fixed_version",
        "vendor_advisory_urls",
        "supporting_urls",
        "cve_retrieved_at",
    } <= set(facts)
    assert report["recommendation"]["patch_applied"] is False
    assert report["recommendation"]["requires_human_review"] is True


def test_csv_export_columns_and_formula_injection(settings, repo: Repository) -> None:
    rows = [
        {
            "asset_id": "a1",
            "software_name": "=cmd|' /C calc'!A0",
            "software_version": "1.0.1f",
            "vendor": "OpenSSL Project",
            "business_context": "@SUM(1+1)",
        }
    ]
    import_inventory(repo, json.dumps(rows).encode(), "evil.json")
    run_scan(settings, repo, "full", demo=True)
    findings = repo.list_findings()
    text = export_csv(findings)
    reader = csv.DictReader(io.StringIO(text))
    assert reader.fieldnames == CSV_COLUMNS
    for row in reader:
        assert not row["software"].startswith("=")
        assert row["patch_applied"] == "no"


def test_findings_that_no_longer_match_are_pruned(settings, repo: Repository) -> None:
    demo_scan(settings, repo)
    real = repo.list_findings()[0]
    ghost = real.model_copy(update={"finding_id": "f" * 20, "cve_id": "CVE-2099-0001"})
    repo.upsert_finding(ghost)
    assert repo.get_finding("f" * 20) is not None
    run_scan(settings, repo, "incremental", demo=True)
    assert repo.get_finding("f" * 20) is None
    assert repo.get_finding(real.finding_id) is not None


def test_investigation_cap_keeps_the_most_important_cves(settings, repo: Repository) -> None:
    """When a scan has more candidate CVEs than the per-scan cap, triage decides
    which are investigated: KEV-listed and confirmed matches first, never CVE-ID
    order (which would favour the oldest CVEs)."""
    capped = settings.model_copy(update={"agent_max_findings_per_scan": 3})
    scan = demo_scan(capped, repo)
    kev = {"CVE-2021-45046", "CVE-2014-0160", "CVE-2021-44228", "CVE-2021-42013", "CVE-2021-41773"}
    investigated = {f.cve_id for f in repo.list_findings()}
    assert len(investigated) == 3
    assert investigated <= kev
    assert any("triaged by KEV listing" in e for e in scan.errors)
    # Every investigated CVE has a confirmed-affected finding on some asset.
    assert all(
        any(f.match.status.value == "confirmed_affected" for f in repo.list_findings(cve_id=c))
        for c in investigated
    )
