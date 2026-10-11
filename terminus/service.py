"""Application services shared by the CLI and the optional API and dashboard."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from terminus.agent.llm import build_llm_researcher
from terminus.config import Settings, get_settings
from terminus.diagnostics import require_research_config
from terminus.inventory import InventoryValidationResult, parse_inventory
from terminus.models import DEMO_SOURCE, Finding, ScanRecord
from terminus.risk.scoring import RiskConfig
from terminus.scanner import ProgressFn, ScanMode, Scanner
from terminus.sources import build_sources
from terminus.storage.repository import Repository


def get_repo(settings: Settings | None = None) -> Repository:
    return Repository((settings or get_settings()).db_path)


def import_inventory(
    repo: Repository, content: bytes, filename: str
) -> tuple[InventoryValidationResult, str | None]:
    """Validate and, only if there are no errors, replace the active inventory."""
    result = parse_inventory(content, filename)
    if not result.ok:
        return result, None
    safe_name = "".join(c for c in filename if c.isalnum() or c in "._- ")[:100] or "inventory"
    return result, repo.replace_inventory(result.items, safe_name, content)


class LiveDataPresent(RuntimeError):
    """A demo scan was requested on a database that holds live results."""


def check_data_mode(repo: Repository, *, demo: bool) -> None:
    """Demo and live data never share a database: recorded demo CVEs would
    otherwise be matched, ranked and reported alongside live results."""
    if demo and repo.cve_sources() - {DEMO_SOURCE}:
        raise LiveDataPresent(
            "this database holds live scan results; a demo scan would mix recorded demo "
            "data into them"
        )


def run_scan(
    settings: Settings,
    repo: Repository,
    mode: ScanMode = "incremental",
    *,
    demo: bool | None = None,
    progress: ProgressFn | None = None,
) -> ScanRecord:
    """Run one scan. Raises ConfigurationError before touching any source when a
    configured research provider cannot run."""
    use_demo = settings.is_demo if demo is None else demo
    require_research_config(settings, demo=use_demo)
    check_data_mode(repo, demo=use_demo)
    llm = build_llm_researcher(settings)
    notices: list[str] = []
    if not use_demo and DEMO_SOURCE in repo.cve_sources():
        findings, cves = repo.remove_demo_data()
        notices.append(
            f"Removed demo data before this live scan: {findings} demo findings and {cves} "
            "recorded CVE records (inventory and scan history kept). Run "
            "`terminus scan --mode full` to assess the whole inventory against live data."
        )
    sources = build_sources(settings, repo, demo=use_demo)
    try:
        scanner = Scanner(
            settings,
            repo,
            sources,
            risk_config=RiskConfig.load(_risk_path()),
            llm=llm,
            progress=progress,
        )
        scan = scanner.run(mode)
    finally:
        sources.close()
    if notices:
        scan.notices = [*notices, *scan.notices]
        repo.save_scan(scan)
    return scan


def _risk_path() -> Path | None:
    value = os.environ.get("TERMINUS_RISK_CONFIG")
    return Path(value) if value else None


def summarize(findings: list[Finding]) -> dict[str, Any]:
    return {
        "total": len(findings),
        "by_status": dict(Counter(f.match.status.value for f in findings)),
        "by_tier": dict(Counter(f.priority.tier for f in findings)),
        "kev_listed": sum(1 for f in findings if f.kev.in_kev),
        "assets_affected": len(
            {f.item.asset_id for f in findings if f.match.status.value == "confirmed_affected"}
        ),
    }
