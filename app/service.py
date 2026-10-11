"""Application services shared by the CLI and the optional API and dashboard."""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path
from typing import Any

from app.agent.llm import build_llm_researcher
from app.config import Settings, get_settings
from app.diagnostics import require_research_config
from app.inventory import InventoryValidationResult, parse_inventory
from app.models import Finding, ScanRecord
from app.risk.scoring import RiskConfig
from app.scanner import ProgressFn, ScanMode, Scanner
from app.sources import build_sources
from app.storage.repository import Repository


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
    llm = build_llm_researcher(settings)
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
        return scanner.run(mode)
    finally:
        sources.close()


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
