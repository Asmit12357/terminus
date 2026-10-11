from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from app.config import Settings
from app.models import (
    ConfigNode,
    Configuration,
    CpeMatchRule,
    CveRecord,
    CvssData,
    InventoryItem,
    OsvAdvisory,
    OsvAffected,
    OsvEvent,
    OsvRange,
    Reference,
)
from app.storage.repository import Repository

# Never let a test pick up a developer's real keys or settings. Test-control flags
# (opt-in suites) are not settings and are kept.
_TEST_FLAGS = {"TERMINUS_INSTALL_TESTS"}
for _name in list(os.environ):
    if _name.startswith("TERMINUS_") and _name not in _TEST_FLAGS:
        del os.environ[_name]

FIXED_TIME = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
DATA_DIR = Path(__file__).resolve().parent.parent / "app" / "data"


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        _env_file=None,
        db_path=tmp_path / "terminus-test.db",
        mode="live",
        http_max_retries=2,
        http_backoff_base_seconds=0.0,
        agent_max_seconds=30,
    )


@pytest.fixture
def repo(settings: Settings) -> Repository:
    return Repository(settings.db_path)


def make_item(**kw: Any) -> InventoryItem:
    base: dict[str, Any] = {
        "asset_id": "srv-01",
        "hostname": "srv-01.corp.example",
        "software_name": "OpenSSL",
        "software_version": "3.0.5",
        "vendor": "OpenSSL Project",
        "criticality": "high",
        "internet_exposed": True,
        "environment": "production",
    }
    base.update(kw)
    return InventoryItem.model_validate(base)


def rule(criteria: str, vulnerable: bool = True, **bounds: str) -> CpeMatchRule:
    return CpeMatchRule(criteria=criteria, vulnerable=vulnerable, **bounds)


def make_cve(
    cve_id: str = "CVE-2022-3602",
    rules: list[CpeMatchRule] | None = None,
    *,
    configurations: list[Configuration] | None = None,
    status: str = "Analyzed",
    score: float | None = 7.5,
    description: str = "A buffer overrun in X.509 certificate verification.",
    references: list[Reference] | None = None,
) -> CveRecord:
    if configurations is None:
        configurations = [Configuration(nodes=[ConfigNode(matches=rules or [])])] if rules else []
    return CveRecord(
        cve_id=cve_id,
        published=FIXED_TIME,
        last_modified=FIXED_TIME,
        vuln_status=status,
        description=description,
        cvss=CvssData(
            version="3.1",
            base_score=score,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            severity="HIGH",
        )
        if score is not None
        else None,
        configurations=configurations,
        references=references or [],
        retrieved_at=FIXED_TIME,
    )


def make_osv(
    osv_id: str,
    cve_id: str,
    ecosystem: str,
    name: str,
    events: list[dict[str, str]],
    range_type: str = "ECOSYSTEM",
) -> OsvAdvisory:
    return OsvAdvisory(
        id=osv_id,
        aliases=[cve_id],
        summary="test advisory",
        affected=[
            OsvAffected(
                ecosystem=ecosystem,
                name=name,
                ranges=[OsvRange(type=range_type, events=[OsvEvent(**e) for e in events])],
            )
        ],
        references=[Reference(url=f"https://github.com/advisories/{osv_id}", tags=["ADVISORY"])],
        retrieved_at=FIXED_TIME,
    )
