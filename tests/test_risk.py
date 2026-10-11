from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.matching.matcher import match_item
from app.models import (
    CvssData,
    EpssStatus,
    FixAssessment,
    FixStatus,
    KevStatus,
    MatchStatus,
)
from app.risk.scoring import RiskConfig, score_finding
from tests.conftest import make_cve, make_item, rule

NOW = datetime(2026, 1, 1, tzinfo=UTC)
RANGE = rule(
    "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
    version_start_including="3.0.0",
    version_end_excluding="3.0.7",
)
FIX = FixAssessment(status=FixStatus.VERIFIED, fixed_version="3.0.7")


def cvss(score: float) -> CvssData:
    return CvssData(version="3.1", base_score=score, severity="HIGH")


def kev(listed: bool | None) -> KevStatus:
    return KevStatus(in_kev=listed, date_added="2022-01-01" if listed else None, retrieved_at=NOW)


def epss(score: float | None) -> EpssStatus:
    return EpssStatus(score=score, percentile=0.5 if score is not None else None, retrieved_at=NOW)


def affected(**item_kw: object):
    item = make_item(**item_kw)
    return item, match_item(item, make_cve(rules=[RANGE]))


def test_exploitation_evidence_and_context_change_priority() -> None:
    """Same CVSS, different exploitation evidence and asset context -> different priority.

    A: KEV-listed, EPSS 0.94, internet-facing, critical, production.
    B: not in KEV, EPSS 0.002, internal, low criticality, development.
    """
    item_a, match_a = affected(
        criticality="critical", internet_exposed=True, environment="production"
    )
    item_b, match_b = affected(criticality="low", internet_exposed=False, environment="development")
    a = score_finding(
        item=item_a, match=match_a, cvss=cvss(7.5), kev=kev(True), epss=epss(0.94), fix=FIX
    )
    b = score_finding(
        item=item_b, match=match_b, cvss=cvss(7.5), kev=kev(False), epss=epss(0.002), fix=FIX
    )
    assert a.tier == "P1"
    assert b.tier in ("P3", "P4")
    assert a.score - b.score > 40
    by_name = {f.name: f for f in a.factors}
    assert by_name["Known exploitation (CISA KEV)"].points == 25
    assert by_name["Severity (CVSS)"].points == pytest.approx(22.5)
    # Raw source values are preserved separately from derived points.
    assert by_name["Exploit likelihood (EPSS)"].raw_value.startswith("0.94000")


def test_kev_outranks_high_epss_and_is_not_conflated() -> None:
    item, match = affected(internet_exposed=False)
    kev_listed = score_finding(
        item=item, match=match, cvss=cvss(7.5), kev=kev(True), epss=epss(0.10), fix=FIX
    )
    epss_high = score_finding(
        item=item, match=match, cvss=cvss(7.5), kev=kev(False), epss=epss(0.97), fix=FIX
    )
    assert kev_listed.score > epss_high.score
    epss_factor = next(f for f in epss_high.factors if f.name.startswith("Exploit likelihood"))
    kev_factor = next(f for f in epss_high.factors if f.name.startswith("Known exploitation"))
    assert "not evidence that exploitation occurred" in epss_factor.explanation
    assert kev_factor.raw_value == "not listed"  # a high EPSS never implies KEV / exploited


def test_missing_data_is_flagged_not_zero() -> None:
    item, match = affected(internet_exposed=None, environment=None)
    result = score_finding(
        item=item, match=match, cvss=None, kev=kev(None), epss=epss(None), fix=FIX
    )
    assert set(result.missing_data) == {
        "CVSS score",
        "CISA KEV status",
        "EPSS score",
        "internet exposure",
        "environment",
    }
    missing = [f for f in result.factors if f.missing]
    assert len(missing) == 5
    assert all(f.points > 0 for f in missing)  # placeholders, not silent zeros
    assert result.score > 0


def test_status_and_confidence_scale_priority() -> None:
    item, confirmed = affected()
    potential = confirmed.model_copy(update={"status": MatchStatus.POTENTIALLY_AFFECTED})
    unverified = confirmed.model_copy(update={"status": MatchStatus.UNVERIFIED})
    unaffected = confirmed.model_copy(update={"status": MatchStatus.CONFIRMED_UNAFFECTED})
    args = dict(item=item, cvss=cvss(9.8), kev=kev(True), epss=epss(0.9), fix=FIX)
    scores = [
        score_finding(match=m, **args) for m in (confirmed, potential, unverified, unaffected)
    ]
    assert scores[0].score > scores[1].score > scores[2].score > scores[3].score == 0
    assert scores[3].tier == "INFO"
    assert scores[2].tier in ("P2", "P3", "P4")  # unverified is capped below P1
    assert any("Capped at P2" in o for o in scores[2].overrides) or scores[2].tier != "P1"


def test_kev_override_raises_tier() -> None:
    item, match = affected(criticality="low", environment="development", internet_exposed=True)
    result = score_finding(
        item=item,
        match=match,
        cvss=cvss(5.0),
        kev=kev(True),
        epss=epss(0.01),
        fix=FixAssessment(status=FixStatus.UNKNOWN),
    )
    assert result.tier == "P1"
    assert result.overrides and "CISA KEV" in result.overrides[0]


def test_ranking_is_deterministic_and_configurable() -> None:
    item, match = affected()
    args = dict(item=item, match=match, cvss=cvss(8.1), kev=kev(False), epss=epss(0.3), fix=FIX)
    assert score_finding(**args) == score_finding(**args)
    heavy_severity = RiskConfig(w_severity=60)
    assert score_finding(config=heavy_severity, **args).score > score_finding(**args).score


def test_risk_config_loads_from_json(tmp_path) -> None:
    path = tmp_path / "risk.json"
    path.write_text('{"w_exposure": 20, "tier_thresholds": {"P1": 80, "P2": 60, "P3": 40}}')
    cfg = RiskConfig.load(path)
    assert cfg.w_exposure == 20 and cfg.tier_thresholds["P1"] == 80
    assert RiskConfig.load(None).w_exposure == 10
