"""Explainable, deterministic risk prioritization.

    raw     = severity + known_exploitation + exploit_likelihood
              + exposure + asset_criticality + environment + actionability
    score   = raw * status_factor * (0.85 + 0.15 * identity_confidence)
    tier    = P1 (>= 70) | P2 (>= 50) | P3 (>= 30) | P4 (< 30) | INFO (unaffected)
    then documented overrides are applied (see ``_overrides``).

Signals are deliberately kept separate:
- CVSS measures technical severity, not likelihood.
- KEV means CISA has evidence of exploitation in the wild.
- EPSS is a probability of exploitation activity in the next 30 days. A high
  EPSS score is never reported as "exploited".

Missing inputs never become zero risk: each uses a documented placeholder
value, is listed in ``missing_data``, and is labelled "missing" in the factor.
All weights and thresholds are configurable via ``RiskConfig``
(``TERMINUS_RISK_CONFIG`` JSON file).
"""

from __future__ import annotations

import json
import math
from pathlib import Path

from pydantic import BaseModel, Field

from terminus.models import (
    Criticality,
    CvssData,
    Environment,
    EpssStatus,
    FixAssessment,
    FixStatus,
    InventoryItem,
    KevStatus,
    MatchResult,
    MatchStatus,
    PriorityFactor,
    PriorityResult,
)


class RiskConfig(BaseModel):
    w_severity: float = Field(30, ge=0)
    w_known_exploitation: float = Field(25, ge=0)
    w_exploit_likelihood: float = Field(15, ge=0)
    w_exposure: float = Field(10, ge=0)
    w_criticality: float = Field(10, ge=0)
    w_environment: float = Field(5, ge=0)
    w_actionability: float = Field(5, ge=0)

    criticality_fraction: dict[Criticality, float] = {
        Criticality.CRITICAL: 1.0,
        Criticality.HIGH: 0.7,
        Criticality.MEDIUM: 0.4,
        Criticality.LOW: 0.1,
    }
    environment_fraction: dict[Environment, float] = {
        Environment.PRODUCTION: 1.0,
        Environment.STAGING: 0.4,
        Environment.DEVELOPMENT: 0.2,
        Environment.TEST: 0.2,
    }
    status_factor: dict[MatchStatus, float] = {
        MatchStatus.CONFIRMED_AFFECTED: 1.0,
        MatchStatus.POTENTIALLY_AFFECTED: 0.75,
        MatchStatus.UNVERIFIED: 0.5,
        MatchStatus.CONFIRMED_UNAFFECTED: 0.0,
    }

    # Placeholders for missing data (documented, flagged, never silent zeros).
    missing_cvss_assumed: float = Field(5.0, ge=0, le=10)
    missing_epss_assumed: float = Field(0.05, ge=0, le=1)
    unknown_kev_fraction: float = Field(0.2, ge=0, le=1)
    unknown_exposure_fraction: float = Field(0.5, ge=0, le=1)
    unknown_environment_fraction: float = Field(0.6, ge=0, le=1)

    tier_thresholds: dict[str, float] = {"P1": 70, "P2": 50, "P3": 30}

    @classmethod
    def load(cls, path: Path | None) -> RiskConfig:
        if path is None:
            return cls()
        return cls.model_validate(json.loads(Path(path).read_text(encoding="utf-8")))


FORMULA = (
    "score = (severity + known_exploitation + exploit_likelihood + exposure + "
    "asset_criticality + environment + actionability) x status_factor x "
    "(0.85 + 0.15 x identity_confidence)"
)


def _tier(score: float, cfg: RiskConfig) -> str:
    for tier in ("P1", "P2", "P3"):
        if score >= cfg.tier_thresholds[tier]:
            return tier
    return "P4"


_ORDER = ["P1", "P2", "P3", "P4"]


def _at_least(tier: str, floor: str) -> str:
    return floor if _ORDER.index(floor) < _ORDER.index(tier) else tier


def _at_most(tier: str, cap: str) -> str:
    return cap if _ORDER.index(tier) < _ORDER.index(cap) else tier


def score_finding(
    *,
    item: InventoryItem,
    match: MatchResult,
    cvss: CvssData | None,
    kev: KevStatus,
    epss: EpssStatus,
    fix: FixAssessment,
    config: RiskConfig | None = None,
) -> PriorityResult:
    cfg = config or RiskConfig()
    factors: list[PriorityFactor] = []
    missing: list[str] = []

    # 1. Severity (CVSS base score)
    if cvss is not None:
        pts = cfg.w_severity * cvss.base_score / 10
        factors.append(
            PriorityFactor(
                name="Severity (CVSS)",
                raw_value=f"{cvss.base_score} (CVSS v{cvss.version}"
                + (f", {cvss.severity}" if cvss.severity else "")
                + ")",
                points=pts,
                max_points=cfg.w_severity,
                explanation="CVSS base score / 10 x weight. Measures technical severity only.",
            )
        )
    else:
        pts = cfg.w_severity * cfg.missing_cvss_assumed / 10
        missing.append("CVSS score")
        factors.append(
            PriorityFactor(
                name="Severity (CVSS)",
                raw_value="missing",
                points=pts,
                max_points=cfg.w_severity,
                explanation=f"No CVSS score published; ranked as if {cfg.missing_cvss_assumed} "
                "(placeholder, not a measured value).",
                missing=True,
            )
        )

    # 2. Known exploitation (CISA KEV)
    if kev.in_kev is True:
        factors.append(
            PriorityFactor(
                name="Known exploitation (CISA KEV)",
                raw_value=f"listed (added {kev.date_added or 'unknown date'})",
                points=cfg.w_known_exploitation,
                max_points=cfg.w_known_exploitation,
                explanation="CISA KEV lists this CVE: there is evidence of exploitation in the wild.",
            )
        )
    elif kev.in_kev is False:
        factors.append(
            PriorityFactor(
                name="Known exploitation (CISA KEV)",
                raw_value="not listed",
                points=0.0,
                max_points=cfg.w_known_exploitation,
                explanation="Not in the KEV catalog. This does not prove the CVE is unexploited.",
            )
        )
    else:
        missing.append("CISA KEV status")
        factors.append(
            PriorityFactor(
                name="Known exploitation (CISA KEV)",
                raw_value="unknown (source unavailable)",
                points=cfg.w_known_exploitation * cfg.unknown_kev_fraction,
                max_points=cfg.w_known_exploitation,
                explanation="KEV catalog could not be checked; a partial placeholder is applied.",
                missing=True,
            )
        )

    # 3. Exploit likelihood (EPSS)
    if epss.score is not None:
        pts = cfg.w_exploit_likelihood * math.sqrt(epss.score)
        pct = f", percentile {epss.percentile:.3f}" if epss.percentile is not None else ""
        factors.append(
            PriorityFactor(
                name="Exploit likelihood (EPSS)",
                raw_value=f"{epss.score:.5f}{pct}",
                points=pts,
                max_points=cfg.w_exploit_likelihood,
                explanation="sqrt(EPSS probability) x weight. A probability of future exploitation "
                "activity, not evidence that exploitation occurred.",
            )
        )
    else:
        missing.append("EPSS score")
        factors.append(
            PriorityFactor(
                name="Exploit likelihood (EPSS)",
                raw_value="missing",
                points=cfg.w_exploit_likelihood * math.sqrt(cfg.missing_epss_assumed),
                max_points=cfg.w_exploit_likelihood,
                explanation=f"No EPSS score available; ranked as if {cfg.missing_epss_assumed}.",
                missing=True,
            )
        )

    # 4. Exposure
    if item.internet_exposed is None:
        missing.append("internet exposure")
        factors.append(
            PriorityFactor(
                name="Internet exposure",
                raw_value="unknown",
                points=cfg.w_exposure * cfg.unknown_exposure_fraction,
                max_points=cfg.w_exposure,
                explanation="Exposure not recorded in inventory; half weight applied.",
                missing=True,
            )
        )
    else:
        factors.append(
            PriorityFactor(
                name="Internet exposure",
                raw_value="internet-facing" if item.internet_exposed else "internal",
                points=cfg.w_exposure if item.internet_exposed else 0.0,
                max_points=cfg.w_exposure,
                explanation="Internet-facing assets are reachable by more attackers.",
            )
        )

    # 5. Asset criticality
    factors.append(
        PriorityFactor(
            name="Asset criticality",
            raw_value=item.criticality.value,
            points=cfg.w_criticality * cfg.criticality_fraction[item.criticality],
            max_points=cfg.w_criticality,
            explanation="Business importance recorded in the inventory.",
        )
    )

    # 6. Environment
    if item.environment is None:
        missing.append("environment")
        env_pts = cfg.w_environment * cfg.unknown_environment_fraction
        env_raw, env_missing = "unknown", True
    else:
        env_pts = cfg.w_environment * cfg.environment_fraction[item.environment]
        env_raw, env_missing = item.environment.value, False
    factors.append(
        PriorityFactor(
            name="Environment",
            raw_value=env_raw,
            points=env_pts,
            max_points=cfg.w_environment,
            explanation="Production systems carry live data and users.",
            missing=env_missing,
        )
    )

    # 7. Actionability (verified fix available)
    fix_known = fix.status in (FixStatus.VERIFIED, FixStatus.SINGLE_SOURCE)
    factors.append(
        PriorityFactor(
            name="Actionability (fix available)",
            raw_value=f"{fix.status.value}"
            + (f" ({fix.fixed_version})" if fix.fixed_version else ""),
            points=cfg.w_actionability if fix_known else 0.0,
            max_points=cfg.w_actionability,
            explanation="A known fixed version makes remediation immediately actionable, so it is "
            "ranked slightly ahead of otherwise-equal findings.",
        )
    )

    raw = sum(f.points for f in factors)
    status_factor = cfg.status_factor[match.status]
    multiplier = status_factor * (0.85 + 0.15 * match.identity_method.confidence)
    score = round(raw * multiplier, 1)

    overrides: list[str] = []
    if match.status == MatchStatus.CONFIRMED_UNAFFECTED:
        tier = "INFO"
    else:
        tier = _tier(score, cfg)
        if match.status == MatchStatus.CONFIRMED_AFFECTED and kev.in_kev:
            floor = "P1" if item.internet_exposed else "P2"
            new = _at_least(tier, floor)
            if new != tier:
                overrides.append(
                    f"Raised to {new}: confirmed affected + CISA KEV"
                    + (" + internet-facing" if item.internet_exposed else "")
                )
                tier = new
        if match.status == MatchStatus.UNVERIFIED:
            new = _at_most(tier, "P2")
            if new != tier:
                overrides.append("Capped at P2: verification is required before P1 escalation")
                tier = new

    return PriorityResult(
        score=score,
        tier=tier,
        factors=[f.model_copy(update={"points": round(f.points, 2)}) for f in factors],
        confidence_multiplier=round(multiplier, 3),
        missing_data=missing,
        overrides=overrides,
        formula=FORMULA,
    )
