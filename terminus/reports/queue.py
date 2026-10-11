"""Consolidated remediation plan: one row per software installation.

For each inventory item with open findings, the plan names the highest fixed
version across those findings (so one change resolves all of them) and lists
caveats wherever a fix is unverified, single-source or conflicting. Shared by
the CLI ``queue`` command and the optional dashboard.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass

from terminus.matching.versions import Scheme, VersionParseError, compare, scheme_for
from terminus.models import Finding, FixStatus, MatchStatus

TIER_ORDER = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "INFO": 4}


@dataclass(frozen=True)
class PlanRow:
    highest_tier: str
    max_score: float
    asset_id: str
    software: str
    installed_version: str | None
    open_cves: list[str]
    kev_listed: int
    target_version: str | None
    caveats: list[str]

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def upgrade_target(findings: list[Finding]) -> tuple[str | None, list[str]]:
    """Highest fixed version across one item's findings and caveats about it."""
    notes: list[str] = []
    item = findings[0].item
    scheme = Scheme.GENERIC if item.ecosystem.is_distro_package else scheme_for(item.ecosystem)
    candidates: list[str] = []
    for f in findings:
        if f.match.status == MatchStatus.CONFIRMED_UNAFFECTED:
            continue
        v = f.fix.fixed_version or f.fix.conservative_target
        if v:
            candidates.append(v)
        if f.fix.status == FixStatus.UNKNOWN and f.match.status == MatchStatus.CONFIRMED_AFFECTED:
            notes.append(f"{f.cve_id}: no verified fix")
        if f.fix.status == FixStatus.CONFLICT:
            notes.append(f"{f.cve_id}: sources conflict")
        if f.fix.status == FixStatus.SINGLE_SOURCE:
            notes.append(f"{f.cve_id}: single source")
    if not candidates:
        return None, notes
    best = candidates[0]
    for v in candidates[1:]:
        try:
            if compare(v, best, scheme) > 0:
                best = v
        except VersionParseError:
            return None, [*notes, "fixed versions could not be ordered"]
    if item.ecosystem.is_distro_package:
        notes.append("upstream version; use the distribution's fixed package")
    return best, notes


def remediation_plan(
    findings: list[Finding], *, include_potential: bool = True, include_unverified: bool = True
) -> list[PlanRow]:
    wanted = {MatchStatus.CONFIRMED_AFFECTED}
    if include_potential:
        wanted.add(MatchStatus.POTENTIALLY_AFFECTED)
    if include_unverified:
        wanted.add(MatchStatus.UNVERIFIED)
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        if f.match.status in wanted:
            groups[f.match.item_id].append(f)
    rows = []
    for fs in groups.values():
        item = fs[0].item
        target, notes = upgrade_target(fs)
        rows.append(
            PlanRow(
                highest_tier=min((f.priority.tier for f in fs), key=lambda t: TIER_ORDER[t]),
                max_score=max(f.priority.score for f in fs),
                asset_id=item.asset_id,
                software=item.software_name,
                installed_version=item.software_version,
                open_cves=sorted({f.cve_id for f in fs}),
                kev_listed=len({f.cve_id for f in fs if f.kev.in_kev}),
                target_version=target,
                caveats=list(dict.fromkeys(notes)),
            )
        )
    return sorted(rows, key=lambda r: (TIER_ORDER[r.highest_tier], -r.max_score, r.asset_id))
