"""Fixed-version verification.

Rules (README, "Fixed versions"):
- Candidates come only from structured sources: NVD ``versionEndExcluding`` on
  the range that contains the installed version, and OSV ``fixed`` events.
- OSV (ecosystem advisory database) alone, or NVD + OSV agreeing  -> VERIFIED.
- NVD alone -> SINGLE_SOURCE, upgraded to VERIFIED only if an allow-listed
  vendor advisory page mentions the CVE and that exact version nearby.
- Sources disagreeing -> CONFLICT (no version is recommended).
- No candidate -> UNKNOWN (consult the official advisory).
- Vendor page text, search results and LLM output can never add a candidate.
- Distribution packages: an upstream fixed version is not the distro package
  version, so it is reported as "upstream" and never marked VERIFIED.
"""

from __future__ import annotations

from terminus.connectors.vendor import VendorPage
from terminus.matching.versions import Scheme, VersionParseError, compare, scheme_for
from terminus.models import (
    FixAssessment,
    FixCandidate,
    FixStatus,
    InventoryItem,
    MatchResult,
    MatchStatus,
    TrustTier,
)


def _same_version(a: str, b: str, scheme: Scheme) -> bool:
    if a == b:
        return True
    try:
        return compare(a, b, scheme) == 0
    except VersionParseError:
        return False


def _highest(versions: list[str], scheme: Scheme) -> str | None:
    """Highest version, or None if any pair cannot be ordered reliably."""
    best = versions[0]
    for v in versions[1:]:
        try:
            if compare(v, best, scheme) > 0:
                best = v
        except VersionParseError:
            return None
    return best


def assess_fix(
    item: InventoryItem,
    match: MatchResult,
    vendor_pages: list[VendorPage] | None = None,
) -> FixAssessment:
    if match.status == MatchStatus.CONFIRMED_UNAFFECTED:
        return FixAssessment(
            status=FixStatus.NOT_APPLICABLE,
            notes=["Installed version is outside the affected ranges; no fix needed for this CVE"],
        )

    candidates = [
        c for c in match.fix_candidates if c.trust_tier == TrustTier.AUTHORITATIVE_STRUCTURED
    ]
    if not candidates:
        return FixAssessment(
            status=FixStatus.UNKNOWN,
            notes=[
                "No structured source states a fixed version for the affected range. "
                "Consult the official vendor advisory; Terminus does not infer patch versions."
            ],
        )

    scheme = Scheme.GENERIC if item.ecosystem.is_distro_package else scheme_for(item.ecosystem)
    groups: list[list[FixCandidate]] = []
    for cand in candidates:
        for group in groups:
            if _same_version(group[0].version, cand.version, scheme):
                group.append(cand)
                break
        else:
            groups.append([cand])

    if len(groups) > 1:
        listed = "; ".join(f"{g[0].version} ({', '.join(c.source for c in g)})" for g in groups)
        target = _highest([g[0].version for g in groups], scheme)
        conflict_notes = [
            f"Structured sources disagree on the fixed version: {listed}. "
            "Confirm the correct target in the official vendor advisory."
        ]
        if target:
            conflict_notes.append(
                f"{target} is the highest fixed version named by any structured source; "
                "upgrading to it satisfies every source's claim."
            )
        return FixAssessment(
            status=FixStatus.CONFLICT,
            sources=candidates,
            conservative_target=target,
            notes=conflict_notes,
        )

    group = groups[0]
    version = group[0].version
    notes: list[str] = []
    has_osv = any(c.source.startswith("OSV") for c in group)
    has_nvd = any(c.source.startswith("NVD") for c in group)
    sources = list(group)

    corroborating = [
        p
        for p in (vendor_pages or [])
        if not p.injection_flags and p.corroborates_fix(match.cve_id, version)
    ]
    for page in corroborating:
        sources.append(
            FixCandidate(
                version=version,
                source="Vendor advisory text (corroboration)",
                trust_tier=TrustTier.VENDOR_ADVISORY,
                url=page.final_url,
            )
        )
        notes.append(f"Vendor advisory {page.final_url} mentions {match.cve_id} and {version}")
    flagged = [p for p in (vendor_pages or []) if p.injection_flags]
    if flagged:
        notes.append(
            "Vendor page(s) contained instruction-like text and were not used for corroboration: "
            + ", ".join(p.final_url for p in flagged)
        )

    if item.ecosystem.is_distro_package:
        notes.append(
            f"{version} is the upstream fixed version. Distribution packages carry their own "
            "version numbers; check the distribution's security tracker for the fixed package."
        )
        return FixAssessment(
            status=FixStatus.SINGLE_SOURCE, fixed_version=version, sources=sources, notes=notes
        )

    if has_osv or (has_nvd and corroborating):
        if has_osv and has_nvd:
            notes.append("NVD and the ecosystem advisory (OSV) agree on the fixed version")
        elif has_osv:
            notes.append("Fixed version taken from the ecosystem advisory database (OSV)")
        return FixAssessment(
            status=FixStatus.VERIFIED, fixed_version=version, sources=sources, notes=notes
        )

    notes.append(
        "Fixed version comes from NVD only (first unaffected version of the range); "
        "confirm against the vendor advisory before deploying."
    )
    return FixAssessment(
        status=FixStatus.SINGLE_SOURCE, fixed_version=version, sources=sources, notes=notes
    )
