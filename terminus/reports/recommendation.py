"""Deterministic remediation recommendations.

Recommendations are generated from verified facts only. Terminus never applies
patches; every recommendation requires human review before any operational
change (``requires_human_review=True``, ``patch_applied=False``).
"""

from __future__ import annotations

from terminus.models import (
    FixAssessment,
    FixStatus,
    IdentityMethod,
    InventoryItem,
    KevStatus,
    MatchResult,
    MatchStatus,
    Recommendation,
)
from terminus.security import sanitize_untrusted


def _status_reason(match: MatchResult) -> str:
    """The reason that explains the status (not the identity line or fix notes)."""
    for reason in match.reasons:
        if not reason.startswith(("Identity:", "No structured source states")):
            return reason
    return ""


def _advisory_hint(advisory_urls: list[str]) -> str:
    return advisory_urls[0] if advisory_urls else "the vendor's official security advisory"


def next_verification_step(item: InventoryItem, match: MatchResult, fix: FixAssessment) -> str:
    reasons = " ".join(match.reasons).lower()
    if match.status == MatchStatus.CONFIRMED_UNAFFECTED:
        return "None required for this CVE; re-assess automatically if NVD or the vendor revises ranges."
    if item.software_version is None:
        return f"Record the installed version of {item.software_name} on {item.asset_id} in the inventory."
    if "could not be compared" in reasons or "cannot compare" in reasons:
        return (
            f"Record the exact upstream version string for {item.software_name} "
            f"(current value '{item.software_version}' could not be parsed reliably)."
        )
    if item.ecosystem.is_distro_package and match.status == MatchStatus.POTENTIALLY_AFFECTED:
        return (
            "Check the distribution security tracker (e.g. Ubuntu USN, Debian DSA/security-tracker, "
            "Red Hat RHSA) for the package version that contains the fix and compare it with "
            f"{item.software_version}."
        )
    if match.identity_method in (IdentityMethod.NAME_ONLY, IdentityMethod.AMBIGUOUS):
        return (
            f"Confirm that '{item.software_name}' on {item.asset_id} is the vendor product named in "
            "the advisory (add a CPE, package URL or vendor to the inventory)."
        )
    if (
        "not completed analysis" in reasons
        or "not published affected" in reasons
        or "analysis is not complete" in reasons
    ):
        return "Review the vendor advisory for affected versions; re-scan after NVD completes analysis."
    if fix.status == FixStatus.CONFLICT:
        return "Resolve the conflicting fixed versions against the official vendor advisory."
    if fix.status == FixStatus.UNKNOWN:
        return "Locate the fixed release or official mitigation in the vendor advisory."
    if fix.status == FixStatus.SINGLE_SOURCE:
        return f"Confirm {fix.fixed_version} as the fixed release in the vendor advisory before deploying."
    return "After the change window, confirm the deployed version and re-scan."


def build_recommendation(
    item: InventoryItem,
    match: MatchResult,
    fix: FixAssessment,
    kev: KevStatus,
    advisory_urls: list[str],
) -> Recommendation:
    where = (
        f"{item.software_name} {item.software_version or '(version unknown)'} on {item.asset_id}"
    )
    advisory = _advisory_hint(advisory_urls)
    steps: list[str] = []

    if match.status == MatchStatus.CONFIRMED_UNAFFECTED:
        return Recommendation(
            action="none",
            summary=f"No action required for {match.cve_id}: {where} is outside the affected ranges.",
            steps=["Keep the inventory version current so future assessments stay accurate."],
        )

    if match.status == MatchStatus.CONFIRMED_AFFECTED:
        if fix.status == FixStatus.VERIFIED:
            action = "upgrade"
            summary = (
                f"Upgrade {where} to {fix.fixed_version} or later "
                f"(fixed version verified: {', '.join(sorted({s.source for s in fix.sources}))})."
            )
            steps += [
                f"Plan an upgrade of {item.software_name} to >= {fix.fixed_version}; check other open "
                "findings for this software so one change resolves all of them.",
                "Test the upgrade in a non-production environment.",
                "Deploy through the normal change process, then confirm the running version.",
                "Re-run a Terminus scan to confirm the finding closes.",
            ]
        elif fix.status == FixStatus.SINGLE_SOURCE:
            action = "upgrade"
            summary = (
                f"Upgrade {where} to {fix.fixed_version} or later - per NVD only; confirm in {advisory} "
                "before deploying."
            )
            steps += [
                f"Confirm in {advisory} that {fix.fixed_version} fixes {match.cve_id}.",
                "Test, deploy through change control, confirm the running version, re-scan.",
            ]
        elif fix.status == FixStatus.CONFLICT and fix.conservative_target:
            action = "upgrade"
            summary = (
                f"Upgrade {where} to {fix.conservative_target} or later. Structured sources "
                f"disagree on the fixed version; {fix.conservative_target} is the highest version "
                f"any of them names, so it satisfies all of them. Confirm in {advisory}."
            )
            steps += fix.notes
            steps.append(
                "Test, deploy through change control, confirm the running version, re-scan."
            )
        elif fix.status == FixStatus.CONFLICT:
            action = "verify"
            summary = (
                f"{where} is affected, but sources disagree on the fixed version. Determine the "
                f"correct target from {advisory}; no version is recommended until then."
            )
            steps += fix.notes
        else:
            action = "mitigate"
            summary = (
                f"{where} is affected and no fixed version could be verified. Consult {advisory} for "
                "a patch or vendor-documented mitigation."
            )
            steps += [
                f"Read {advisory} for patches, workarounds or configuration mitigations.",
                "Until fixed, reduce exposure (restrict network access, disable the affected "
                "feature if the vendor documents that as a mitigation).",
            ]
    elif match.status == MatchStatus.POTENTIALLY_AFFECTED:
        action = "verify"
        summary = (
            f"{where} may be affected by {match.cve_id}; verification is required. "
            f"{_status_reason(match)}"
        )
        if fix.fixed_version:
            steps.append(
                f"If confirmed affected, the structured sources indicate {fix.fixed_version} "
                f"({fix.status.value}) as the fixed upstream version."
            )
    else:
        action = "verify"
        summary = (
            f"Exposure of {where} to {match.cve_id} could not be determined. "
            f"{_status_reason(match)}"
        )

    if kev.in_kev and kev.required_action:
        required = sanitize_untrusted(kev.required_action, max_chars=400).text
        due = f" (CISA due date for US federal agencies: {kev.due_date})" if kev.due_date else ""
        steps.append(f"CISA KEV required action: {required}{due}")
    if item.internet_exposed and action in ("upgrade", "mitigate", "verify"):
        steps.append(
            "The asset is internet-facing: consider temporary exposure reduction while the change is scheduled."
        )
    steps.append(next_verification_step(item, match, fix))
    steps.append(
        "Human review required: Terminus generates recommendations only and has not changed any system."
    )

    return Recommendation(action=action, summary=summary.strip(), steps=steps)
