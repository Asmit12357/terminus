"""Structured finding reports and JSON/CSV export.

Every report separates ``verified_facts`` (values from structured sources,
each with retrieval timestamps) from ``ai_interpretation`` (optional LLM
narrative, explicitly labelled unverified). Exports state that Terminus only
recommends: no patch has been applied.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any

from app.models import Finding, utcnow
from app.security import csv_safe

DISCLAIMER = (
    "Terminus generates recommendations only. No patches or configuration changes were applied. "
    "All recommendations require human review before any operational change."
)


def _ts(value: Any) -> str | None:
    return value.isoformat() if value is not None else None


def finding_report(f: Finding) -> dict[str, Any]:
    return {
        "finding_id": f.finding_id,
        "cve_id": f.cve_id,
        "summary": f.summary,
        "asset": {
            "asset_id": f.item.asset_id,
            "hostname": f.item.hostname,
            "os": " ".join(p for p in (f.item.os_name, f.item.os_version) if p) or None,
            "criticality": f.item.criticality.value,
            "internet_exposed": f.item.internet_exposed,
            "environment": f.item.environment.value if f.item.environment else None,
        },
        "software": {
            "name": f.item.software_name,
            "installed_version": f.item.software_version,
            "ecosystem": f.item.ecosystem.value,
            "vendor": f.item.vendor,
            "cpe": f.item.cpe,
            "purl": f.item.purl,
        },
        "assessment": {
            "match_status": f.match.status.value,
            "match_status_label": f.match.status.label,
            "confidence": f.match.confidence,
            "identity_method": f.match.identity_method.value,
            "version_scheme": f.match.version_scheme,
            "reasons": f.match.reasons,
            "vulnerable_ranges": f.match.vulnerable_ranges,
        },
        "verified_facts": {
            "data_source": f.cve_source,
            "cve_published": _ts(f.cve_published),
            "cve_last_modified": _ts(f.cve_last_modified),
            "cve_retrieved_at": _ts(f.cve_retrieved_at),
            "cvss": f.cvss.model_dump() if f.cvss else None,
            "kev": f.kev.model_dump(mode="json"),
            "epss": f.epss.model_dump(mode="json"),
            "affected_version_evidence": [e.model_dump(mode="json") for e in f.match.evidence],
            "fixed_version": f.fix.model_dump(mode="json"),
            "vendor_advisory_urls": f.vendor_advisory_urls,
            "supporting_urls": f.supporting_urls,
        },
        "priority": f.priority.model_dump(mode="json"),
        "recommendation": f.recommendation.model_dump(),
        "missing_information": f.missing_information,
        "uncertainties": f.uncertainties,
        "next_verification_step": f.next_verification_step,
        "ai_interpretation": (
            {"label": "AI-generated interpretation - not verified", "text": f.ai_interpretation}
            if f.ai_interpretation
            else None
        ),
        "research_trace": f.research.model_dump(mode="json") if f.research else None,
        "first_seen": _ts(f.first_seen),
        "last_assessed": _ts(f.last_assessed),
        "scan_id": f.scan_id,
    }


def export_json(findings: list[Finding], *, demo: bool = False) -> str:
    return json.dumps(
        {
            "generated_at": utcnow().isoformat(),
            "generator": "Terminus 0.1.0",
            "data_mode": "demo (recorded fixtures)" if demo else "live",
            "disclaimer": DISCLAIMER,
            "finding_count": len(findings),
            "findings": [finding_report(f) for f in findings],
        },
        indent=2,
    )


CSV_COLUMNS = [
    "priority_tier",
    "priority_score",
    "cve_id",
    "match_status",
    "confidence",
    "asset_id",
    "hostname",
    "software",
    "installed_version",
    "ecosystem",
    "criticality",
    "internet_exposed",
    "environment",
    "cvss_score",
    "cvss_vector",
    "kev_listed",
    "kev_date_added",
    "kev_retrieved_at",
    "epss_score",
    "epss_percentile",
    "epss_retrieved_at",
    "fix_status",
    "fixed_version",
    "action",
    "recommendation",
    "contributing_factors",
    "vendor_advisory_urls",
    "supporting_urls",
    "missing_information",
    "uncertainties",
    "next_verification_step",
    "summary",
    "last_assessed",
    "patch_applied",
]


def _row(f: Finding) -> dict[str, Any]:
    kev = {True: "yes", False: "no", None: "unknown"}[f.kev.in_kev]
    factors = "; ".join(f"{x.name}: {x.raw_value} (+{x.points})" for x in f.priority.factors)
    return {
        "priority_tier": f.priority.tier,
        "priority_score": f.priority.score,
        "cve_id": f.cve_id,
        "match_status": f.match.status.value,
        "confidence": f.match.confidence,
        "asset_id": f.item.asset_id,
        "hostname": f.item.hostname,
        "software": f.item.software_name,
        "installed_version": f.item.software_version,
        "ecosystem": f.item.ecosystem.value,
        "criticality": f.item.criticality.value,
        "internet_exposed": f.item.internet_exposed,
        "environment": f.item.environment.value if f.item.environment else "",
        "cvss_score": f.cvss.base_score if f.cvss else "",
        "cvss_vector": f.cvss.vector if f.cvss else "",
        "kev_listed": kev,
        "kev_date_added": f.kev.date_added or "",
        "kev_retrieved_at": _ts(f.kev.retrieved_at) or "",
        "epss_score": f.epss.score if f.epss.score is not None else "",
        "epss_percentile": f.epss.percentile if f.epss.percentile is not None else "",
        "epss_retrieved_at": _ts(f.epss.retrieved_at) or "",
        "fix_status": f.fix.status.value,
        "fixed_version": f.fix.fixed_version or "",
        "action": f.recommendation.action,
        "recommendation": f.recommendation.summary,
        "contributing_factors": factors,
        "vendor_advisory_urls": " ".join(f.vendor_advisory_urls),
        "supporting_urls": " ".join(f.supporting_urls),
        "missing_information": "; ".join(f.missing_information),
        "uncertainties": "; ".join(f.uncertainties),
        "next_verification_step": f.next_verification_step,
        "summary": f.summary,
        "last_assessed": _ts(f.last_assessed),
        "patch_applied": "no",
    }


def export_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=CSV_COLUMNS, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    for f in findings:
        writer.writerow({k: csv_safe(v) for k, v in _row(f).items()})
    return buf.getvalue()
