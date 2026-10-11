"""Dashboard helpers: safe rendering, status presentation, charts.

Untrusted text (CVE descriptions, vendor excerpts, search snippets) is shown
with ``st.text`` - never interpreted as Markdown/HTML, so it cannot inject
links, images or styling. Inventory strings shown inside Markdown are escaped.
"""

from __future__ import annotations

import re
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

from app.matching.versions import Scheme, VersionParseError, compare, scheme_for
from app.models import Finding, FixStatus, MatchStatus

# Reserved status palette (validated): critical / serious / warning / good.
CRITICAL, SERIOUS, WARNING, GOOD, NEUTRAL = "#d03b3b", "#ec835a", "#fab219", "#0ca30c", "#8a8a85"

STATUS_META: dict[MatchStatus, dict[str, str]] = {
    MatchStatus.CONFIRMED_AFFECTED: {
        "icon": "✖",
        "badge": "red",
        "color": CRITICAL,
        "material": ":material/error:",
    },
    MatchStatus.POTENTIALLY_AFFECTED: {
        "icon": "▲",
        "badge": "orange",
        "color": SERIOUS,
        "material": ":material/warning:",
    },
    MatchStatus.UNVERIFIED: {
        "icon": "?",
        "badge": "yellow",
        "color": WARNING,
        "material": ":material/help:",
    },
    MatchStatus.CONFIRMED_UNAFFECTED: {
        "icon": "✔",
        "badge": "green",
        "color": GOOD,
        "material": ":material/check_circle:",
    },
}
TIER_COLOR = {"P1": CRITICAL, "P2": SERIOUS, "P3": WARNING, "P4": NEUTRAL, "INFO": GOOD}
TIER_BADGE = {"P1": "red", "P2": "orange", "P3": "yellow", "P4": "gray", "INFO": "green"}
TIER_HELP = {
    "P1": "Act now",
    "P2": "Act soon",
    "P3": "Plan",
    "P4": "Monitor",
    "INFO": "No action for this CVE",
}

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|>~<:$])")
_SAFE_URL = re.compile(r"^https?://[^\s<>\"'()\[\]]+$")


def md(text: Any) -> str:
    """Escape a value for inclusion in Markdown."""
    return _MD_SPECIAL.sub(r"\\\1", "" if text is None else str(text))


def safe_url(url: str | None) -> str | None:
    return url if url and _SAFE_URL.match(url) and len(url) < 2000 else None


def status_label(status: MatchStatus) -> str:
    return f"{STATUS_META[status]['icon']} {status.label}"


def status_badge(status: MatchStatus) -> None:
    meta = STATUS_META[status]
    st.badge(status.label, icon=meta["material"], color=meta["badge"])  # type: ignore[arg-type]


def tier_badge(tier: str) -> None:
    st.badge(f"{tier} - {TIER_HELP.get(tier, '')}", color=TIER_BADGE.get(tier, "gray"))  # type: ignore[arg-type]


def kev_text(f: Finding) -> str:
    return {True: "Listed", False: "Not listed", None: "Unknown"}[f.kev.in_kev]


def epss_text(f: Finding) -> str:
    return f"{f.epss.score:.3f}" if f.epss.score is not None else "n/a"


def fix_text(f: Finding) -> str:
    if f.fix.fixed_version:
        return f"{f.fix.fixed_version} ({f.fix.status.value.replace('_', ' ')})"
    if f.fix.conservative_target:
        return f">= {f.fix.conservative_target} (sources conflict)"
    return f.fix.status.value.replace("_", " ")


def findings_frame(findings: list[Finding]) -> pd.DataFrame:
    rows = []
    for f in findings:
        rows.append(
            {
                "Tier": f.priority.tier,
                "Score": f.priority.score,
                "CVE": f.cve_id,
                "Status": status_label(f.match.status),
                "Confidence": f.match.confidence,
                "Asset": f.item.asset_id,
                "Software": f.item.software_name,
                "Installed": f.item.software_version or "unknown",
                "CVSS": f.cvss.base_score if f.cvss else None,
                "KEV": kev_text(f),
                "EPSS": f.epss.score,
                "Fix": fix_text(f),
                "Action": f.recommendation.action,
                "Exposure": {True: "internet", False: "internal", None: "unknown"}[
                    f.item.internet_exposed
                ],
                "Last assessed": f.last_assessed.strftime("%Y-%m-%d %H:%M"),
                "_id": f.finding_id,
            }
        )
    return pd.DataFrame(rows)


FINDING_COLUMNS = {
    "Score": st.column_config.ProgressColumn("Score", min_value=0, max_value=100, format="%.1f"),
    "Confidence": st.column_config.NumberColumn("Confidence", format="%.2f"),
    "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f"),
    "EPSS": st.column_config.NumberColumn(
        "EPSS", format="%.3f", help="Probability of exploitation activity in 30 days"
    ),
    "_id": None,
}


def bar_chart(
    df: pd.DataFrame,
    category: str,
    value: str,
    colors: dict[str, str],
    order: list[str],
    title: str,
) -> alt.Chart:
    domain = [c for c in order if c in set(df[category])]
    base = alt.Chart(df, title=title).encode(
        x=alt.X(f"{category}:N", sort=domain, title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y(
            f"{value}:Q", title="Findings", axis=alt.Axis(tickMinStep=1, grid=True, gridOpacity=0.3)
        ),
        tooltip=[alt.Tooltip(f"{category}:N"), alt.Tooltip(f"{value}:Q", title="Findings")],
    )
    bars = base.mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4, size=36).encode(
        color=alt.Color(
            f"{category}:N",
            scale=alt.Scale(domain=domain, range=[colors[c] for c in domain]),
            legend=None,
        )
    )
    labels = base.mark_text(dy=-8).encode(text=alt.Text(f"{value}:Q"))
    return (bars + labels).properties(height=240)


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
        if (
            f.fix.status in (FixStatus.UNKNOWN,)
            and f.match.status == MatchStatus.CONFIRMED_AFFECTED
        ):
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
