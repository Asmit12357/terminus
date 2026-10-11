"""Evidence state for one CVE investigation."""

from __future__ import annotations

from dataclasses import dataclass, field

from terminus.connectors.search import SearchResult
from terminus.connectors.vendor import VendorPage
from terminus.matching.normalize import package_identity
from terminus.models import (
    CveRecord,
    EpssStatus,
    FixAssessment,
    FixStatus,
    InventoryItem,
    KevStatus,
    MatchResult,
    MatchStatus,
    OsvAdvisory,
    Recommendation,
)


@dataclass
class ResearchState:
    cve_id: str
    items: list[InventoryItem]
    cve: CveRecord | None = None
    matches: dict[str, MatchResult] = field(default_factory=dict)
    osv: dict[str, OsvAdvisory] = field(default_factory=dict)
    kev: KevStatus | None = None
    epss: EpssStatus | None = None
    vendor_pages: dict[str, VendorPage] = field(default_factory=dict)
    advisory_urls: set[str] = field(default_factory=set)
    supplementary: list[SearchResult] = field(default_factory=list)
    fixes: dict[str, FixAssessment] = field(default_factory=dict)
    recommendations: dict[str, Recommendation] = field(default_factory=dict)
    injection_flags: set[str] = field(default_factory=set)
    # Keys of research steps already taken ("cve", "verify:<n>", "research:<key>", ...).
    # Each key runs at most once and the number of keys is finite -> termination.
    steps_done: set[str] = field(default_factory=set)
    research_done: set[str] = field(default_factory=set)
    # Incremented whenever research adds structured evidence; triggers re-verification.
    evidence_version: int = 0

    def item(self, item_id: str) -> InventoryItem:
        for item in self.items:
            if item.item_id == item_id:
                return item
        raise ValueError("unknown item_id for this investigation")

    def verify_key(self) -> str:
        return f"verify:{self.evidence_version}"

    def research_key(self, item_id: str) -> str:
        """Advisory research is shared by every host running the same package."""
        pid = package_identity(self.item(item_id))
        if pid is not None and pid.ecosystem.osv_name:
            return f"pkg:{pid.ecosystem.value}:{pid.name}"
        return "cve-references"

    def advisory_list(self) -> list[str]:
        """Official advisory URLs: NVD 'Vendor Advisory' refs first, then OSV advisories."""
        urls: list[str] = []
        if self.cve is not None:
            urls += self.cve.vendor_advisory_urls
        for adv in self.osv.values():
            urls += adv.advisory_urls
        return list(dict.fromkeys(urls))

    def needs_advisory_research(self, item_id: str) -> bool:
        """Useful when the match is not settled or the fix is not verified yet."""
        if self.research_key(item_id) in self.research_done:
            return False
        match = self.matches.get(item_id)
        if match is None or match.status == MatchStatus.CONFIRMED_UNAFFECTED:
            return False
        fix = self.fixes.get(item_id)
        return not (fix is not None and fix.status == FixStatus.VERIFIED)

    def unresolved(self) -> list[str]:
        """Items whose status or fixed version is still uncertain after verification."""
        out = []
        for item_id, match in self.matches.items():
            fix = self.fixes.get(item_id)
            if match.status in (MatchStatus.UNVERIFIED, MatchStatus.POTENTIALLY_AFFECTED) or (
                fix is not None and fix.status in (FixStatus.UNKNOWN, FixStatus.CONFLICT)
            ):
                out.append(item_id)
        return out
