"""Deterministic inventory-to-CVE matching.

Decision rules (documented in README, "Matching"):

1. Product identity must come from a CPE, a package identifier, the curated
   alias table, or an exact normalized vendor+product match. A similar name
   alone never produces "affected".
2. Each structured source (NVD configurations, each OSV advisory) yields a
   verdict for the installed version: IN, OUT or UNKNOWN.
3. CONFIRMED_AFFECTED requires a reliable identity and an IN verdict that is not
   contradicted by another reliable source, not conditional on an unevaluated
   platform, not an unbounded "all versions" entry and not an upstream range
   applied to a distribution package (distros backport fixes).
4. CONFIRMED_UNAFFECTED requires a reliable identity and every reliable source
   saying OUT, with NVD analysis complete (or an ecosystem advisory present).
5. Everything else is POTENTIALLY_AFFECTED (weak identity, in range) or
   UNVERIFIED (unknown version, unparseable version, ambiguous identity,
   incomplete source data).
"""

from __future__ import annotations

from dataclasses import dataclass

from terminus.matching.normalize import (
    IdentityCandidate,
    PackageId,
    compare_identity,
    mentions_product,
    normalize_package_name,
    package_identity,
    parse_cpe,
)
from terminus.matching.versions import (
    RangeCheck,
    Scheme,
    VersionParseError,
    VersionRange,
    scheme_for,
    upstream_version,
)
from terminus.models import (
    CpeMatchRule,
    CveRecord,
    Evidence,
    FixCandidate,
    IdentityMethod,
    InventoryItem,
    MatchResult,
    MatchStatus,
    OsvAdvisory,
    OsvAffected,
    TrustTier,
)

NVD_SOURCE = "NVD CVE API 2.0 configurations"


@dataclass
class _Hit:
    source_key: str  # "nvd" or "osv:<id>"
    identity: IdentityCandidate
    range: VersionRange
    check: RangeCheck
    detail: str
    fix: str | None
    url: str
    conditional: bool = False
    upstream_compare: bool = False  # distro package compared against upstream range

    @property
    def label(self) -> str:
        return f"{self.identity.vendor}:{self.identity.product} {self.range.describe()}"


def _nvd_range(rule: CpeMatchRule, cpe_version: str | None) -> VersionRange:
    if any(
        (
            rule.version_start_including,
            rule.version_start_excluding,
            rule.version_end_including,
            rule.version_end_excluding,
        )
    ):
        return VersionRange(
            start=rule.version_start_including or rule.version_start_excluding,
            start_inclusive=rule.version_start_excluding is None,
            end=rule.version_end_excluding or rule.version_end_including,
            end_inclusive=rule.version_end_excluding is None,
        )
    if cpe_version:
        return VersionRange(exact=cpe_version)
    return VersionRange()


def _item_version_for_nvd(item: InventoryItem) -> tuple[str | None, Scheme, bool, str | None]:
    """Version string and scheme used against upstream (CPE) ranges."""
    version = item.software_version
    if version is None:
        return None, Scheme.GENERIC, False, None
    if item.ecosystem.is_distro_package:
        try:
            return upstream_version(version, item.ecosystem), Scheme.GENERIC, True, None
        except VersionParseError as exc:
            return None, Scheme.GENERIC, True, str(exc)
    return version, scheme_for(item.ecosystem), False, None


def _nvd_hits(item: InventoryItem, cve: CveRecord) -> list[_Hit]:
    hits: list[_Hit] = []
    version, scheme, upstream, parse_error = _item_version_for_nvd(item)
    for config in cve.configurations:
        is_and = (config.operator or "").upper() == "AND" and len(config.nodes) > 1
        platform_only_nodes = [
            n for n in config.nodes if n.matches and not any(m.vulnerable for m in n.matches)
        ]
        conditional = is_and and bool(platform_only_nodes)
        for node in config.nodes:
            if node.negate:
                continue
            for rule in node.matches:
                if not rule.vulnerable:
                    continue
                cpe = parse_cpe(rule.criteria)
                if cpe is None:
                    continue
                ident = compare_identity(item, cpe)
                if ident is None:
                    continue
                rng = _nvd_range(rule, cpe.full_version)
                if cpe.version == "-" and rng.unbounded:
                    check, detail = RangeCheck.UNKNOWN, "CPE version is 'NA' (not applicable)"
                elif version is None:
                    check = RangeCheck.UNKNOWN
                    detail = parse_error or "installed version not recorded"
                else:
                    check, detail = rng.check(version, scheme)
                hits.append(
                    _Hit(
                        source_key="nvd",
                        identity=ident,
                        range=rng,
                        check=check,
                        detail=detail,
                        fix=rule.version_end_excluding,
                        url=cve.nvd_url,
                        conditional=conditional,
                        upstream_compare=upstream,
                    )
                )
    return hits


def _osv_affected_matches(aff: OsvAffected, pid: PackageId) -> bool:
    if not aff.name or not aff.ecosystem or pid.ecosystem.osv_name is None:
        return False
    if aff.ecosystem.split(":")[0] != pid.ecosystem.osv_name:
        return False
    return normalize_package_name(aff.name, pid.ecosystem) == pid.name


def _osv_intervals(aff: OsvAffected) -> list[tuple[VersionRange, str | None, str]]:
    """Flatten OSV events into (range, fixed_version, range_type) intervals."""
    out: list[tuple[VersionRange, str | None, str]] = []
    for r in aff.ranges:
        if r.type.upper() == "GIT":
            continue  # commit ranges cannot be evaluated against a version string
        start: str | None = None
        open_ = False
        for ev in r.events:
            if ev.introduced is not None:
                start = None if ev.introduced == "0" else ev.introduced
                open_ = True
            elif ev.fixed is not None:
                out.append((VersionRange(start=start, end=ev.fixed), ev.fixed, r.type))
                open_ = False
            elif ev.last_affected is not None:
                out.append(
                    (
                        VersionRange(start=start, end=ev.last_affected, end_inclusive=True),
                        None,
                        r.type,
                    )
                )
                open_ = False
        if open_:
            out.append((VersionRange(start=start), None, r.type))
    return out


def _osv_hits(item: InventoryItem, advisories: list[OsvAdvisory]) -> list[_Hit]:
    pid = package_identity(item)
    if pid is None:
        return []
    hits: list[_Hit] = []
    for adv in advisories:
        for aff in adv.affected:
            if not _osv_affected_matches(aff, pid):
                continue
            ident = IdentityCandidate(
                aff.ecosystem or "",
                aff.name or "",
                IdentityMethod.PACKAGE_EXACT,
                f"package {pid.ecosystem.value}/{pid.name} listed in {adv.id}",
            )
            version = item.software_version
            intervals = _osv_intervals(aff)
            if version is not None and version in aff.versions:
                rng = VersionRange(exact=version)
                hits.append(
                    _Hit(
                        f"osv:{adv.id}",
                        ident,
                        rng,
                        RangeCheck.IN,
                        "listed in advisory 'versions'",
                        None,
                        adv.url,
                    )
                )
            for rng, fixed, rtype in intervals:
                if version is None:
                    check, detail = RangeCheck.UNKNOWN, "installed version not recorded"
                else:
                    scheme = (
                        Scheme.SEMVER if rtype.upper() == "SEMVER" else scheme_for(item.ecosystem)
                    )
                    check, detail = rng.check(version, scheme)
                hits.append(_Hit(f"osv:{adv.id}", ident, rng, check, detail, fixed, adv.url))
    return hits


def _source_verdicts(hits: list[_Hit]) -> dict[str, tuple[RangeCheck, list[_Hit]]]:
    by_source: dict[str, list[_Hit]] = {}
    for h in hits:
        by_source.setdefault(h.source_key, []).append(h)
    verdicts: dict[str, tuple[RangeCheck, list[_Hit]]] = {}
    for key, hs in by_source.items():
        if any(h.check == RangeCheck.IN for h in hs):
            verdicts[key] = (RangeCheck.IN, [h for h in hs if h.check == RangeCheck.IN])
        elif any(h.check == RangeCheck.UNKNOWN for h in hs):
            verdicts[key] = (RangeCheck.UNKNOWN, [h for h in hs if h.check == RangeCheck.UNKNOWN])
        else:
            verdicts[key] = (RangeCheck.OUT, hs)
    return verdicts


def _best(hs: list[_Hit]) -> IdentityMethod:
    return max((h.identity.method for h in hs), key=lambda m: m.confidence)


def _evidence_for(
    hit: _Hit, cve: CveRecord, version: str | None, osv_by_key: dict[str, OsvAdvisory]
) -> Evidence:
    installed = version or "unknown"
    verdict = {
        RangeCheck.IN: "is within",
        RangeCheck.OUT: "is outside",
        RangeCheck.UNKNOWN: "cannot be compared with",
    }[hit.check]
    if hit.source_key == "nvd":
        return Evidence(
            claim=(
                f"NVD lists {hit.identity.vendor}:{hit.identity.product} {hit.range.describe()} as "
                f"vulnerable; installed {installed} {verdict} this range"
                + (" (upstream version of a distribution package)" if hit.upstream_compare else "")
                + (" (only when combined with a listed platform)" if hit.conditional else "")
            ),
            source=NVD_SOURCE,
            trust_tier=TrustTier.AUTHORITATIVE_STRUCTURED,
            url=hit.url,
            retrieved_at=cve.retrieved_at,
            flags=[hit.check.value, f"identity:{hit.identity.method.value}"],
        )
    adv = osv_by_key[hit.source_key]
    return Evidence(
        claim=(
            f"{adv.id} lists {hit.identity.vendor}/{hit.identity.product} {hit.range.describe()} "
            f"as affected; installed {installed} {verdict} this range"
        ),
        source=f"OSV.dev advisory {adv.id}",
        trust_tier=TrustTier.AUTHORITATIVE_STRUCTURED,
        url=adv.url,
        retrieved_at=adv.retrieved_at,
        flags=[hit.check.value, "identity:package_exact"],
    )


def match_item(
    item: InventoryItem, cve: CveRecord, osv_advisories: list[OsvAdvisory] | None = None
) -> MatchResult | None:
    """Assess one inventory item against one CVE. None = no relationship at all
    (which is *not* the same as unaffected)."""
    osv_advisories = osv_advisories or []
    hits = _nvd_hits(item, cve) + _osv_hits(item, osv_advisories)
    scheme = scheme_for(item.ecosystem).value

    if not hits:
        if (
            not cve.configurations
            and not osv_advisories
            and mentions_product(item, cve.description)
        ):
            return MatchResult(
                item_id=item.item_id,
                cve_id=cve.cve_id,
                status=MatchStatus.UNVERIFIED,
                identity_method=IdentityMethod.AMBIGUOUS,
                version_scheme=scheme,
                reasons=[
                    f"NVD has not published affected-product configurations "
                    f"(status: {cve.vuln_status or 'unknown'})",
                    f"The CVE description mentions '{item.software_name}'; product identity and "
                    "affected versions must be verified against the vendor advisory",
                ],
                evidence=[
                    Evidence(
                        claim="CVE description mentions this product name (keyword candidate only)",
                        source="NVD CVE API 2.0 description",
                        trust_tier=TrustTier.AUTHORITATIVE_STRUCTURED,
                        url=cve.nvd_url,
                        retrieved_at=cve.retrieved_at,
                    )
                ],
            )
        return None

    osv_by_key = {f"osv:{a.id}": a for a in osv_advisories}
    # Reliable and weak identities are judged separately so an ambiguous name hit
    # can neither create nor mask a verdict reached through a reliable identity.
    reliable = _source_verdicts([h for h in hits if h.identity.method.is_reliable])
    weak = _source_verdicts([h for h in hits if not h.identity.method.is_reliable])
    reasons: list[str] = []
    best_identity = _best(hits)
    best_hit = next(h for h in hits if h.identity.method == best_identity)
    reasons.append(f"Identity: {best_hit.identity.basis} ({best_identity.value})")

    in_sources = [k for k, (c, _) in reliable.items() if c == RangeCheck.IN]
    out_sources = [k for k, (c, _) in reliable.items() if c == RangeCheck.OUT]
    unknown_sources = [k for k, (c, _) in reliable.items() if c == RangeCheck.UNKNOWN]
    in_hits = [h for k in in_sources for h in reliable[k][1]]
    conditional = bool(in_hits) and all(h.conditional for h in in_hits)

    if item.software_version is None:
        status = MatchStatus.UNVERIFIED
        reasons.append("Installed version is not recorded, so affected ranges cannot be evaluated")
    elif in_sources:
        if out_sources:
            status = MatchStatus.POTENTIALLY_AFFECTED
            reasons.append(
                f"Sources disagree: {', '.join(in_sources)} place the version in an affected "
                f"range but {', '.join(out_sources)} do not"
            )
        elif all(h.upstream_compare for h in in_hits):
            status = MatchStatus.POTENTIALLY_AFFECTED
            reasons.append(
                "Upstream version falls in the NVD range, but this is a distribution package; "
                "distributions often backport fixes without changing the upstream version"
            )
        elif all(h.range.unbounded for h in in_hits):
            status = MatchStatus.POTENTIALLY_AFFECTED
            reasons.append("NVD lists the product without any version bounds (all versions)")
        elif conditional:
            status = MatchStatus.POTENTIALLY_AFFECTED
            reasons.append(
                "NVD marks this vulnerable only together with a specific platform, "
                "which Terminus cannot evaluate from the inventory"
            )
        else:
            status = MatchStatus.CONFIRMED_AFFECTED
            reasons.append(
                f"Installed version {item.software_version} is inside an affected range "
                f"({', '.join(in_sources)})"
            )
    elif unknown_sources:
        status = MatchStatus.UNVERIFIED
        reasons.append(
            "Version could not be compared reliably: "
            + "; ".join(h.detail for k in unknown_sources for h in reliable[k][1][:1])
        )
    elif out_sources:
        nvd_only = out_sources == ["nvd"]
        if nvd_only and not cve.is_analyzed:
            status = MatchStatus.UNVERIFIED
            reasons.append(
                f"Version is outside NVD ranges, but NVD analysis is not complete "
                f"(status: {cve.vuln_status or 'unknown'})"
            )
        else:
            status = MatchStatus.CONFIRMED_UNAFFECTED
            reasons.append(
                f"Installed version {item.software_version} is outside every affected range "
                f"listed by {', '.join(out_sources)}"
            )
    elif any(
        c == RangeCheck.IN and any(h.identity.method == IdentityMethod.NAME_ONLY for h in hs)
        for c, hs in weak.values()
    ):
        status = MatchStatus.POTENTIALLY_AFFECTED
        reasons.append(
            "Version is in an affected range, but identity rests on the product name only "
            "(no vendor, CPE or package identifier)"
        )
    else:
        status = MatchStatus.UNVERIFIED
        reasons.append(
            "Product identity is ambiguous or weak; a matching name is not treated as evidence "
            "of exposure"
        )

    # Evidence: the hits that drove the decision (bounded to keep reports readable).
    decisive = in_hits or [h for k in out_sources for h in reliable[k][1]] or hits
    evidence = [_evidence_for(h, cve, item.software_version, osv_by_key) for h in decisive[:6]]
    fixes: list[FixCandidate] = []
    for h in in_hits:
        if h.fix:
            fixes.append(
                FixCandidate(
                    version=h.fix,
                    source="NVD versionEndExcluding"
                    if h.source_key == "nvd"
                    else f"OSV {h.source_key[4:]} 'fixed' event",
                    trust_tier=TrustTier.AUTHORITATIVE_STRUCTURED,
                    url=h.url,
                )
            )
    if in_hits and not fixes:
        reasons.append("No structured source states a fixed version for the affected range")

    ranges = sorted(
        {f"{'NVD' if h.source_key == 'nvd' else h.source_key[4:]}: {h.label}" for h in hits}
    )
    return MatchResult(
        item_id=item.item_id,
        cve_id=cve.cve_id,
        status=status,
        identity_method=best_identity,
        version_scheme="generic (upstream)" if item.ecosystem.is_distro_package else scheme,
        reasons=reasons,
        evidence=evidence,
        vulnerable_ranges=ranges[:20],
        fix_candidates=fixes,
        conditional=conditional,
    )


def match_inventory(
    items: list[InventoryItem], cve: CveRecord, osv_advisories: list[OsvAdvisory] | None = None
) -> list[tuple[InventoryItem, MatchResult]]:
    out = []
    for item in items:
        result = match_item(item, cve, osv_advisories)
        if result is not None:
            out.append((item, result))
    return out


__all__ = ["match_inventory", "match_item"]
