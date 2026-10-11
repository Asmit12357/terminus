from __future__ import annotations

from app.matching.matcher import match_item
from app.matching.normalize import (
    compare_identity,
    normalize_product,
    normalize_vendor,
    package_identity,
    parse_cpe,
    parse_purl,
)
from app.models import (
    ConfigNode,
    Configuration,
    Ecosystem,
    IdentityMethod,
    MatchStatus,
    TrustTier,
)
from tests.conftest import make_cve, make_item, make_osv, rule

OPENSSL_RANGE = rule(
    "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
    version_start_including="3.0.0",
    version_end_excluding="3.0.7",
)


# --------------------------------------------------------------------------- normalization


def test_vendor_normalization() -> None:
    assert normalize_vendor("The Apache Software Foundation") == "apache"
    assert normalize_vendor("OpenSSL Project") == "openssl"
    assert normalize_vendor("F5, Inc.") == "f5"
    assert normalize_vendor("Microsoft Corporation") == "microsoft"
    assert normalize_vendor(None) is None


def test_product_normalization_keeps_distinctions() -> None:
    assert normalize_product("Apache HTTP Server", "apache") == "http_server"
    assert normalize_product("log4j-core") != normalize_product("log4j-api")
    assert normalize_product("Python3") != normalize_product("Python2")
    assert normalize_product("ＯｐｅｎＳＳＬ") == "openssl"  # full-width Unicode folded by NFKC


def test_cpe_parsing_handles_escapes() -> None:
    cpe = parse_cpe(r"cpe:2.3:a:vendor\:x:prod:1.0:beta9:*:*:*:*:*:*")
    assert cpe is not None
    assert cpe.vendor == "vendor:x"
    assert cpe.full_version == "1.0-beta9"
    assert parse_cpe("cpe:/a:apache:http_server") is None


def test_purl_parsing() -> None:
    maven = parse_purl("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
    assert maven is not None and maven.name == "org.apache.logging.log4j:log4j-core"
    scoped = parse_purl("pkg:npm/%40babel/core@7.0.0")
    assert scoped is not None and scoped.name == "@babel/core"
    pypi = parse_purl("pkg:pypi/Jinja_2@3.0")
    assert pypi is not None and pypi.name == "jinja-2"  # PEP 503 normalization
    deb = parse_purl("pkg:deb/ubuntu/openssh-server@1:8.9p1-3")
    assert deb is not None and deb.ecosystem == Ecosystem.DEB and deb.name == "openssh-server"


def test_identity_methods() -> None:
    cpe = parse_cpe("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")
    assert cpe is not None
    exact = make_item(cpe="cpe:2.3:a:openssl:openssl:3.0.5:*:*:*:*:*:*:*")
    assert compare_identity(exact, cpe).method == IdentityMethod.CPE_EXACT
    assert compare_identity(make_item(), cpe).method == IdentityMethod.CURATED_ALIAS
    assert compare_identity(make_item(vendor=None), cpe).method == IdentityMethod.NAME_ONLY
    fork = make_item(vendor="Acme Appliances Inc.")
    assert compare_identity(fork, cpe).method == IdentityMethod.AMBIGUOUS
    libs = make_item(software_name="openssl-libs", vendor=None)
    assert compare_identity(libs, cpe).method == IdentityMethod.AMBIGUOUS
    assert compare_identity(make_item(software_name="LibreSSL", vendor="OpenBSD"), cpe) is None


def test_similar_name_is_not_the_same_product() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*")
    assert cpe is not None
    # "log4net" and "log4js" share a prefix with log4j but are different products.
    assert compare_identity(make_item(software_name="log4net", vendor="Apache"), cpe) is None
    assert compare_identity(make_item(software_name="log4js", vendor=None), cpe) is None


def test_package_identity_for_maven_alias() -> None:
    item = make_item(
        software_name="log4j-core",
        ecosystem="maven",
        vendor=None,
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
    )
    pid = package_identity(item)
    assert pid is not None and pid.name == "org.apache.logging.log4j:log4j-core"


# --------------------------------------------------------------------------- statuses


def test_confirmed_affected_with_evidence_and_fix() -> None:
    result = match_item(make_item(software_version="3.0.5"), make_cve(rules=[OPENSSL_RANGE]))
    assert result is not None
    assert result.status == MatchStatus.CONFIRMED_AFFECTED
    assert result.identity_method == IdentityMethod.CURATED_ALIAS
    assert result.fix_candidates[0].version == "3.0.7"
    assert result.fix_candidates[0].trust_tier == TrustTier.AUTHORITATIVE_STRUCTURED
    ev = result.evidence[0]
    assert ev.url == "https://nvd.nist.gov/vuln/detail/CVE-2022-3602"
    assert "3.0.5 is within" in ev.claim
    assert ev.retrieved_at is not None


def test_fixed_version_boundary_is_unaffected() -> None:
    result = match_item(make_item(software_version="3.0.7"), make_cve(rules=[OPENSSL_RANGE]))
    assert result is not None
    assert result.status == MatchStatus.CONFIRMED_UNAFFECTED
    assert not result.fix_candidates


def test_start_boundary_inclusive_and_below_range() -> None:
    cve = make_cve(rules=[OPENSSL_RANGE])
    assert (
        match_item(make_item(software_version="3.0.0"), cve).status
        == MatchStatus.CONFIRMED_AFFECTED
    )
    assert (
        match_item(make_item(software_version="1.1.1w"), cve).status
        == MatchStatus.CONFIRMED_UNAFFECTED
    )


def test_end_including_boundary() -> None:
    cve = make_cve(
        rules=[rule("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", version_end_including="1.0.1f")]
    )
    result = match_item(make_item(software_version="1.0.1f"), cve)
    assert result.status == MatchStatus.CONFIRMED_AFFECTED
    assert not result.fix_candidates  # endIncluding names the last affected, not a fix
    assert any("No structured source states a fixed version" in r for r in result.reasons)
    assert (
        match_item(make_item(software_version="1.0.1g"), cve).status
        == MatchStatus.CONFIRMED_UNAFFECTED
    )


def test_exact_cpe_version_match() -> None:
    cve = make_cve(
        "CVE-2021-41773", rules=[rule("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")]
    )
    httpd = make_item(
        software_name="Apache HTTP Server",
        vendor="Apache Software Foundation",
        software_version="2.4.49",
    )
    assert match_item(httpd, cve).status == MatchStatus.CONFIRMED_AFFECTED
    assert match_item(httpd.model_copy(update={"software_version": "2.4.51"}), cve).status == (
        MatchStatus.CONFIRMED_UNAFFECTED
    )


def test_missing_version_is_unverified_never_safe() -> None:
    result = match_item(make_item(software_version=None), make_cve(rules=[OPENSSL_RANGE]))
    assert result.status == MatchStatus.UNVERIFIED
    assert any("not recorded" in r for r in result.reasons)


def test_unparseable_version_is_unverified() -> None:
    cve = make_cve(
        rules=[
            rule(
                "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
                version_start_including="0.6.18",
                version_end_excluding="1.20.1",
            )
        ]
    )
    item = make_item(software_name="nginx", vendor="F5", software_version="1.18.0-acme-build7")
    result = match_item(item, cve)
    assert result.status == MatchStatus.UNVERIFIED
    assert "could not be compared" in " ".join(result.reasons)


def test_name_only_identity_is_at_most_potentially_affected() -> None:
    result = match_item(
        make_item(vendor=None, software_version="3.0.5"), make_cve(rules=[OPENSSL_RANGE])
    )
    assert result.status == MatchStatus.POTENTIALLY_AFFECTED
    assert result.identity_method == IdentityMethod.NAME_ONLY
    # out of range with weak identity is NOT confirmed unaffected
    out = match_item(
        make_item(vendor=None, software_version="3.0.9"), make_cve(rules=[OPENSSL_RANGE])
    )
    assert out.status == MatchStatus.UNVERIFIED


def test_vendor_mismatch_is_ambiguous_and_unverified() -> None:
    item = make_item(vendor="Acme Appliances Inc.", software_version="3.0.5")
    result = match_item(item, make_cve(rules=[OPENSSL_RANGE]))
    assert result.status == MatchStatus.UNVERIFIED
    assert result.identity_method == IdentityMethod.AMBIGUOUS


def test_distro_package_in_upstream_range_is_potentially_affected() -> None:
    cve = make_cve(
        "CVE-2024-6387",
        rules=[
            rule(
                "cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                version_start_including="8.5p1",
                version_end_excluding="9.8p1",
            )
        ],
    )
    item = make_item(
        software_name="openssh-server",
        vendor=None,
        ecosystem="deb",
        software_version="1:8.9p1-3ubuntu0.10",
    )
    result = match_item(item, cve)
    assert result.status == MatchStatus.POTENTIALLY_AFFECTED
    assert "backport" in " ".join(result.reasons)
    newer = item.model_copy(update={"software_version": "1:9.8p1-1"})
    assert match_item(newer, cve).status == MatchStatus.CONFIRMED_UNAFFECTED


def test_unbounded_cpe_is_potentially_affected() -> None:
    cve = make_cve(rules=[rule("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*")])
    assert match_item(make_item(), cve).status == MatchStatus.POTENTIALLY_AFFECTED


def test_platform_conditional_configuration() -> None:
    conf = Configuration(
        operator="AND",
        nodes=[
            ConfigNode(matches=[OPENSSL_RANGE]),
            ConfigNode(
                matches=[rule("cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", vulnerable=False)]
            ),
        ],
    )
    result = match_item(make_item(), make_cve(configurations=[conf]))
    assert result.status == MatchStatus.POTENTIALLY_AFFECTED
    assert result.conditional


def test_incomplete_nvd_analysis_does_not_confirm_unaffected() -> None:
    cve = make_cve(rules=[OPENSSL_RANGE], status="Undergoing Analysis")
    assert match_item(make_item(software_version="3.0.9"), cve).status == MatchStatus.UNVERIFIED


def test_unrelated_product_has_no_relationship() -> None:
    assert (
        match_item(make_item(software_name="nginx", vendor="F5"), make_cve(rules=[OPENSSL_RANGE]))
        is None
    )


def test_awaiting_analysis_cve_creates_keyword_candidate_only() -> None:
    cve = make_cve(
        "CVE-2026-10001",
        rules=None,
        status="Awaiting Analysis",
        description="A flaw in OpenSSL allows remote attackers to crash the service.",
    )
    result = match_item(make_item(), cve)
    assert result is not None
    assert result.status == MatchStatus.UNVERIFIED
    assert result.identity_method == IdentityMethod.AMBIGUOUS
    # short or partial names never trigger a keyword candidate
    assert match_item(make_item(software_name="SSL", vendor=None), cve) is None


def test_osv_ecosystem_range_confirms_package() -> None:
    adv = make_osv(
        "GHSA-j8r2-6x86-q33q",
        "CVE-2023-32681",
        "PyPI",
        "requests",
        [{"introduced": "2.3.0"}, {"fixed": "2.31.0"}],
    )
    cve = make_cve("CVE-2023-32681", rules=None, status="Modified")
    item = make_item(
        software_name="requests", ecosystem="pypi", vendor=None, software_version="2.28.1"
    )
    result = match_item(item, cve, [adv])
    assert result.status == MatchStatus.CONFIRMED_AFFECTED
    assert result.identity_method == IdentityMethod.PACKAGE_EXACT
    assert result.fix_candidates[0].version == "2.31.0"
    assert "OSV" in result.fix_candidates[0].source
    fixed = item.model_copy(update={"software_version": "2.31.0"})
    assert match_item(fixed, cve, [adv]).status == MatchStatus.CONFIRMED_UNAFFECTED


def test_osv_and_nvd_disagreement_is_potentially_affected() -> None:
    adv = make_osv(
        "GHSA-test",
        "CVE-2023-32681",
        "PyPI",
        "requests",
        [{"introduced": "2.3.0"}, {"fixed": "2.30.0"}],
    )
    cve = make_cve(
        "CVE-2023-32681",
        rules=[
            rule(
                "cpe:2.3:a:python:requests:*:*:*:*:*:*:*:*",
                version_start_including="2.3.0",
                version_end_excluding="2.31.0",
            )
        ],
    )
    item = make_item(
        software_name="requests", ecosystem="pypi", vendor=None, software_version="2.30.0"
    )
    result = match_item(item, cve, [adv])
    assert result.status == MatchStatus.POTENTIALLY_AFFECTED
    assert "disagree" in " ".join(result.reasons)


def test_osv_introduced_zero_and_last_affected() -> None:
    adv = make_osv(
        "GHSA-x",
        "CVE-2021-23337",
        "npm",
        "lodash",
        [{"introduced": "0"}, {"last_affected": "4.17.20"}],
        range_type="SEMVER",
    )
    cve = make_cve("CVE-2021-23337", rules=None)
    item = make_item(
        software_name="lodash", ecosystem="npm", vendor=None, software_version="4.17.20"
    )
    assert match_item(item, cve, [adv]).status == MatchStatus.CONFIRMED_AFFECTED
    newer = item.model_copy(update={"software_version": "4.17.21"})
    assert match_item(newer, cve, [adv]).status == MatchStatus.CONFIRMED_UNAFFECTED


def test_osv_git_ranges_are_ignored_not_guessed() -> None:
    adv = make_osv(
        "OSV-git",
        "CVE-2023-0001",
        "PyPI",
        "requests",
        [{"introduced": "abc123"}, {"fixed": "def456"}],
        range_type="GIT",
    )
    cve = make_cve("CVE-2023-0001", rules=None)
    item = make_item(
        software_name="requests", ecosystem="pypi", vendor=None, software_version="2.0.0"
    )
    assert match_item(item, cve, [adv]) is None


def test_maven_prerelease_range_from_cpe_update_field() -> None:
    cve = make_cve("CVE-2021-44228", rules=[rule("cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*")])
    item = make_item(
        software_name="log4j-core",
        ecosystem="maven",
        vendor=None,
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.0-beta9",
        software_version="2.0-beta9",
    )
    assert match_item(item, cve).status == MatchStatus.CONFIRMED_AFFECTED
    release = item.model_copy(update={"software_version": "2.0"})
    assert match_item(release, cve).status == MatchStatus.CONFIRMED_UNAFFECTED


def test_keyword_candidates_need_corroboration() -> None:
    """A package name that is also an English word must not match every CVE."""
    item = make_item(
        software_name="requests", ecosystem="pypi", vendor=None, software_version="2.31.0"
    )
    noise = make_cve(
        "CVE-2026-20001",
        rules=None,
        status="Awaiting Analysis",
        description="The server mishandles crafted HTTP requests, causing a crash.",
    )
    assert match_item(item, noise) is None
    versioned = make_cve(
        "CVE-2026-20002",
        rules=None,
        status="Received",
        description="requests before 2.32.0 leaks credentials on redirect.",
    )
    assert match_item(item, versioned).status == MatchStatus.UNVERIFIED
    ecosystem = make_cve(
        "CVE-2026-20003",
        rules=None,
        status="Received",
        description="The Python requests library mishandles proxy credentials.",
    )
    assert match_item(item, ecosystem) is not None
    vendor_item = make_item(software_name="nginx", vendor="F5", software_version="1.25.0")
    vendor_cve = make_cve(
        "CVE-2026-20004",
        rules=None,
        status="Received",
        description="A flaw in F5 nginx allows request smuggling.",
    )
    assert match_item(vendor_item, vendor_cve) is not None
