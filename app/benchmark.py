"""Matching benchmark: known CVEs x synthetic installed versions.

Ground truth comes from the vendors' published affected/fixed versions (cited
per case), not from Terminus output. Matching runs against the recorded NVD and
OSV responses in ``data/fixtures``, so results reflect real source data.

Outcome classes: affected | unaffected | uncertain | none (no relationship).
- false positive: predicted affected, truth unaffected/none
- false negative: predicted unaffected/none, truth affected
- uncertain predictions are reported separately (never counted as correct
  or as safe), together with whether uncertainty was the expected outcome.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.matching.matcher import match_item
from app.matching.normalize import package_identity
from app.models import InventoryItem, MatchStatus
from app.sources import build_demo_sources


@dataclass(frozen=True)
class Case:
    cve_id: str
    item: dict[str, Any]
    expected: str  # affected | unaffected | uncertain | none
    basis: str


def _i(name: str, version: str | None, **kw: Any) -> dict[str, Any]:
    return {"asset_id": "bench", "software_name": name, "software_version": version, **kw}


LOG4J = {"ecosystem": "maven", "purl": "pkg:maven/org.apache.logging.log4j/log4j-core"}
HTTPD = {"vendor": "Apache Software Foundation"}
OPENSSL = {"vendor": "OpenSSL Project"}
CURL = {"vendor": "Haxx"}
NGINX = {"vendor": "F5"}
OPENSSH = {"vendor": "OpenBSD"}

CASES: list[Case] = [
    # Log4Shell: affected 2.0-beta9..2.14.1 except 2.12.2+ (Java 7) / 2.3.1+ (Java 6) lines.
    Case(
        "CVE-2021-44228",
        _i("log4j-core", "2.14.1", **LOG4J),
        "affected",
        "Apache Log4j security page",
    ),
    Case(
        "CVE-2021-44228",
        _i("log4j-core", "2.0-beta9", **LOG4J),
        "affected",
        "first affected release",
    ),
    Case("CVE-2021-44228", _i("log4j-core", "2.15.0", **LOG4J), "unaffected", "fixed in 2.15.0"),
    Case("CVE-2021-44228", _i("log4j-core", "2.12.2", **LOG4J), "unaffected", "Java 7 fix 2.12.2"),
    Case("CVE-2021-44228", _i("log4j-core", "2.3.1", **LOG4J), "unaffected", "Java 6 fix 2.3.1"),
    Case("CVE-2021-44228", _i("log4net", "2.0.8", vendor="Apache"), "none", "different product"),
    # Apache HTTP Server path traversal
    Case("CVE-2021-41773", _i("Apache HTTP Server", "2.4.49", **HTTPD), "affected", "only 2.4.49"),
    Case(
        "CVE-2021-41773",
        _i("Apache HTTP Server", "2.4.50", **HTTPD),
        "unaffected",
        "fixed in 2.4.50",
    ),
    Case(
        "CVE-2021-42013",
        _i("Apache HTTP Server", "2.4.50", **HTTPD),
        "affected",
        "2.4.49 and 2.4.50",
    ),
    Case(
        "CVE-2021-42013",
        _i("Apache HTTP Server", "2.4.51", **HTTPD),
        "unaffected",
        "fixed in 2.4.51",
    ),
    # OpenSSL
    Case("CVE-2014-0160", _i("OpenSSL", "1.0.1f", **OPENSSL), "affected", "1.0.1 through 1.0.1f"),
    Case("CVE-2014-0160", _i("OpenSSL", "1.0.1g", **OPENSSL), "unaffected", "fixed in 1.0.1g"),
    Case(
        "CVE-2014-0160", _i("OpenSSL", "1.0.0t", **OPENSSL), "unaffected", "1.0.0 branch unaffected"
    ),
    Case("CVE-2014-0160", _i("OpenSSL", "1.0.1f"), "uncertain", "no vendor: name-only identity"),
    Case("CVE-2014-0160", _i("LibreSSL", "2.0.0", vendor="OpenBSD"), "none", "different product"),
    Case("CVE-2022-3602", _i("OpenSSL", "3.0.6", **OPENSSL), "affected", "3.0.0 through 3.0.6"),
    Case("CVE-2022-3602", _i("OpenSSL", "3.0.7", **OPENSSL), "unaffected", "fixed in 3.0.7"),
    Case("CVE-2022-3602", _i("OpenSSL", "1.1.1q", **OPENSSL), "unaffected", "1.1.1 not affected"),
    # curl SOCKS5 heap overflow: 7.69.0 to 8.3.0
    Case("CVE-2023-38545", _i("curl", "8.3.0", **CURL), "affected", "curl.se advisory"),
    Case("CVE-2023-38545", _i("curl", "7.69.0", **CURL), "affected", "first affected"),
    Case("CVE-2023-38545", _i("curl", "8.4.0", **CURL), "unaffected", "fixed in 8.4.0"),
    Case("CVE-2023-38545", _i("curl", "7.68.0", **CURL), "unaffected", "introduced in 7.69.0"),
    Case("CVE-2023-38545", _i("curl", None, **CURL), "uncertain", "version unknown"),
    Case(
        "CVE-2023-38545",
        _i("curl", "7.76.1-26.el9", ecosystem="rpm"),
        "uncertain",
        "RHEL backports fixes; upstream version alone is inconclusive",
    ),
    # Python requests
    Case(
        "CVE-2023-32681", _i("requests", "2.30.0", ecosystem="pypi"), "affected", "2.3.0 to <2.31.0"
    ),
    Case(
        "CVE-2023-32681",
        _i("requests", "2.31.0", ecosystem="pypi"),
        "unaffected",
        "fixed in 2.31.0",
    ),
    Case(
        "CVE-2023-32681",
        _i("requests", "2.2.1", ecosystem="pypi"),
        "unaffected",
        "introduced 2.3.0",
    ),
    # lodash template injection
    Case("CVE-2021-23337", _i("lodash", "4.17.20", ecosystem="npm"), "affected", "< 4.17.21"),
    # OpenSSH regreSSHion: 8.5p1 <= v < 9.8p1
    Case(
        "CVE-2024-6387", _i("OpenSSH", "9.7p1", **OPENSSH), "affected", "openssh.com release notes"
    ),
    Case("CVE-2024-6387", _i("OpenSSH", "8.5p1", **OPENSSH), "affected", "regression in 8.5p1"),
    Case("CVE-2024-6387", _i("OpenSSH", "9.8p1", **OPENSSH), "unaffected", "fixed in 9.8p1"),
    Case(
        "CVE-2024-6387",
        _i("openssh-server", "1:8.9p1-3ubuntu0.10", ecosystem="deb"),
        "uncertain",
        "Ubuntu shipped the fix as a package revision",
    ),
    # nginx resolver: 0.6.18 - 1.20.0
    Case("CVE-2021-23017", _i("nginx", "1.20.0", **NGINX), "affected", "nginx.org advisory"),
    Case("CVE-2021-23017", _i("nginx", "1.20.1", **NGINX), "unaffected", "fixed in 1.20.1"),
    Case(
        "CVE-2021-23017",
        _i("nginx", "1.18.0-acme-build7", **NGINX),
        "uncertain",
        "unparseable version",
    ),
]


def _predict(status: MatchStatus | None) -> str:
    if status is None:
        return "none"
    return {
        MatchStatus.CONFIRMED_AFFECTED: "affected",
        MatchStatus.CONFIRMED_UNAFFECTED: "unaffected",
    }.get(status, "uncertain")


def run_benchmark() -> dict[str, Any]:
    sources = build_demo_sources()
    rows = []
    for case in CASES:
        item = InventoryItem.model_validate(case.item)
        cve = sources.nvd.fetch_cve(case.cve_id)
        if cve is None:
            rows.append({"case": case, "predicted": "missing-fixture", "status": None})
            continue
        osv = []
        pid = package_identity(item)
        if pid is not None:
            osv = [
                a
                for a in sources.osv.advisories_for_package(pid)
                if case.cve_id in a.aliases or a.id == case.cve_id
            ]
        result = match_item(item, cve, osv)
        rows.append(
            {
                "case": case,
                "predicted": _predict(result.status if result else None),
                "status": result.status.value if result else "no relationship",
            }
        )

    def count(pred: Any) -> int:
        return sum(1 for r in rows if pred(r))

    fp = count(
        lambda r: r["predicted"] == "affected" and r["case"].expected in ("unaffected", "none")
    )
    fn = count(
        lambda r: r["predicted"] in ("unaffected", "none") and r["case"].expected == "affected"
    )
    unc = count(lambda r: r["predicted"] == "uncertain")
    unc_expected = count(
        lambda r: r["predicted"] == "uncertain" and r["case"].expected == "uncertain"
    )
    correct = count(lambda r: r["predicted"] == r["case"].expected)
    return {
        "cases": len(rows),
        "correct": correct,
        "false_positives": fp,
        "false_negatives": fn,
        "uncertain": unc,
        "uncertain_expected": unc_expected,
        "missing_fixtures": count(lambda r: r["predicted"] == "missing-fixture"),
        "rows": rows,
    }


def format_report(report: dict[str, Any]) -> str:
    lines = [
        f"Benchmark: {report['cases']} cases against recorded NVD/OSV data",
        f"  correct            {report['correct']}",
        f"  false positives    {report['false_positives']}",
        f"  false negatives    {report['false_negatives']}",
        f"  uncertain          {report['uncertain']} ({report['uncertain_expected']} expected)",
        f"  missing fixtures   {report['missing_fixtures']}",
        "",
    ]
    for r in report["rows"]:
        c: Case = r["case"]
        mark = "ok " if r["predicted"] == c.expected else "XX "
        lines.append(
            f"{mark} {c.cve_id:15} {c.item['software_name']:20} {c.item['software_version'] or '-':22} "
            f"expected={c.expected:10} got={r['predicted']:10} ({r['status']}) - {c.basis}"
        )
    return "\n".join(lines)
