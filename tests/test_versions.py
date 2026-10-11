from __future__ import annotations

from itertools import pairwise

import pytest

from terminus.matching.versions import (
    RangeCheck,
    Scheme,
    VersionParseError,
    VersionRange,
    compare,
    upstream_version,
)
from terminus.models import Ecosystem


def ordered(scheme: Scheme, versions: list[str]) -> None:
    for lo, hi in pairwise(versions):
        assert compare(lo, hi, scheme) == -1, f"{lo} < {hi} ({scheme})"
        assert compare(hi, lo, scheme) == 1, f"{hi} > {lo} ({scheme})"


def test_not_lexical_ordering() -> None:
    # Lexically "1.10" < "1.9" and "2.4.100" < "2.4.49"; semantically the opposite.
    for scheme in (Scheme.GENERIC, Scheme.PEP440, Scheme.MAVEN, Scheme.DPKG, Scheme.RPM):
        assert compare("1.10", "1.9", scheme) == 1
        assert compare("2.4.100", "2.4.49", scheme) == 1


def test_pep440() -> None:
    ordered(Scheme.PEP440, ["1.0.dev1", "1.0a1", "1.0b2", "1.0rc1", "1.0", "1.0.post1", "1.1"])
    assert compare("2.31", "2.31.0", Scheme.PEP440) == 0
    with pytest.raises(VersionParseError):
        compare("not-a-version!", "1.0", Scheme.PEP440)


def test_semver_precedence_from_spec() -> None:
    ordered(
        Scheme.SEMVER,
        [
            "1.0.0-alpha",
            "1.0.0-alpha.1",
            "1.0.0-alpha.beta",
            "1.0.0-beta",
            "1.0.0-beta.2",
            "1.0.0-beta.11",
            "1.0.0-rc.1",
            "1.0.0",
            "2.0.0",
            "2.1.0",
            "2.1.1",
        ],
    )
    assert compare("1.0.0+build.1", "1.0.0+build.2", Scheme.SEMVER) == 0  # build metadata ignored
    assert compare("v4.17.21", "4.17.21", Scheme.SEMVER) == 0
    with pytest.raises(VersionParseError):
        compare("4.17", "4.17.21", Scheme.SEMVER)  # incomplete versions are not guessed


def test_maven_qualifiers() -> None:
    ordered(
        Scheme.MAVEN, ["2.0-alpha1", "2.0-beta9", "2.0-rc1", "2.0", "2.0-sp1", "2.0.1", "2.15.0"]
    )
    assert compare("2.0", "2.0.0", Scheme.MAVEN) == 0
    assert compare("2.0-ga", "2.0", Scheme.MAVEN) == 0


def test_dpkg_rules() -> None:
    ordered(Scheme.DPKG, ["1.0~rc1", "1.0", "1.0-1", "1.0-2", "1.0+dfsg-1", "1.1", "1:0.9"])
    assert compare("1:8.9p1-3ubuntu0.10", "1:8.9p1-3ubuntu0.6", Scheme.DPKG) == 1
    assert compare("1:9.2p1-2+deb12u3", "1:9.2p1-2", Scheme.DPKG) == 1
    assert compare("2.0", "2.0-0", Scheme.DPKG) == 0
    with pytest.raises(VersionParseError):
        compare("abc", "1.0", Scheme.DPKG)  # upstream must start with a digit


def test_rpm_rules() -> None:
    ordered(Scheme.RPM, ["1.0~rc1", "1.0", "1.0^git1", "1.0a", "1.0.1", "1:0.1"])
    assert compare("7.76.1-26.el9", "7.76.1-19.el9", Scheme.RPM) == 1
    assert (
        compare("7.76.1", "7.76.1-26.el9", Scheme.RPM) == 0
    )  # release ignored when one side lacks it


def test_generic_upstream_versions() -> None:
    ordered(
        Scheme.GENERIC, ["1.0.1", "1.0.1a", "1.0.1f", "1.0.1g", "1.0.2", "1.1.0"]
    )  # OpenSSL letters
    ordered(Scheme.GENERIC, ["8.5p1", "9.2p1", "9.8p1"])  # OpenSSH portable
    ordered(Scheme.GENERIC, ["2.0-beta9", "2.0-rc1", "2.0", "2.0.1"])
    ordered(Scheme.GENERIC, ["1.0b2", "1.0"])  # "b" followed by a number is a pre-release


@pytest.mark.parametrize(
    "bad", ["1.18.0-acme-build7", "2.4.x", "latest", "v1.2", "1.2 (Unix)", "1.2+deb"]
)
def test_generic_rejects_unreliable_versions(bad: str) -> None:
    with pytest.raises(VersionParseError):
        compare(bad, "1.0", Scheme.GENERIC)


def test_upstream_version_of_distro_packages() -> None:
    assert upstream_version("1:8.9p1-3ubuntu0.10", Ecosystem.DEB) == "8.9p1"
    assert upstream_version("1.2.3+dfsg-1", Ecosystem.DEB) == "1.2.3"
    assert upstream_version("7.76.1-26.el9", Ecosystem.RPM) == "7.76.1"


@pytest.mark.parametrize(
    ("rng", "version", "expected"),
    [
        (VersionRange(start="2.0", end="2.15.0"), "2.14.1", RangeCheck.IN),
        (
            VersionRange(start="2.0", end="2.15.0"),
            "2.15.0",
            RangeCheck.OUT,
        ),  # end exclusive = fixed
        (VersionRange(start="2.0", end="2.15.0", end_inclusive=True), "2.15.0", RangeCheck.IN),
        (VersionRange(start="2.0", end="2.15.0"), "2.0", RangeCheck.IN),  # start inclusive
        (VersionRange(start="2.0", start_inclusive=False, end="2.15.0"), "2.0", RangeCheck.OUT),
        (VersionRange(start="2.0", end="2.15.0"), "1.9.9", RangeCheck.OUT),
        (VersionRange(end="1.0.1g"), "1.0.1f", RangeCheck.IN),  # unbounded below
        (VersionRange(start="3.0.0"), "9.9.9", RangeCheck.IN),  # unbounded above
        (VersionRange(exact="2.4.49"), "2.4.49", RangeCheck.IN),
        (VersionRange(exact="2.4.49"), "2.4.50", RangeCheck.OUT),
        (VersionRange(start="2.0", end="2.15.0"), "2.x", RangeCheck.UNKNOWN),
    ],
)
def test_range_boundaries(rng: VersionRange, version: str, expected: RangeCheck) -> None:
    check, _ = rng.check(version, Scheme.GENERIC)
    assert check == expected


def test_range_describe() -> None:
    assert VersionRange(start="1", end="2").describe() == ">= 1, < 2"
    assert (
        VersionRange(start="1", start_inclusive=False, end="2", end_inclusive=True).describe()
        == "> 1, <= 2"
    )
    assert VersionRange().describe() == "all versions"
