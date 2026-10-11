"""Ecosystem-aware version comparison and range evaluation.

Lexical string comparison is never used to order versions. Each scheme
implements the ordering rules of its ecosystem; anything a scheme cannot parse
raises :class:`VersionParseError`, which callers turn into an explicit
UNKNOWN / unverified result instead of guessing.

Schemes
-------
- ``pep440``  Python packages, via ``packaging.version`` (PEP 440).
- ``semver``  npm, Cargo, Go modules: Semantic Versioning 2.0.0 precedence.
- ``maven``   Maven: qualifier ordering alpha < beta < milestone < rc < snapshot
              < release < sp/other, trailing zeros insignificant.
- ``dpkg``    Debian packages: epoch, upstream and revision with dpkg ordering
              (``~`` sorts before everything, letters before non-letters).
- ``rpm``     RPM packages: epoch, version, release with ``rpmvercmp`` rules.
- ``generic`` Upstream/vendor versions (CPE): numeric segments, recognised
              pre-release words, and single-letter patch suffixes
              (OpenSSL ``1.0.1g``, OpenSSH ``9.2p1``). Unknown words are rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from packaging.version import InvalidVersion, Version

from terminus.models import Ecosystem


class VersionParseError(ValueError):
    pass


class Scheme(StrEnum):
    PEP440 = "pep440"
    SEMVER = "semver"
    MAVEN = "maven"
    DPKG = "dpkg"
    RPM = "rpm"
    GENERIC = "generic"


def scheme_for(ecosystem: Ecosystem) -> Scheme:
    return {
        Ecosystem.PYPI: Scheme.PEP440,
        Ecosystem.NPM: Scheme.SEMVER,
        Ecosystem.CARGO: Scheme.SEMVER,
        Ecosystem.GO: Scheme.SEMVER,
        Ecosystem.MAVEN: Scheme.MAVEN,
        Ecosystem.DEB: Scheme.DPKG,
        Ecosystem.RPM: Scheme.RPM,
    }.get(ecosystem, Scheme.GENERIC)


def _sign(n: int) -> int:
    return (n > 0) - (n < 0)


# ---------------------------------------------------------------------------
# PEP 440
# ---------------------------------------------------------------------------


def _cmp_pep440(a: str, b: str) -> int:
    try:
        va, vb = Version(a), Version(b)
    except InvalidVersion as exc:
        raise VersionParseError(f"not a PEP 440 version: {exc}") from exc
    return (va > vb) - (va < vb)


# ---------------------------------------------------------------------------
# Semantic Versioning 2.0.0
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^v?(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$"
)


def _parse_semver(v: str) -> tuple[tuple[int, int, int], list[str]]:
    m = _SEMVER_RE.match(v.strip())
    if not m:
        raise VersionParseError(f"not a semantic version: {v!r}")
    core = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    pre = m.group(4).split(".") if m.group(4) else []
    return core, pre


def _cmp_semver(a: str, b: str) -> int:
    (ca, pa), (cb, pb) = _parse_semver(a), _parse_semver(b)
    if ca != cb:
        return (ca > cb) - (ca < cb)
    if not pa or not pb:
        # A version without pre-release has higher precedence.
        return (not pa) - (not pb)
    for x, y in zip(pa, pb, strict=False):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return _sign(int(x) - int(y))
        if xn != yn:
            return -1 if xn else 1  # numeric identifiers sort lower
        return (x > y) - (x < y)  # ASCII order for alphanumeric identifiers (per spec)
    return _sign(len(pa) - len(pb))


# ---------------------------------------------------------------------------
# Token-based comparison shared by Maven and generic upstream versions
# ---------------------------------------------------------------------------

# Token kinds, in sort order at the same position.
_PRE, _RELEASE, _POST, _NUM = 0, 1, 2, 3

_PRE_RANK = {
    "alpha": 0,
    "a": 0,
    "beta": 1,
    "b": 1,
    "milestone": 2,
    "m": 2,
    "pre": 3,
    "preview": 3,
    "rc": 4,
    "cr": 4,
    "c": 4,
    "snapshot": 5,
    "dev": -1,
}
_RELEASE_WORDS = {"ga", "final", "release"}
_POST_WORDS = {"sp", "p", "patch", "post", "pl"}

Token = tuple[int, int | str]


def _tokens(v: str, *, strict_words: bool) -> list[Token]:
    raw = re.findall(r"\d+|[a-z]+", v.lower())
    if not raw:
        raise VersionParseError(f"no version components in {v!r}")
    out: list[Token] = []
    for idx, tok in enumerate(raw):
        if tok.isdigit():
            out.append((_NUM, int(tok)))
            continue
        nxt_is_num = idx + 1 < len(raw) and raw[idx + 1].isdigit()
        if tok in _RELEASE_WORDS:
            continue
        if tok in _POST_WORDS:
            out.append((_POST, tok if tok != "pl" else "p"))
        elif tok in _PRE_RANK and (len(tok) > 1 or nxt_is_num):
            # Single letters a/b/c/m are pre-release markers only when followed by a
            # number ("1.0b2"); a bare trailing letter is a patch suffix ("1.0.1b").
            out.append((_PRE, _PRE_RANK[tok]))
        elif len(tok) == 1:
            out.append((_POST, tok))
        elif strict_words:
            raise VersionParseError(f"unrecognised version qualifier {tok!r} in {v!r}")
        else:
            out.append((_POST, tok))
    return out


def _cmp_tokens(ta: list[Token], tb: list[Token]) -> int:
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x is None:
            x = (_NUM, 0) if y is not None and y[0] == _NUM else (_RELEASE, 0)
        if y is None:
            y = (_NUM, 0) if x[0] == _NUM else (_RELEASE, 0)
        if x == y:
            continue
        if x[0] != y[0]:
            return _sign(x[0] - y[0])
        xv, yv = x[1], y[1]
        if isinstance(xv, int) and isinstance(yv, int):
            return _sign(xv - yv)
        return (str(xv) > str(yv)) - (str(xv) < str(yv))
    return 0


_GENERIC_ALLOWED = re.compile(r"^[0-9][0-9A-Za-z._\-]*$")
_MAVEN_ALLOWED = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._\-]*$")


_WILDCARD_SEGMENT = re.compile(r"(^|[.\-_])x($|[.\-_])", re.I)


def _cmp_generic(a: str, b: str) -> int:
    for v in (a, b):
        if not _GENERIC_ALLOWED.match(v):
            raise VersionParseError(f"unsupported characters in version {v!r}")
        if _WILDCARD_SEGMENT.search(v):
            raise VersionParseError(f"wildcard segment in version {v!r}")
    return _cmp_tokens(_tokens(a, strict_words=True), _tokens(b, strict_words=True))


def _cmp_maven(a: str, b: str) -> int:
    for v in (a, b):
        if not _MAVEN_ALLOWED.match(v):
            raise VersionParseError(f"unsupported characters in Maven version {v!r}")
    return _cmp_tokens(_tokens(a, strict_words=False), _tokens(b, strict_words=False))


# ---------------------------------------------------------------------------
# dpkg (Debian policy 5.6.12)
# ---------------------------------------------------------------------------

_DPKG_RE = re.compile(r"^(?:(\d+):)?([0-9][A-Za-z0-9.+~:\-]*?)(?:-([A-Za-z0-9.+~]+))?$")


def _dpkg_order(c: str) -> int:
    if c == "":
        return 0
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _verrevcmp(a: str, b: str) -> int:
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < la else "")
            bc = _dpkg_order(b[j] if j < lb else "")
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and a[i].isdigit() and j < lb and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _parse_dpkg(v: str) -> tuple[int, str, str]:
    m = _DPKG_RE.match(v.strip())
    if not m or not v.isascii():
        raise VersionParseError(f"not a Debian version: {v!r}")
    return int(m.group(1) or 0), m.group(2), m.group(3) or ""


def _cmp_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _parse_dpkg(a)
    eb, ub, rb = _parse_dpkg(b)
    if ea != eb:
        return _sign(ea - eb)
    return _verrevcmp(ua, ub) or _verrevcmp(ra, rb)


# ---------------------------------------------------------------------------
# RPM (rpmvercmp)
# ---------------------------------------------------------------------------

_RPM_ALLOWED = re.compile(r"^[A-Za-z0-9._+~^\-:]+$")


def _rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)

    def sep(c: str) -> bool:
        return not c.isalnum() and c not in "~^"

    while i < la or j < lb:
        while i < la and sep(a[i]):
            i += 1
        while j < lb and sep(b[j]):
            j += 1
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i += 1
            j += 1
            continue
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (i < la and j < lb):
            break
        si, sj = i, j
        if a[i].isdigit():
            isnum = True
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
        else:
            isnum = False
            while i < la and a[i].isalpha():
                i += 1
            while j < lb and b[j].isalpha():
                j += 1
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            return 1 if isnum else -1
        if isnum:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def _parse_evr(v: str) -> tuple[int, str, str | None]:
    v = v.strip()
    if not v or not _RPM_ALLOWED.match(v) or not v.isascii():
        raise VersionParseError(f"not an RPM version: {v!r}")
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        if not e.isdigit():
            raise VersionParseError(f"invalid RPM epoch in {v!r}")
        epoch = int(e)
    version, _, release = v.partition("-")
    if not version:
        raise VersionParseError("empty RPM version")
    return epoch, version, release or None


def _cmp_rpm(a: str, b: str) -> int:
    ea, va, ra = _parse_evr(a)
    eb, vb, rb = _parse_evr(b)
    if ea != eb:
        return _sign(ea - eb)
    c = _rpmvercmp(va, vb)
    if c or ra is None or rb is None:
        return c
    return _rpmvercmp(ra, rb)


_COMPARATORS = {
    Scheme.PEP440: _cmp_pep440,
    Scheme.SEMVER: _cmp_semver,
    Scheme.MAVEN: _cmp_maven,
    Scheme.DPKG: _cmp_dpkg,
    Scheme.RPM: _cmp_rpm,
    Scheme.GENERIC: _cmp_generic,
}


def compare(a: str, b: str, scheme: Scheme) -> int:
    """Return -1, 0 or 1. Raises VersionParseError when either side is unusable."""
    if not a or not b:
        raise VersionParseError("empty version")
    return _COMPARATORS[scheme](a.strip(), b.strip())


def upstream_version(version: str, ecosystem: Ecosystem) -> str:
    """Upstream part of a distribution package version (drops epoch/revision)."""
    if ecosystem == Ecosystem.DEB:
        _, upstream, _ = _parse_dpkg(version)
        # Distro upstream strings may carry +dfsg / ~ suffixes; keep the leading part.
        return re.split(r"[+~]", upstream, maxsplit=1)[0]
    if ecosystem == Ecosystem.RPM:
        _, ver, _ = _parse_evr(version)
        return ver
    return version


# ---------------------------------------------------------------------------
# Ranges
# ---------------------------------------------------------------------------


class RangeCheck(StrEnum):
    IN = "in_range"
    OUT = "out_of_range"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VersionRange:
    """A single affected range. ``start`` None means unbounded below."""

    start: str | None = None
    start_inclusive: bool = True
    end: str | None = None
    end_inclusive: bool = False
    exact: str | None = None

    @property
    def unbounded(self) -> bool:
        return self.exact is None and self.start is None and self.end is None

    def describe(self) -> str:
        if self.exact is not None:
            return f"== {self.exact}"
        parts = []
        if self.start is not None:
            parts.append(f"{'>=' if self.start_inclusive else '>'} {self.start}")
        if self.end is not None:
            parts.append(f"{'<=' if self.end_inclusive else '<'} {self.end}")
        return ", ".join(parts) if parts else "all versions"

    def check(self, version: str, scheme: Scheme) -> tuple[RangeCheck, str]:
        try:
            if self.exact is not None:
                hit = compare(version, self.exact, scheme) == 0
                return (RangeCheck.IN if hit else RangeCheck.OUT), self.describe()
            if self.start is not None:
                c = compare(version, self.start, scheme)
                if c < 0 or (c == 0 and not self.start_inclusive):
                    return RangeCheck.OUT, self.describe()
            if self.end is not None:
                c = compare(version, self.end, scheme)
                if c > 0 or (c == 0 and not self.end_inclusive):
                    return RangeCheck.OUT, self.describe()
            return RangeCheck.IN, self.describe()
        except VersionParseError as exc:
            return RangeCheck.UNKNOWN, f"{self.describe()} (cannot compare: {exc})"
