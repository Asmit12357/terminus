"""Product identity: CPE parsing, name normalization and a curated alias table.

Normalization is deliberately conservative. It unifies case, Unicode forms and
separators, and drops legal/organizational suffixes from *vendor* names only.
It never strips digits, editions or component names, so ``log4j-core`` stays
distinct from ``log4j-api`` and ``python3`` from ``python2``.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from urllib.parse import unquote

from terminus.models import Ecosystem, IdentityMethod, InventoryItem

_VENDOR_NOISE = {
    "the",
    "inc",
    "incorporated",
    "corp",
    "corporation",
    "co",
    "company",
    "ltd",
    "limited",
    "llc",
    "gmbh",
    "ag",
    "sa",
    "plc",
    "foundation",
    "software",
    "project",
    "org",
    "community",
    "team",
    "group",
    "technologies",
    "systems",
}


@lru_cache(maxsize=65536)
def _base(text: str) -> str:
    text = unicodedata.normalize("NFKC", text).lower()
    text = re.sub(r"[^0-9a-z]+", "_", text)
    return text.strip("_")


@lru_cache(maxsize=65536)
def normalize_product(name: str, vendor: str | None = None) -> str:
    """``Apache HTTP Server`` (vendor ``apache``) -> ``http_server``."""
    product = _base(name)
    if vendor:
        prefix = vendor + "_"
        if product.startswith(prefix) and len(product) > len(prefix):
            product = product[len(prefix) :]
    return product


@lru_cache(maxsize=65536)
def normalize_vendor(name: str | None) -> str | None:
    """``The Apache Software Foundation`` -> ``apache``; ``F5, Inc.`` -> ``f5``."""
    if not name:
        return None
    tokens = [t for t in _base(name).split("_") if t]
    kept = [t for t in tokens if t not in _VENDOR_NOISE]
    result = "_".join(kept or tokens)
    return result or None


def normalize_package_name(name: str, ecosystem: Ecosystem) -> str:
    if ecosystem == Ecosystem.PYPI:  # PEP 503
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in (Ecosystem.NPM, Ecosystem.CARGO, Ecosystem.NUGET, Ecosystem.RUBYGEMS):
        return name.lower()
    return name  # Maven and Go names are case-sensitive


# ---------------------------------------------------------------------------
# CPE 2.3
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Cpe:
    part: str
    vendor: str
    product: str
    version: str
    update: str
    target_sw: str

    @property
    def key(self) -> tuple[str, str]:
        return (self.vendor, self.product)

    @property
    def full_version(self) -> str | None:
        """Version including the update field, or None for ANY/NA."""
        if self.version in ("*", "-", ""):
            return None
        if self.update not in ("*", "-", ""):
            return f"{self.version}-{self.update}"
        return self.version


def _split_cpe(cpe: str) -> list[str]:
    fields, buf, escaped = [], [], False
    for ch in cpe:
        if escaped:
            buf.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":":
            fields.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    fields.append("".join(buf))
    return fields


@lru_cache(maxsize=65536)
def parse_cpe(cpe: str) -> Cpe | None:
    fields = _split_cpe(cpe.strip().lower())
    if len(fields) != 13 or fields[0] != "cpe" or fields[1] != "2.3":
        return None
    return Cpe(
        part=fields[2],
        vendor=fields[3],
        product=fields[4],
        version=fields[5],
        update=fields[6],
        target_sw=fields[10],
    )


# ---------------------------------------------------------------------------
# Package URLs
# ---------------------------------------------------------------------------

_PURL_TYPES = {
    "pypi": Ecosystem.PYPI,
    "npm": Ecosystem.NPM,
    "maven": Ecosystem.MAVEN,
    "nuget": Ecosystem.NUGET,
    "golang": Ecosystem.GO,
    "cargo": Ecosystem.CARGO,
    "gem": Ecosystem.RUBYGEMS,
    "deb": Ecosystem.DEB,
    "rpm": Ecosystem.RPM,
}


@dataclass(frozen=True)
class PackageId:
    ecosystem: Ecosystem
    name: str  # Maven: group:artifact ; npm: @scope/name ; Go: module path


def parse_purl(purl: str) -> PackageId | None:
    m = re.match(r"^pkg:([a-z0-9.+\-]+)/([^@?#]+)", purl.strip())
    if not m:
        return None
    eco = _PURL_TYPES.get(m.group(1))
    if eco is None:
        return None
    path = unquote(m.group(2))
    parts = path.split("/")
    if eco == Ecosystem.MAVEN and len(parts) == 2:
        name = f"{parts[0]}:{parts[1]}"
    elif eco in (Ecosystem.DEB, Ecosystem.RPM):
        name = parts[-1]  # distro namespace (debian/ubuntu/fedora) is not part of the name
    else:
        name = path
    return PackageId(eco, normalize_package_name(name, eco))


def package_identity(item: InventoryItem) -> PackageId | None:
    if item.purl:
        pid = parse_purl(item.purl)
        if pid:
            return pid
    if item.ecosystem == Ecosystem.GENERIC:
        return None
    return PackageId(item.ecosystem, normalize_package_name(item.software_name, item.ecosystem))


# ---------------------------------------------------------------------------
# Curated aliases: package / product names -> NVD CPE vendor:product
# ---------------------------------------------------------------------------
# Each entry is documented in README ("Product identity"). Package-ecosystem
# entries are reliable because a package name is unique within its ecosystem.
# Generic-name entries additionally require the inventory vendor to be one of
# the listed spellings; without a vendor they only yield NAME_ONLY.

PACKAGE_ALIASES: dict[tuple[Ecosystem, str], tuple[tuple[str, str], ...]] = {
    (Ecosystem.MAVEN, "org.apache.logging.log4j:log4j-core"): (("apache", "log4j"),),
    (Ecosystem.MAVEN, "org.apache.tomcat:tomcat"): (("apache", "tomcat"),),
    (Ecosystem.MAVEN, "org.springframework:spring-beans"): (("vmware", "spring_framework"),),
    (Ecosystem.PYPI, "requests"): (("python", "requests"),),
    (Ecosystem.PYPI, "django"): (("djangoproject", "django"),),
    (Ecosystem.PYPI, "jinja2"): (("palletsprojects", "jinja"),),
    (Ecosystem.PYPI, "urllib3"): (("python", "urllib3"),),
    (Ecosystem.NPM, "lodash"): (("lodash", "lodash"),),
    (Ecosystem.NPM, "express"): (("expressjs", "express"), ("openjsf", "express")),
    (Ecosystem.DEB, "openssh-server"): (("openbsd", "openssh"),),
    (Ecosystem.DEB, "openssh-client"): (("openbsd", "openssh"),),
    (Ecosystem.RPM, "openssh-server"): (("openbsd", "openssh"),),
    (Ecosystem.RPM, "openssh"): (("openbsd", "openssh"),),
    (Ecosystem.DEB, "openssl"): (("openssl", "openssl"),),
    (Ecosystem.DEB, "libssl3"): (("openssl", "openssl"),),
    (Ecosystem.RPM, "openssl"): (("openssl", "openssl"),),
    (Ecosystem.RPM, "openssl-libs"): (("openssl", "openssl"),),
    (Ecosystem.DEB, "curl"): (("haxx", "curl"),),
    (Ecosystem.DEB, "libcurl4"): (("haxx", "libcurl"), ("haxx", "curl")),
    (Ecosystem.RPM, "curl"): (("haxx", "curl"),),
    (Ecosystem.RPM, "libcurl"): (("haxx", "libcurl"), ("haxx", "curl")),
    (Ecosystem.DEB, "apache2"): (("apache", "http_server"),),
    (Ecosystem.RPM, "httpd"): (("apache", "http_server"),),
    (Ecosystem.DEB, "nginx"): (("f5", "nginx"), ("nginx", "nginx")),
    (Ecosystem.RPM, "nginx"): (("f5", "nginx"), ("nginx", "nginx")),
    (Ecosystem.DEB, "xz-utils"): (("tukaani", "xz"),),
    (Ecosystem.RPM, "xz"): (("tukaani", "xz"),),
}


@dataclass(frozen=True)
class NameAlias:
    names: frozenset[str]  # normalized product names
    vendors: frozenset[str]  # normalized vendor spellings that confirm identity
    cpes: tuple[tuple[str, str], ...]


NAME_ALIASES: tuple[NameAlias, ...] = (
    NameAlias(
        frozenset({"http_server", "httpd", "apache_httpd", "apache_http_server", "apache2"}),
        frozenset({"apache"}),
        (("apache", "http_server"),),
    ),
    NameAlias(
        frozenset({"openssh", "openssh_server", "sshd"}),
        frozenset({"openbsd", "openssh"}),
        (("openbsd", "openssh"),),
    ),
    NameAlias(
        frozenset({"curl", "libcurl"}),
        frozenset({"haxx", "curl", "daniel_stenberg"}),
        (("haxx", "curl"), ("haxx", "libcurl")),
    ),
    NameAlias(
        frozenset({"nginx", "nginx_open_source"}),
        frozenset({"f5", "nginx", "f5_networks"}),
        (("f5", "nginx"), ("nginx", "nginx")),
    ),
    NameAlias(frozenset({"openssl"}), frozenset({"openssl"}), (("openssl", "openssl"),)),
    NameAlias(
        frozenset({"log4j", "log4j2", "log4j_core"}),
        frozenset({"apache"}),
        (("apache", "log4j"),),
    ),
    NameAlias(frozenset({"xz", "xz_utils"}), frozenset({"tukaani"}), (("tukaani", "xz"),)),
)


@dataclass(frozen=True)
class IdentityCandidate:
    vendor: str
    product: str
    method: IdentityMethod
    basis: str  # human-readable reason


def cpe_identities(item: InventoryItem) -> list[IdentityCandidate]:
    """All CPE vendor:product identities this inventory item can claim, best first."""
    return list(_cpe_identities(item))


@lru_cache(maxsize=16384)
def _cpe_identities(item: InventoryItem) -> tuple[IdentityCandidate, ...]:
    found: dict[tuple[str, str], IdentityCandidate] = {}

    def add(vendor: str, product: str, method: IdentityMethod, basis: str) -> None:
        key = (vendor, product)
        if key not in found or method.confidence > found[key].method.confidence:
            found[key] = IdentityCandidate(vendor, product, method, basis)

    if item.cpe:
        cpe = parse_cpe(item.cpe)
        if cpe:
            add(cpe.vendor, cpe.product, IdentityMethod.CPE_EXACT, f"inventory CPE {item.cpe}")

    pid = package_identity(item)
    if pid:
        for v, p in PACKAGE_ALIASES.get((pid.ecosystem, pid.name), ()):
            add(v, p, IdentityMethod.CURATED_ALIAS, f"alias table: {pid.ecosystem}/{pid.name}")

    vendor = normalize_vendor(item.vendor)
    product = normalize_product(item.software_name, vendor)
    for alias in NAME_ALIASES:
        if product in alias.names or _base(item.software_name) in alias.names:
            for v, p in alias.cpes:
                if vendor is None:
                    add(v, p, IdentityMethod.NAME_ONLY, f"name '{item.software_name}' (no vendor)")
                elif vendor in alias.vendors:
                    add(
                        v,
                        p,
                        IdentityMethod.CURATED_ALIAS,
                        f"alias table: name '{item.software_name}' + vendor '{item.vendor}'",
                    )
    return tuple(sorted(found.values(), key=lambda c: -c.method.confidence))


def compare_identity(item: InventoryItem, cpe: Cpe) -> IdentityCandidate | None:
    """Relate an inventory item to one NVD CPE. Returns None when unrelated."""
    for cand in cpe_identities(item):
        if cand.vendor == cpe.vendor and cand.product == cpe.product:
            return cand

    vendor = normalize_vendor(item.vendor)
    product = normalize_product(item.software_name, vendor)
    base_name = _base(item.software_name)
    product_equal = cpe.product in (product, base_name)
    if product_equal:
        if vendor is None:
            return IdentityCandidate(
                cpe.vendor,
                cpe.product,
                IdentityMethod.NAME_ONLY,
                f"product name equals CPE product '{cpe.product}'; vendor not recorded",
            )
        if vendor == cpe.vendor:
            return IdentityCandidate(
                cpe.vendor,
                cpe.product,
                IdentityMethod.VENDOR_PRODUCT,
                f"normalized vendor+product equal CPE {cpe.vendor}:{cpe.product}",
            )
        return IdentityCandidate(
            cpe.vendor,
            cpe.product,
            IdentityMethod.AMBIGUOUS,
            f"product name equals '{cpe.product}' but vendor '{item.vendor}' "
            f"differs from CPE vendor '{cpe.vendor}' (possible fork or different product)",
        )
    # Whole-token containment, e.g. 'openssl_libs' vs 'openssl'. Candidate only.
    item_tokens = set(product.split("_"))
    cpe_tokens = set(cpe.product.split("_"))
    if (
        len(cpe.product) >= 4
        and cpe_tokens <= item_tokens
        and (vendor is None or vendor == cpe.vendor)
    ):
        return IdentityCandidate(
            cpe.vendor,
            cpe.product,
            IdentityMethod.AMBIGUOUS,
            f"name '{item.software_name}' contains CPE product '{cpe.product}' "
            "but is not an exact identity",
        )
    return None


# Words that tie a package name in free text to its ecosystem ("requests" alone is
# usually the English word; "Python requests" or "PyPI package requests" is not).
_ECOSYSTEM_CONTEXT: dict[Ecosystem, tuple[str, ...]] = {
    Ecosystem.PYPI: ("python", "pypi", "pip"),
    Ecosystem.NPM: ("npm", "node", "nodejs", "javascript"),
    Ecosystem.MAVEN: ("java", "maven"),
    Ecosystem.NUGET: ("nuget", "dotnet", "net"),
    Ecosystem.GO: ("golang", "go_module"),
    Ecosystem.CARGO: ("rust", "crate", "crates"),
    Ecosystem.RUBYGEMS: ("ruby", "rubygems", "gem"),
}


def mentions_product(item: InventoryItem, text: str) -> bool:
    """Keyword candidate test for CVEs that have no structured product data yet.

    Requires a whole-word mention of the product name (>= 4 chars) PLUS one
    corroborating signal: the vendor's name, an ecosystem context word, or a
    version expression right after the product name ("curl before 8.4.0").
    """
    vendor = normalize_vendor(item.vendor)
    product = normalize_product(item.software_name, vendor)
    if len(product) < 4:
        return False
    words = f"_{_base(text)}_"
    if f"_{product}_" not in words:
        return False
    if vendor and any(f"_{t}_" in words for t in vendor.split("_") if len(t) >= 2):
        return True
    if any(f"_{w}_" in words for w in _ECOSYSTEM_CONTEXT.get(item.ecosystem, ())):
        return True
    name_re = re.escape(product).replace("_", r"[\s_.\-]+")
    versioned = rf"\b{name_re}\b[^.;\n]{{0,25}}?\b(before|through|prior to|versions?|v?\d+\.\d+)"
    return re.search(versioned, unicodedata.normalize("NFKC", text), re.I) is not None
