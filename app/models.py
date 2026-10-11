"""Core domain models shared by every layer.

Raw source data (NVD, KEV, EPSS, OSV) is kept in dedicated models that carry
their retrieval timestamps. Derived values (match status, priority, fix
assessment) live in separate models so they can never be confused with what a
source actually said.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
ASSET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,63}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)"
    r"(\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*$"
)
CPE23_RE = re.compile(r"^cpe:2\.3:[aho\*\-](?::(?:[^:\\]|\\.)*){10}$")
PURL_RE = re.compile(r"^pkg:[a-z][a-z0-9.+\-]*/[^\s]+$")
_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f​-‏‪-‮⁦-⁩]")


def utcnow() -> datetime:
    return datetime.now(UTC)


def clean_text(value: str) -> str:
    """Normalize user-supplied text: NFKC, strip control/bidi chars, trim."""
    value = unicodedata.normalize("NFKC", value)
    value = _CONTROL_CHARS.sub("", value)
    return value.strip()


def validate_cve_id(value: str) -> str:
    value = clean_text(value).upper()
    if not CVE_ID_RE.match(value):
        raise ValueError(f"invalid CVE identifier: {value[:40]!r}")
    return value


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Ecosystem(StrEnum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    NUGET = "nuget"
    GO = "go"
    CARGO = "cargo"
    RUBYGEMS = "rubygems"
    DEB = "deb"
    RPM = "rpm"
    GENERIC = "generic"

    @property
    def is_distro_package(self) -> bool:
        return self in (Ecosystem.DEB, Ecosystem.RPM)

    @property
    def osv_name(self) -> str | None:
        """Ecosystem name as used by OSV.dev (None if OSV does not apply)."""
        return {
            Ecosystem.PYPI: "PyPI",
            Ecosystem.NPM: "npm",
            Ecosystem.MAVEN: "Maven",
            Ecosystem.NUGET: "NuGet",
            Ecosystem.GO: "Go",
            Ecosystem.CARGO: "crates.io",
            Ecosystem.RUBYGEMS: "RubyGems",
        }.get(self)


class Criticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Environment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"


class MatchStatus(StrEnum):
    CONFIRMED_AFFECTED = "confirmed_affected"
    POTENTIALLY_AFFECTED = "potentially_affected"
    CONFIRMED_UNAFFECTED = "confirmed_unaffected"
    UNVERIFIED = "unverified"

    @property
    def label(self) -> str:
        return {
            MatchStatus.CONFIRMED_AFFECTED: "Confirmed affected",
            MatchStatus.POTENTIALLY_AFFECTED: "Potentially affected",
            MatchStatus.CONFIRMED_UNAFFECTED: "Confirmed unaffected",
            MatchStatus.UNVERIFIED: "Unverified",
        }[self]


class IdentityMethod(StrEnum):
    """How the inventory item was tied to the vulnerable product."""

    CPE_EXACT = "cpe_exact"  # inventory CPE vendor+product == NVD CPE vendor+product
    PACKAGE_EXACT = "package_exact"  # ecosystem + package name == OSV affected package
    CURATED_ALIAS = "curated_alias"  # documented alias table entry
    VENDOR_PRODUCT = "vendor_product"  # normalized vendor AND product both equal
    NAME_ONLY = "name_only"  # product equal, vendor not supplied
    AMBIGUOUS = "ambiguous"  # similar name / vendor mismatch: candidate only

    @property
    def confidence(self) -> float:
        return {
            IdentityMethod.CPE_EXACT: 1.0,
            IdentityMethod.PACKAGE_EXACT: 1.0,
            IdentityMethod.CURATED_ALIAS: 0.9,
            IdentityMethod.VENDOR_PRODUCT: 0.85,
            IdentityMethod.NAME_ONLY: 0.5,
            IdentityMethod.AMBIGUOUS: 0.25,
        }[self]

    @property
    def is_reliable(self) -> bool:
        return self.confidence >= 0.85


class TrustTier(StrEnum):
    AUTHORITATIVE_STRUCTURED = "authoritative_structured"  # NVD, OSV, KEV, EPSS APIs
    VENDOR_ADVISORY = "vendor_advisory"  # page on an allow-listed vendor domain
    SUPPLEMENTARY = "supplementary"  # web search / GitHub discussion
    AI_INTERPRETATION = "ai_interpretation"  # LLM-written narrative


class FixStatus(StrEnum):
    VERIFIED = "verified"  # >=1 ecosystem advisory or >=2 agreeing structured sources
    SINGLE_SOURCE = "single_source"  # only NVD states the first unaffected version
    CONFLICT = "conflict"  # structured sources disagree
    UNKNOWN = "unknown"  # no trustworthy source states a fixed version
    NOT_APPLICABLE = "not_applicable"  # item is not affected


class SourceState(StrEnum):
    OK = "ok"
    CACHED = "cached"
    UNAVAILABLE = "unavailable"
    ERROR = "error"
    DISABLED = "disabled"
    DEMO = "demo"


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


class InventoryItem(BaseModel):
    """One software installation on one asset (the unit that gets matched)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid", frozen=True)

    asset_id: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=253)
    os_name: str | None = Field(default=None, max_length=100)
    os_version: str | None = Field(default=None, max_length=100)
    software_name: str = Field(min_length=1, max_length=200)
    software_version: str | None = Field(default=None, max_length=100)
    ecosystem: Ecosystem = Ecosystem.GENERIC
    vendor: str | None = Field(default=None, max_length=200)
    cpe: str | None = Field(default=None, max_length=500)
    purl: str | None = Field(default=None, max_length=500)
    criticality: Criticality = Criticality.MEDIUM
    internet_exposed: bool | None = None
    environment: Environment | None = None
    business_context: str | None = Field(default=None, max_length=500)
    owner: str | None = Field(default=None, max_length=200)

    @field_validator(
        "hostname",
        "os_name",
        "os_version",
        "software_name",
        "software_version",
        "vendor",
        "business_context",
        "owner",
        "cpe",
        "purl",
        mode="before",
    )
    @classmethod
    def _clean_optional(cls, v: Any) -> Any:
        if v is None:
            return None
        if isinstance(v, (int, float)) and not isinstance(v, bool):
            v = str(v)
        if not isinstance(v, str):
            raise ValueError("must be a string")
        v = clean_text(v)
        return v or None

    @field_validator("asset_id")
    @classmethod
    def _asset_id(cls, v: str) -> str:
        v = clean_text(v)
        if not ASSET_ID_RE.match(v):
            raise ValueError("asset_id may contain letters, digits, '.', '_', ':', '-' only")
        return v

    @field_validator("hostname")
    @classmethod
    def _hostname(cls, v: str | None) -> str | None:
        if v is not None and not HOSTNAME_RE.match(v):
            raise ValueError("hostname is not a valid DNS name")
        return v

    @field_validator("cpe")
    @classmethod
    def _cpe(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.lower()
            if not CPE23_RE.match(v):
                raise ValueError("cpe must be a CPE 2.3 formatted string (cpe:2.3:part:vendor:...)")
        return v

    @field_validator("purl")
    @classmethod
    def _purl(cls, v: str | None) -> str | None:
        if v is not None and not PURL_RE.match(v):
            raise ValueError("purl must look like pkg:type/namespace/name@version")
        return v

    @property
    def item_id(self) -> str:
        key = "|".join(
            [
                self.asset_id,
                self.ecosystem.value,
                (self.vendor or "").lower(),
                self.software_name.lower(),
                self.software_version or "",
            ]
        )
        return hashlib.sha256(key.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Source records (raw facts, each with retrieval timestamps)
# ---------------------------------------------------------------------------


class CvssData(BaseModel):
    version: str
    base_score: float = Field(ge=0, le=10)
    vector: str | None = None
    severity: str | None = None
    source: str | None = None  # who scored it (NVD or CNA)
    score_type: str | None = None  # Primary / Secondary


class CpeMatchRule(BaseModel):
    criteria: str
    vulnerable: bool = True
    version_start_including: str | None = None
    version_start_excluding: str | None = None
    version_end_including: str | None = None
    version_end_excluding: str | None = None


class ConfigNode(BaseModel):
    operator: str = "OR"
    negate: bool = False
    matches: list[CpeMatchRule] = Field(default_factory=list)


class Configuration(BaseModel):
    operator: str | None = None
    nodes: list[ConfigNode] = Field(default_factory=list)


class Reference(BaseModel):
    url: str
    source: str | None = None
    tags: list[str] = Field(default_factory=list)


class CveRecord(BaseModel):
    cve_id: str
    published: datetime | None = None
    last_modified: datetime | None = None
    vuln_status: str | None = None
    description: str = ""
    cvss: CvssData | None = None
    cwes: list[str] = Field(default_factory=list)
    configurations: list[Configuration] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    source: str = "nvd"
    retrieved_at: datetime = Field(default_factory=utcnow)

    @field_validator("cve_id")
    @classmethod
    def _cve_id(cls, v: str) -> str:
        return validate_cve_id(v)

    @property
    def is_analyzed(self) -> bool:
        """True when NVD has completed analysis (configurations are curated)."""
        return (self.vuln_status or "").lower() in {"analyzed", "modified"}

    @property
    def vendor_advisory_urls(self) -> list[str]:
        return [r.url for r in self.references if "Vendor Advisory" in r.tags]

    @property
    def nvd_url(self) -> str:
        return f"https://nvd.nist.gov/vuln/detail/{self.cve_id}"


class KevEntry(BaseModel):
    cve_id: str
    vendor_project: str | None = None
    product: str | None = None
    vulnerability_name: str | None = None
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = None
    known_ransomware_use: str | None = None
    catalog_version: str | None = None
    retrieved_at: datetime = Field(default_factory=utcnow)


class EpssScore(BaseModel):
    cve_id: str
    epss: float = Field(ge=0, le=1)
    percentile: float = Field(ge=0, le=1)
    score_date: str | None = None
    retrieved_at: datetime = Field(default_factory=utcnow)


class OsvEvent(BaseModel):
    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


class OsvRange(BaseModel):
    type: str
    events: list[OsvEvent] = Field(default_factory=list)


class OsvAffected(BaseModel):
    ecosystem: str | None = None
    name: str | None = None
    purl: str | None = None
    ranges: list[OsvRange] = Field(default_factory=list)
    versions: list[str] = Field(default_factory=list)


class OsvAdvisory(BaseModel):
    id: str
    aliases: list[str] = Field(default_factory=list)
    summary: str | None = None
    modified: str | None = None
    published: str | None = None
    affected: list[OsvAffected] = Field(default_factory=list)
    references: list[Reference] = Field(default_factory=list)
    retrieved_at: datetime = Field(default_factory=utcnow)
    source: str = "osv"

    @property
    def url(self) -> str:
        return f"https://osv.dev/vulnerability/{self.id}"

    @property
    def advisory_urls(self) -> list[str]:
        return [r.url for r in self.references if "ADVISORY" in r.tags]


class SourceStatus(BaseModel):
    """Outcome of one attempt to use a data source."""

    source: str
    state: SourceState
    detail: str | None = None
    retrieved_at: datetime | None = None


# ---------------------------------------------------------------------------
# Derived assessments
# ---------------------------------------------------------------------------


class Evidence(BaseModel):
    claim: str
    source: str
    trust_tier: TrustTier
    url: str | None = None
    retrieved_at: datetime | None = None
    excerpt: str | None = None  # untrusted text; never interpreted as instructions
    flags: list[str] = Field(default_factory=list)


class FixCandidate(BaseModel):
    version: str
    source: str
    trust_tier: TrustTier
    url: str | None = None


class MatchResult(BaseModel):
    item_id: str
    cve_id: str
    status: MatchStatus
    identity_method: IdentityMethod
    version_scheme: str
    reasons: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    vulnerable_ranges: list[str] = Field(default_factory=list)
    fix_candidates: list[FixCandidate] = Field(default_factory=list)
    conditional: bool = False  # NVD config requires additional platform conditions

    @property
    def confidence(self) -> float:
        """Confidence that the status is correct for this item (0..1)."""
        base = self.identity_method.confidence
        if self.status == MatchStatus.POTENTIALLY_AFFECTED:
            base = min(base, 0.6)
        elif self.status == MatchStatus.UNVERIFIED:
            base = min(base, 0.3)
        if self.conditional:
            base = min(base, 0.6)
        return round(base, 2)


class KevStatus(BaseModel):
    in_kev: bool | None  # None = source unavailable / unknown
    date_added: str | None = None
    due_date: str | None = None
    required_action: str | None = None
    known_ransomware_use: str | None = None
    retrieved_at: datetime | None = None
    source_state: SourceState = SourceState.OK


class EpssStatus(BaseModel):
    score: float | None  # None = not available
    percentile: float | None = None
    score_date: str | None = None
    retrieved_at: datetime | None = None
    source_state: SourceState = SourceState.OK


class FixAssessment(BaseModel):
    status: FixStatus
    fixed_version: str | None = None  # set only when the fix is established (not on conflict)
    # On CONFLICT: the highest version any structured source names as fixed.
    # Upgrading to it satisfies every source's claim; it is still not "verified".
    conservative_target: str | None = None
    sources: list[FixCandidate] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class PriorityFactor(BaseModel):
    name: str
    raw_value: str  # exactly what the source said (or "missing")
    points: float
    max_points: float
    explanation: str
    missing: bool = False


class PriorityResult(BaseModel):
    score: float
    tier: str  # P1..P4, or INFO
    factors: list[PriorityFactor]
    confidence_multiplier: float
    missing_data: list[str] = Field(default_factory=list)
    overrides: list[str] = Field(default_factory=list)
    formula: str


class Recommendation(BaseModel):
    action: str  # upgrade | mitigate | verify | monitor | none
    summary: str
    steps: list[str] = Field(default_factory=list)
    requires_human_review: bool = True
    patch_applied: bool = False  # Terminus never applies patches


class ToolCallRecord(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool
    error: str | None = None
    summary: str | None = None
    started_at: datetime
    duration_ms: int


class ResearchTrace(BaseModel):
    mode: str  # deterministic | llm
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    stop_reason: str = ""
    budget: dict[str, float] = Field(default_factory=dict)
    injection_flags: list[str] = Field(default_factory=list)


class Finding(BaseModel):
    """Complete, report-ready assessment of one CVE on one inventory item."""

    finding_id: str
    cve_id: str
    summary: str
    item: InventoryItem
    match: MatchResult
    cvss: CvssData | None = None
    cve_published: datetime | None = None
    cve_last_modified: datetime | None = None
    cve_retrieved_at: datetime | None = None
    cve_source: str = "nvd"
    kev: KevStatus
    epss: EpssStatus
    priority: PriorityResult
    fix: FixAssessment
    recommendation: Recommendation
    vendor_advisory_urls: list[str] = Field(default_factory=list)
    supporting_urls: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    next_verification_step: str = ""
    ai_interpretation: str | None = None
    research: ResearchTrace | None = None
    first_seen: datetime = Field(default_factory=utcnow)
    last_assessed: datetime = Field(default_factory=utcnow)
    scan_id: str | None = None

    @staticmethod
    def make_id(item_id: str, cve_id: str) -> str:
        return hashlib.sha256(f"{item_id}|{cve_id}".encode()).hexdigest()[:20]


# ``CveRecord.source`` / ``Finding.cve_source`` of records served from the bundled
# demo fixtures. Live and demo data are never mixed in one database.
DEMO_SOURCE = "demo-fixture"


class ScanRecord(BaseModel):
    scan_id: str
    mode: str  # incremental | full | demo
    status: str  # running | completed | completed_with_errors | failed
    started_at: datetime
    finished_at: datetime | None = None
    window_start: datetime | None = None
    window_end: datetime | None = None
    cves_processed: int = 0
    findings_count: int = 0
    source_status: list[SourceStatus] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    notices: list[str] = Field(default_factory=list)
