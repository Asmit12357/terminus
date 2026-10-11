"""CISA Known Exploited Vulnerabilities (KEV) catalog connector.

Source: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
The JSON feed is a single document (~1-2 MB). KEV membership means CISA has
reliable evidence of exploitation in the wild; absence from KEV does NOT mean
a CVE is not exploited.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError

from app.config import Settings
from app.connectors.http import HttpClient, SourceUnavailable
from app.models import CVE_ID_RE, KevEntry


def _s(value: Any, limit: int = 2000) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


def parse_catalog(payload: Any, retrieved_at: datetime) -> tuple[list[KevEntry], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("KEV feed has no 'vulnerabilities' list")
    version = _s(payload.get("catalogVersion"), 50)
    entries, errors = [], []
    for idx, v in enumerate(payload["vulnerabilities"]):
        cve_id = v.get("cveID") if isinstance(v, dict) else None
        if not isinstance(cve_id, str) or not CVE_ID_RE.match(cve_id.strip()):
            errors.append(f"entry {idx}: invalid cveID")
            continue
        try:
            entries.append(
                KevEntry(
                    cve_id=cve_id.strip(),
                    vendor_project=_s(v.get("vendorProject"), 200),
                    product=_s(v.get("product"), 200),
                    vulnerability_name=_s(v.get("vulnerabilityName"), 300),
                    date_added=_s(v.get("dateAdded"), 20),
                    due_date=_s(v.get("dueDate"), 20),
                    required_action=_s(v.get("requiredAction"), 1000),
                    known_ransomware_use=_s(v.get("knownRansomwareCampaignUse"), 20),
                    catalog_version=version,
                    retrieved_at=retrieved_at,
                )
            )
        except ValidationError as exc:
            errors.append(f"entry {idx}: {exc.error_count()} validation errors")
    return entries, errors


class KevConnector:
    name = "cisa_kev"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings
        self.errors: list[str] = []
        self.stale = False

    def fetch_catalog(self) -> list[KevEntry]:
        result = self.http.request(
            "GET",
            self.settings.kev_url,
            source=self.name,
            cache_ttl=timedelta(hours=self.settings.cache_ttl_hours),
            max_bytes=25_000_000,
        )
        self.stale = result.stale
        try:
            entries, errors = parse_catalog(result.json(), result.fetched_at)
        except ValueError as exc:
            raise SourceUnavailable(self.name, f"malformed feed: {exc}") from exc
        self.errors.extend(errors)
        return entries
