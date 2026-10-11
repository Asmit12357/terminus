"""OSV.dev connector: structured, ecosystem-native advisories.

Docs: https://google.github.io/osv.dev/api/
OSV aggregates maintainer/ecosystem advisory databases (GitHub Security
Advisories, PyPA, RustSec, Go, ...). Its ``affected[].ranges`` use the
package ecosystem's own version semantics, which makes it the authoritative
structured source for package-level fixed versions.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit

from pydantic import ValidationError

from app.config import Settings
from app.connectors.http import HttpClient, SourceUnavailable
from app.matching.normalize import PackageId
from app.models import OsvAdvisory, OsvAffected, OsvEvent, OsvRange, Reference

_OSV_ID = r"^[A-Za-z0-9][A-Za-z0-9._:\-]{2,80}$"


def parse_osv(vuln: Any, retrieved_at: datetime) -> OsvAdvisory:
    if not isinstance(vuln, dict) or not isinstance(vuln.get("id"), str):
        raise ValueError("OSV record has no id")
    affected = []
    for a in vuln.get("affected") or []:
        if not isinstance(a, dict):
            continue
        pkg = a.get("package") or {}
        ranges = []
        for r in a.get("ranges") or []:
            if not isinstance(r, dict) or not isinstance(r.get("type"), str):
                continue
            events = []
            for e in r.get("events") or []:
                if not isinstance(e, dict):
                    continue
                events.append(
                    OsvEvent(
                        introduced=_str(e.get("introduced")),
                        fixed=_str(e.get("fixed")),
                        last_affected=_str(e.get("last_affected")),
                        limit=_str(e.get("limit")),
                    )
                )
            ranges.append(OsvRange(type=r["type"], events=events))
        versions = [v for v in a.get("versions") or [] if isinstance(v, str)][:2000]
        affected.append(
            OsvAffected(
                ecosystem=_str(pkg.get("ecosystem")),
                name=_str(pkg.get("name")),
                purl=_str(pkg.get("purl")),
                ranges=ranges,
                versions=versions,
            )
        )
    refs = []
    for r in vuln.get("references") or []:
        if (
            isinstance(r, dict)
            and isinstance(r.get("url"), str)
            and urlsplit(r["url"]).scheme in ("http", "https")
        ):
            refs.append(Reference(url=r["url"][:2000], tags=[str(r.get("type") or "WEB")]))
    return OsvAdvisory(
        id=vuln["id"][:80],
        aliases=[a for a in vuln.get("aliases") or [] if isinstance(a, str)][:50],
        summary=_str(vuln.get("summary"), 500),
        modified=_str(vuln.get("modified")),
        published=_str(vuln.get("published")),
        affected=affected,
        references=refs[:100],
        retrieved_at=retrieved_at,
    )


def _str(value: Any, limit: int = 200) -> str | None:
    return value[:limit] if isinstance(value, str) and value else None


class OsvConnector:
    name = "osv"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings
        self.errors: list[str] = []

    def advisories_for_package(self, pid: PackageId) -> list[OsvAdvisory]:
        """Every OSV advisory for a package (all versions), following pagination."""
        if pid.ecosystem.osv_name is None:
            return []
        out: list[OsvAdvisory] = []
        token: str | None = None
        for _ in range(10):  # hard page cap
            body: dict[str, Any] = {
                "package": {"name": pid.name, "ecosystem": pid.ecosystem.osv_name}
            }
            if token:
                body["page_token"] = token
            result = self.http.request(
                "POST",
                f"{self.settings.osv_base_url}/query",
                source=self.name,
                json_body=body,
                cache_ttl=timedelta(hours=self.settings.cache_ttl_hours),
                max_bytes=15_000_000,
            )
            try:
                payload = result.json()
            except ValueError as exc:
                raise SourceUnavailable(self.name, str(exc)) from exc
            if not isinstance(payload, dict):
                raise SourceUnavailable(self.name, "malformed response")
            for vuln in payload.get("vulns") or []:
                try:
                    out.append(parse_osv(vuln, result.fetched_at))
                except (ValueError, ValidationError) as exc:
                    self.errors.append(f"OSV record skipped: {str(exc)[:120]}")
            token = payload.get("next_page_token")
            if not token:
                break
        return out

    def get(self, osv_id: str) -> OsvAdvisory:
        if not re.match(_OSV_ID, osv_id):
            raise SourceUnavailable(self.name, "invalid OSV id")
        result = self.http.request(
            "GET",
            f"{self.settings.osv_base_url}/vulns/{quote(osv_id, safe='')}",
            source=self.name,
            cache_ttl=timedelta(hours=self.settings.cache_ttl_hours),
            max_bytes=5_000_000,
        )
        try:
            return parse_osv(result.json(), result.fetched_at)
        except (ValueError, ValidationError) as exc:
            raise SourceUnavailable(self.name, f"malformed record: {exc}") from exc
