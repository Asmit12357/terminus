"""NVD CVE API 2.0 connector.

Docs: https://nvd.nist.gov/developers/vulnerabilities
- Date-window queries (``lastModStartDate``/``lastModEndDate`` or
  ``pubStartDate``/``pubEndDate``) are limited to 120 days; longer windows are
  split into chunks.
- Pagination via ``startIndex``/``resultsPerPage`` (max 2000).
- Rate limits: 5 requests / 30 s without a key, 50 / 30 s with one. NVD asks
  clients to pace requests; we keep 6 s (no key) or 0.7 s (key) spacing.
- The API key is sent in the ``apiKey`` header, never in the URL.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import ValidationError

from terminus.config import Settings
from terminus.connectors.http import HttpClient, SourceUnavailable
from terminus.models import (
    CVE_ID_RE,
    ConfigNode,
    Configuration,
    CpeMatchRule,
    CveRecord,
    CvssData,
    Reference,
    utcnow,
    validate_cve_id,
)

log = logging.getLogger("terminus.nvd")

MAX_WINDOW = timedelta(days=120)
_METRIC_PREFERENCE = ("cvssMetricV31", "cvssMetricV40", "cvssMetricV30", "cvssMetricV2")


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt


def _pick_cvss(metrics: dict[str, Any]) -> CvssData | None:
    for key in _METRIC_PREFERENCE:
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        # Prefer the Primary (NVD) score, fall back to the CNA's Secondary score.
        ordered = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        for entry in ordered:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if not isinstance(score, (int, float)):
                continue
            severity = data.get("baseSeverity") or entry.get("baseSeverity")
            try:
                return CvssData(
                    version=str(data.get("version") or key[len("cvssMetricV") :]),
                    base_score=float(score),
                    vector=data.get("vectorString"),
                    severity=severity,
                    source=entry.get("source"),
                    score_type=entry.get("type"),
                )
            except ValidationError:
                continue
    return None


def parse_cve(
    item: dict[str, Any], retrieved_at: datetime | None = None, source: str = "nvd"
) -> CveRecord:
    """Convert one ``vulnerabilities[]`` element into a CveRecord. Raises ValueError."""
    cve = item.get("cve") if isinstance(item, dict) else None
    if not isinstance(cve, dict):
        raise ValueError("vulnerability entry has no 'cve' object")
    cve_id = cve.get("id")
    if not isinstance(cve_id, str) or not CVE_ID_RE.match(cve_id):
        raise ValueError("vulnerability entry has an invalid CVE id")

    description = ""
    for d in cve.get("descriptions") or []:
        if isinstance(d, dict) and d.get("lang") == "en" and isinstance(d.get("value"), str):
            description = d["value"]
            break

    configurations: list[Configuration] = []
    for conf in cve.get("configurations") or []:
        if not isinstance(conf, dict):
            continue
        nodes = []
        for node in conf.get("nodes") or []:
            if not isinstance(node, dict):
                continue
            matches = []
            for m in node.get("cpeMatch") or []:
                if not isinstance(m, dict) or not isinstance(m.get("criteria"), str):
                    continue
                matches.append(
                    CpeMatchRule(
                        criteria=m["criteria"],
                        vulnerable=bool(m.get("vulnerable", False)),
                        version_start_including=m.get("versionStartIncluding"),
                        version_start_excluding=m.get("versionStartExcluding"),
                        version_end_including=m.get("versionEndIncluding"),
                        version_end_excluding=m.get("versionEndExcluding"),
                    )
                )
            nodes.append(
                ConfigNode(
                    operator=str(node.get("operator") or "OR"),
                    negate=bool(node.get("negate", False)),
                    matches=matches,
                )
            )
        configurations.append(Configuration(operator=conf.get("operator"), nodes=nodes))

    references = []
    for r in cve.get("references") or []:
        if not isinstance(r, dict) or not isinstance(r.get("url"), str):
            continue
        url = r["url"].strip()
        if urlsplit(url).scheme not in ("http", "https"):
            continue  # drop javascript:, data:, file: and other schemes
        tags = [t for t in r.get("tags") or [] if isinstance(t, str)]
        references.append(Reference(url=url[:2000], source=r.get("source"), tags=tags))

    cwes = []
    for w in cve.get("weaknesses") or []:
        for d in (w or {}).get("description") or []:
            value = (d or {}).get("value")
            if isinstance(value, str) and value.startswith("CWE-"):
                cwes.append(value)

    return CveRecord(
        cve_id=validate_cve_id(cve_id),
        published=_parse_dt(cve.get("published")),
        last_modified=_parse_dt(cve.get("lastModified")),
        vuln_status=cve.get("vulnStatus"),
        description=description[:8000],
        cvss=_pick_cvss(cve.get("metrics") or {}),
        cwes=sorted(set(cwes)),
        configurations=configurations,
        references=references[:200],
        source=source,
        retrieved_at=retrieved_at or utcnow(),
    )


def parse_response(
    payload: Any, retrieved_at: datetime, source: str = "nvd"
) -> tuple[list[CveRecord], int, list[str]]:
    """Returns (records, totalResults, errors). Malformed entries are skipped, not guessed."""
    if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
        raise ValueError("NVD response has no 'vulnerabilities' list")
    total = payload.get("totalResults")
    if not isinstance(total, int) or total < 0:
        raise ValueError("NVD response has no valid 'totalResults'")
    records, errors = [], []
    for idx, item in enumerate(payload["vulnerabilities"]):
        try:
            records.append(parse_cve(item, retrieved_at, source))
        except (ValueError, ValidationError) as exc:
            errors.append(f"entry {idx}: {str(exc)[:200]}")
    return records, total, errors


class NvdConnector:
    name = "nvd"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings
        host = urlsplit(settings.nvd_base_url).hostname or ""
        self.http.set_rate_limit(host, 0.7 if settings.nvd_api_key else 6.0)
        self.errors: list[str] = []

    def _headers(self) -> dict[str, str]:
        key = self.settings.nvd_api_key
        return {"apiKey": key.get_secret_value()} if key else {}

    def _get(self, params: dict[str, Any], cache: bool = False) -> tuple[list[CveRecord], int]:
        result = self.http.request(
            "GET",
            self.settings.nvd_base_url,
            source=self.name,
            params=params,
            headers=self._headers(),
            cache_ttl=timedelta(hours=self.settings.cache_ttl_hours) if cache else None,
            # NVD answers 403 when the rate limit is exceeded.
            retry_statuses=frozenset({403, 429, 500, 502, 503, 504}),
        )
        try:
            records, total, errors = parse_response(result.json(), result.fetched_at)
        except ValueError as exc:
            raise SourceUnavailable(self.name, f"malformed response: {exc}") from exc
        self.errors.extend(errors)
        return records, total

    def _paginate(
        self, base_params: dict[str, Any], cache: bool = False
    ) -> Iterator[list[CveRecord]]:
        start = 0
        per_page = self.settings.nvd_results_per_page
        for _ in range(self.settings.nvd_max_pages):
            records, total = self._get(
                {**base_params, "startIndex": start, "resultsPerPage": per_page}, cache
            )
            yield records
            start += per_page
            if start >= total or not records:
                return
        self.errors.append(
            f"stopped after {self.settings.nvd_max_pages} pages (TERMINUS_NVD_MAX_PAGES); "
            "results are incomplete"
        )

    @staticmethod
    def _window_params(
        start: datetime, end: datetime, field: Literal["lastMod", "pub"]
    ) -> Iterator[dict[str, Any]]:
        cursor = start
        while cursor < end:
            chunk_end = min(cursor + MAX_WINDOW, end)
            yield {
                f"{field}StartDate": cursor.strftime("%Y-%m-%dT%H:%M:%S.000"),
                f"{field}EndDate": chunk_end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            }
            cursor = chunk_end

    def window_size(
        self, start: datetime, end: datetime, field: Literal["lastMod", "pub"] = "lastMod"
    ) -> int:
        """How many CVEs NVD has in the window: one one-record request per 120-day chunk."""
        total = 0
        for params in self._window_params(start, end, field):
            _, count = self._get({**params, "startIndex": 0, "resultsPerPage": 1})
            total += count
        return total

    def fetch_window(
        self,
        start: datetime,
        end: datetime,
        field: Literal["lastMod", "pub"] = "lastMod",
        product: tuple[str, str] | None = None,
    ) -> Iterator[list[CveRecord]]:
        """Yield pages of CVEs modified (or published) in [start, end], optionally only
        those whose configurations reference ``product`` = (vendor, product)."""
        if end <= start:
            return
        scope = {"virtualMatchString": _product_match(*product)} if product else {}
        for params in self._window_params(start, end, field):
            yield from self._paginate({**params, **scope})

    def fetch_by_product(self, vendor: str, product: str) -> Iterator[list[CveRecord]]:
        """All CVEs whose configurations reference vendor:product (any version)."""
        yield from self._paginate(
            {"virtualMatchString": _product_match(vendor, product)}, cache=True
        )

    def fetch_cve(self, cve_id: str) -> CveRecord | None:
        records, _ = self._get({"cveId": validate_cve_id(cve_id)}, cache=True)
        return records[0] if records else None


def _product_match(vendor: str, product: str) -> str:
    return f"cpe:2.3:*:{_cpe_escape(vendor)}:{_cpe_escape(product)}"


def _cpe_escape(value: str) -> str:
    # Only CPE-safe characters; anything else is escaped per CPE 2.3 rules.
    return "".join(c if c.isalnum() or c in "_-." else f"\\{c}" for c in value)
