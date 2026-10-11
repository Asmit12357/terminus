"""FIRST EPSS API connector.

Docs: https://www.first.org/epss/api
EPSS is a *probability* that a CVE will see exploitation activity in the next
30 days. It is not evidence that exploitation has happened; Terminus never
reports a CVE as "exploited" because of a high EPSS score.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from pydantic import ValidationError

from app.config import Settings
from app.connectors.http import HttpClient, SourceUnavailable
from app.models import CVE_ID_RE, EpssScore, validate_cve_id

BATCH_SIZE = 50  # keeps the query string well under URL length limits


def parse_epss(payload: Any, retrieved_at: datetime) -> tuple[list[EpssScore], list[str]]:
    if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
        raise ValueError("EPSS response has no 'data' list")
    scores, errors = [], []
    for idx, row in enumerate(payload["data"]):
        if not isinstance(row, dict):
            errors.append(f"row {idx}: not an object")
            continue
        cve = row.get("cve")
        try:
            if not isinstance(cve, str) or not CVE_ID_RE.match(cve):
                raise ValueError("invalid cve")
            scores.append(
                EpssScore(
                    cve_id=cve,
                    epss=float(row["epss"]),
                    percentile=float(row["percentile"]),
                    score_date=str(row.get("date"))[:20] if row.get("date") else None,
                    retrieved_at=retrieved_at,
                )
            )
        except (KeyError, TypeError, ValueError, ValidationError) as exc:
            errors.append(f"row {idx}: {type(exc).__name__}")
    return scores, errors


class EpssConnector:
    name = "first_epss"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings
        self.errors: list[str] = []

    def fetch_scores(self, cve_ids: list[str]) -> list[EpssScore]:
        ids = sorted({validate_cve_id(c) for c in cve_ids})
        out: list[EpssScore] = []
        for i in range(0, len(ids), BATCH_SIZE):
            batch = ids[i : i + BATCH_SIZE]
            result = self.http.request(
                "GET",
                self.settings.epss_base_url,
                source=self.name,
                params={"cve": ",".join(batch)},
                cache_ttl=timedelta(hours=self.settings.cache_ttl_hours),
                max_bytes=2_000_000,
            )
            try:
                scores, errors = parse_epss(result.json(), result.fetched_at)
            except ValueError as exc:
                raise SourceUnavailable(self.name, f"malformed response: {exc}") from exc
            self.errors.extend(errors)
            out.extend(s for s in scores if s.cve_id in batch)
        return out
