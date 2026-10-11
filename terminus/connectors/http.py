"""Hardened HTTP client used by every connector.

- HTTPS only; redirects are not followed automatically (a redirect is treated
  as a failure so a source cannot bounce us to an arbitrary host).
- Per-host minimum request spacing (rate limiting) and bounded retries with
  exponential backoff + jitter, honouring ``Retry-After`` up to a cap.
- Hard response-size limit enforced while streaming.
- Optional SQLite-backed cache with TTL; a stale cached copy may be used when
  the source is down, and is always reported as stale.
- Only host and path are logged, never headers, query strings or bodies.
"""

from __future__ import annotations

import hashlib
import json
import logging
import random
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

import httpx

from terminus.config import Settings
from terminus.models import utcnow
from terminus.storage.repository import Repository

log = logging.getLogger("terminus.http")

USER_AGENT = "Terminus/0.1 (read-only vulnerability research)"
RETRY_AFTER_CAP_SECONDS = 60.0
STALE_CACHE_MAX_AGE = timedelta(days=7)


class SourceUnavailable(Exception):
    """A data source could not provide a usable response."""

    def __init__(self, source: str, detail: str) -> None:
        super().__init__(f"{source}: {detail}")
        self.source = source
        self.detail = detail


class ResponseTooLarge(SourceUnavailable):
    pass


class RedirectEncountered(SourceUnavailable):
    """Raised instead of following a redirect; callers may follow it explicitly
    after validating the target against an allowlist."""

    def __init__(self, source: str, status: int, location: str | None) -> None:
        super().__init__(source, f"unexpected redirect (HTTP {status})")
        self.location = location


@dataclass
class FetchResult:
    body: bytes
    fetched_at: datetime
    from_cache: bool = False
    stale: bool = False

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"malformed JSON: {exc}") from exc


def host_allowed(url: str, allowlist: Iterable[str]) -> bool:
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return False
    host = parts.hostname.lower().rstrip(".")
    return any(host == d or host.endswith("." + d) for d in allowlist)


class HttpClient:
    def __init__(
        self,
        settings: Settings,
        repo: Repository | None = None,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.settings = settings
        self.repo = repo
        self._sleep = sleep
        self._clock = clock
        self._client = httpx.Client(
            timeout=httpx.Timeout(settings.http_timeout_seconds, connect=10.0),
            follow_redirects=False,
            transport=transport,
            headers={"User-Agent": USER_AGENT},
        )
        self._min_interval: dict[str, float] = {}
        self._last_request: dict[str, float] = {}
        self._lock = threading.Lock()

    def close(self) -> None:
        self._client.close()

    def set_rate_limit(self, host: str, min_interval_seconds: float) -> None:
        self._min_interval[host] = min_interval_seconds

    # ------------------------------------------------------------------
    def _wait_for_slot(self, host: str) -> None:
        interval = self._min_interval.get(host, 0.0)
        if interval <= 0:
            return
        with self._lock:
            now = self._clock()
            last = self._last_request.get(host)
            if last is not None and now - last < interval:
                self._sleep(interval - (now - last))
            self._last_request[host] = self._clock()

    def _backoff(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), RETRY_AFTER_CAP_SECONDS)
            except ValueError:
                pass
        base = self.settings.http_backoff_base_seconds
        return min(base * (2**attempt) + random.uniform(0, base), RETRY_AFTER_CAP_SECONDS)  # noqa: S311

    @staticmethod
    def _cache_key(method: str, url: str, params: Any, body: Any) -> str:
        raw = json.dumps([method, url, params, body], sort_keys=True, default=str)
        return hashlib.sha256(raw.encode()).hexdigest()

    def request(
        self,
        method: str,
        url: str,
        *,
        source: str,
        params: dict[str, Any] | None = None,
        json_body: Any = None,
        headers: dict[str, str] | None = None,
        max_bytes: int | None = None,
        cache_ttl: timedelta | None = None,
        retry_statuses: frozenset[int] = frozenset({429, 500, 502, 503, 504}),
        allow_stale: bool = True,
    ) -> FetchResult:
        parts = urlsplit(url)
        if parts.scheme != "https" or not parts.hostname:
            raise SourceUnavailable(source, "only https:// URLs are permitted")
        host = parts.hostname
        limit = max_bytes or self.settings.http_max_response_bytes
        key = self._cache_key(method, url, params, json_body)

        if cache_ttl is not None and self.repo is not None:
            cached = self.repo.cache_get(key, cache_ttl)
            if cached is not None:
                return FetchResult(cached[0], cached[1], from_cache=True)

        last_error = "no attempt made"
        for attempt in range(self.settings.http_max_retries + 1):
            self._wait_for_slot(host)
            try:
                with self._client.stream(
                    method, url, params=params, json=json_body, headers=headers
                ) as resp:
                    status = resp.status_code
                    if status in retry_statuses:
                        last_error = f"HTTP {status}"
                        delay = self._backoff(attempt, resp.headers.get("Retry-After"))
                        log.warning("%s %s%s -> %s, retrying", source, host, parts.path, status)
                        if attempt < self.settings.http_max_retries:
                            self._sleep(delay)
                        continue
                    if 300 <= status < 400:
                        raise RedirectEncountered(source, status, resp.headers.get("Location"))
                    if status >= 400:
                        raise SourceUnavailable(source, f"HTTP {status}")
                    declared = resp.headers.get("Content-Length")
                    if declared and declared.isdigit() and int(declared) > limit:
                        raise ResponseTooLarge(source, f"response exceeds {limit} bytes")
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in resp.iter_bytes():
                        size += len(chunk)
                        if size > limit:
                            raise ResponseTooLarge(source, f"response exceeds {limit} bytes")
                        chunks.append(chunk)
                    body = b"".join(chunks)
            except httpx.TimeoutException:
                last_error = "request timed out"
                log.warning("%s %s%s timed out (attempt %d)", source, host, parts.path, attempt + 1)
                if attempt < self.settings.http_max_retries:
                    self._sleep(self._backoff(attempt, None))
                continue
            except httpx.TransportError as exc:
                last_error = f"network error: {type(exc).__name__}"
                log.warning("%s %s%s %s", source, host, parts.path, last_error)
                if attempt < self.settings.http_max_retries:
                    self._sleep(self._backoff(attempt, None))
                continue

            if cache_ttl is not None and self.repo is not None:
                self.repo.cache_put(key, body)
            return FetchResult(body, utcnow())

        if allow_stale and cache_ttl is not None and self.repo is not None:
            stale = self.repo.cache_get(key, STALE_CACHE_MAX_AGE)
            if stale is not None:
                log.warning("%s unavailable (%s); using stale cache", source, last_error)
                return FetchResult(stale[0], stale[1], from_cache=True, stale=True)
        raise SourceUnavailable(source, last_error)
