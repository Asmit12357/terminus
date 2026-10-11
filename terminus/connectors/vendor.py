"""Official vendor advisory retrieval.

Advisory URLs come only from structured sources (NVD references tagged
"Vendor Advisory"/"Patch", OSV references of type ADVISORY). A page is fetched
only when its host is on the configured vendor-domain allowlist, over HTTPS,
with a size cap, following at most three redirects that stay on the allowlist.

Fetched text is untrusted. It is used for one deterministic purpose:
*corroboration* - checking that the page mentions the CVE and a candidate
fixed version that a structured source already supplied. Page text can never
introduce a fixed version on its own.

One fetcher lives for one scan and remembers what it fetched: many CVEs cite the
same advisory page (every Apache httpd CVE cites one security page), so each URL
is downloaded at most once per scan, and a host that already failed at network
level after all retries is not asked again in that scan.
"""

from __future__ import annotations

import re
from datetime import datetime
from html.parser import HTMLParser
from typing import ClassVar
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, Field

from terminus.config import Settings
from terminus.connectors.http import (
    HttpClient,
    RedirectEncountered,
    SourceUnavailable,
    host_allowed,
)
from terminus.security import sanitize_untrusted

MAX_REDIRECTS = 3
# HttpClient failure details meaning the host itself could not be reached (after retries).
_NETWORK_FAILURES = ("network error", "request timed out")


class _TextExtractor(HTMLParser):
    _SKIP: ClassVar[frozenset[str]] = frozenset(
        {"script", "style", "noscript", "template", "svg", "head"}
    )

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in {"p", "br", "li", "tr", "h1", "h2", "h3", "h4", "div", "pre"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    parser = _TextExtractor()
    parser.feed(html)
    parser.close()
    return "".join(parser.parts)


class VendorPage(BaseModel):
    url: str
    final_url: str
    text: str
    retrieved_at: datetime
    injection_flags: list[str] = Field(default_factory=list)
    truncated: bool = False

    def mentions(self, token: str) -> bool:
        return bool(re.search(rf"(?<![\w.]){re.escape(token)}(?![\w])", self.text, re.I))

    def corroborates_fix(self, cve_id: str, version: str) -> bool:
        """True when the page names the CVE and the exact version string near it.

        "Near" = within 1500 characters of a CVE mention, so a version that only
        appears in an unrelated release list does not count.
        """
        if not self.mentions(cve_id):
            return False
        ver_re = re.compile(rf"(?<![\w.]){re.escape(version)}(?![\w]|\.\d)", re.I)
        for m in re.finditer(re.escape(cve_id), self.text, re.I):
            window = self.text[max(0, m.start() - 1500) : m.end() + 1500]
            if ver_re.search(window):
                return True
        return False


class VendorAdvisoryFetcher:
    name = "vendor_advisory"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        self.http = http
        self.settings = settings
        self._pages: dict[str, VendorPage] = {}
        self._failures: dict[str, str] = {}
        self._unreachable_hosts: set[str] = set()

    def allowed(self, url: str) -> bool:
        return host_allowed(url, self.settings.vendor_domain_allowlist)

    def fetch(self, url: str) -> VendorPage:
        if url in self._pages:
            return self._pages[url]
        if url in self._failures:
            raise SourceUnavailable(self.name, self._failures[url])
        host = (urlsplit(url).hostname or "").lower()
        if host in self._unreachable_hosts:
            raise SourceUnavailable(self.name, f"{host} was unreachable earlier in this scan")
        try:
            page = self._fetch(url)
        except SourceUnavailable as exc:
            self._failures[url] = exc.detail
            if exc.detail.startswith(_NETWORK_FAILURES):
                self._unreachable_hosts.add(host)
            raise
        self._pages[url] = page
        return page

    def _fetch(self, url: str) -> VendorPage:
        if not self.settings.fetch_vendor_pages:
            raise SourceUnavailable(self.name, "vendor page fetching disabled")
        if not self.allowed(url):
            raise SourceUnavailable(self.name, "host not on vendor allowlist")
        current = url
        for _ in range(MAX_REDIRECTS + 1):
            try:
                result = self.http.request(
                    "GET",
                    current,
                    source=self.name,
                    max_bytes=self.settings.vendor_page_max_bytes,
                    headers={"Accept": "text/html, text/plain;q=0.9"},
                    retry_statuses=frozenset({429, 502, 503, 504}),
                )
            except RedirectEncountered as redirect:
                target = urljoin(current, redirect.location or "")
                if not redirect.location or not self.allowed(target):
                    raise SourceUnavailable(
                        self.name, "redirect to a host outside the vendor allowlist"
                    ) from redirect
                current = target
                continue
            raw = result.body.decode("utf-8", errors="replace")
            text = html_to_text(raw) if "<" in raw[:2000] else raw
            clean = sanitize_untrusted(text, max_chars=200_000)
            return VendorPage(
                url=url,
                final_url=current,
                text=clean.text,
                retrieved_at=result.fetched_at,
                injection_flags=clean.flags,
                truncated=clean.truncated,
            )
        raise SourceUnavailable(self.name, "too many redirects")
