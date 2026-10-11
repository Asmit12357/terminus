"""Optional web research providers (Tavily, Exa).

Search results are SUPPLEMENTARY evidence: they can point an analyst to
discussion, write-ups or advisories, but they never set a match status or a
fixed version. All result text passes through ``sanitize_untrusted``.
"""

from __future__ import annotations

from typing import Any, Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from app.config import Settings
from app.connectors.http import HttpClient, SourceUnavailable
from app.security import sanitize_untrusted

TAVILY_URL = "https://api.tavily.com/search"
EXA_URL = "https://api.exa.ai/search"


class SearchResult(BaseModel):
    title: str
    url: str
    snippet: str
    injection_flags: list[str] = Field(default_factory=list)


class SearchProvider(Protocol):
    name: str

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]: ...


def _results(rows: Any, text_key: str) -> list[SearchResult]:
    if not isinstance(rows, list):
        raise ValueError("search response has no result list")
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        url = row.get("url")
        if not isinstance(url, str) or urlsplit(url).scheme not in ("http", "https"):
            continue
        snippet = sanitize_untrusted(row.get(text_key) or "", max_chars=1500)
        title = sanitize_untrusted(row.get("title") or "", max_chars=200)
        out.append(
            SearchResult(
                title=title.text,
                url=url[:2000],
                snippet=snippet.text,
                injection_flags=sorted(set(snippet.flags) | set(title.flags)),
            )
        )
    return out


class TavilySearch:
    name = "tavily"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        if not settings.tavily_api_key:
            raise ValueError("TERMINUS_TAVILY_API_KEY is not set")
        self.http = http
        self._key = settings.tavily_api_key

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        result = self.http.request(
            "POST",
            TAVILY_URL,
            source=self.name,
            headers={"Authorization": f"Bearer {self._key.get_secret_value()}"},
            json_body={
                "query": query[:400],
                "max_results": max(1, min(max_results, 10)),
                "search_depth": "basic",
                "include_answer": False,
            },
            max_bytes=2_000_000,
        )
        try:
            return _results(result.json().get("results"), "content")
        except (ValueError, AttributeError) as exc:
            raise SourceUnavailable(self.name, f"malformed response: {exc}") from exc


class ExaSearch:
    name = "exa"

    def __init__(self, http: HttpClient, settings: Settings) -> None:
        if not settings.exa_api_key:
            raise ValueError("TERMINUS_EXA_API_KEY is not set")
        self.http = http
        self._key = settings.exa_api_key

    def search(self, query: str, max_results: int = 5) -> list[SearchResult]:
        result = self.http.request(
            "POST",
            EXA_URL,
            source=self.name,
            headers={"x-api-key": self._key.get_secret_value()},
            json_body={
                "query": query[:400],
                "numResults": max(1, min(max_results, 10)),
                "contents": {"text": {"maxCharacters": 1500}},
            },
            max_bytes=2_000_000,
        )
        try:
            return _results(result.json().get("results"), "text")
        except (ValueError, AttributeError) as exc:
            raise SourceUnavailable(self.name, f"malformed response: {exc}") from exc


def build_search_provider(http: HttpClient, settings: Settings) -> SearchProvider | None:
    try:
        if settings.search_provider == "tavily":
            return TavilySearch(http, settings)
        if settings.search_provider == "exa":
            return ExaSearch(http, settings)
    except ValueError:
        return None
    return None
