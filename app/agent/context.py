"""Data-source bundle and per-scan research context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.config import Settings
from app.storage.repository import Repository


@dataclass
class SourceBundle:
    """Connectors used by a scan. Live and demo bundles expose the same methods."""

    nvd: Any = None
    kev: Any = None
    epss: Any = None
    osv: Any = None
    vendor: Any = None
    search: Any = None
    demo: bool = False
    closers: list[Any] = field(default_factory=list)

    def close(self) -> None:
        for c in self.closers:
            c.close()


@dataclass
class ResearchContext:
    settings: Settings
    repo: Repository
    sources: SourceBundle
    kev_available: bool = False
    kev_stale: bool = False
    epss_failed: bool = False  # skip per-CVE EPSS retries once the source is known to be down

    @property
    def demo(self) -> bool:
        return self.sources.demo
