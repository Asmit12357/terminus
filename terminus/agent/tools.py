"""Research tools, their input schemas, and the budget-enforcing registry.

Every tool:
- has a Pydantic input model (``extra="forbid"``) - arguments are validated
  before anything runs;
- is read-only (no tool writes to external systems or executes anything);
- returns a ``ToolResult``; failures are recorded as failures and are never
  reported as successful verification.

The registry is the only way an agent (deterministic or LLM) can act. Unknown
tool names are rejected, budgets are enforced per investigation, and every
call is logged to the research trace.
"""

from __future__ import annotations

import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from terminus.agent.state import ResearchState
from terminus.connectors.http import SourceUnavailable
from terminus.matching.fixes import assess_fix
from terminus.matching.matcher import match_item
from terminus.matching.normalize import package_identity
from terminus.models import (
    EpssStatus,
    InventoryItem,
    KevStatus,
    SourceState,
    ToolCallRecord,
    utcnow,
    validate_cve_id,
)
from terminus.reports.recommendation import build_recommendation
from terminus.security import sanitize_untrusted

# ---------------------------------------------------------------------------
# Input schemas
# ---------------------------------------------------------------------------


class _Input(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class CveInput(_Input):
    cve_id: str = Field(description="CVE identifier, e.g. CVE-2021-44228")

    @field_validator("cve_id")
    @classmethod
    def _cve(cls, v: str) -> str:
        return validate_cve_id(v)


class CveItemInput(CveInput):
    item_id: str = Field(description="Inventory item id returned by get_inventory_matches")

    @field_validator("item_id")
    @classmethod
    def _item(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-f]{16}", v):
            raise ValueError("item_id must be a 16-character hex id")
        return v


class CveOptionalItemInput(CveInput):
    item_id: str | None = Field(
        default=None, description="Inventory item id; omit to process every candidate"
    )

    @field_validator("item_id")
    @classmethod
    def _item(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[0-9a-f]{16}", v):
            raise ValueError("item_id must be a 16-character hex id")
        return v


class SearchInput(CveInput):
    focus: str | None = Field(
        default=None,
        max_length=80,
        description="Optional extra keywords (letters, digits, spaces, dots, hyphens only)",
    )

    @field_validator("focus")
    @classmethod
    def _focus(cls, v: str | None) -> str | None:
        if v is not None and not re.fullmatch(r"[A-Za-z0-9 .\-_]*", v):
            raise ValueError("focus may only contain letters, digits, spaces, '.', '-', '_'")
        return v


# ---------------------------------------------------------------------------
# Results and budget
# ---------------------------------------------------------------------------


class ToolResult(BaseModel):
    tool: str
    ok: bool
    summary: str
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None


@dataclass
class Budget:
    max_tool_calls: int = 12
    max_search_calls: int = 2
    max_seconds: float = 60.0
    started: float = field(default_factory=time.monotonic)
    tool_calls: int = 0
    search_calls: int = 0

    def elapsed(self) -> float:
        return time.monotonic() - self.started

    def exhausted_reason(self, is_search: bool = False) -> str | None:
        if self.tool_calls >= self.max_tool_calls:
            return f"tool-call budget exhausted ({self.max_tool_calls})"
        if self.elapsed() >= self.max_seconds:
            return f"time budget exhausted ({self.max_seconds:.0f}s)"
        if is_search and self.search_calls >= self.max_search_calls:
            return f"search budget exhausted ({self.max_search_calls})"
        return None

    def snapshot(self) -> dict[str, float]:
        return {
            "max_tool_calls": self.max_tool_calls,
            "tool_calls": self.tool_calls,
            "max_search_calls": self.max_search_calls,
            "search_calls": self.search_calls,
            "max_seconds": self.max_seconds,
            "elapsed_seconds": round(self.elapsed(), 2),
        }


@dataclass
class ToolSpec:
    name: str
    description: str
    input_model: type[_Input]
    fn: Callable[[Any], ToolResult]
    is_search: bool = False


class BudgetExceeded(Exception):
    pass


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


class ResearchTools:
    """Binds tool functions to one investigation's state and data sources."""

    def __init__(self, state: ResearchState, ctx: Any) -> None:
        # ctx: terminus.agent.context.ResearchContext (kept as Any to avoid an import cycle)
        self.state = state
        self.ctx = ctx

    def _item(self, item_id: str) -> InventoryItem:
        return self.state.item(item_id)

    def _require_cve(self, cve_id: str) -> None:
        if cve_id != self.state.cve_id:
            raise ValueError("tools may only research the CVE under investigation")

    # -- get_cve_details ---------------------------------------------------
    def get_cve_details(self, args: CveInput) -> ToolResult:
        self._require_cve(args.cve_id)
        self.state.steps_done.add("cve")
        cve = self.ctx.repo.get_cve(args.cve_id)
        if cve is None and self.ctx.sources.nvd is not None:
            cve = self.ctx.sources.nvd.fetch_cve(args.cve_id)
            if cve is not None:
                self.ctx.repo.upsert_cve(cve)
        if cve is None:
            return ToolResult(
                tool="get_cve_details",
                ok=False,
                summary="CVE not found",
                error="NVD returned no record for this CVE",
            )
        self.state.cve = cve
        desc = sanitize_untrusted(cve.description, max_chars=1500)
        if desc.flags:
            self.state.injection_flags.update(f"cve_description:{f}" for f in desc.flags)
        return ToolResult(
            tool="get_cve_details",
            ok=True,
            summary=f"{cve.cve_id}: status {cve.vuln_status}, CVSS "
            f"{cve.cvss.base_score if cve.cvss else 'n/a'}, {len(cve.configurations)} configurations",
            data={
                "cve_id": cve.cve_id,
                "vuln_status": cve.vuln_status,
                "cvss": cve.cvss.model_dump() if cve.cvss else None,
                "description_untrusted": desc.text,
                "description_flags": desc.flags,
                "configurations": len(cve.configurations),
                "vendor_advisories": cve.vendor_advisory_urls,
                "retrieved_at": cve.retrieved_at.isoformat(),
            },
        )

    # -- get_inventory_matches ---------------------------------------------
    def get_inventory_matches(self, args: CveInput) -> ToolResult:
        self._require_cve(args.cve_id)
        self.state.steps_done.add("matches")
        if self.state.cve is None:
            return ToolResult(
                tool="get_inventory_matches",
                ok=False,
                summary="no CVE details",
                error="call get_cve_details first",
            )
        osv = self.ctx.repo.osv_for_cve(args.cve_id)
        self.state.osv = {a.id: a for a in osv}
        self.state.matches = {}
        for item in self.state.items:
            result = match_item(item, self.state.cve, osv)
            if result is not None:
                self.state.matches[item.item_id] = result
        return ToolResult(
            tool="get_inventory_matches",
            ok=True,
            summary=f"{len(self.state.matches)} inventory candidates",
            data={
                "candidates": [
                    {
                        "item_id": m.item_id,
                        "asset_id": self._item(m.item_id).asset_id,
                        "software": self._item(m.item_id).software_name,
                        "version": self._item(m.item_id).software_version,
                        "status": m.status.value,
                        "identity": m.identity_method.value,
                    }
                    for m in self.state.matches.values()
                ]
            },
        )

    # -- search_official_vendor_advisories ---------------------------------
    def search_official_vendor_advisories(self, args: CveItemInput) -> ToolResult:
        self._require_cve(args.cve_id)
        item = self._item(args.item_id)
        research_key = self.state.research_key(args.item_id)
        self.state.steps_done.add(f"research:{research_key}")
        self.state.research_done.add(research_key)
        known_osv, known_pages = set(self.state.osv), set(self.state.vendor_pages)
        found: list[str] = []
        failures: list[str] = []

        # 1. Ecosystem advisory database (OSV) for package items.
        pid = package_identity(item)
        if pid is not None and pid.ecosystem.osv_name and self.ctx.sources.osv is not None:
            try:
                for adv in self.ctx.sources.osv.advisories_for_package(pid):
                    self.ctx.repo.upsert_osv(adv)
                    if self.state.cve_id in adv.aliases or adv.id == self.state.cve_id:
                        self.state.osv[adv.id] = adv
                        found.append(adv.url)
            except SourceUnavailable as exc:
                failures.append(f"OSV: {exc.detail}")

        # 2. Vendor advisory pages referenced by structured sources.
        urls: list[str] = []
        if self.state.cve is not None:
            urls += [
                r.url
                for r in self.state.cve.references
                if {"Vendor Advisory", "Patch", "Release Notes"} & set(r.tags)
            ]
        for adv in self.state.osv.values():
            urls += adv.advisory_urls
        vendor = self.ctx.sources.vendor
        fetched = 0
        for url in dict.fromkeys(urls):  # de-duplicate, keep order
            if vendor is None or not vendor.allowed(url) or url in self.state.vendor_pages:
                continue
            if fetched >= 3:
                break
            fetched += 1
            try:
                page = vendor.fetch(url)
            except SourceUnavailable as exc:
                failures.append(f"{url}: {exc.detail}")
                continue
            self.state.vendor_pages[url] = page
            if page.injection_flags:
                self.state.injection_flags.update(f"vendor_page:{f}" for f in page.injection_flags)
            found.append(page.final_url)

        self.state.advisory_urls.update(urls)
        if set(self.state.osv) != known_osv or set(self.state.vendor_pages) != known_pages:
            self.state.evidence_version += 1  # new structured evidence -> re-verify
        ok = bool(found) or not failures
        return ToolResult(
            tool="search_official_vendor_advisories",
            ok=ok,
            summary=f"{len(found)} advisory sources retrieved"
            + (f", {len(failures)} failed" if failures else ""),
            data={
                "retrieved": found,
                "advisory_urls": list(dict.fromkeys(urls))[:10],
                "failures": failures,
            },
            error="; ".join(failures) if failures and not found else None,
        )

    # -- search_additional_research_sources --------------------------------
    def search_additional_research_sources(self, args: SearchInput) -> ToolResult:
        self._require_cve(args.cve_id)
        self.state.steps_done.add("search")
        provider = self.ctx.sources.search
        if provider is None:
            return ToolResult(
                tool="search_additional_research_sources",
                ok=False,
                summary="no search provider configured",
                error="set TERMINUS_SEARCH_PROVIDER and an API key to enable",
            )
        query = f"{args.cve_id} {args.focus or ''} advisory fixed version".strip()
        try:
            results = provider.search(query, max_results=5)
        except SourceUnavailable as exc:
            return ToolResult(
                tool="search_additional_research_sources",
                ok=False,
                summary="search failed",
                error=exc.detail,
            )
        self.state.supplementary.extend(results)
        for r in results:
            if r.injection_flags:
                self.state.injection_flags.update(f"search_result:{f}" for f in r.injection_flags)
        return ToolResult(
            tool="search_additional_research_sources",
            ok=True,
            summary=f"{len(results)} supplementary results (untrusted; cannot set status or fix)",
            data={"results": [r.model_dump() for r in results]},
        )

    # -- get_kev_status ----------------------------------------------------
    def get_kev_status(self, args: CveInput) -> ToolResult:
        self._require_cve(args.cve_id)
        self.state.steps_done.add("kev")
        kev_time = self.ctx.repo.kev_retrieved_at()
        if kev_time is None or not self.ctx.kev_available:
            self.state.kev = KevStatus(in_kev=None, source_state=SourceState.UNAVAILABLE)
            return ToolResult(
                tool="get_kev_status",
                ok=False,
                summary="KEV catalog unavailable",
                error="KEV catalog could not be loaded during this scan",
            )
        entry = self.ctx.repo.get_kev(args.cve_id)
        state = (
            SourceState.DEMO
            if self.ctx.demo
            else (SourceState.CACHED if self.ctx.kev_stale else SourceState.OK)
        )
        if entry is None:
            self.state.kev = KevStatus(in_kev=False, retrieved_at=kev_time, source_state=state)
        else:
            self.state.kev = KevStatus(
                in_kev=True,
                date_added=entry.date_added,
                due_date=entry.due_date,
                required_action=entry.required_action,
                known_ransomware_use=entry.known_ransomware_use,
                retrieved_at=entry.retrieved_at,
                source_state=state,
            )
        return ToolResult(
            tool="get_kev_status",
            ok=True,
            summary="listed in CISA KEV" if entry else "not listed in CISA KEV",
            data=self.state.kev.model_dump(mode="json"),
        )

    # -- get_epss_score ----------------------------------------------------
    def get_epss_score(self, args: CveInput) -> ToolResult:
        self._require_cve(args.cve_id)
        self.state.steps_done.add("epss")
        score = self.ctx.repo.get_epss(args.cve_id)
        if self.ctx.epss_failed and score is None:
            self.state.epss = EpssStatus(score=None, source_state=SourceState.UNAVAILABLE)
            return ToolResult(
                tool="get_epss_score",
                ok=False,
                summary="EPSS unavailable",
                error="EPSS API was unavailable during this scan",
            )
        if score is None and self.ctx.sources.epss is not None and not self.ctx.demo:
            try:
                fetched = self.ctx.sources.epss.fetch_scores([args.cve_id])
                self.ctx.repo.upsert_epss(fetched)
                score = fetched[0] if fetched else None
            except SourceUnavailable as exc:
                self.state.epss = EpssStatus(score=None, source_state=SourceState.UNAVAILABLE)
                return ToolResult(
                    tool="get_epss_score", ok=False, summary="EPSS unavailable", error=exc.detail
                )
        if score is None:
            self.state.epss = EpssStatus(score=None, source_state=SourceState.OK)
            return ToolResult(
                tool="get_epss_score",
                ok=True,
                summary="no EPSS score published",
                data={"score": None},
            )
        self.state.epss = EpssStatus(
            score=score.epss,
            percentile=score.percentile,
            score_date=score.score_date,
            retrieved_at=score.retrieved_at,
            source_state=SourceState.DEMO if self.ctx.demo else SourceState.OK,
        )
        return ToolResult(
            tool="get_epss_score",
            ok=True,
            summary=f"EPSS {score.epss:.5f} (percentile {score.percentile:.3f}); "
            "a probability, not evidence of exploitation",
            data=self.state.epss.model_dump(mode="json"),
        )

    # -- verify_affected_and_fixed_versions -------------------------------
    def verify_affected_and_fixed_versions(self, args: CveOptionalItemInput) -> ToolResult:
        self._require_cve(args.cve_id)
        if self.state.cve is None:
            return ToolResult(
                tool="verify_affected_and_fixed_versions",
                ok=False,
                summary="no CVE details",
                error="call get_cve_details first",
            )
        if args.item_id is None:
            self.state.steps_done.add(self.state.verify_key())
            targets = list(self.state.matches)
        else:
            targets = [self._item(args.item_id).item_id]
        results: dict[str, dict[str, Any]] = {}
        for item_id in targets:
            item = self._item(item_id)
            # Re-run deterministic matching with every structured advisory now known.
            match = match_item(item, self.state.cve, list(self.state.osv.values()))
            if match is None:
                self.state.matches.pop(item_id, None)
                results[item_id] = {"status": "no relationship"}
                continue
            self.state.matches[item_id] = match
            fix = assess_fix(item, match, list(self.state.vendor_pages.values()))
            self.state.fixes[item_id] = fix
            results[item_id] = {
                "status": match.status.value,
                "reasons": match.reasons,
                "fix_status": fix.status.value,
                "fixed_version": fix.fixed_version,
                "fix_notes": fix.notes,
            }
        statuses = [r["status"] for r in results.values()]
        return ToolResult(
            tool="verify_affected_and_fixed_versions",
            ok=bool(results),
            summary=f"verified {len(results)} candidate(s): "
            + ", ".join(f"{statuses.count(x)} {x}" for x in sorted(set(statuses))),
            data={"results": results},
            error=None if results else "no candidates to verify",
        )

    # -- generate_remediation_recommendation ------------------------------
    def generate_remediation_recommendation(self, args: CveOptionalItemInput) -> ToolResult:
        self._require_cve(args.cve_id)
        if args.item_id is None:
            self.state.steps_done.add("rec:all")
            targets = list(self.state.matches)
        else:
            targets = [self._item(args.item_id).item_id]
        kev = self.state.kev or KevStatus(in_kev=None, source_state=SourceState.UNAVAILABLE)
        made: dict[str, str] = {}
        missing: list[str] = []
        for item_id in targets:
            match = self.state.matches.get(item_id)
            fix = self.state.fixes.get(item_id)
            if match is None or fix is None:
                missing.append(item_id)
                continue
            rec = build_recommendation(
                self._item(item_id), match, fix, kev, self.state.advisory_list()
            )
            self.state.recommendations[item_id] = rec
            made[item_id] = f"{rec.action}: {rec.summary[:160]}"
        return ToolResult(
            tool="generate_remediation_recommendation",
            ok=bool(made) and not missing,
            summary=f"{len(made)} recommendation(s)"
            + (f", {len(missing)} skipped (not verified)" if missing else ""),
            data={"recommendations": made},
            error="call verify_affected_and_fixed_versions first" if missing else None,
        )


def build_specs(tools: ResearchTools) -> list[ToolSpec]:
    return [
        ToolSpec(
            "get_cve_details",
            "Fetch the authoritative NVD record for the CVE under "
            "investigation (severity, status, configurations, references).",
            CveInput,
            tools.get_cve_details,
        ),
        ToolSpec(
            "get_inventory_matches",
            "Deterministically match the CVE against the software "
            "inventory; returns candidate items with status and identity method.",
            CveInput,
            tools.get_inventory_matches,
        ),
        ToolSpec(
            "search_official_vendor_advisories",
            "Retrieve structured ecosystem advisories "
            "(OSV) and allow-listed vendor advisory pages for one inventory item.",
            CveItemInput,
            tools.search_official_vendor_advisories,
        ),
        ToolSpec(
            "search_additional_research_sources",
            "Optional web search (Tavily/Exa). Results are supplementary and untrusted.",
            SearchInput,
            tools.search_additional_research_sources,
            is_search=True,
        ),
        ToolSpec(
            "get_kev_status",
            "Check whether the CVE is in the CISA KEV catalog.",
            CveInput,
            tools.get_kev_status,
        ),
        ToolSpec(
            "get_epss_score",
            "Get the FIRST EPSS exploitation probability.",
            CveInput,
            tools.get_epss_score,
        ),
        ToolSpec(
            "verify_affected_and_fixed_versions",
            "Re-evaluate affected status and verify the "
            "fixed version (all candidates, or one item_id) using all structured evidence "
            "gathered so far.",
            CveOptionalItemInput,
            tools.verify_affected_and_fixed_versions,
        ),
        ToolSpec(
            "generate_remediation_recommendation",
            "Produce deterministic remediation "
            "recommendations for verified candidates (all, or one item_id).",
            CveOptionalItemInput,
            tools.generate_remediation_recommendation,
        ),
    ]


class ToolRegistry:
    def __init__(self, specs: list[ToolSpec], budget: Budget, trace: list[ToolCallRecord]) -> None:
        self.specs = {s.name: s for s in specs}
        self.budget = budget
        self.trace = trace

    @property
    def names(self) -> list[str]:
        return list(self.specs)

    def call(self, name: str, arguments: dict[str, Any] | None) -> ToolResult:
        started = utcnow()
        t0 = time.monotonic()
        arguments = arguments if isinstance(arguments, dict) else {}
        safe_args = {k: str(v)[:100] for k, v in list(arguments.items())[:10]}

        def record(result: ToolResult) -> ToolResult:
            self.trace.append(
                ToolCallRecord(
                    tool=name[:64],
                    arguments=safe_args,
                    ok=result.ok,
                    error=result.error,
                    summary=result.summary[:300],
                    started_at=started,
                    duration_ms=int((time.monotonic() - t0) * 1000),
                )
            )
            return result

        spec = self.specs.get(name)
        if spec is None:
            return record(
                ToolResult(
                    tool=name[:64],
                    ok=False,
                    summary="rejected",
                    error="unknown tool: only registered read-only tools may be used",
                )
            )
        reason = self.budget.exhausted_reason(spec.is_search)
        if reason:
            record(ToolResult(tool=name, ok=False, summary="rejected", error=reason))
            raise BudgetExceeded(reason)
        self.budget.tool_calls += 1
        if spec.is_search:
            self.budget.search_calls += 1
        try:
            parsed = spec.input_model.model_validate(arguments)
        except ValidationError as exc:
            return record(
                ToolResult(
                    tool=name,
                    ok=False,
                    summary="invalid arguments",
                    error=f"{exc.error_count()} validation error(s)",
                )
            )
        try:
            return record(spec.fn(parsed))
        except SourceUnavailable as exc:
            return record(
                ToolResult(tool=name, ok=False, summary="source unavailable", error=exc.detail)
            )
        except ValueError as exc:
            return record(ToolResult(tool=name, ok=False, summary="rejected", error=str(exc)[:200]))
        except Exception as exc:  # a tool bug must not crash the scan or look like success
            return record(
                ToolResult(tool=name, ok=False, summary="tool error", error=type(exc).__name__)
            )


__all__ = ["Budget", "BudgetExceeded", "ResearchTools", "ToolRegistry", "ToolResult", "build_specs"]
