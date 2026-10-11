"""Bounded research orchestration.

The deterministic policy (``next_step``) picks the next research action from
the evidence already gathered:

    CVE details -> inventory matches -> (stop if none) -> KEV -> EPSS
    -> verify all candidates -> official advisory research, once per distinct
       package/product, for candidates that are unsettled or lack a verified fix
    -> re-verify if research added evidence
    -> optional web search if uncertainty remains and a provider is configured
    -> deterministic recommendations -> stop

Termination is guaranteed: every step has a unique key that is executed at
most once, the set of keys is finite, and the registry enforces tool-call,
search and wall-clock budgets.
If an optional LLM researcher is configured it runs first through the same
registry; the deterministic policy then fills any gaps, so verification and
recommendations never depend on the LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Protocol

from app.agent.context import ResearchContext
from app.agent.state import ResearchState
from app.agent.tools import Budget, BudgetExceeded, ResearchTools, ToolRegistry, build_specs
from app.matching.fixes import assess_fix
from app.models import InventoryItem, KevStatus, ResearchTrace, SourceState
from app.reports.recommendation import build_recommendation

log = logging.getLogger("terminus.agent")


class LlmResearcher(Protocol):
    def run(self, state: ResearchState, registry: ToolRegistry) -> str | None: ...


def next_step(state: ResearchState, search_enabled: bool) -> tuple[str, str, dict[str, Any]] | None:
    """Return (step_key, tool_name, arguments) or None when research is complete."""
    cid = state.cve_id
    done = state.steps_done

    if state.cve is None:
        return None if "cve" in done else ("cve", "get_cve_details", {"cve_id": cid})
    if "matches" not in done:
        return ("matches", "get_inventory_matches", {"cve_id": cid})
    if not state.matches:
        return None
    if state.kev is None and "kev" not in done:
        return ("kev", "get_kev_status", {"cve_id": cid})
    if state.epss is None and "epss" not in done:
        return ("epss", "get_epss_score", {"cve_id": cid})

    key = state.verify_key()
    if key not in done:
        return (key, "verify_affected_and_fixed_versions", {"cve_id": cid})
    for item_id in sorted(state.matches):
        key = f"research:{state.research_key(item_id)}"
        if key not in done and state.needs_advisory_research(item_id):
            return (key, "search_official_vendor_advisories", {"cve_id": cid, "item_id": item_id})
    if search_enabled and "search" not in done and state.unresolved():
        return ("search", "search_additional_research_sources", {"cve_id": cid})
    if "rec:all" not in done:
        return ("rec:all", "generate_remediation_recommendation", {"cve_id": cid})
    return None


@dataclass
class Investigation:
    state: ResearchState
    trace: ResearchTrace
    ai_interpretation: str | None
    gaps: dict[str, list[str]]  # item_id -> research steps that did not complete


class ResearchAgent:
    def __init__(self, ctx: ResearchContext, llm: LlmResearcher | None = None) -> None:
        self.ctx = ctx
        self.llm = llm

    def investigate(self, cve_id: str, items: list[InventoryItem]) -> Investigation:
        s = self.ctx.settings
        state = ResearchState(cve_id=cve_id, items=items)
        trace = ResearchTrace(mode="llm+deterministic" if self.llm else "deterministic")
        budget = Budget(
            max_tool_calls=s.agent_max_tool_calls,
            max_search_calls=s.agent_max_search_calls,
            max_seconds=s.agent_max_seconds,
        )
        registry = ToolRegistry(
            build_specs(ResearchTools(state, self.ctx)), budget, trace.tool_calls
        )
        stop_reason = ""
        ai_text: str | None = None

        if self.llm is not None:
            try:
                ai_text = self.llm.run(state, registry)
            except BudgetExceeded as exc:
                stop_reason = f"LLM phase stopped: {exc}"
            except Exception as exc:  # LLM failures must not break deterministic research
                log.warning("LLM research failed: %s", type(exc).__name__)
                trace.injection_flags.append(f"llm_error:{type(exc).__name__}")

        search_enabled = self.ctx.sources.search is not None
        try:
            # Upper bound on iterations in addition to the budget: number of distinct step keys.
            for _ in range(10 + 2 * max(1, len(items))):
                step = next_step(state, search_enabled)
                if step is None:
                    if not stop_reason:
                        stop_reason = (
                            "no inventory candidates"
                            if state.cve is not None and not state.matches
                            else "CVE details unavailable"
                            if state.cve is None
                            else "sufficient evidence collected"
                        )
                    break
                key, tool, args = step
                state.steps_done.add(key)
                registry.call(tool, args)
        except BudgetExceeded as exc:
            stop_reason = str(exc)

        gaps = self._finalize(state)
        trace.stop_reason = stop_reason or "iteration limit reached"
        trace.budget = budget.snapshot()
        trace.injection_flags = sorted(set(trace.injection_flags) | state.injection_flags)
        return Investigation(state=state, trace=trace, ai_interpretation=ai_text, gaps=gaps)

    def _finalize(self, state: ResearchState) -> dict[str, list[str]]:
        """Complete any candidate the research loop could not finish.

        Uses only deterministic computation over evidence already gathered, and
        records which research steps were skipped so reports show the gap.
        """
        gaps: dict[str, list[str]] = {}
        items = {i.item_id: i for i in state.items}
        kev = state.kev or KevStatus(in_kev=None, source_state=SourceState.UNAVAILABLE)
        for item_id, match in state.matches.items():
            missing: list[str] = []
            if item_id not in state.fixes:
                missing.append("version verification step was not run (budget)")
            if state.needs_advisory_research(item_id):
                missing.append("official advisory research was not performed (budget)")
            if item_id not in state.fixes:
                state.fixes[item_id] = assess_fix(
                    items[item_id], match, list(state.vendor_pages.values())
                )
            if item_id not in state.recommendations:
                state.recommendations[item_id] = build_recommendation(
                    items[item_id], match, state.fixes[item_id], kev, state.advisory_list()
                )
            if missing:
                gaps[item_id] = missing
        return gaps
