"""Configuration and optional-component checks.

Optional features are never enabled or disabled behind the user's back: when a
provider is configured but its key or package is missing, the scan refuses to
start and says how to fix it, instead of silently running without it.

Package presence is checked through installed-distribution metadata, so these
checks never import Streamlit, FastAPI or LlamaIndex.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import metadata
from typing import Literal

from terminus.config import Settings

REPO_URL = "https://github.com/Asmit12357/terminus.git"

State = Literal["ok", "off", "missing", "misconfigured"]


class ConfigurationError(RuntimeError):
    """A configured feature cannot run; ``problems`` say why and how to fix it."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class Component:
    name: str
    state: State
    detail: str
    hint: str | None = None


def installed(distribution: str) -> bool:
    try:
        metadata.version(distribution)
    except metadata.PackageNotFoundError:
        return False
    return True


def not_installed(distributions: list[str]) -> str:
    verb = "is" if len(distributions) == 1 else "are"
    return f"{' and '.join(distributions)} {verb} not installed"


def install_hint(extra: str) -> str:
    return (
        f'uv tool install --force "terminus[{extra}] @ git+{REPO_URL}"  '
        f"(source checkout: uv sync --extra {extra})"
    )


_LLM_PACKAGES = {
    "openai": ("llama-index-core", "llama-index-llms-openai"),
    "anthropic": ("llama-index-core", "llama-index-llms-anthropic"),
}


def llm_component(settings: Settings) -> Component:
    provider = settings.llm_provider
    if provider == "none":
        return Component(
            "LLM research",
            "off",
            "deterministic research only (TERMINUS_LLM_PROVIDER=none)",
            "optional; set TERMINUS_LLM_PROVIDER=openai|anthropic plus its API key",
        )
    key_name = f"{provider}_api_key"
    key = getattr(settings, key_name)
    if key is None or not key.get_secret_value():
        return Component(
            "LLM research",
            "misconfigured",
            f"TERMINUS_LLM_PROVIDER={provider} but TERMINUS_{key_name.upper()} is not set",
            f"set TERMINUS_{key_name.upper()} in {settings.config_file}, "
            "or set TERMINUS_LLM_PROVIDER=none",
        )
    missing = [d for d in _LLM_PACKAGES[provider] if not installed(d)]
    if missing:
        return Component(
            "LLM research",
            "missing",
            f"TERMINUS_LLM_PROVIDER={provider} but {not_installed(missing)}",
            f"install it: {install_hint(f'agent-{provider}')}",
        )
    return Component("LLM research", "ok", f"{provider} via LlamaIndex")


def search_component(settings: Settings) -> Component:
    provider = settings.search_provider
    if provider == "none":
        return Component(
            "Web search",
            "off",
            "no supplementary web search (TERMINUS_SEARCH_PROVIDER=none)",
            "optional; set TERMINUS_SEARCH_PROVIDER=tavily|exa plus its API key",
        )
    key_name = f"{provider}_api_key"
    key = getattr(settings, key_name)
    if key is None or not key.get_secret_value():
        return Component(
            "Web search",
            "misconfigured",
            f"TERMINUS_SEARCH_PROVIDER={provider} but TERMINUS_{key_name.upper()} is not set",
            f"set TERMINUS_{key_name.upper()} in {settings.config_file}, "
            "or set TERMINUS_SEARCH_PROVIDER=none",
        )
    return Component("Web search", "ok", provider)


def nvd_component(settings: Settings) -> Component:
    if settings.nvd_api_key and settings.nvd_api_key.get_secret_value():
        return Component("NVD API key", "ok", "set (higher NVD rate limit)")
    return Component(
        "NVD API key",
        "off",
        "not set; live scans use the public rate limit (~6 s between NVD requests)",
        "optional, free: https://nvd.nist.gov/developers/request-an-api-key",
    )


def extra_component(name: str, extra: str, distributions: tuple[str, ...]) -> Component:
    missing = [d for d in distributions if not installed(d)]
    if missing:
        return Component(name, "off", "not installed (optional)", install_hint(extra))
    return Component(name, "ok", "installed")


def optional_components() -> list[Component]:
    return [
        extra_component("Dashboard", "dashboard", ("streamlit", "pandas")),
        extra_component("REST API", "api", ("fastapi", "uvicorn", "python-multipart")),
    ]


def research_problems(settings: Settings, *, demo: bool) -> list[str]:
    """Blocking problems for a scan. Web search is only used by live scans."""
    components = [llm_component(settings)]
    if not demo:
        components.append(search_component(settings))
    return [
        f"{c.name}: {c.detail}. Fix: {c.hint}"
        for c in components
        if c.state in ("missing", "misconfigured")
    ]


def require_research_config(settings: Settings, *, demo: bool) -> None:
    problems = research_problems(settings, demo=demo)
    if problems:
        raise ConfigurationError(problems)
