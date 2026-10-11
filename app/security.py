"""Handling of untrusted text (CVE descriptions, vendor pages, search results).

Retrieved content is *data*. It is normalized, stripped of invisible/control
characters, truncated, scanned for prompt-injection patterns, and - when it is
shown to an LLM - fenced inside explicit ``<untrusted_document>`` delimiters.
Detection is a defence-in-depth signal: the primary control is that no
retrieved text can select tools, change verdicts or set a fixed version.
"""

from __future__ import annotations

import re
import unicodedata

from pydantic import BaseModel, Field

_INVISIBLE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f­​-‏‪-‮⁠-⁤⁦-⁩﻿]")
_ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
_WS = re.compile(r"[ \t\r\f\v]+")

INJECTION_PATTERNS: dict[str, re.Pattern[str]] = {
    "override_instructions": re.compile(
        r"\b(ignore|disregard|forget|override)\b.{0,40}\b(previous|prior|above|earlier|all|system|"
        r"original)\b.{0,20}\b(instructions?|prompts?|rules|directives|guidelines)\b",
        re.I | re.S,
    ),
    "role_reassignment": re.compile(
        r"\b(you are now|from now on,? you|new instructions?:|act as (an? )?(admin|root|system))",
        re.I,
    ),
    "system_prompt_reference": re.compile(
        r"\b(system prompt|developer (mode|message)|jailbreak|prompt injection test)\b", re.I
    ),
    # No word boundary before the secret noun: names like TERMINUS_API_TOKEN must match.
    "secret_exfiltration": re.compile(
        r"\b(reveal|print|show|output|send|leak|exfiltrate|dump|return)\b.{0,50}"
        r"(api[ _-]?keys?|secrets?|tokens?|passwords?|credentials?|env(ironment)? var(iable)?s?|"
        r"\.env)(?![a-z])",
        re.I | re.S,
    ),
    "verdict_tampering": re.compile(
        r"\b(mark|classify|report|label|set|treat)\b.{0,40}\b(as|to)\b\s*"
        r"(safe|not (affected|vulnerable)|unaffected|resolved|false positive|patched|low priority)",
        re.I | re.S,
    ),
    "tool_invocation": re.compile(
        r"\b(call|invoke|use|trigger)\b.{0,20}\b(the )?(tool|function)\b|\btool_call\b|"
        r"\bfunction_call\b",
        re.I | re.S,
    ),
    "command_execution": re.compile(
        r"(\b(execute|run)\b.{0,30}\b(command|shell|script|powershell|bash|payload)\b|"
        r"curl\s+\S+\s*\|\s*(ba)?sh|wget\s+\S+\s*\|\s*(ba)?sh|\brm\s+-rf\b|powershell(\.exe)?\s+-e(nc)?\b)",
        re.I | re.S,
    ),
    "fake_delimiters": re.compile(
        r"<\s*/?\s*(system|assistant|instructions?|tool_call|untrusted_document)\b[^>]*>|"
        r"\[/?(INST|SYS)\]|^#{2,}\s*(system|instructions?)\b",
        re.I | re.M,
    ),
    "encoded_blob": re.compile(r"[A-Za-z0-9+/]{160,}={0,2}"),
}


class SanitizedText(BaseModel):
    text: str
    flags: list[str] = Field(default_factory=list)
    truncated: bool = False

    @property
    def suspicious(self) -> bool:
        return bool(self.flags)


def detect_injection(text: str) -> list[str]:
    return sorted(name for name, pat in INJECTION_PATTERNS.items() if pat.search(text))


def sanitize_untrusted(text: str | None, max_chars: int = 4000) -> SanitizedText:
    if not text:
        return SanitizedText(text="")
    value = unicodedata.normalize("NFKC", str(text))
    value = _ANSI.sub("", value)
    value = _INVISIBLE.sub("", value)
    value = _WS.sub(" ", value)
    value = re.sub(r"\n{3,}", "\n\n", value).strip()
    flags = detect_injection(value)
    truncated = len(value) > max_chars
    if truncated:
        value = value[:max_chars] + " [truncated]"
    return SanitizedText(text=value, flags=flags, truncated=truncated)


def fence(text: str, source: str, flags: list[str] | None = None) -> str:
    """Wrap untrusted text for inclusion in an LLM prompt.

    Any delimiter-like tags inside the text are neutralized so the content
    cannot close the fence early.
    """
    safe = re.sub(r"<\s*/?\s*untrusted_document", "&lt;untrusted_document", text, flags=re.I)
    safe_source = re.sub(r"[^A-Za-z0-9:/._\-?=&%#]", "", source)[:300]
    flag_attr = f' injection_flags="{",".join(flags)}"' if flags else ""
    return f'<untrusted_document source="{safe_source}"{flag_attr}>\n{safe}\n</untrusted_document>'


def csv_safe(value: object) -> str:
    """Neutralize spreadsheet formula injection in exported cells."""
    text = "" if value is None else str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text
