"""Compile grok pattern strings to Python regexes and extract fields locally.

The grok string's literal parts are already regex-escaped by rule_builder;
here we only expand %{NAME} / %{NAME:key} references against a catalog.

Uses stdlib re: the atomic groups and variable-length lookbehind used by the
StreamSets pattern set need Python 3.11+ (this project runs on 3.14), which
is why the `regex` package is not required.
"""

from __future__ import annotations

import re

# A Logstash-style type hint may follow the capture key, e.g.
# %{HTTPDATE:timestamp;date;dd/MMM/yyyy:HH:mm:ss Z}. Graylog-synced patterns
# can contain them; the hint is irrelevant to local matching, so only the key
# is kept.
TOKEN_RE = re.compile(
    r"%\{([A-Za-z_][A-Za-z0-9_]*)(?::([A-Za-z_][A-Za-z0-9_]*)(?:;[^}]*)?)?\}"
)

MAX_EXPAND_DEPTH = 30


class GrokError(Exception):
    """Base error for grok compilation problems."""


class UnknownPatternError(GrokError):
    def __init__(self, name: str):
        super().__init__(f"unknown grok pattern: {name}")
        self.name = name


def tokenize(grok: str) -> list[tuple[str, str, str | None]]:
    """Split a grok string into ('literal', text, None) and ('ref', name, key)."""
    parts: list[tuple[str, str, str | None]] = []
    pos = 0
    for m in TOKEN_RE.finditer(grok):
        if m.start() > pos:
            parts.append(("literal", grok[pos : m.start()], None))
        parts.append(("ref", m.group(1), m.group(2)))
        pos = m.end()
    if pos < len(grok):
        parts.append(("literal", grok[pos:], None))
    return parts


def check_tokens(grok: str, catalog: dict[str, str]) -> list[str]:
    """Non-raising lint: report references to patterns missing from the catalog."""
    return [
        f"unknown pattern %{{{value}}}"
        for kind, value, _key in tokenize(grok)
        if kind == "ref" and value not in catalog
    ]


def _expand(s: str, catalog: dict[str, str], key_map: dict[int, str],
            counter: list[int], depth: int) -> str:
    if depth > MAX_EXPAND_DEPTH:
        raise GrokError("pattern expansion too deep (cycle?)")
    out: list[str] = []
    for kind, value, key in tokenize(s):
        if kind == "literal":
            if "%{" in value:
                raise GrokError(
                    f"malformed grok token near: {value[value.index('%{'):][:30]}"
                )
            out.append(value)
            continue
        if value not in catalog:
            raise UnknownPatternError(value)
        body = _expand(catalog[value], catalog, key_map, counter, depth + 1)
        if key:
            counter[0] += 1
            key_map[counter[0]] = key
            out.append(f"(?P<g{counter[0]}>{body})")
        else:
            out.append(f"(?:{body})")
    return "".join(out)


def compile_grok(grok: str, catalog: dict[str, str]) -> tuple[re.Pattern, dict[int, str]]:
    """Compile grok -> (regex, {group_index: key}). Raises GrokError."""
    key_map: dict[int, str] = {}
    try:
        expanded = _expand(grok, catalog, key_map, [0], 0)
    except UnknownPatternError:
        raise
    except re.error as e:
        raise GrokError(f"invalid regex after expansion: {e}") from e
    try:
        compiled = re.compile(expanded)
    except re.error as e:
        raise GrokError(f"invalid regex: {e}") from e
    return compiled, key_map


def match(grok: str, text: str, catalog: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Match text against grok.

    Returns (status, fields) where status is one of:
      'full'    - pattern covers the whole string
      'partial' - pattern found but does not cover the whole string
      'none'    - no match at all
    """
    compiled, key_map = compile_grok(grok, catalog)
    m = compiled.fullmatch(text)
    status = "full"
    if m is None:
        m = compiled.search(text)
        status = "partial" if m is not None else "none"
    fields: dict[str, str] = {}
    if m is not None:
        for idx, key in key_map.items():
            val = m.group(f"g{idx}")
            if val is not None:
                fields[key] = val
    return status, fields
