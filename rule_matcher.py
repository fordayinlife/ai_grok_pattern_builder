"""Decide whether a log message is already handled by an existing pipeline rule.

A rule "covers" a message when it would fire on it and extract fields: its
`when` condition holds AND its grok produced at least one named capture. That
is the same thing Graylog does when it processes the message, so a message a
rule covers does not need a new rule built for it.

Everything here is judged locally from the rule's source text - one
`list_rules()` call provides the sources and the rest is plain Python, so
filtering a page of messages costs no extra Graylog requests. The trade-off is
that only the condition shapes this tool itself generates can be read; rules
written by hand in Graylog are reported as unparsed rather than misread, and
never hide a message.
"""

from __future__ import annotations

import re

from rule_builder import compile_regex, unescape_rule_string


class RuleParseError(Exception):
    """A rule whose coverage cannot be judged from its source."""


_WHEN_RE = re.compile(r"^when\b(.*?)^then\b", re.S | re.M)
_THEN_RE = re.compile(r"^then\b(.*?)^end\b", re.S | re.M)

_GROK_RE = re.compile(r'pattern:\s*"((?:\\.|[^"\\])*)"')
_SRC_FIELD_RE = re.compile(r"value:\s*to_string\(\$message\.`?([^`)`]+)`?\)")

# The condition atoms this tool and Graylog's own rule examples produce.
_HAS_FIELD_RE = re.compile(r'^has_field\(\s*"((?:\\.|[^"\\])*)"\s*\)$')
_CONTAINS_RE = re.compile(
    r'^contains\(\s*to_string\(\$message\.`?([^`)`]+)`?\)\s*,\s*'
    r'"((?:\\.|[^"\\])*)"\s*\)$')
_REGEX_COND_RE = re.compile(
    r'^regex\(\s*pattern:\s*"((?:\\.|[^"\\])*)"\s*,\s*'
    r'value:\s*to_string\(\$message\.`?([^`)`]+)`?\)\s*\)'
    r'(?:\.matches)?\s*==\s*true$')
# Graylog's rules also write the regex call positionally and sometimes skip
# `.matches == true`, which evaluates to a truthy match result.
_REGEX_POSITIONAL_RE = re.compile(
    r'^regex\(\s*"((?:\\.|[^"\\])*)"\s*,\s*'
    r'to_string\(\$message\.`?([^`)`]+)`?\)\s*\)'
    r'(?:\.matches)?\s*(?:==\s*true)?$')
# Field comparisons, as used by rules that target one specific input.
_FIELD_EQ_RE = re.compile(
    r'^to_string\(\$message\.`?([^`)`]+)`?\)\s*(==|!=)\s*"((?:\\.|[^"\\])*)"$')

# Conjunction: `&&`, or the keyword form (Graylog accepts `AND` too).
_AND_KW_RE = re.compile(r"\s+(?:AND|and)\s+")

# Always / has_field / contains / regex / field_eq / and, in the order tested.
ALWAYS = "always"
HAS_FIELD = "has_field"
CONTAINS = "contains"
REGEX = "regex"
FIELD_EQ = "field_eq"
FIELD_NE = "field_ne"
ALL = "all"


class RuleMatcher:
    """One pipeline rule, reduced to what coverage needs."""

    def __init__(self, title: str, grok: str | None, source_field: str,
                 condition: dict, raw_grok: str):
        self.title = title
        self.grok = grok
        self.raw_grok = raw_grok      # as stored in the rule source
        self.source_field = source_field
        self.condition = condition
        self._regexes: dict[str, re.Pattern] = {}
        self._regex_failed: set[str] = set()

    @property
    def value_field(self) -> str:
        """Which message field has to be looked at to judge this rule.

        A grok rule reads it from its `value:` argument; a rule without a grok
        only has the field its own `when` condition mentions.
        """
        if self.grok is not None:
            return self.source_field
        atoms = self.condition.get("atoms") or [self.condition]
        for atom in atoms:
            if atom["kind"] == REGEX:
                return atom["field"]
        return "message"

    def _regex_for(self, pattern: str) -> re.Pattern:
        """Compiled condition regex, cached.

        A pattern that cannot be compiled is remembered as a failure so the
        same rule is not retried for every message. `_atom_holds` turns the
        failure into "this rule covers nothing" rather than an exception.
        """
        compiled = self._regexes.get(pattern)
        if compiled is None and pattern not in self._regex_failed:
            try:
                compiled = compile_regex(pattern)
            except (re.error, ValueError):
                self._regex_failed.add(pattern)
                compiled = None
        if compiled is None:
            raise RuleParseError(
                f"regex condition does not compile here: {pattern[:40]!r}")
        return compiled

    # -- condition -----------------------------------------------------
    def _condition_holds(self, value: str, fields: dict) -> bool:
        condition = self.condition
        if condition["kind"] == ALL:
            return all(self._atom_holds(atom, value, fields)
                       for atom in condition["atoms"])
        return self._atom_holds(condition, value, fields)

    def _atom_holds(self, atom: dict, value: str, fields: dict) -> bool:
        kind = atom["kind"]
        if kind == ALWAYS:
            return True
        if kind == HAS_FIELD:
            return atom["field"] in (fields or {})
        if kind == CONTAINS:
            needle = atom["value"]
            haystack = str((fields or {}).get(atom["field"], "") or "")
            return needle in haystack
        if kind == REGEX:
            # regex() uses search semantics in Graylog.
            try:
                return self._regex_for(atom["pattern"]).search(value) is not None
            except RuleParseError:
                return False            # a pattern we cannot run tells us nothing
        if kind in (FIELD_EQ, FIELD_NE):
            present = (fields or {}).get(atom["field"])
            if present is None:
                return False                 # to_string(null) matches nothing
            equal = str(present) == atom["value"]
            return equal if kind == FIELD_EQ else not equal
        return False

    def covers(self, value: str, fields: dict, catalog: dict[str, str]) -> bool:
        """True when this rule would extract fields from this message."""
        from grok_compiler import GrokError, match

        if not self._condition_holds(value or "", fields or {}):
            return False
        if self.grok is None:
            # No grok: the rule sets the same fields whenever it fires, so the
            # condition alone decides (pfSense filterlog rules do exactly this).
            return True
        try:
            status, extracted = match(self.grok, value or "", catalog)
        except GrokError:
            # A pattern this catalog cannot expand or compile: judge nothing.
            return False
        if status not in ("full", "partial"):
            return False
        # A match with no named captures means the rule sets no fields.
        return any(v not in (None, "") for v in extracted.values())


def _blocks(source: str) -> tuple[str, str]:
    when = _WHEN_RE.search(source or "")
    then = _THEN_RE.search(source or "")
    if not when or not then:
        raise RuleParseError("rule has no when/then block")
    return when.group(1).strip(), then.group(1).strip()


def _strip_outer_parens(text: str) -> str:
    """Drop one balanced pair of parentheses wrapping the whole expression."""
    text = text.strip()
    while text.startswith("(") and text.endswith(")"):
        depth = 0
        for i, ch in enumerate(text):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i < len(text) - 1:
                    return text            # the pair is not the outermost
        text = text[1:-1].strip()
    return text


def _split_conjuncts(text: str) -> list[str]:
    """Split a `when` block on `&&` / `AND`, ignoring either inside strings."""
    parts: list[str] = []
    buf: list[str] = []
    quote = False
    i = 0
    while i < len(text):
        ch = text[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(text):
                buf.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                quote = False
            i += 1
            continue
        if ch == '"':
            quote = True
            buf.append(ch)
            i += 1
            continue
        if text.startswith("&&", i):
            parts.append("".join(buf))
            buf = []
            i += 2
            continue
        kw = _AND_KW_RE.match(text, i)
        if kw:
            parts.append("".join(buf))
            buf = []
            i = kw.end()
            continue
        buf.append(ch)
        i += 1
    parts.append("".join(buf))
    return [_strip_outer_parens(p) for p in parts if p.strip()]


def _parse_atom(atom: str) -> dict:
    if atom == "true":
        return {"kind": ALWAYS}

    m = _REGEX_POSITIONAL_RE.match(atom) or _REGEX_COND_RE.match(atom)
    if m:
        return {"kind": REGEX, "pattern": unescape_rule_string(m.group(1)),
                "field": m.group(2)}

    m = _CONTAINS_RE.match(atom)
    if m:
        return {"kind": CONTAINS, "field": m.group(1),
                "value": unescape_rule_string(m.group(2))}

    m = _FIELD_EQ_RE.match(atom)
    if m:
        return {"kind": FIELD_EQ if m.group(2) == "==" else FIELD_NE,
                "field": m.group(1),
                "value": unescape_rule_string(m.group(3))}

    m = _HAS_FIELD_RE.match(atom)
    if m:
        return {"kind": HAS_FIELD, "field": unescape_rule_string(m.group(1))}

    raise RuleParseError(f"unsupported when condition: {atom[:60]!r}")


def _parse_condition(when_block: str) -> dict:
    atoms = [_parse_atom(part) for part in _split_conjuncts(when_block)]
    if len(atoms) == 1:
        return atoms[0]
    return {"kind": ALL, "atoms": atoms}


_SETS_FIELDS_RE = re.compile(r"\bset_fields?\s*\(")


def _parse_grok(then_block: str, catalog: dict[str, str]) -> str | None:
    """Grok pattern from the `then` block, or None when the rule uses none.

    A rule that only calls `set_field(...)` (pfSense's filterlog rules split a
    CSV line that way) still extracts fields - it just needs no grok - so the
    grok is optional for those. None means "covered whenever the rule fires".
    """
    m = _GROK_RE.search(then_block)
    if not m:
        return None
    grok = unescape_rule_string(m.group(1))
    from grok_compiler import check_tokens
    unknown = check_tokens(grok, catalog)
    if unknown:
        raise RuleParseError(
            f"grok uses patterns this catalog does not define: "
            f"{', '.join(unknown[:3])}")
    return grok


def _parse_source_field(then_block: str) -> str:
    m = _SRC_FIELD_RE.search(then_block)
    if not m:
        raise RuleParseError("cannot tell which field the rule matches on")
    return m.group(1).strip()


def parse_rule(source: str, catalog: dict[str, str],
               title: str = "") -> RuleMatcher:
    """Turn one rule source into a RuleMatcher. Raises RuleParseError."""
    when_block, then_block = _blocks(source)
    condition = _parse_condition(when_block)
    grok = _parse_grok(then_block, catalog)
    if grok is None:
        if not _SETS_FIELDS_RE.search(then_block):
            # Routing-only rules (route_to_stream and friends) set no fields,
            # so even when they fire the message still has nothing built for it.
            raise RuleParseError("rule sets no fields")
        # Without a grok there is no `value:` argument to read the field from;
        # the condition names the field it looks at.
        source_field = ""
    else:
        source_field = _parse_source_field(then_block)
    return RuleMatcher(title=title,
                       grok=grok,
                       source_field=source_field,
                       condition=condition,
                       raw_grok=then_block)


def parse_matchers(rules: list[dict],
                   catalog: dict[str, str]) -> tuple[list[RuleMatcher],
                                                    list[dict]]:
    """Parse every rule we can read.

    Returns (matchers, unparsed). `unparsed` lists {title, reason} for rules
    whose coverage cannot be judged; those rules hide nothing.
    """
    matchers: list[RuleMatcher] = []
    unparsed: list[dict] = []
    for rule in rules or []:
        source = rule.get("source") if isinstance(rule, dict) else None
        title = str(rule.get("title") or rule.get("name") or "") \
            if isinstance(rule, dict) else ""
        if not source:
            continue
        try:
            matchers.append(parse_rule(source, catalog, title=title))
        except RuleParseError as e:
            unparsed.append({"title": title or "(untitled)", "reason": str(e)})
    return matchers, unparsed


def covered(message: dict, matchers: list[RuleMatcher],
            catalog: dict[str, str]) -> bool:
    """True when any of `matchers` already extracts fields from `message`."""
    fields = message.get("fields") or {}
    sample = message.get("message") or ""
    for matcher in matchers:
        if matcher.value_field == "message":
            value = sample
        else:
            value = fields.get(matcher.value_field)
            if value is None:
                continue
            value = str(value)
        if matcher.covers(value, fields, catalog):
            return True
    return False
