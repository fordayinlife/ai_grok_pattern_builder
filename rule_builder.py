"""Segments + config -> grok string -> Graylog pipeline rule source.

This module is the ONLY place that performs escaping:

1. escape_literal(): regex-escapes literal gaps so arbitrary sample text
   (brackets, dots, quotes) is safe inside a grok pattern.
2. escape_rule_string(): escapes for Graylog's double-quoted rule strings.
"""

from __future__ import annotations

import re
from collections import Counter

NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
SOURCE_FIELD_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
FIELD_RE = re.compile(r"^[A-Za-z0-9_@.-]+$")

# Rule-language parser tokens; unusable as bare $message.<name> references.
RESERVED_WORDS = {
    "all", "either", "pass", "and", "or", "not", "pipeline", "rule",
    "during", "stage", "when", "then", "end", "let", "match",
}

_REGEX_METACHARS = re.compile(r"([\\.^$|(){}\[\]*+?])")


class ValidationError(Exception):
    """Input cannot be represented as a grok pattern / rule."""


def escape_literal(text: str) -> str:
    """Regex-escape literal text so it matches itself inside a grok pattern."""
    return _REGEX_METACHARS.sub(r"\\\1", text)


def escape_rule_string(text: str) -> str:
    """Escape a value for embedding in a Graylog double-quoted string."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


_RULE_STRING_ESCAPES = {"n": "\n", "r": "\r", "t": "\t",
                        '"': '"', "\\": "\\"}


def unescape_rule_string(text: str) -> str:
    """Inverse of escape_rule_string.

    Rule sources store their strings escaped (`\\[`, `\\"`), so a pattern read
    back out of a rule has to be unescaped before it is a usable regex.
    An escape we did not write is kept verbatim.
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        if ch == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_RULE_STRING_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


# `(?i)` and friends. Graylog runs Java's regex, where these may appear
# anywhere in a pattern; Python's re puts them at the start or nowhere.
_FLAG_GROUP_RE = re.compile(r"\(\?[aiLmsux]+\)")


def _skip_literal_span(pattern: str, i: int) -> int:
    """End index of the escape sequence or character class starting at `i`."""
    if pattern[i] == "\\":
        return min(i + 2, len(pattern))
    # Character class: ] first, or after ^, is a literal.
    j = i + 1
    if pattern[j:j + 1] == "^":
        j += 1
    if pattern[j:j + 1] == "]":
        j += 1
    while j < len(pattern) and pattern[j] != "]":
        j += 2 if pattern[j] == "\\" else 1
    return j


def _open_parens(text: str) -> int | None:
    """Unclosed `(` count, or None when the text is unbalanced."""
    depth = 0
    i = 0
    while i < len(text):
        ch = text[i]
        if ch in "\\[":
            i = _skip_literal_span(text, i)
            continue
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth < 0:
                return None
        i += 1
    return depth


def _find_mid_flag(pattern: str) -> tuple[int, re.Match] | None:
    """Last flag group that does not sit at the very start of the pattern.

    Working right to left matters: each wrap encloses a scoped group and a
    later flag group ends up nested inside an earlier one, which Python
    accepts. Left to right, the second wrap would have to close the first.
    """
    found: tuple[int, re.Match] | None = None
    i = 0
    while i < len(pattern):
        if pattern[i] in "\\[":
            i = _skip_literal_span(pattern, i)
            continue
        match = _FLAG_GROUP_RE.match(pattern, i)
        if match and i > 0:
            found = (i, match)
        i += 1
    return found


def portable_regex(pattern: str) -> str:
    """Rewrite mid-pattern flag groups into scoped ones Python accepts.

    Java reads `a(?i)b` as "the rest is case-insensitive"; Python's re rejects
    it outright. Wrapping the remainder - `a(?i:b)` - matches the same text, so
    a rule can be judged the way Graylog would judge it. Raises ValueError for
    a remainder that cannot be wrapped (an unbalanced pattern), which leaves
    whatever contains it unread.
    """
    while True:
        found = _find_mid_flag(pattern)
        if found is None:
            return pattern
        start, match = found
        head, flags = pattern[:start], match.group(0)[2:-1]
        rest = pattern[match.end():]
        closers = _open_parens(rest)
        if closers is None:
            raise ValueError("unbalanced parentheses")
        # +1 for the group this very wrap opened.
        pattern = head + f"(?{flags}:" + rest + (")" * (closers + 1))


def compile_regex(pattern: str) -> re.Pattern:
    """Compile a rule-language regex, accepting what Graylog's engine accepts.

    Raises ValidationError for a pattern neither engine can run.
    """
    try:
        return re.compile(portable_regex(pattern))
    except (re.error, ValueError) as e:
        raise ValidationError(f"not a valid regex for Graylog: {e}")


def rename_rule_source(source: str, new_name: str) -> str:
    """Return a rule source whose first line names the rule `new_name`.

    Graylog derives a pipeline rule's stored title from the `rule "..."`
    line in its source (the POST `title` field is ignored), and titles must
    be unique, so renaming must edit the source itself.
    """
    first = f'rule "{escape_rule_string(new_name)}"'
    nl = source.find("\n")
    if nl == -1:
        return first
    return first + source[nl:]


def _message_ref(field: str) -> str:
    """Render a `$message.<field>` reference Graylog can parse.

    Bare identifiers are used as-is; names containing dots, dashes, `@` or a
    leading digit (e.g. `event.id`, `ip-c_geolocation`, `@timestamp`) must be
    backtick-quoted or the rule parser reads them as arithmetic/attributes.
    """
    if NAME_RE.match(field) and field.lower() not in RESERVED_WORDS:
        return f"$message.{field}"
    return f"$message.`{field}`"


def normalize_ranges(sample: str, ranges: list[dict]) -> list[dict]:
    """Validate and sort capture ranges against the sample.

    Raises ValidationError on out-of-bounds, overlaps, or bad key/pattern names.
    """
    if not sample:
        raise ValidationError("sample string is empty")
    cleaned: list[dict] = []
    for i, r in enumerate(ranges):
        try:
            start, end = int(r["start"]), int(r["end"])
            key, pattern = str(r["key"]), str(r["pattern"])
        except (KeyError, TypeError, ValueError):
            raise ValidationError(f"capture #{i + 1} is malformed")
        if not NAME_RE.match(key):
            raise ValidationError(
                f"capture #{i + 1}: key '{key}' must match [A-Za-z_][A-Za-z0-9_]*"
            )
        if not NAME_RE.match(pattern):
            raise ValidationError(
                f"capture #{i + 1}: pattern '{pattern}' must match [A-Za-z_][A-Za-z0-9_]*"
            )
        if key == 'message':
            raise ValidationError(
                f"capture #{i + 1}: key 'message' is reserved and cannot be used"
            )
        if key.lower() in RESERVED_WORDS:
            raise ValidationError(
                f"capture #{i + 1}: key '{key}' is a rule-language word and "
                "cannot be used as a field name"
            )
        if start < 0 or end > len(sample) or start >= end:
            raise ValidationError(f"capture '{key}' has an invalid text range")
        cleaned.append({"key": key, "pattern": pattern, "start": start, "end": end})

    cleaned.sort(key=lambda r: r["start"])
    prev_end = 0
    for r in cleaned:
        if r["start"] < prev_end:
            raise ValidationError(f"capture '{r['key']}' overlaps another capture")
        prev_end = r["end"]
    return cleaned


def build_grok(sample: str, ranges: list[dict]) -> str:
    """Render the grok pattern string from sample + capture ranges."""
    ranges = normalize_ranges(sample, ranges)
    out: list[str] = []
    pos = 0
    for r in ranges:
        out.append(escape_literal(sample[pos : r["start"]]))
        out.append(f"%{{{r['pattern']}:{r['key']}}}")
        pos = r["end"]
    out.append(escape_literal(sample[pos:]))
    return "".join(out)


def build_rule(grok: str, config: dict) -> str:
    """Render the full Graylog pipeline rule source.

    Follows the canonical grok-rule shape: a boolean `when` condition, then a
    single `grok(...)` call whose result feeds `set_fields`. When the line does
    not match, `grok()` yields an empty map and `set_fields` is a safe no-op, so
    there is no need to (and we must not) duplicate the grok call in `when`.

    config keys (all optional except as noted):
      name          rule title (default 'AI generated grok rule')
      source_field  message field the pattern is matched against (default 'message')
      condition     'always' | 'has_field' | 'contains' | 'regex'
      condition_field  field name for has_field / contains
      condition_value  substring for the contains condition
      condition_regex  regex for the regex condition
    """
    name = str(config.get("name") or "").strip() or "AI generated grok rule"
    name = name.replace("\n", " ").replace("\r", " ")

    source_field = str(config.get("source_field") or "message").strip()
    if not SOURCE_FIELD_RE.match(source_field):
        raise ValidationError(
            f"source field '{source_field}' must match [A-Za-z_][A-Za-z0-9_]*"
        )
    if source_field.lower() in RESERVED_WORDS:
        raise ValidationError(
            f"source field '{source_field}' is a reserved rule-language word"
        )

    condition = str(config.get("condition") or "always")
    if condition == "always":
        cond_expr = "true"
    elif condition == "has_field":
        field = str(config.get("condition_field") or "").strip()
        if not FIELD_RE.match(field):
            raise ValidationError("has_field condition needs a valid field name")
        cond_expr = f'has_field("{escape_rule_string(field)}")'
    elif condition == "contains":
        field = str(config.get("condition_field") or "").strip()
        if not FIELD_RE.match(field):
            raise ValidationError("contains condition needs a valid field name")
        needle = str(config.get("condition_value") or "")
        if not needle:
            raise ValidationError("contains condition needs a value to look for")
        cond_expr = (
            f'has_field("{escape_rule_string(field)}") && '
            f'contains(to_string({_message_ref(field)}), "{escape_rule_string(needle)}")'
        )
    elif condition == "regex":
        rx = str(config.get("condition_regex") or "").strip()
        if not rx:
            raise ValidationError("regex condition needs a pattern")
        # Catch a broken pattern here: Graylog would only reject it on push,
        # leaving a `when` clause that can never fire.
        compile_regex(rx)
        # regex() returns a RegexMatchResult; `.matches == true` makes it boolean.
        cond_expr = (
            f'regex(pattern: "{escape_rule_string(rx)}", '
            f"value: to_string({_message_ref(source_field)})).matches == true"
        )
    else:
        raise ValidationError(f"unknown condition type '{condition}'")

    grok_esc = escape_rule_string(grok)
    return (
        f'rule "{escape_rule_string(name)}"\n'
        f"when\n"
        f"  {cond_expr}\n"
        f"then\n"
        f"  set_fields(grok(\n"
        f'    pattern: "{grok_esc}",\n'
        f"    value: to_string({_message_ref(source_field)}),\n"
        f"    only_named_captures: true\n"
        f"  ));\n"
        f"end\n"
    )


def anchor_segments(sample: str, segments: list[dict]) -> tuple[list[dict], list[str]]:
    """Re-anchor AI-produced capture segments onto the sample.

    The model's text segments are used as positional anchors so that repeated
    values (e.g. two `0`s for uid and gid) land in the right place. Capture
    values are still re-located in the sample; text is never trusted verbatim.
    Returns (ranges, warnings).
    """
    ranges: list[dict] = []
    warnings: list[str] = []
    pos = 0
    for i, seg in enumerate(segments):
        if not isinstance(seg, dict):
            continue
        stype = seg.get("type")

        if stype == "text":
            text = str(seg.get("value") or "")
            if text:
                idx = sample.find(text, pos)
                if idx >= 0:
                    pos = idx + len(text)
            continue
        if stype != "capture":
            continue

        value = str(seg.get("value") or "")
        key = str(seg.get("key") or "").strip()
        pattern = str(seg.get("pattern") or "").strip()
        label = f"capture #{i + 1}"
        if not value:
            warnings.append(f"{label}: empty value, skipped")
            continue
        if not NAME_RE.match(key):
            warnings.append(f"{label}: invalid key '{key}', skipped")
            continue
        if not NAME_RE.match(pattern):
            warnings.append(f"{label}: invalid pattern '{pattern}', skipped")
            continue
        if key == "message":
            warnings.append(f"{label}: key 'message' is reserved; skipped")
            continue
        if key.lower() in RESERVED_WORDS:
            warnings.append(
                f"{label}: key '{key}' is a rule-language word; skipped"
            )
            continue
        idx = sample.find(value, pos)
        if idx < 0:
            warnings.append(
                f"{label}: value `{value[:50]}` not found later in the sample, skipped"
            )
            continue
        ranges.append(
            {"key": key, "pattern": pattern, "start": idx, "end": idx + len(value)}
        )
        pos = idx + len(value)
    return ranges, warnings


def ranges_to_segments(sample: str, ranges: list[dict]) -> list[dict]:
    """Inverse of anchor_segments: (sample, ranges) -> ordered text/capture segments.

    Used to snapshot a verified pattern as a teachable example. Raises
    ValidationError when the ranges do not describe a valid decomposition.
    """
    ordered = normalize_ranges(sample, ranges)
    segments: list[dict] = []
    pos = 0
    for r in ordered:
        if r["start"] > pos:
            segments.append({"type": "text", "value": sample[pos:r["start"]]})
        segments.append({
            "type": "capture",
            "key": r["key"],
            "pattern": r["pattern"],
            "value": sample[r["start"]:r["end"]],
        })
        pos = r["end"]
    if pos < len(sample):
        segments.append({"type": "text", "value": sample[pos:]})
    return segments


def _occurrences(sample: str, text: str) -> list[int]:
    """Every offset at which `text` occurs in `sample`, left to right."""
    offsets: list[int] = []
    pos = 0
    while True:
        idx = sample.find(text, pos)
        if idx < 0:
            return offsets
        offsets.append(idx)
        pos = idx + 1


def _free_occurrence(offsets: list[int], length: int,
                     claimed: list[tuple[int, int]]) -> int | None:
    """First occurrence that does not overlap any claimed span."""
    for offset in offsets:
        end = offset + length
        if not any(offset < c_end and c_start < end
                   for c_start, c_end in claimed):
            return offset
    return None


def anchor_fields(sample: str, fields: dict,
                  catalog: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Turn existing Graylog message fields into captures.

    Only scalars whose value text actually appears in the sample become
    captures; each is given the most specific catalog pattern that matches.
    A value that appears several times is anchored on the first occurrence
    that no other field already covers, so a repeated string (an IP that also
    shows up in a hostname, a uid that also appears elsewhere in the line)
    does not get pinned to the wrong spot. Captures are handed out left to
    right, one per field. Returns (ranges, skipped) where skipped explains
    every field left out.
    """
    pending: list[dict] = []
    skipped: list[dict] = []
    for key, value in (fields or {}).items():
        name = str(key)
        if name == "message" or name.startswith("gl2_"):
            continue  # the sample itself / Graylog internals
        if value is None or isinstance(value, bool) or isinstance(value, (list, dict)):
            skipped.append({"key": name, "reason": "not a scalar value"})
            continue
        text = str(value)
        if not text:
            skipped.append({"key": name, "reason": "empty value"})
            continue
        if not NAME_RE.match(name):
            skipped.append({"key": name, "reason": "field name is not a valid capture key"})
            continue
        offsets = _occurrences(sample, text)
        if not offsets:
            skipped.append({"key": name, "reason": "value not found in the sample"})
            continue
        pending.append({"key": name, "text": text, "offsets": offsets,
                        "done": False})

    ranges: list[dict] = []
    claimed: list[tuple[int, int]] = []
    while True:
        # Leftmost free occurrence across all fields wins, so captures come out
        # in sample order; each field is claimed at most once.
        best: tuple[int, dict | None] = (len(sample) + 1, None)
        for entry in pending:
            if entry["done"]:
                continue
            offset = _free_occurrence(entry["offsets"], len(entry["text"]), claimed)
            if offset is None:
                entry["done"] = True  # every occurrence is taken
                skipped.append({
                    "key": entry["key"],
                    "reason": "every occurrence overlaps another field",
                })
                continue
            if offset < best[0]:
                best = (offset, entry)
        if best[1] is None:
            break
        entry = best[1]
        entry["done"] = True
        start = best[0]
        end = start + len(entry["text"])
        if len(entry["offsets"]) > 1:
            skipped.append({
                "key": entry["key"],
                "reason": f"value appears {len(entry['offsets'])} times - "
                          "anchored on the first free occurrence",
            })
        sugg = suggest_patterns(entry["text"], catalog)
        pattern = sugg[0] if sugg else "GREEDYDATA"
        ranges.append({"key": entry["key"], "pattern": pattern,
                       "start": start, "end": end})
        claimed.append((start, end))
    return ranges, skipped


def preview(sample: str, ranges: list[dict], catalog: dict[str, str]) -> dict:
    """Build grok string + match preview. Never raises for catalog/match issues."""
    from grok_compiler import GrokError, UnknownPatternError, check_tokens, match

    result: dict = {
        "grok": "",
        "warnings": [],
        "status": "error",
        "fields": {},
        "compile_error": None,
    }
    key_counts = Counter(r.get("key", "") for r in ranges)
    duplicates = sorted(k for k, n in key_counts.items() if n > 1)
    for key in duplicates:
        result["warnings"].append(f"duplicate key '{key}' - last match wins in Graylog")

    try:
        grok = build_grok(sample, ranges)
    except ValidationError as e:
        result["compile_error"] = str(e)
        return result

    result["grok"] = grok
    result["warnings"].extend(check_tokens(grok, catalog))
    try:
        status, fields = match(grok, sample, catalog)
    except UnknownPatternError as e:
        result["compile_error"] = str(e)
        return result
    except GrokError as e:
        result["compile_error"] = str(e)
        return result

    result["status"] = status
    result["fields"] = fields
    if status == "partial":
        result["warnings"].append(
            "pattern does not cover the whole sample (Graylog may match partially)"
        )
    return result


def failing_captures(sample: str, ranges: list[dict],
                     catalog: dict[str, str]) -> list[dict]:
    """Return captures whose own value does not match their pattern.

    Each item: {key, pattern, value, status}. Used to give the AI precise
    feedback so it can correct pattern choices.
    """
    from grok_compiler import GrokError, match

    bad: list[dict] = []
    for r in ranges:
        try:
            start, end = int(r["start"]), int(r["end"])
            value = sample[start:end]
            pattern = str(r["pattern"])
        except (KeyError, TypeError, ValueError):
            bad.append({"key": r.get("key"), "pattern": None, "value": None,
                        "status": "malformed"})
            continue
        try:
            status, _ = match(f"%{{{pattern}}}", value, catalog)
        except GrokError:
            status = "error"
        if status != "full":
            bad.append({"key": r.get("key"), "pattern": pattern,
                        "value": value, "status": status})
    return bad


# Very broad patterns - deprioritized when suggesting concrete alternatives.
_GENERIC_PATTERNS = {"DATA", "GREEDYDATA", "NOTSPACE", "WORD", "QS"}

# Preference order when several catalog patterns match a value equally well.
# Without this, "specific first" degenerated into alphabetical order and the
# first suggestion for 1.2.3.4 was HOSTNAME instead of IP.
_PATTERN_PRIORITY = (
    # numbers first: a bare digit string must never suggest HOSTNAME
    "POSINT", "NONNEGINT", "INT", "NUMBER", "BASE10NUM", "BASE16NUM",
    "BASE16FLOAT",
    # network identities
    "IP", "IPV4", "IPV6", "UUID", "MAC", "CISCOMAC", "WINDOWSMAC", "COMMONMAC",
    # typed values
    "LOGLEVEL", "TIMESTAMP_ISO8601", "DATESTAMP_RFC2822", "DATESTAMP_RFC822",
    "HTTPDATE", "SYSLOGTIMESTAMP", "DATESTAMP", "DATESTAMP_EVENTLOG",
    "DATE", "DATE_US", "DATE_EU",
    # URIs / paths
    "URI", "URIPATHPARAM", "URIPATH", "UNIXPATH", "WINPATH", "PATH",
    # hosts / composite line patterns
    "HOSTNAME", "IPORHOST", "HOSTPORT", "SYSLOGHOST", "URIHOST",
    "SYSLOGBASE", "SYSLOGPROG", "COMMONAPACHELOG", "COMBINEDAPACHELOG",
    # permissive free text (still better than a catch-all)
    "WORD", "USERNAME", "USER", "PROG",
)


def _pattern_rank(name: str) -> tuple[int, int]:
    """Sort key making specific patterns come first, generic ones last."""
    if name in _GENERIC_PATTERNS:
        return (2, 0)
    try:
        return (0, _PATTERN_PRIORITY.index(name))
    except ValueError:
        return (1, 0)  # unlisted but not generic: alphabetical among themselves


def suggest_patterns(value: str, catalog: dict[str, str],
                     limit: int = 15) -> list[str]:
    """Catalog patterns that fully match `value`, most specific first.

    Used to give the AI a verified shortlist instead of free choice.
    """
    from grok_compiler import GrokError, match

    hits: list[str] = []
    for name in catalog:
        try:
            status, _ = match(f"%{{{name}}}", value, catalog)
        except GrokError:
            continue
        if status == "full":
            hits.append(name)
    hits.sort(key=lambda n: (_pattern_rank(n), n.lower()))
    return hits[:limit]


def is_coarse(sample: str, ranges: list[dict]) -> bool:
    """True when a single generic capture swallows (most of) the whole sample.

    A pattern like `%{GREEDYDATA:log}` "matches" but is useless to Graylog.
    """
    if len(ranges) != 1 or not sample:
        return False
    r = ranges[0]
    try:
        start, end = int(r["start"]), int(r["end"])
    except (KeyError, TypeError, ValueError):
        return False
    pattern = str(r.get("pattern") or "")
    if pattern not in _GENERIC_PATTERNS:
        return False
    return start <= 0 and end >= len(sample)


def autofix_patterns(sample: str, ranges: list[dict],
                     catalog: dict[str, str]) -> tuple[list[dict], list[dict]]:
    """Deterministically replace patterns that do not match their value.

    For each capture whose own value fails `match`, substitute the most
    specific catalog pattern that does match. Returns (new_ranges, changes)
    where changes is a list of {key, from, to}. Never drops captures.
    """
    from grok_compiler import GrokError, match

    fixed: list[dict] = []
    changes: list[dict] = []
    for r in ranges:
        r2 = dict(r)
        value = ""
        try:
            value = sample[int(r["start"]):int(r["end"])]
            status, _ = match(f"%{{{r['pattern']}}}", value, catalog)
        except (KeyError, TypeError, ValueError, GrokError):
            status = "error"
        if status != "full":
            sugg = suggest_patterns(value, catalog) if value else []
            if sugg and sugg[0] != r.get("pattern"):
                r2["pattern"] = sugg[0]
                changes.append({"key": r.get("key"), "from": r.get("pattern"),
                                "to": sugg[0]})
        fixed.append(r2)
    return fixed, changes


def build_all(sample: str, ranges: list[dict], config: dict,
              catalog: dict[str, str]) -> dict:
    """Full render: preview + rule source. Raises ValidationError if rule is impossible."""
    prev = preview(sample, ranges, catalog)
    if prev["compile_error"] and prev["grok"] == "":
        raise ValidationError(prev["compile_error"])
    prev["rule"] = build_rule(prev["grok"], config)
    return prev
