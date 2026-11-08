"""AI Graylog Pipeline Rule Builder - Flask application."""

from __future__ import annotations

import difflib
import json
import os
import re
import threading
import time

from dotenv import load_dotenv
from flask import Flask, jsonify, render_template, request

import grok_catalog
import grok_compiler
import examples
import llm
import rule_builder
import rule_matcher
from graylog_client import GraylogClient, GraylogError

load_dotenv()

app = Flask(__name__)
app.json.sort_keys = False  # keep the response key order we build

MAX_SAMPLE = 8192


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def ollama_config() -> dict:
    return {
        "base_url": env("OLLAMA_BASE_URL", "http://localhost:11434"),
        "model": env("OLLAMA_MODEL", "qwen2.5-coder:7b"),
        "timeout": float(env("OLLAMA_TIMEOUT", "300")),
    }


def examples_in_prompt() -> int:
    """How many learned examples to inject into the model prompt (0 = off)."""
    try:
        return max(0, int(env("EXAMPLES_IN_PROMPT", "3")))
    except ValueError:
        return 3


def graylog_client() -> tuple[GraylogClient | None, str | None]:
    """Returns (client, error). Exactly one side is set."""
    base = env("GRAYLOG_URL")
    token = env("GRAYLOG_TOKEN")
    if not base:
        return None, "Graylog not configured (set GRAYLOG_URL in .env)"
    if not token:
        return None, "Graylog not configured (set GRAYLOG_TOKEN in .env)"
    verify = env("GRAYLOG_VERIFY_SSL", "true").lower() not in ("0", "false", "no")
    return GraylogClient(base, token, verify_ssl=verify), None


# Field names change rarely and /system/fields only reads indexer mapping
# metadata, so cache them in-process. The list is offered to the model so it
# reuses existing field names instead of inventing duplicates.
_FIELDS_CACHE: dict = {"at": 0.0, "names": None}
_FIELDS_TTL = 3600.0
# The dev server serves requests on several threads; keep the cache consistent.
_FIELDS_LOCK = threading.Lock()
# Names that are internal/Graylog-managed and make poor capture keys.
_INTERNAL_FIELDS = {
    "message", "full_message", "fields", "streams", "source_streams",
    "origin_context", "scores", "key", "key_tuple", "group_by_fields",
    "timerange_start", "timerange_end",
}


def field_hints_enabled() -> bool:
    return env("GRAYLOG_FIELD_HINTS", "true").lower() not in ("0", "false", "no")


def field_hint_limit() -> int:
    """Cap on how many field names are injected into the model prompt."""
    try:
        return max(0, int(env("GRAYLOG_FIELD_HINTS_LIMIT", "300")))
    except ValueError:
        return 300


def graylog_field_names(force: bool = False) -> list[str]:
    """All existing Graylog field names, cached. Returns [] when unavailable.

    Reads the indexer mapping (cheap metadata), never the message data. If the
    unlimited response is rejected by a huge deployment we retry with a bounded
    limit, then fall back to the last known list.
    """
    now = time.time()
    cached = _FIELDS_CACHE["names"]
    if not force and cached is not None and now - _FIELDS_CACHE["at"] < _FIELDS_TTL:
        return cached
    client, _ = graylog_client()
    if client is None:
        return cached or []
    try:
        names = client.list_fields(limit=0)
    except GraylogError:
        try:
            names = client.list_fields(limit=field_hint_limit() or 300)
        except GraylogError:
            return cached or []
    with _FIELDS_LOCK:
        _FIELDS_CACHE.update({"at": now, "names": names})
    return names


def field_names_for_prompt() -> list[str]:
    """Filtered, capped field names to hand to the model as naming hints."""
    if not field_hints_enabled():
        return []
    names = [
        n for n in graylog_field_names()
        if n and not n.startswith("gl2_") and n not in _INTERNAL_FIELDS
    ]
    limit = field_hint_limit()
    return names[:limit] if limit else names


def _merge_suggested(suggested: dict, meta: dict) -> None:
    """Keep the last non-empty AI label/description produced."""
    if meta.get("name"):
        suggested["name"] = str(meta["name"]).strip()
    if meta.get("description"):
        suggested["description"] = str(meta["description"]).strip()


def sample_from_payload() -> tuple[str | None, str | None]:
    data = request.get_json(silent=True) or {}
    sample = data.get("sample")
    if not isinstance(sample, str) or not sample.strip():
        return None, "sample string is required"
    if len(sample) > MAX_SAMPLE:
        return None, f"sample longer than {MAX_SAMPLE} characters"
    return sample, None


def config_from_payload() -> tuple[dict, str | None]:
    data = request.get_json(silent=True) or {}
    config = data.get("config")
    if config is None:
        config = {}
    if not isinstance(config, dict):
        return {}, "config must be an object"
    return config, None


# ---------------------------------------------------------------- pages
@app.get("/")
def index():
    return render_template("index.html", default_model=env("OLLAMA_MODEL", ""))


# ---------------------------------------------------------------- health
@app.get("/api/health")
def health():
    cfg = ollama_config()
    ollama = {"ok": False, "error": "not reachable"}
    try:
        llm.list_models(cfg["base_url"], timeout=5)
        ollama = {"ok": True}
    except llm.LLMError as e:
        ollama = {"ok": False, "error": str(e)}

    client, err = graylog_client()
    if client is None:
        graylog = {"ok": False, "error": err, "configured": False}
    else:
        result = client.health()
        graylog = {"ok": result["ok"], "error": result.get("error"),
                   "configured": True}
    return jsonify({"ollama": ollama, "graylog": graylog,
                    "default_model": cfg["model"]})


@app.get("/api/ollama/models")
def ollama_models():
    cfg = ollama_config()
    try:
        models = llm.list_models(cfg["base_url"])
    except llm.LLMError as e:
        return jsonify({"error": str(e), "models": []}), 502
    return jsonify({"models": models, "default": cfg["model"]})


# ---------------------------------------------------------------- patterns
@app.get("/api/patterns")
def patterns():
    cat = grok_catalog.load_catalog()
    return jsonify({
        "categories": cat.grouped(),
        "names": cat.names,
        "synced": cat.synced_names,
    })


@app.post("/api/patterns/sync")
def patterns_sync():
    client, err = graylog_client()
    if client is None:
        return jsonify({"error": err}), 400
    try:
        found = client.list_grok_patterns()
    except GraylogError as e:
        return jsonify({"error": str(e)}), 502
    count = grok_catalog.save_synced(
        [{"name": n, "pattern": p} for n, p in found.items()]
    )
    return jsonify({"count": count})


@app.get("/api/graylog/fields")
def graylog_fields():
    client, err = graylog_client()
    if client is None:
        return jsonify({"error": err}), 400
    force = request.args.get("refresh", "").lower() in ("1", "true", "yes")
    names = graylog_field_names(force=force)
    return jsonify({"fields": names, "count": len(names)})


# ---------------------------------------------------------------- AI
_STATUS_RANK = {"error": 0, "none": 1, "partial": 2, "full": 3}


def pattern_status(sample: str, ranges: list[dict], catalog: dict[str, str]) -> str:
    """best-effort compile+match status for a set of captures."""
    if not ranges:
        return "none"
    try:
        grok = rule_builder.build_grok(sample, ranges)
        status, _ = grok_compiler.match(grok, sample, catalog)
    except (rule_builder.ValidationError, grok_compiler.GrokError):
        return "error"
    return status


def capture_score(sample: str, ranges: list[dict],
                  catalog: dict[str, str]) -> tuple[int, int]:
    """(match rank, number of captures whose own pattern matches). Higher is better."""
    if not ranges:
        return (0, 0)
    status = pattern_status(sample, ranges, catalog)
    matched = len(ranges) - len(rule_builder.failing_captures(sample, ranges, catalog))
    return (_STATUS_RANK.get(status, 0), matched)


def coarse_feedback(segments: list[dict] | None = None) -> str:
    msg = (
        "Your previous answer put the entire log line into a single capture. "
        "That is useless for Graylog. Decompose the line into many meaningful "
        "fields (timestamps, log levels, pids, IPs, ports, quoted requests, "
        "paths, status codes, sizes, versions...), keeping the literal "
        "separators between them as text segments. Use specific patterns, not "
        "GREEDYDATA for the whole line."
    )
    if segments is not None:
        msg += ("\nYour previous segments were:\n"
                + json.dumps({"segments": segments}, ensure_ascii=False))
    msg += ('\nReply with ONLY the corrected JSON: {"segments": [...]}')
    return msg


def repair_feedback(status: str, bad: list[dict], catalog: dict[str, str],
                    segments: list[dict] | None = None) -> str:
    lines = [
        f"Your previous segments did not produce a matching grok (local match "
        f"status: {status}). The segment structure is fine; only these pattern "
        f"names are wrong:",
    ]
    for b in bad:
        line = (f"- key={b['key']!r} value={b['value']!r} "
                f"pattern={b['pattern']!r} -> {b['status']}")
        if b.get("value"):
            # Ranked and capped: a long tail of near-misses only confuses the
            # model about which pattern to pick.
            sugg = rule_builder.suggest_patterns(b["value"], catalog, limit=8)
            if sugg:
                line += f". Patterns that DO match this value: {', '.join(sugg)}"
        lines.append(line)
    if segments is not None:
        lines.append(
            "Here are your previous segments verbatim:\n"
            + json.dumps({"segments": segments}, ensure_ascii=False)
        )
    lines.append(
        "Return the SAME segments in the SAME order with the SAME keys, values "
        "and number of captures - do NOT drop, merge or re-split any capture. "
        "Change ONLY the pattern field of the captures listed above. Reply with "
        'ONLY corrected JSON: {"segments": [...]}'
    )
    return "\n".join(lines)


def enrich_feedback(segments: list[dict] | None = None) -> str:
    """Feedback for the enriching pass: add missing fields, keep every capture."""
    lines = [
        "Your previous segments produced a matching grok, but the pattern may "
        "have left meaningful structured fields as literal text. Keep EVERY "
        "existing capture exactly as it is (same keys, values and order) and ADD "
        "new captures for any structured fields still present in the line - for "
        "example key: value pairs (client, server, request, upstream, host) and "
        "method, path, HTTP version, status code, bytes, ports, versions.",
        "Only add captures whose values are exact, non-empty substrings of the "
        "line, in left-to-right order. Do NOT drop, merge, rename or re-split "
        "any existing capture. If nothing structured is missing, return the "
        "previous segments unchanged.",
    ]
    if segments is not None:
        lines.append(
            "Here are your previous segments verbatim:\n"
            + json.dumps({"segments": segments}, ensure_ascii=False)
        )
    lines.append('Reply with ONLY the JSON: {"segments": [...]}')
    return "\n".join(lines)


_GUARD_CONTROL_CHARS = {"\b": "\\b", "\f": "\\f", "\n": "\\n",
                        "\r": "\\r", "\t": "\\t"}


def _recover_guard(text: str) -> str:
    """Reverse JSON's decoding of single-backslash regex escapes.

    Models sometimes write `\b` (word boundary) as a single backslash inside
    the JSON string, which JSON decoding turns into a literal backspace byte.
    Re-encode those control chars back into regex escapes so the guard can
    still be validated.
    """
    return "".join(_GUARD_CONTROL_CHARS.get(ch, ch) for ch in text)


# Generic regex token per grok pattern, used when a captured value or a
# structural guard has to be rebuilt without the sample's per-message data.
_GUARD_TOKENS = {
    "IP": r"\d{1,3}(?:\.\d{1,3}){3}",
    "IPV4": r"\d{1,3}(?:\.\d{1,3}){3}",
    "IPV6": r"[0-9A-Fa-f:]+",
    "IPORHOST": r"\S+",
    "HOSTNAME": r"[A-Za-z0-9._-]+",
    "HOSTPORT": r"\S+",
    "INT": r"\d+",
    "POSINT": r"\d+",
    "NONNEGINT": r"\d+",
    "BASE10NUM": r"-?\d+(?:\.\d+)?",
    "NUMBER": r"-?\d+(?:\.\d+)?",
    "WORD": r"\w+",
    "NOTSPACE": r"\S+",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "QUOTEDSTRING": r'"[^"]*"',
    "UUID": r"[0-9A-Fa-f-]+",
    "TIMESTAMP_ISO8601": r"\S+(?: \S+)?",
    "HTTPDATE": r"\S+ \S+",
    "SYSLOGTIMESTAMP": r"\S+ \d+ \d+:\d+:\d+",
    "DATE_US": r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
    "DATE_EU": r"\d{1,2}[/-]\d{1,2}[/-]\d{2,4}",
    "PATH": r"\S+",
    "URI": r"\S+",
    "URIPATH": r"\S+",
    "URIPARAM": r"\S*",
    "URIPATHPARAM": r"\S+",
    "LOGLEVEL": r"\w+",
    "USER": r"\S+",
    "USERNAME": r"\S+",
    "EMAILADDRESS": r"\S+",
}

_GUARD_MONTH_WORD = re.compile(
    r"(?<!\w)(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?=\s+\d)")
_GUARD_MONTH_SLASH = re.compile(
    r"(?<=\d[/-])(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)(?=[/-]\d)")
# key=value / key: value pairs whose value is a plain literal (not a regex).
_GUARD_KV = re.compile(
    r"(?<![\w\\])([A-Za-z_][\w.-]*)(\s*[=:]\s*)"
    r"(\"[^\"]*\"|[A-Za-z0-9][A-Za-z0-9_.-]*)")


def _guard_token(pattern: str, value: str = "") -> str:
    """A generic, Java-compatible regex for one capture pattern."""
    token = _GUARD_TOKENS.get(str(pattern or "").strip().upper(), r"\S+")
    if any(ch.isspace() for ch in value) and not any(
            marker in token for marker in (r"\s", ".*", " ")):
        return r".+?"
    return token


def _replace_guard_literal(guard: str, value: str, token: str) -> tuple[str, bool]:
    """Replace one literal sample value inside a regex with a generic token."""
    needles = {value, re.escape(value)}
    for needle in sorted(needles, key=len, reverse=True):
        if re.fullmatch(r"[A-Za-z0-9_]+", value):
            # Allow the value to be wrapped in \b ... \b as models often do.
            pattern = re.compile(
                rf"(?:(?<=\\b)|(?<!\w)){re.escape(needle)}"
                rf"(?:(?=\\b)|(?!\w))")
        else:
            pattern = re.compile(re.escape(needle))
        guard, count = pattern.subn(lambda _m: token, guard)
        if count:
            return guard, True
    return guard, False


def _replace_captured_values(sample: str, guard: str,
                             ranges: list[dict] | None) -> tuple[str, list[str]]:
    """Remove every captured per-message value from the guard."""
    notes: list[str] = []
    for r in ranges or []:
        if not isinstance(r, dict):
            continue
        try:
            value = sample[int(r["start"]):int(r["end"])]
        except (KeyError, TypeError, ValueError):
            continue
        if len(value) < 2:
            continue
        token = _guard_token(str(r.get("pattern") or ""), value)
        guard, changed = _replace_guard_literal(guard, value, token)
        if changed:
            notes.append(f"replaced captured {r.get('pattern') or 'value'} "
                         f"'{value}' with {token}")
    return guard, notes


def _replace_kv_values(guard: str) -> tuple[str, bool]:
    """Generalize literal values in key=value / key: value pairs."""
    def repl(match: re.Match) -> str:
        key, sep, value = match.groups()
        if value.startswith('"') and value.endswith('"'):
            token = '"[^"]*"'
        elif re.fullmatch(r"\d+", value):
            token = r"\d+"
        elif re.fullmatch(r"[A-Za-z0-9_]+", value):
            token = r"\w+"
        else:
            token = r"\S+"
        return key + sep + token

    new, count = _GUARD_KV.subn(repl, guard)
    return new, count > 0


def _replace_months(guard: str) -> tuple[str, bool]:
    """Make date months generic (a guard for January must match any month)."""
    guard, count = _GUARD_MONTH_WORD.subn("[A-Za-z]{3}", guard)
    guard, count2 = _GUARD_MONTH_SLASH.subn("[A-Za-z]{3}", guard)
    return guard, bool(count or count2)


_GUARD_PATH_CHARS = set(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
    "._~%!&',;=:@-?#"
)
_GUARD_PATH_ESCAPABLE = set("._~%!&',;=:@-?#/")


def _replace_paths(guard: str) -> tuple[str, int]:
    """Replace literal URL/file paths with \\S+ (a path is message data).

    Scans the regex so escapes and character classes are left alone, and only
    treats `/` as a path start at a token boundary (so `and/or` stays intact).
    """
    out: list[str] = []
    count = 0
    i = 0
    in_class = False
    while i < len(guard):
        ch = guard[i]
        if ch == "\\":
            out.append(guard[i:i + 2])
            i += 2
            continue
        if in_class:
            out.append(ch)
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append(ch)
            i += 1
            continue
        if ch == "{":
            end = guard.find("}", i)
            if end >= 0:
                out.append(guard[i:end + 1])
                i = end + 1
                continue
        if ch == "/" and (i == 0 or not (guard[i - 1].isalnum()
                                          or guard[i - 1] in "_-")):
            end = i + 1
            while end < len(guard):
                if (guard[end] == "\\" and end + 1 < len(guard)
                        and guard[end + 1] in _GUARD_PATH_ESCAPABLE):
                    end += 2
                    continue
                if guard[end] in _GUARD_PATH_CHARS:
                    end += 1
                    continue
                break
            if end > i + 1:
                out.append(r"\S+")
                count += 1
                i = end
                continue
        out.append(ch)
        i += 1
    return "".join(out), count


def _replace_long_ids(guard: str) -> tuple[str, int]:
    """Replace long alphanumeric tokens (session/request IDs) with \\w+.

    Scans the regex so character classes such as [A-Za-z0-9._-] and escapes
    are never touched.
    """
    out: list[str] = []
    count = 0
    i = 0
    in_class = False
    while i < len(guard):
        ch = guard[i]
        if ch == "\\":
            out.append(guard[i:i + 2])
            i += 2
            continue
        if in_class:
            out.append(ch)
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append(ch)
            i += 1
            continue
        if ch == "{":
            end = guard.find("}", i)
            if end >= 0:
                out.append(guard[i:end + 1])
                i = end + 1
                continue
        if ch.isalnum() or ch in "_-":
            end = i
            while end < len(guard) and (guard[end].isalnum() or guard[end] in "_-"):
                end += 1
            token = guard[i:end]
            if (len(token) >= 8 and any(c.isdigit() for c in token)
                    and any(c.isalpha() for c in token)):
                out.append(r"\w+")
                count += 1
            else:
                out.append(token)
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out), count


def _rewrite_literal_digits(guard: str) -> tuple[str, list[str]]:
    """Replace literal digit runs (ports, PIDs, counts) with \\d+.

    Digits inside escapes, character classes, quantifiers and named groups are
    left alone, so \\d{1,3} and (?P<g1>...) survive unchanged.
    """
    out: list[str] = []
    runs: list[str] = []
    i = 0
    in_class = False
    while i < len(guard):
        ch = guard[i]
        if ch == "\\":
            out.append(guard[i:i + 2])
            i += 2
            continue
        if in_class:
            out.append(ch)
            if ch == "]":
                in_class = False
            i += 1
            continue
        if ch == "[":
            in_class = True
            out.append(ch)
            i += 1
            continue
        if ch == "{":
            end = guard.find("}", i)
            if end >= 0:
                out.append(guard[i:end + 1])
                i = end + 1
                continue
        if ch == "(" and (guard.startswith("(?P<", i) or guard.startswith("(?<", i)):
            end = guard.find(">", i)
            if end >= 0:
                out.append(guard[i:end + 1])
                i = end + 1
                continue
        if ch.isdigit():
            end = i
            while end < len(guard) and guard[end].isdigit():
                end += 1
            runs.append(guard[i:end])
            out.append(r"\d+")
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out), runs


def _guard_has_specifics(guard: str) -> bool:
    """True when a guard still contains literal sample data."""
    _rewritten, digit_runs = _rewrite_literal_digits(guard)
    if digit_runs:
        return True
    _ids, id_count = _replace_long_ids(guard)
    return id_count > 0


def structural_guard(sample: str, ranges: list[dict] | None) -> str:
    """Build a generic guard from the sample's captures and literal gaps.

    The result matches the sample by construction and carries no per-message
    values: each capture becomes a generic token for its grok pattern and the
    gaps between captures stay literal.
    """
    def start_of(r: dict) -> int:
        try:
            return int(r.get("start", 0))
        except (TypeError, ValueError):
            return 0

    ordered = sorted(
        (r for r in (ranges or []) if isinstance(r, dict)),
        key=start_of,
    )
    parts: list[str] = []
    pos = 0
    for r in ordered:
        try:
            start = int(r["start"])
            end = int(r["end"])
        except (KeyError, TypeError, ValueError):
            continue
        if start < pos or end <= start or end > len(sample):
            continue
        parts.append(re.escape(sample[pos:start]))
        parts.append(_guard_token(str(r.get("pattern") or ""), sample[start:end]))
        pos = end
    parts.append(re.escape(sample[pos:]))
    guard = "".join(parts)
    # A value the model failed to capture still sits in a literal gap; strip
    # the same per-message shapes there too.
    guard, _paths = _replace_paths(guard)
    guard, _changed = _replace_months(guard)
    guard, _ids = _replace_long_ids(guard)
    guard, _digits = _rewrite_literal_digits(guard)
    return guard


def generalize_guard(sample: str, candidate,
                     ranges: list[dict] | None = None) -> tuple[str, list[str]]:
    """Make a model-proposed guard independent of this one message.

    Replaces captured values, key=value payloads, month names, long IDs and
    bare digit runs with generic classes. When the result still looks tied to
    the sample (or no longer matches it), falls back to a structural guard
    built from the verified captures.
    """
    original = _recover_guard(str(candidate or "")).strip()
    if not original:
        return "", []

    guard = original
    notes: list[str] = []

    guard, value_notes = _replace_captured_values(sample, guard, ranges)
    notes.extend(value_notes)

    guard, changed = _replace_kv_values(guard)
    if changed:
        notes.append("replaced literal key=value payloads with generic values")

    guard, path_count = _replace_paths(guard)
    if path_count:
        notes.append("replaced literal paths with \\S+")

    guard, changed = _replace_months(guard)
    if changed:
        notes.append("replaced literal month names with [A-Za-z]{3}")

    guard, id_count = _replace_long_ids(guard)
    if id_count:
        notes.append("replaced literal IDs with \\w+")

    guard, digit_runs = _rewrite_literal_digits(guard)
    if digit_runs:
        notes.append("replaced literal digits (ports, PIDs, counts) with \\d+")

    if _guard_has_specifics(guard) and ranges:
        rebuilt = structural_guard(sample, ranges)
        if rebuilt:
            guard = rebuilt
            notes.append("used a structural guard built from the captures")

    try:
        matches = re.compile(guard).search(sample) is not None
    except re.error:
        matches = False
    if not matches and ranges:
        rebuilt = structural_guard(sample, ranges)
        if rebuilt:
            guard = rebuilt
            notes.append("model guard did not match the sample; used a "
                         "structural guard")

    return guard, list(dict.fromkeys(notes))


def guard_for_sample(sample: str, candidate) -> tuple[str, str]:
    """Validate a model-proposed message-matching regex.

    Returns (regex_or_empty, warning_or_empty). The guard must compile, must
    actually match the sample (otherwise the rule would never fire on the line
    it was built from) and must not match every message (a bare `.*` guard is
    no guard).
    """
    candidate = _recover_guard(str(candidate or "")).strip()
    if not candidate:
        return "", ""
    try:
        compiled = re.compile(candidate)
    except re.error:
        return "", (f"model-suggested guard '{candidate}' is not a valid "
                    "regex; rule will run on every message")
    if compiled.search(""):
        return "", (f"model-suggested guard '{candidate}' matches every "
                    "message; rule will run on every message")
    if not compiled.search(sample):
        return "", (f"model-suggested guard '{candidate}' does not match the "
                    "sample; rule will run on every message")
    return candidate, ""


@app.post("/api/generate")
def generate():
    sample, err = sample_from_payload()
    if err:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    cfg = ollama_config()
    model = (data.get("model") or cfg["model"]).strip() or cfg["model"]
    # Repair rounds: user picks 0..N extra model calls, each one fed back the
    # exact failing captures, stopping early once the pattern fully matches.
    try:
        max_repairs = int(data.get("max_repairs", 0))
    except (TypeError, ValueError):
        max_repairs = 0
    if "max_repairs" not in data and data.get("repair"):
        max_repairs = 1  # backward compat with the old checkbox
    max_repairs = max(0, min(max_repairs, 5))
    enrich = bool(data.get("enrich"))
    context = str(data.get("context") or "").strip()

    catalog = grok_catalog.load_catalog()
    catalog_map = catalog.by_name
    prompt_examples = examples.select_examples(sample, examples_in_prompt())
    field_hints = field_names_for_prompt()
    suggested: dict = {}
    guard_candidate: str = ""
    try:
        segments, meta = llm.generate_segments(
            cfg["base_url"], model, sample, catalog.names, timeout=cfg["timeout"],
            context=context, examples=prompt_examples, field_names=field_hints,
        )
        _merge_suggested(suggested, meta)
        guard_candidate = meta.get("guard") or guard_candidate
    except llm.LLMError as e:
        return jsonify({"error": str(e), "model": model}), 502

    ranges, warnings = rule_builder.anchor_segments(sample, segments)
    if not ranges:
        return jsonify({
            "error": "model returned segments that could not be located in the sample",
            "warnings": warnings,
            "raw": meta.get("raw", ""),
            "model": model,
        }), 422

    attempts = meta.get("attempts", 1)
    status = pattern_status(sample, ranges, catalog_map)
    repaired = False
    enriched = False
    autofixed: list[dict] = []
    coarse = rule_builder.is_coarse(sample, ranges)

    # Verification rounds. Each round: if the pattern does not fully match,
    # hand the model the exact failing captures; if it "matches" but is a
    # single whole-line GREEDYDATA, ask it to decompose instead. Rounds keep
    # going until a full non-coarse match or the user's chosen count is spent.
    # A round's answer is only accepted if it keeps every previous capture
    # (unless decomposing a coarse capture) and scores strictly better, so
    # repeated calls can only build on - never lose - what was already right.
    for _ in range(max_repairs):
        if status == "full" and not coarse:
            break
        bad = rule_builder.failing_captures(sample, ranges, catalog_map)
        original_keys = {r["key"] for r in ranges}
        feedback = (coarse_feedback(segments) if (coarse and status == "full")
                    else repair_feedback(status, bad, catalog_map, segments))
        try:
            segments2, meta2 = llm.generate_segments(
                cfg["base_url"], model, sample, catalog.names,
                timeout=cfg["timeout"], feedback=feedback, context=context,
                examples=prompt_examples, field_names=field_hints,
            )
        except llm.LLMError:
            break  # keep the current answer if a repair call fails
        attempts += meta2.get("attempts", 1)
        ranges2, warnings2 = rule_builder.anchor_segments(sample, segments2)
        if not ranges2:
            continue
        keeps_all = {r["key"] for r in ranges2} >= original_keys
        score_up = (capture_score(sample, ranges2, catalog_map) >
                    capture_score(sample, ranges, catalog_map))
        if coarse:
            # replacing one giant capture with a real decomposition wins
            accept = len(ranges2) > len(ranges) and not rule_builder.is_coarse(
                sample, ranges2)
        else:
            accept = keeps_all and score_up
        if accept:
            ranges, warnings = ranges2, warnings2
            segments = segments2
            status = pattern_status(sample, ranges2, catalog_map)
            _merge_suggested(suggested, meta2)
            guard_candidate = meta2.get("guard") or guard_candidate
            repaired = True
            coarse = rule_builder.is_coarse(sample, ranges)
        # a rejected round just means the model had nothing better - keep
        # trying with the same feedback while rounds remain

    # Enriching mode: exactly ONE automatic extra pass when the pattern already
    # matches fully but may have left structured fields as literal text. Capped
    # at one round by design, so it can never loop forever. The answer is kept
    # only if it keeps every existing capture and adds at least one matching one.
    if enrich and status == "full" and not rule_builder.is_coarse(sample, ranges):
        original_keys = {r["key"] for r in ranges}
        try:
            segments3, meta3 = llm.generate_segments(
                cfg["base_url"], model, sample, catalog.names,
                timeout=cfg["timeout"], feedback=enrich_feedback(segments),
                context=context, examples=prompt_examples,
                field_names=field_hints,
            )
            attempts += meta3.get("attempts", 1)
            ranges3, warnings3 = rule_builder.anchor_segments(sample, segments3)
            if ranges3:
                keeps_all = {r["key"] for r in ranges3} >= original_keys
                score_up = (capture_score(sample, ranges3, catalog_map) >
                            capture_score(sample, ranges, catalog_map))
                if keeps_all and score_up:
                    ranges, warnings = ranges3, warnings3
                    status = pattern_status(sample, ranges3, catalog_map)
                    _merge_suggested(suggested, meta3)
                    guard_candidate = meta3.get("guard") or guard_candidate
                    enriched = True
        except llm.LLMError:
            pass  # keep the current answer if the enrich call fails

    # Deterministic last resort: fix any still-failing pattern locally from the
    # verified catalog shortlist so a bad model round cannot lose captures.
    if status != "full":
        fixed, changes = rule_builder.autofix_patterns(sample, ranges, catalog_map)
        if changes and capture_score(sample, fixed, catalog_map) > \
                capture_score(sample, ranges, catalog_map):
            ranges = fixed
            status = pattern_status(sample, fixed, catalog_map)
            autofixed = changes

    # Every autofix change is reported: assigning `warnings` inside the loop
    # kept only the last change and dropped the warnings added before it.
    autofix_notes = [
        f"auto-corrected {c['key']}: {c['from']} -> {c['to']}" for c in autofixed
    ]
    if rule_builder.is_coarse(sample, ranges):
        autofix_notes.append(
            "the model captured the whole line as one field - try Generate "
            "again or split the text into captures manually"
        )
    if status != "full":
        autofix_notes.append(
            "generated pattern does not fully match the sample - review the "
            "captures and their patterns"
        )
    warnings = list(warnings) + autofix_notes

    # The model's guard must describe the line's format, not the values in this
    # one message. Generalize it before validation so a port, IP, timestamp or
    # ID can never become part of the rule's `when` condition.
    guard, guard_notes = generalize_guard(sample, guard_candidate, ranges)
    if guard_notes:
        warnings = list(warnings) + [
            "guard made generic: " + "; ".join(guard_notes)
        ]
    guard, guard_warning = guard_for_sample(sample, guard)
    if guard_warning:
        warnings = list(warnings) + [guard_warning]

    return jsonify({"ranges": ranges, "warnings": warnings, "model": model,
                    "attempts": attempts, "status": status, "repaired": repaired,
                    "enriched": enriched, "autofixed": autofixed,
                    "examples_used": len(prompt_examples),
                    "suggested_name": suggested.get("name", ""),
                    "suggested_description": suggested.get("description", ""),
                    "guard": guard})


# ---------------------------------------------------------------- render / validate
@app.post("/api/render")
def render():
    sample, err = sample_from_payload()
    if err:
        return jsonify({"error": err}), 400
    config, err = config_from_payload()
    if err:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    ranges = data.get("ranges") or []
    if not isinstance(ranges, list):
        return jsonify({"error": "ranges must be a list"}), 400

    catalog = grok_catalog.load_catalog().by_name
    try:
        out = rule_builder.build_all(sample, ranges, config, catalog)
    except rule_builder.ValidationError as e:
        return jsonify({"error": str(e)}), 422
    return jsonify(out)


@app.post("/api/graylog/grok-test")
def graylog_grok_test():
    sample, err = sample_from_payload()
    if err:
        return jsonify({"error": err}), 400
    client, gerr = graylog_client()
    if client is None:
        return jsonify({"error": gerr}), 400
    data = request.get_json(silent=True) or {}
    ranges = data.get("ranges") or []
    catalog = grok_catalog.load_catalog().by_name
    try:
        grok_str = rule_builder.build_grok(sample, ranges)
    except rule_builder.ValidationError as e:
        return jsonify({"error": str(e)}), 422
    try:
        result = client.test_grok(grok_str, sample)
        return jsonify({"result": result, "grok": grok_str, "source": "graylog"})
    except GraylogError as e:
        try:
            from grok_compiler import match, GrokError
            status, fields = match(grok_str, sample, catalog)
            return jsonify({"result": {"status": status, "matches": fields}, "grok": grok_str, "source": "local", "warning": f"Graylog remote test failed ({e}); using local test"})
        except Exception:
            return jsonify({"error": str(e)}), 502


# ---------------------------------------------------------------- rules
def _rule_payload() -> tuple[dict | None, dict | None, str | None, int]:
    sample, err = sample_from_payload()
    if err:
        return None, None, err, 400
    config, err = config_from_payload()
    if err:
        return None, None, err, 400
    data = request.get_json(silent=True) or {}
    ranges = data.get("ranges") or []
    if not isinstance(ranges, list):
        return None, None, "ranges must be a list", 400
    catalog = grok_catalog.load_catalog().by_name
    try:
        out = rule_builder.build_all(sample, ranges, config, catalog)
    except rule_builder.ValidationError as e:
        return None, None, str(e), 422
    if out.get("compile_error"):
        return None, None, f"cannot push: {out['compile_error']}", 422
    # The preview travels with the rule so callers can tell a rule that really
    # reproduces the sample (`full`) from one that only looks plausible.
    return out, config, None, 0


def _rule_from_payload() -> tuple[dict | None, str | None, int]:
    out, _cfg, err, code = _rule_payload()
    return out, err, code


@app.post("/api/captures/from-fields")
def captures_from_fields():
    sample, err = sample_from_payload()
    if err:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    fields = data.get("fields")
    if not isinstance(fields, dict):
        return jsonify({"error": "fields must be an object"}), 400
    catalog = grok_catalog.load_catalog().by_name
    ranges, skipped = rule_builder.anchor_fields(sample, fields, catalog)
    return jsonify({"ranges": ranges, "skipped": skipped})


@app.post("/api/rule/parse")
def rule_parse():
    out, err, code = _rule_from_payload()
    if err:
        return jsonify({"error": err}), code
    client, gerr = graylog_client()
    if client is None:
        return jsonify({"error": gerr}), 400
    try:
        parsed = client.parse_rule(out["rule"])
    except GraylogError as e:
        return jsonify({"error": str(e), "rule": out["rule"]}), 502
    return jsonify({"ok": True, "parsed": parsed, "rule": out["rule"]})


def unique_rule_title(existing_titles, title):
    """Pick a rule title that is not already used by an existing pipeline rule.

    Graylog refuses duplicate rule titles, so append a counter ("-2", "-3",
    ...) until the name is free. The check is case-insensitive.
    """
    taken = {str(t).strip().lower() for t in existing_titles}
    base = str(title).strip()
    candidate, n = base, 2
    while candidate.lower() in taken:
        candidate = f"{base}-{n}"
        n += 1
    return candidate


_DUP_SIMILARITY = 0.85
_GROK_PATTERN_RE = re.compile(r'pattern:\s*"((?:\\.|[^"\\])*)"')
_THEN_BLOCK_RE = re.compile(r"^then\b(.*?)^end\b", re.S | re.M)


def rule_grok_patterns(source):
    """Extract the grok pattern strings referenced by a rule source.

    Only the `then` block is scanned: `regex(pattern: "...")` in a `when`
    condition is also written `pattern: "..."`, and matching a guard regex
    would make unrelated rules look like duplicates of each other.
    """
    then = _THEN_BLOCK_RE.search(source or "")
    haystack = then.group(1) if then else (source or "")
    return [m.group(1) for m in _GROK_PATTERN_RE.finditer(haystack)]


def normalize_rule_body(source):
    """Rule source minus its `rule "..."` name line, whitespace-collapsed.

    Used for exact-duplicate detection so two rules that differ only by the
    name line (the standard way names get uniquified) still compare equal.
    """
    body = re.sub(r'^rule\s+"(?:\\.|[^"\\])*"\s*', "", source or "", count=1)
    return re.sub(r"\s+", " ", body).strip()


def find_rule_duplicates(source, existing_rules):
    """Return rules in `existing_rules` whose matching logic matches `source`.

    `exact` lists rules that are byte-for-byte the same once the name line and
    whitespace are ignored. `similar` lists rules whose grok pattern array is
    identical or textually close (SequenceMatcher ratio >= _DUP_SIMILARITY).
    """
    exact, similar = [], []
    needle_patterns = rule_grok_patterns(source)
    needle_body = normalize_rule_body(source)
    checked = 0
    for rule in existing_rules:
        other_source = rule.get("source") if isinstance(rule, dict) else None
        if not other_source:
            continue
        checked += 1
        if normalize_rule_body(other_source) == needle_body:
            exact.append({"id": rule.get("id"), "title": rule.get("title")})
            continue
        other_patterns = rule_grok_patterns(other_source)
        if other_patterns and other_patterns == needle_patterns:
            similar.append({"id": rule.get("id"), "title": rule.get("title"),
                            "score": 1.0})
            continue
        best = max(
            (difflib.SequenceMatcher(None, a, b).ratio()
             for a in needle_patterns for b in other_patterns),
            default=0.0,
        )
        if best >= _DUP_SIMILARITY:
            similar.append({"id": rule.get("id"), "title": rule.get("title"),
                            "score": round(best, 3)})
    similar.sort(key=lambda m: m.get("score", 0.0), reverse=True)
    return {"checked": checked, "exact": exact, "similar": similar}


@app.post("/api/rule/duplicates")
def rule_duplicates():
    out, err, code = _rule_from_payload()
    if err:
        return jsonify({"error": err}), code
    client, gerr = graylog_client()
    if client is None:
        return jsonify({"error": gerr, "checked": 0, "exact": [],
                        "similar": []}), 400
    try:
        existing = client.list_rules()
    except GraylogError as e:
        return jsonify({"error": str(e), "checked": 0, "exact": [],
                        "similar": []}), 502
    return jsonify(find_rule_duplicates(out["rule"], existing))


def simulate_before_push(client, rule: str, sample: str):
    """Dry-run a rule in Graylog. Returns the simulate result, or None.

    Running the rule catches what parse cannot. A simulation that answers 4xx
    arrives as a GraylogError, and a Graylog (or client) without the endpoint
    yields None so the push carries on.
    """
    simulate = getattr(client, "simulate_rule", None)
    if not callable(simulate):
        return None
    try:
        return simulate(rule, sample or "")
    except GraylogError:
        return None


def _simulation_error(result) -> str:
    """Error reported explicitly inside a (HTTP 200) simulate response."""
    if not isinstance(result, dict):
        return ""
    errors = result.get("errors")
    if isinstance(errors, list) and errors:
        return "; ".join(str(e)[:200] for e in errors[:3])
    if isinstance(errors, str) and errors.strip():
        return errors.strip()[:300]
    if result.get("failed") and isinstance(result.get("message"), str):
        return result["message"][:300]
    return ""


def _simulation_missing(result, expected_keys) -> list[str]:
    """Capture keys the rule did not produce when it ran on the sample.

    Graylog answers 200 and extracts nothing when a rule cannot run (an
    undefined grok pattern, a pattern that does not match), so the only way to
    notice is to compare the fields that came back with the ones we expected.
    """
    if not isinstance(result, dict) or not expected_keys:
        return []
    produced = set(result.get("field_names") or [])
    produced |= set((result.get("fields") or {}).keys())
    return [k for k in expected_keys if k not in produced]


def _simulation_error(result) -> str:
    """First error reported inside a (HTTP 200) simulate response, if any."""
    if not isinstance(result, dict):
        return ""
    errors = result.get("errors")
    if isinstance(errors, list) and errors:
        return "; ".join(str(e)[:200] for e in errors[:3])
    if isinstance(errors, str) and errors.strip():
        return errors.strip()[:300]
    if result.get("failed") and isinstance(result.get("message"), str):
        return result["message"][:300]
    return ""


@app.post("/api/rule/simulate")
def rule_simulate():
    """Run the built rule against the sample inside Graylog and report it."""
    out, err, code = _rule_from_payload()
    if err:
        return jsonify({"error": err}), code
    client, gerr = graylog_client()
    if client is None:
        return jsonify({"error": gerr}), 400
    data = request.get_json(silent=True) or {}
    sample = str(data.get("sample") or "")
    simulation = simulate_before_push(client, out["rule"], sample)
    return jsonify({"ok": True, "simulated": simulation, "rule": out["rule"],
                    "local_status": out.get("status"),
                    "missing_fields": _simulation_missing(
                        simulation,
                        [str(r.get("key")) for r in (data.get("ranges") or [])
                         if isinstance(r, dict) and r.get("key")])})


@app.post("/api/rule/push")
def rule_push():
    out, config, err, code = _rule_payload()
    if err:
        return jsonify({"error": err}), code
    rule = out["rule"]
    client, gerr = graylog_client()
    if client is None:
        return jsonify({"error": gerr}), 400

    data = request.get_json(silent=True) or {}
    title = str(config.get("name") or "").strip() or "AI generated grok rule"
    description = str(config.get("description") or "").strip()

    # Rule titles must be unique in Graylog; if this name is taken, bump it
    # with a trailing number and rename the rule inside its own source (the
    # stored title comes from the `rule "..."` line, not the POST field).
    from_title = title
    try:
        existing = client.list_rules()
    except GraylogError:
        existing = []
    title = unique_rule_title([r.get("title") or r.get("name") for r in existing], title)
    if title != from_title:
        rule = rule_builder.rename_rule_source(rule, title)

    # Always parse first so bad rules never reach the rule list.
    try:
        client.parse_rule(rule)
    except GraylogError as e:
        return jsonify({"error": f"rule failed Graylog validation: {e}", "rule": rule}), 422

    # Simulate before creating. parse only proves the rule compiles; running it
    # is the only way to see whether it really extracts fields on this sample.
    runs_on_sample = [str(r["key"]) for r in (data.get("ranges") or [])
                      if isinstance(r, dict) and r.get("key")]
    simulation = simulate_before_push(client, rule,
                                      str(data.get("sample") or ""))
    sim_error = _simulation_error(simulation)
    if sim_error:
        return jsonify({"error": f"rule failed Graylog simulation: {sim_error}",
                        "rule": rule, "simulated": simulation}), 422
    missing = _simulation_missing(simulation, runs_on_sample)
    simulation_warning = ""
    if missing:
        simulation_warning = (
            "Graylog ran the rule on this sample and produced none of the "
            f"fields {', '.join(missing[:5])}"
            + (" ..." if len(missing) > 5 else "")
            + " - the rule may never match")

    try:
        created = client.create_rule(title, description, rule)
    except GraylogError as e:
        return jsonify({"error": str(e), "rule": rule}), 502

    # Optional: also reference the rule in stage 0 of the pipeline named after
    # the input the message arrived on. A failure here is reported but does not
    # undo the already-created rule.
    pipeline_name = str(data.get("pipeline_name") or "").strip()
    pipeline = None
    if pipeline_name:
        try:
            pipeline = client.add_rule_to_pipeline(pipeline_name, title)
        except GraylogError as e:
            pipeline = {"error": str(e)}

    # A rule that reproduces the sample becomes a learned example so the
    # builder keeps reproducing the formats you actually use. A pattern that
    # does not fully match is NOT taught back: it would teach the model a
    # decomposition that does not work.
    sample = str(data.get("sample") or "")
    ranges = data.get("ranges") or []
    learned = False
    verified = out.get("status") == "full"
    if verified and sample.strip() and isinstance(ranges, list) and ranges:
        try:
            segments = rule_builder.ranges_to_segments(sample, ranges)
            examples.add_example(sample, segments, source="push")
            learned = True
        except (rule_builder.ValidationError, ValueError):
            pass

    return jsonify({"ok": True, "created": created, "rule": rule, "title": title,
                    "pipeline": pipeline, "learned": learned,
                    "simulated": simulation,
                    "simulation_warning": simulation_warning})


# ---------------------------------------------------------------- messages
# How many messages to pull per Graylog request while scanning for one that is
# not covered by a rule yet, and the default/ceiling of a whole scan.
MESSAGE_PAGE = 50
DEFAULT_SCAN = 300
MAX_SCAN = 2000


def _uncovered_messages(client, query: str, range_seconds: int, need: int,
                        max_scan: int, matchers: list,
                        catalog: dict[str, str]) -> tuple[list[dict], int, int, bool]:
    """Page through the search until `need` messages have no rule yet.

    Returns (messages, scanned, covered, exhausted). `exhausted` says the whole
    result set was walked (so "no more" really means "no more exist").
    """
    kept: list[dict] = []
    scanned = 0
    covered = 0
    offset = 0
    exhausted = False
    while len(kept) < need and scanned < max_scan:
        page_size = min(MESSAGE_PAGE, max_scan - scanned)
        try:
            page = client.search_messages(query, range_seconds, page_size,
                                          offset=offset)[:page_size]
        except GraylogError:
            if scanned == 0:
                raise
            break                      # keep what we have on a late failure
        scanned += len(page)
        offset += len(page)
        for message in page:
            if rule_matcher.covered(message, matchers, catalog):
                covered += 1
            else:
                kept.append(message)
        if len(page) < page_size:
            exhausted = True           # Graylog ran out of messages
            break
    return kept[:need], scanned, covered, exhausted


@app.post("/api/messages")
def messages():
    client, err = graylog_client()
    if client is None:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    query = str(data.get("query") or "*").strip() or "*"
    try:
        range_seconds = max(60, min(int(data.get("range", 3600)), 30 * 86400))
        # `limit` stays accepted for older callers; `need` is the real knob.
        need = max(1, min(int(data.get("need", data.get("limit", 20))), 100))
        max_scan = max(need, min(int(data.get("max_scan", DEFAULT_SCAN)),
                                 MAX_SCAN))
    except (TypeError, ValueError):
        return jsonify({"error": "range, limit and max_scan must be numbers"}), 400
    require_unmatched = data.get("require_unmatched", True)
    if not isinstance(require_unmatched, bool):
        require_unmatched = str(require_unmatched).lower() in ("1", "true", "yes")

    if not require_unmatched:
        try:
            found = client.search_messages(query, range_seconds, need)
        except GraylogError as e:
            return jsonify({"error": str(e)}), 502
        return jsonify({"messages": found, "scanned": len(found),
                        "covered": 0, "exhausted": False,
                        "rules_used": 0, "unparsed_rules": 0, "filtered": False})

    catalog = grok_catalog.load_catalog().by_name
    try:
        existing_rules = client.list_rules()
    except GraylogError as e:
        # Without the rule list we cannot tell what is covered: say so and
        # hand back what was asked for rather than failing the whole fetch.
        try:
            found = client.search_messages(query, range_seconds, need)
        except GraylogError:
            return jsonify({"error": str(e)}), 502
        return jsonify({"messages": found, "scanned": len(found),
                        "covered": 0, "exhausted": False,
                        "rules_used": 0, "unparsed_rules": 0, "filtered": False,
                        "notice": "could not read the existing rules "
                                  f"({e}); showing every message"})

    matchers, unparsed = rule_matcher.parse_matchers(existing_rules, catalog)
    try:
        found, scanned, covered, exhausted = _uncovered_messages(
            client, query, range_seconds, need, max_scan, matchers, catalog)
    except GraylogError as e:
        return jsonify({"error": str(e)}), 502
    return jsonify({"messages": found, "scanned": scanned, "covered": covered,
                    "exhausted": exhausted, "rules_used": len(matchers),
                    "unparsed_rules": len(unparsed), "filtered": True})


# ---------------------------------------------------------------- examples
def _example_payload() -> tuple[str | None, list[dict] | None, str | None]:
    """Accept either {sample, segments} or {sample, ranges}."""
    data = request.get_json(silent=True) or {}
    sample = str(data.get("sample") or "")
    if not sample.strip():
        return None, None, "sample is required"
    if isinstance(data.get("segments"), list):
        return sample, data["segments"], None
    ranges = data.get("ranges")
    if isinstance(ranges, list) and ranges:
        try:
            return sample, rule_builder.ranges_to_segments(sample, ranges), None
        except rule_builder.ValidationError as e:
            return None, None, str(e)
    return None, None, "provide segments or ranges"


@app.get("/api/examples")
def examples_list():
    return jsonify({
        "examples": examples.load_examples(),
        "stats": examples.stats(),
        "in_prompt": examples_in_prompt(),
    })


@app.post("/api/examples")
def examples_add():
    sample, segments, err = _example_payload()
    if err:
        return jsonify({"error": err}), 400
    data = request.get_json(silent=True) or {}
    source = "manual" if data.get("source") != "push" else "push"
    try:
        entry = examples.add_example(sample, segments, source=source)
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    return jsonify({"ok": True, "example": entry, "stats": examples.stats()})


@app.post("/api/examples/<example_id>")
def examples_update(example_id):
    sample, segments, err = _example_payload()
    if err:
        return jsonify({"error": err}), 400
    try:
        entry = examples.update_example(example_id, sample, segments)
    except ValueError as e:
        return jsonify({"error": str(e)}), 422
    if entry is None:
        return jsonify({"error": "example not found"}), 404
    return jsonify({"ok": True, "example": entry, "stats": examples.stats()})


@app.delete("/api/examples/<example_id>")
def examples_delete(example_id):
    if not examples.delete_example(example_id):
        return jsonify({"error": "example not found"}), 404
    return jsonify({"ok": True, "stats": examples.stats()})


@app.post("/api/examples/clear")
def examples_clear():
    return jsonify({"ok": True, "removed": examples.clear_examples(),
                    "stats": examples.stats()})


if __name__ == "__main__":
    app.run(
        host=env("FLASK_HOST", "127.0.0.1"),
        port=int(env("FLASK_PORT", "5000")),
        debug=False,
    )
