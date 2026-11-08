"""Ollama client: model listing + segment generation via the OpenAI-compatible API."""

from __future__ import annotations

import json
import re

import requests

SYSTEM_PROMPT = """You are a precise grok pattern engineer for Graylog pipeline rules. 

Your task is to decompose a raw log line into an exact, ordered sequence of segments (literals and captures) that reconstructs the original string perfectly when concatenated.

### Output Format
Respond with ONLY a valid JSON object matching this exact structure, with no markdown code blocks and no surrounding prose:
{
  "name": "<2-5 word label for this kind of log line, e.g. 'Nginx access request'>",
  "description": "<one or two sentences: what this log line is and which captures matter>",
  "guard": "<a message-matching regex for this exact kind of log line, or an empty string \"\" if no stable text exists>",
  "segments": [
    {"type": "text", "value": "<exact literal text>"},
    {"type": "capture", "key": "<field_name>", "pattern": "<ALLOWED_PATTERN>", "value": "<exact substring>"}
  ]
}

### Decomposition Rules
1. **Decompose Aggressively**: Break lines down into 5 to 15 meaningful fields (timestamps, IPs, ports, methods, status codes, process names, IDs). NEVER use a single `GREEDYDATA` for the whole line.
2. **Trailing Data Only**: `GREEDYDATA` is strictly reserved for unstructured trailing free-text messages at the end of a log line.
3. **Key-Value Pairs**: For structured logs (e.g., Nginx/Caddy or key:value formats like `client: 1.2.3.4, server: foo`), explicitly capture every individual key's value rather than letting a generic pattern swallow them.
4. **No "message" Key**: Never name a capture `key: "message"`. The raw log message is already preserved by Graylog.
5. **Exact Reconstruction**: Every character of the log line must be accounted for across alternating `text` and `capture` segments in exact left-to-right order.
6. **Label It**: The `name` must be 2-5 words (no quotes/colons); the `description` one or two plain sentences describing what this log line is.
7. **Guard**: The `guard` is a plain regex (no grok) that matches ANY line of this log format, not just the sample, as it will be the rule's `when` condition. It MUST actually match the sample — silently test it against the sample before answering. It must NEVER contain per-message values: no literal port numbers, IP addresses, timestamps, dates, PIDs, request/session IDs, usernames, hostnames, file paths, status codes, byte counts, or any other value you captured. Use generic classes (`\\d+`, `\\S+`, `[A-Za-z]{3}`) for every part that changes between messages. Prefer the shortest stable skeleton (e.g. `^sshd\\[\\d+\\]:` or `^\\d{1,3}(\\.\\d{1,3}){3} - - \\[`), never a full line copied from the sample. Bad guard: `^Jan 14 09:22:31 host sshd\\[1234\\]: Failed password for root from 10\\.0\\.0\\.5 port 55512`. Good guard: `^sshd\\[\\d+\\]: Failed password for \\S+ from \\d{1,3}(\\.\\d{1,3}){3} port \\d+`. Return an empty string `""` only when the line has no stable distinguishing text. Do not copy grok capture syntax into it, do not use `.*` alone, and never spell punctuation out as words (write `\\.` for a dot, never `dot`).
8. **JSON Escaping**: The answer is JSON, so every regex backslash must be doubled — write `\\d`, `\\.`, `\\s`. A single backslash (e.g. `\b`) is decoded as an invisible control character and the guard will be rejected; a `dot` spelled as a word is rejected too.

### Allowed Pattern Catalog
{catalog}
(Examples: IP, WORD, INT, POSINT, NONNEGINT, BASE10NUM, DATA, GREEDYDATA, PATH, URI, QUOTEDSTRING, UUID, LOGLEVEL, TIMESTAMP_ISO8601, HTTPDATE, SYSLOGTIMESTAMP, HOSTNAME, HOSTPORT)

### Example Log:
172.16.0.1 - - [10/Oct/2026:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326

### Example Answer:
{
  "name": "Nginx access request",
  "description": "An Apache/Nginx style HTTP access log line: client IP, request timestamp, method, path, status code and response size.",
  "guard": "^\\d{1,3}(\\.\\d{1,3}){3} - - \\[",
  "segments": [
    {"type": "capture", "key": "src_ip", "pattern": "IP", "value": "172.16.0.1"},
    {"type": "text", "value": " - - ["},
    {"type": "capture", "key": "timestamp", "pattern": "HTTPDATE", "value": "10/Oct/2026:13:55:36 -0700"},
    {"type": "text", "value": "] \""},
    {"type": "capture", "key": "http_method", "pattern": "WORD", "value": "GET"},
    {"type": "text", "value": " "},
    {"type": "capture", "key": "request_path", "pattern": "PATH", "value": "/index.html"},
    {"type": "text", "value": " HTTP/1.1\" "},
    {"type": "capture", "key": "status_code", "pattern": "INT", "value": "200"},
    {"type": "text", "value": " "},
    {"type": "capture", "key": "bytes", "pattern": "INT", "value": "2326"}
  ]
}
    """


class LLMError(Exception):
    """Ollama request or response problem."""


def list_models(base_url: str, timeout: float = 8.0) -> list[dict]:
    """GET /api/tags -> [{id, label}] (raises LLMError when unreachable)."""
    try:
        resp = requests.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        raise LLMError(f"cannot reach Ollama at {base_url}: {e}") from e

    models = []
    for m in data.get("models", []):
        mid = m.get("name") or m.get("model") or ""
        if not mid:
            continue
        details = m.get("details") or {}
        bits = [b for b in (
            details.get("parameter_size"),
            details.get("quantization_level"),
        ) if b]
        models.append({"id": mid, "label": f"{mid} ({', '.join(bits)})" if bits else mid})
    models.sort(key=lambda m: m["id"].lower())
    return models


def _format_examples(examples: list[dict]) -> str:
    """Render learned examples as a few-shot block appended to the system prompt."""
    blocks = [
        "\n\n### Examples Learned From This Environment",
        "Decompose new lines the same way these verified lines were decomposed.",
    ]
    for i, ex in enumerate(examples, 1):
        sample = str(ex.get("sample") or "")[:600]
        segments = ex.get("segments") or []
        blocks.append(
            f"\nExample {i} line:\n{sample}\n"
            f"Example {i} answer:\n"
            + json.dumps({"segments": segments}, ensure_ascii=False)
        )
    return "\n".join(blocks)


def _format_field_names(field_names: list[str]) -> str:
    """Hint block listing field names that already exist in this Graylog."""
    names = ", ".join(sorted({n for n in field_names if n}))
    return (
        "\n\n### Existing Graylog Field Names\n"
        "These field names already exist in this Graylog instance. When a captured "
        "value clearly corresponds to one of them, use that exact name as the capture "
        "`key` so new rules stay consistent with existing data. If none fits, choose a "
        "clear new snake_case name. Do not invent a near-duplicate of an existing name.\n"
        f"{names}"
    )


def build_system_prompt(catalog_names: list[str],
                        examples: list[dict] | None = None,
                        field_names: list[str] | None = None) -> str:
    """Fill the catalog slot without .format() (the prompt contains literal JSON braces)."""
    prompt = SYSTEM_PROMPT.replace("{catalog}", ", ".join(sorted(catalog_names)))
    if field_names:
        prompt += _format_field_names(field_names)
    if examples:
        prompt += _format_examples(examples)
    return prompt


def _extract_json(text: str) -> dict:
    """Pull the first balanced JSON object out of a model response."""
    start = text.find("{")
    if start < 0:
        raise LLMError("model response contains no JSON object")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    obj = json.loads(text[start : i + 1])
                except json.JSONDecodeError as e:
                    raise LLMError(f"model returned invalid JSON: {e}") from e
                return obj
    raise LLMError("model returned malformed JSON")


def generate_segments(
    base_url: str,
    model: str,
    sample: str,
    catalog_names: list[str],
    timeout: float = 300.0,
    feedback: str | None = None,
    context: str = "",
    examples: list[dict] | None = None,
    field_names: list[str] | None = None,
) -> tuple[list[dict], dict]:
    """Ask the model for segments. Returns (segments, meta).

    meta: {model, raw, attempts, name, description, guard}. Raises LLMError
    after one retry. `feedback` (optional) is an extra user turn used to
    correct a previous, non-matching answer. `examples` (optional) are learned
    few-shot pairs. `field_names` (optional) are existing Graylog fields the
    model should reuse as capture keys when they fit.
    """
    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    system = build_system_prompt(catalog_names, examples, field_names)
    user_content = f"Log line:\n{sample}"
    if context:
        user_content = f"Context: {context}\n\nLog line:\n{sample}"
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": user_content},
    ]
    if feedback:
        messages.append({"role": "user", "content": feedback})
    raw_shown = ""
    last_err: LLMError | None = None

    for attempt in (1, 2):
        payload = {
            "model": model,
            "messages": messages,
            "temperature": 0.1,
            "stream": False,
            "response_format": {"type": "json_object"},
        }
        try:
            resp = requests.post(url, json=payload, timeout=timeout)
            if resp.status_code == 400:
                payload.pop("response_format", None)  # older Ollama: ignore
                resp = requests.post(url, json=payload, timeout=timeout)
            resp.raise_for_status()
            body = resp.json()
        except (requests.RequestException, ValueError) as e:
            raise LLMError(f"Ollama request failed: {e}") from e

        try:
            content = body["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            raise LLMError(f"unexpected Ollama response shape: {str(body)[:300]}")

        raw_shown = content or ""
        try:
            obj = _extract_json(content)
        except LLMError as e:
            last_err = e
            messages.append({"role": "assistant", "content": content or ""})
            messages.append(
                {"role": "user", "content":
                    f"That response could not be parsed ({e}). "
                    "Reply with ONLY the JSON object."}
            )
            continue

        segments = obj.get("segments")
        if not isinstance(segments, list) or not segments:
            last_err = LLMError("JSON has no 'segments' array")
            messages.append({"role": "assistant", "content": content or ""})
            messages.append(
                {"role": "user", "content":
                    'The JSON must contain {"segments": [...]} with at least '
                    "one element. Reply with ONLY the corrected JSON object."}
            )
            continue

        cleaned = [s for s in segments if isinstance(s, dict)]
        if not cleaned:
            last_err = LLMError("segments array contains no objects")
            continue
        name = str(obj.get("name") or "").strip()
        description = str(obj.get("description") or "").strip()
        guard = str(obj.get("guard") or "").strip()
        return cleaned, {"model": model, "raw": raw_shown, "attempts": attempt,
                         "name": name, "description": description, "guard": guard}

    raise last_err or LLMError("model failed to produce segments")
