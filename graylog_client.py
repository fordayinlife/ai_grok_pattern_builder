"""Graylog REST client (6.x/7.x).

Auth: HTTP Basic with the access token as username and the literal "token"
as password. Every non-GET request must carry X-Requested-By (CSRF).
"""

from __future__ import annotations

import re

import requests


class GraylogError(Exception):
    """Graylog API or connectivity failure."""


def _message_from(resp: requests.Response) -> str:
    try:
        body = resp.json()
    except ValueError:
        return resp.text[:300] or f"HTTP {resp.status_code}"
    if isinstance(body, dict):
        for key in ("message", "detail", "type"):
            if body.get(key):
                return str(body[key])[:500]
        return str(body)[:500]
    return str(body)[:500]


class GraylogClient:
    def __init__(self, base_url: str, token: str, verify_ssl: bool = True,
                 timeout: float = 15.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.auth = (token, "token")
        self.session.headers.update({
            "X-Requested-By": "ai-grok-pattern-builder",
            "Accept": "application/json",
        })
        self.session.verify = verify_ssl

    def _request(self, method: str, path: str, **kwargs) -> dict | list:
        url = f"{self.base_url}{path}"
        kwargs.setdefault("timeout", self.timeout)
        try:
            resp = self.session.request(method, url, **kwargs)
        except requests.RequestException as e:
            raise GraylogError(f"cannot reach Graylog at {self.base_url}: {e}") from e
        if resp.status_code >= 400:
            raise GraylogError(f"{method} {path} -> {resp.status_code}: {_message_from(resp)}")
        if not resp.content:
            return {}
        try:
            return resp.json()
        except ValueError:
            return {"raw": resp.text}

    # ---- health ----
    def health(self) -> dict:
        """Cheap reachability/auth probe. Returns {ok, error?}."""
        try:
            self._request("GET", "/system")
            return {"ok": True}
        except GraylogError as e:
            msg = str(e)
            if "401" in msg or "403" in msg:
                return {"ok": False, "error": "token rejected (401/403) - check GRAYLOG_TOKEN"}
            if "cannot reach" in msg:
                return {"ok": False, "error": msg}
            return {"ok": False, "error": msg}

    # ---- messages ----
    def get_input_titles(self) -> dict[str, str]:
        """GET /system/inputs - map input id -> human title.

        Messages carry the id in `gl2_source_input`, so this lets the UI (and
        the model prompt) know which input/log type a sample came from.
        """
        data = self._request("GET", "/system/inputs")
        titles: dict[str, str] = {}
        for inp in (data.get("inputs") or []):
            iid = inp.get("id") or inp.get("input_id")
            title = inp.get("title") or (inp.get("configuration") or {}).get("title")
            if iid and title:
                titles[iid] = title
        return titles

    def search_messages(self, query: str, range_seconds: int = 3600,
                        limit: int = 20, offset: int = 0) -> list[dict]:
        """GET /search/universal/relative (legacy but active in 6.x/7.x).

        `offset` pages through the result set so a caller can keep scanning
        past messages it has already looked at.
        """
        data = self._request(
            "GET",
            "/search/universal/relative",
            params={"query": query or "*", "range": range_seconds,
                    "limit": limit, "offset": max(0, int(offset))},
        )
        messages = []
        input_titles: dict[str, str] | None = None
        for m in (data.get("messages") or []):
            msg = m.get("message") or {}
            input_id = msg.get("gl2_source_input")
            input_title = None
            if input_id:
                if input_titles is None:
                    try:
                        input_titles = self.get_input_titles()
                    except GraylogError:
                        input_titles = {}
                input_title = input_titles.get(input_id)
            messages.append({
                "id": msg.get("id"),
                "index": m.get("index"),
                "timestamp": msg.get("timestamp"),
                "source": msg.get("source"),
                "message": msg.get("message", ""),
                "input_id": input_id,
                "input_title": input_title,
                # every field Graylog already parsed for this message
                "fields": dict(msg),
            })
        return messages

    # ---- grok patterns ----
    def list_fields(self, limit: int = 0) -> list[str]:
        """GET /system/fields - existing field names from the indexer mapping.

        This reads the indexer mapping (metadata), not the message data, so it is
        cheap. `limit` > 0 caps how many names are returned and keeps the response
        small on very large deployments; 0 returns all fields.
        """
        data = self._request("GET", "/system/fields", params={"limit": int(limit)})
        return sorted(data.get("fields") or [])

    def list_grok_patterns(self) -> dict[str, str]:
        data = self._request("GET", "/system/grok")
        out: dict[str, str] = {}
        for p in (data.get("patterns") or []):
            if p.get("name") and p.get("pattern"):
                out[p["name"]] = p["pattern"]
        return out

    def test_grok(self, pattern: str, text: str) -> dict:
        """POST /system/grok/test - authoritative match on the Graylog side."""
        # Try common payload shapes across Graylog versions
        candidates = [
            {"pattern": pattern, "string": text},
            {"grokPattern": pattern, "testString": text},
            {"grokPattern": pattern, "string": text},
            {"grokPattern": pattern, "sample": text},
            {"grokPattern": pattern, "input": text},
            {"pattern": pattern, "text": text},
        ]
        last_err = None
        for body in candidates:
            try:
                return self._request("POST", "/system/grok/test", json=body)
            except GraylogError as e:
                last_err = e
                continue
        if last_err:
            raise last_err
        return {}

    # ---- pipeline rules ----
    def parse_rule(self, source: str) -> dict:
        """POST /system/pipelines/rule/parse - syntax/type check without saving."""
        return self._request(
            "POST", "/system/pipelines/rule/parse", json={"source": source}
        )

    def create_rule(self, title: str, description: str, source: str) -> dict:
        # 'errors' is read-only - never send it (Graylog 400s on it).
        return self._request(
            "POST",
            "/system/pipelines/rule",
            json={"title": title, "description": description or "", "source": source},
        )

    def simulate_rule(self, source: str, message: str) -> dict:
        """POST /system/pipelines/rule/simulate - run a rule against one message.

        Unlike parse, this executes the rule and returns the resulting message,
        so it catches runtime/type errors and shows which fields were extracted.
        """
        return self._request(
            "POST",
            "/system/pipelines/rule/simulate",
            json={"message": message, "rule_source": {"source": source}},
        )

    # ---- pipelines (source-text based in Graylog 7.x) ----
    def list_pipelines(self) -> list[dict]:
        data = self._request("GET", "/system/pipelines/pipeline")
        if isinstance(data, list):
            return data
        return data.get("pipelines") or data.get("pipeline") or []

    def list_rules(self) -> list[dict]:
        """Return pipeline rules as [{id, title, ...}]. Titles are unique."""
        data = self._request("GET", "/system/pipelines/rule")
        if isinstance(data, list):
            return data
        return data.get("rules") or data.get("pipeline_rules") or []

    def get_pipeline(self, pipeline_id: str) -> dict:
        return self._request("GET", f"/system/pipelines/pipeline/{pipeline_id}")

    def create_pipeline(self, title: str, description: str = "",
                        source: str = "") -> dict:
        return self._request(
            "POST",
            "/system/pipelines/pipeline",
            json={"title": title, "description": description or "",
                  "source": source or _pipeline_source(title, [])},
        )

    def update_pipeline(self, pipeline_id: str, title: str,
                        description: str = "", source: str = "") -> dict:
        return self._request(
            "PUT",
            f"/system/pipelines/pipeline/{pipeline_id}",
            json={"title": title, "description": description or "",
                  "source": source},
        )

    def add_rule_to_pipeline(self, pipeline_title: str,
                             rule_title: str) -> dict:
        """Reference `rule_title` in stage 0 of the pipeline named `pipeline_title`.

        Matches pipeline names case-insensitively (e.g. input title "SWAG" finds
        pipeline "swag"). Creates the pipeline (stage 0, match either) when it
        does not exist, and skips the insert when the rule is already referenced.
        """
        lower = pipeline_title.strip().lower()
        match = next(
            (p for p in self.list_pipelines()
             if (p.get("title") or "").strip().lower() == lower),
            None,
        )
        if match is None:
            created = self.create_pipeline(
                pipeline_title, "",
                _pipeline_source(pipeline_title, [rule_title]),
            )
            return {"id": created.get("id"), "title": created.get("title")
                    or pipeline_title, "created": True, "rule_added": rule_title}
        pipe = self.get_pipeline(match["id"])
        source = (pipe.get("source") or "").strip()
        wanted = rule_title.strip().lower()
        # The source text is what Graylog compiles, so it decides whether the
        # rule is already referenced; the stage metadata is only a fallback for
        # a pipeline that came back without any source.
        referenced = {t.strip().lower() for t in _stage0_rule_titles(source)}
        if not source:
            for stage in pipe.get("stages") or []:
                if _stage_number(stage) == 0:
                    referenced.update(str(t).strip().lower()
                                      for t in stage.get("rules") or [])
        if wanted in referenced:
            return {"id": pipe.get("id"), "title": pipe.get("title")
                    or pipeline_title, "created": False, "rule_added": None,
                    "already_present": True}
        updated = _add_rule_to_stage0(
            source or _pipeline_source(pipeline_title, [rule_title]),
            rule_title,
        )
        self.update_pipeline(pipe.get("id"), pipe.get("title") or pipeline_title,
                             pipe.get("description") or "", updated)
        return {"id": pipe.get("id"), "title": pipe.get("title")
                or pipeline_title, "created": False, "rule_added": rule_title}


def _stage_number(stage: dict) -> int | None:
    """Stage index, or None when it is missing or not a number."""
    try:
        return int(stage.get("stage", -1))
    except (TypeError, ValueError):
        return None


_PIPELINE_RULE_RE = re.compile(r'rule\s+"((?:\\.|[^"\\])*)"')
_PIPELINE_STAGE_RE = re.compile(r'stage\s+(\d+)')


def _stage0_rule_titles(source: str) -> list[str]:
    """Rule titles referenced inside the `stage 0` block of a pipeline source."""
    titles: list[str] = []
    stage: int | None = None
    for line in (source or "").splitlines():
        stripped = line.strip()
        stage_match = _PIPELINE_STAGE_RE.match(stripped)
        if stage_match:
            stage = int(stage_match.group(1))
            continue
        if stage == 0:
            title = _PIPELINE_RULE_RE.search(stripped)
            if title:
                titles.append(title.group(1))
    return titles


def _escape_pipeline_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _pipeline_source(title: str, rule_titles: list[str]) -> str:
    lines = [f'pipeline "{_escape_pipeline_string(title)}"', "stage 0 match either"]
    lines += [f'rule "{_escape_pipeline_string(t)}"' for t in rule_titles]
    lines.append("end")
    return "\n".join(lines)


def _add_rule_to_stage0(source: str, rule_title: str) -> str:
    """Insert `rule "<title>"` right after the `stage 0` line of a pipeline source.

    When the pipeline has no stage-0 block, a fresh one is prepended before the
    first existing stage/end line.
    """
    titles_escaped = _escape_pipeline_string(rule_title)
    lines = (source or "").split("\n")
    out = []
    added = False
    for ln in lines:
        out.append(ln)
        if not added and ln.strip().startswith("stage 0"):
            out.append(f'rule "{titles_escaped}"')
            added = True
    if added:
        return "\n".join(out)
    first = next(
        (i for i, ln in enumerate(lines)
         if ln.strip() and (ln.strip().startswith("stage ") or ln.strip() == "end")),
        len(lines),
    )
    block = ["stage 0 match either", f'rule "{titles_escaped}"']
    out = lines[:first] + block + lines[first:]
    return "\n".join(out)
