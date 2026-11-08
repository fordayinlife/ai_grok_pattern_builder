# AGENTS.md

AI Graylog Grok Builder: turn a raw log line into a Graylog pipeline rule.
A local Ollama model proposes grok captures; the server verifies/repairs them
against a bundled grok catalog, and the UI lets you edit captures and copy or
push the resulting rule to a Graylog instance.

## Toolchain

- Python 3.14 (stdlib only for the core logic; no build step, no package manager).
- Runtime deps (see `requirements.txt`): `flask`, `requests`, `python-dotenv`.
- Dev dep: `pytest`.
- Front-end: Bootstrap 5 + vanilla JS served from CDN; no bundler.

A virtualenv cannot be created on this box (`ensurepip` unavailable, no sudo),
so deps are installed per-user:

```
pip3 install --user --break-system-packages -r requirements.txt pytest
```

Python 3.14's stdlib `re` supports atomic groups and fixed-lookbehind, so the
`regex` package was intentionally dropped.

## Run

```
cp .env.example .env      # then edit values
ollama pull qwen2.5-coder:7b   # required once; no models ship by default
python3 app.py                 # http://127.0.0.1:5000
```

Config comes from `.env` (via `python-dotenv`): `OLLAMA_BASE_URL`,
`OLLAMA_MODEL`, `OLLAMA_TIMEOUT`, `GRAYLOG_URL` (must include the `/api`
prefix), `GRAYLOG_TOKEN`, `GRAYLOG_VERIFY_SSL`, `FLASK_HOST`, `FLASK_PORT`.
Graylog features degrade gracefully when `GRAYLOG_URL`/`GRAYLOG_TOKEN` are blank.

## Test

```
python3 -m pytest -q
```

Tests live at the repository root and import the flat top-level modules
directly (there is no package). Run pytest from the repo root.

## Architecture (flat modules)

- `app.py` - Flask app and all routes. Also owns the AI orchestration:
  `pattern_status` / `capture_score` / `repair_feedback` implement one
  verify-and-repair round (see below).
- `llm.py` - Ollama client: `list_models` (via `/api/tags`) and
  `generate_segments` (OpenAI-compatible `/v1/chat/completions`). Builds the
  prompt with `build_system_prompt` (uses `.replace`, never `.format`, because
  the prompt contains literal JSON braces) and extracts JSON with a
  brace-aware scanner. The model is asked for `name` (2-5 words) and
  `description` (1-2 sentences) alongside `segments`; `generate_segments`
  returns them in `meta` so the app can name/describe the rule.
- `graylog_client.py` - Graylog 6/7 REST client. HTTP Basic auth with the token
  as username and literal password `token`; every non-GET carries
  `X-Requested-By`. Never sends the read-only `errors` field on rule create.
  `search_messages` resolves each message's `gl2_source_input` to an
  `input_title` via `get_input_titles` (`/system/inputs`); `simulate_rule` runs a
  rule against one message (`/system/pipelines/rule/simulate`); `list_fields`
  reads existing field names from `/system/fields` (indexer-mapping metadata).
  Pipeline support is source-text based (Graylog 7.x): `list_pipelines` /
  `get_pipeline` / `create_pipeline` / `update_pipeline` speak `{title,
  description, source}` (`pipeline "..." / stage 0 match either / rule "..." /
  end`), and `add_rule_to_pipeline(name, rule_title)` references a rule in
  stage 0 of the case-insensitively matching pipeline, creating it if absent and
  skipping insert when already present (`_pipeline_source` / `_add_rule_to_stage0`).
- `rule_builder.py` - the ONLY place escaping happens. Literal gaps are
  regex-escaped (`escape_literal`) and rule strings escaped
  (`escape_rule_string`, undone by `unescape_rule_string`). `anchor_segments`
  re-locates AI capture values into the sample (AI output is never trusted
  verbatim). `failing_captures` / `suggest_patterns` power repair;
  `suggest_patterns` ranks candidates with a curated `_PATTERN_PRIORITY` (bare
  numbers before hostnames, IP before HOSTNAME, generic catch-alls last) so
  autofix/repair do not propose `IP -> HOSTNAME`. Capture keys may not collide
  with `RESERVED_WORDS`, and a `regex` condition is compiled locally
  (`compile_regex` / `portable_regex`, which also accepts the mid-pattern
  `(?i)` flags Graylog's Java engine allows and Python's `re` does not).
- `rule_matcher.py` - decides whether a message is already handled by an
  existing rule: `parse_matchers(rules, catalog)` reads each rule's `then`
  block (grok, source field) and `when` block (condition) into a `RuleMatcher`
  whose `covers()` is what `/api/messages` uses to hide covered messages.
  Judged locally, so no per-message API calls; anything it cannot read
  (hand-written conditions, `%{HOST}` which Graylog 7.x does not define,
  routing-only rules) is reported as unparsed and hides nothing.
- `grok_compiler.py` - grok -> stdlib regex compiler plus `match` returning
  `full` / `partial` / `none` and named fields.
- `grok_catalog.py` - loads `data/grok_patterns.json` (bundled) and merges
  optional `data/synced_patterns.json` (pulled from Graylog; gitignored).
- `examples.py` - user-taught few-shot examples stored in `data/examples.json`
  (gitignored): add/update/delete/clear/stats plus `select_examples`, which
  relevance-ranks stored lines against the current sample. Verified patterns
  are added here automatically when a rule is pushed to Graylog.
- `data/grok_patterns.json` - generated by `tools/gen_patterns.py`
  (`python3 tools/gen_patterns.py`); regenerate rather than hand-editing.
- `templates/index.html`, `static/app.js`, `static/style.css` - single-page UI.
  Bootstrap 5.3's `data-bs-theme` drives the light/dark toggle in the navbar;
  the choice is stored in `localStorage` (`ai-grok-builder:theme`) and falls
  back to `prefers-color-scheme` on first visit. Custom colors use Bootstrap
  CSS variables so both themes stay readable.

## Data model & AI pipeline

A job is a raw `sample` string plus ordered capture ranges
`{key, pattern, start, end}`. Literal text between captures is escaped.

`POST /api/generate` flow: ask the model for ordered segments -> anchor capture
values onto the sample (the model's text segments are used as positional
anchors, so repeated values like two `0`s land correctly) -> compile locally and
check for a `full` match. If it is not full, the failing captures (with a
verified shortlist of catalog patterns that actually match each value) are sent
back for up to `max_repairs` repair rounds (0..5, chosen by the user in the UI;
rounds stop early once the pattern fully matches); each round's answer is kept
only if it improves `capture_score` AND keeps every capture from the previous
round (a repair may never drop captures), so rounds only ever build on what was
already right. A first pass that is a single whole-line generic capture
(`rule_builder.is_coarse`) is treated as a failure and sent back asking for a
decomposition instead. **Enriching mode** (`enrich` flag, on by default in the
UI) then runs exactly ONE extra automatic pass when the result already matches
fully but may have left structured fields as literal text; it is capped at one
round so it can never loop, and kept only if it adds a matching capture without
dropping any. If the pattern still does not fully match,
`autofix_patterns` deterministically substitutes the most specific matching
catalog pattern for each still-failing capture. Response includes `status`,
`attempts`, `repaired`, `enriched`, `autofixed`, and `examples_used`.

**Field-name hints**: existing Graylog field names (from `/system/fields`, which
reads the indexer mapping, not message data, so it is cheap) are filtered
(drops `gl2_*` and internal names) and injected into the prompt so the model
reuses an existing field name for a capture when it fits, and only invents a new
name otherwise. Cached in-process for `_FIELDS_TTL` (1 h); capped by
`GRAYLOG_FIELD_HINTS_LIMIT` (default 300); toggled by `GRAYLOG_FIELD_HINTS`
(default on). Served for the UI by `GET /api/graylog/fields` (`?refresh=1`).

**Auto naming**: loading a Graylog message sets the rule name to the input
title. A successful `POST /api/generate` returns `suggested_name` (2-5 words)
and `suggested_description` (longer) from the model; the UI composes the rule
name as `"<input title> - <suggested name>"` (or just the name without an input
title) and fills the Description field.

**Fetching only unhandled messages**: `POST /api/messages` takes
`require_unmatched` (default true), `need` (how many to return, 1-100, default
20) and `max_scan` (how many to walk through, default 300, ceiling 2000). When
filtering, the app reads every existing rule once (`list_rules()`), parses them
with `rule_matcher.parse_matchers` and pages through the search
(`search_messages(..., offset=...)` in pages of `MESSAGE_PAGE`=50) until `need`
messages are found that no rule covers, or the budget is spent. A rule covers a
message when its `when` condition holds AND its grok produced at least one
named capture (`partial` counts, Graylog's grok is unanchored); rules with no
grok but a `set_field` (pfSense filterlog) are covered by their condition
alone. The response adds `scanned`, `covered`, `exhausted`, `rules_used` and
`unparsed_rules`; a `list_rules()` failure returns the first page unfiltered
with a `notice`. The UI's messages modal has the "Only messages with no rule
yet" checkbox (checked) plus a "scan up to" control, and reports
`X with no rule yet · Y already covered · scanned Z`.

**Message guard (AI-proposed)**: the model also returns a `guard` regex (the
rule's intended `when` message matcher). Before validation, `generate` runs it
through `generalize_guard`, which removes per-message data: captured values,
literal ports/PIDs/counts (digit runs), month names, long session/request IDs,
and literal `key=value` payloads are replaced with generic classes (`\d+`,
`\S+`, `\w+`, `[A-Za-z]{3}`). If the result is still specific or no longer
matches the sample, a `structural_guard` built from the verified capture
ranges and literal gaps is used instead, so a guard never contains a port, IP,
timestamp, username or other value from just one message. `generate` then
validates the generic guard with `guard_for_sample`: it must compile, must
match the sample (else the rule would never fire), and must not match every
message (a bare `.*`); single-backslash regex escapes that JSON decoding turned
into control chars are recovered via `_recover_guard`. When valid, the
response carries `guard` plus a "guard made generic" warning describing what
was replaced; the UI sets the rule condition to `regex` with that pattern
(visible and editable in "Rule settings"), so `build_rule` emits `when
regex(...).matches == true` instead of `when true`. When it comes back empty a
warning explains why (e.g. "does not match the sample"). The guard is only
auto-applied when the user hasn't set their own condition (`state.autoguard`
tracks the last auto-applied guard so manual edits or a new message reset it).
Note: small local models (qwen2.5-coder) frequently emit regexes with
unescaped `\b`/`dot` garbage; validation drops those rather than risking a rule
that never fires.

**Push to pipeline**: `POST /api/rule/push` accepts an optional `pipeline_name`
(the loaded message's `input_title`). When set, after creating the rule the
server calls `GraylogClient.add_rule_to_pipeline` to reference the new rule in
stage 0 of the pipeline whose title matches (case-insensitive), creating that
pipeline if it does not exist. Pipeline failures are reported in the response's
`pipeline.error` and never undo the already-created rule. The UI offers a
"Also add this rule to pipeline <input> (stage 0)" checkbox while a message
with an input title is loaded. `add_rule_to_pipeline` treats the pipeline's
`source` text as authoritative when deciding whether the rule is already
referenced (the stage metadata is only a fallback for a pipeline returned
without a source): the source is what Graylog compiles, so a rule that appears
only in the metadata never runs and must still be inserted.

**Simulate before push**: after `parse_rule`, `push` runs
`GraylogClient.simulate_rule` with the sample. `parse` only proves the rule
compiles, and Graylog answers HTTP 200 while extracting nothing when a rule
cannot run (undefined grok pattern, pattern that does not match), so the only
usable signal is which fields came back: `app._simulation_missing` compares
them with the capture keys and the response carries a non-blocking
`simulation_warning`. An explicit `errors` field in the response (a Graylog
that reports runtime failures there) blocks the push with 422. A Graylog or
client without the endpoint simply skips the step. `POST /api/rule/simulate`
exposes the same check on its own for the UI's "Simulate on Graylog" button,
returning `{ok, simulated, rule, local_status, missing_fields}`.

**Unique rule titles**: pipeline rule titles must be unique (Graylog rejects
duplicates — MongoDB E11000). Before creating, the server checks
`GraylogClient.list_rules` and, when the configured name is taken, appends a
counter (`-2`, `-3`, ...; case-insensitive) via `app.unique_rule_title`. The
stored title comes from the `rule "..."` line inside the source (the POST
`title` field is ignored), so the renamed rule's source is rewritten with
`rule_builder.rename_rule_source` before validation and creation; the pipeline
reference then uses the final name.

**Duplicate detection**: `POST /api/rule/duplicates` builds the current rule
(like `/api/rule/push` does) and compares it against `GraylogClient.list_rules`
sources (`GET /system/pipelines/rule` already returns each rule's `source`).
`find_rule_duplicates` reports `exact` matches (rule bodies equal once the name
line and whitespace are stripped via `normalize_rule_body`) and `similar`
matches (identical grok pattern arrays, or a `SequenceMatcher` ratio >=
`_DUP_SIMILARITY` (0.85) over `rule_grok_patterns`; sorted by score). Response
is `{checked, exact:[{id,title}], similar:[{id,title,score}]}`. The UI has a
"Check duplicates" button (`doCheckDuplicates` / `renderDupResult`), and
`doPush` runs the check before the confirm dialog, listing any identical or
close rules without blocking the push.

**Learned examples**: stored `(sample, segments)` pairs are injected into the
system prompt as few-shot demonstrations. `examples.select_examples` ranks the
store against the current sample and keeps the top `EXAMPLES_IN_PROMPT` (env,
default 3; 0 disables). A pattern is saved automatically on a
`POST /api/rule/push` **only when its grok fully matches the sample** (via
`rule_builder.ranges_to_segments`, response flag `learned`); a partial match is
pushed but not taught back. Examples can also be saved/edited/deleted/cleared
from the UI or the `/api/examples*` routes. Repair and enrich model rounds are
given the same examples as the first call, so the few-shot demos are present in
every prompt.

**Duplicate detection**: `POST /api/rule/duplicates` builds the current rule
(like `/api/rule/push` does) and compares it against `GraylogClient.list_rules`
sources (`GET /system/pipelines/rule` already returns each rule's `source`).
`find_rule_duplicates` reports `exact` matches (rule bodies equal once the name
line and whitespace are stripped via `normalize_rule_body`) and `similar`
matches (identical grok pattern arrays, or a `SequenceMatcher` ratio >=
`_DUP_SIMILARITY` (0.85) over `rule_grok_patterns`; sorted by score). Response
is `{checked, exact:[{id,title}], similar:[{id,title,score}]}`. The UI has a
"Check duplicates" button (`doCheckDuplicates` / `renderDupResult`), and
`doPush` runs the check before the confirm dialog, listing any identical or
close rules without blocking the push. `rule_grok_patterns` reads the `then`
block only: `regex(pattern: "...")` in a `when` condition is spelled the same
way, so comparing the whole source would make two rules with the same guard but
different groks look like duplicates.

## Key API routes

`GET /` UI; `GET /api/health`; `GET /api/ollama/models`;
`GET /api/patterns`; `POST /api/patterns/sync`; `POST /api/generate`;
`POST /api/render`; `POST /api/captures/from-fields`;
`POST /api/graylog/grok-test`; `POST /api/rule/parse`;
`POST /api/rule/duplicates`; `POST /api/rule/simulate`; `POST /api/rule/push`;
`POST /api/messages`; `GET /api/graylog/fields`; `GET /api/examples`;
`POST /api/examples`; `POST /api/examples/<id>`;
`DELETE /api/examples/<id>`; `POST /api/examples/clear`.

## Graylog rule language notes

- No `if` statements in the rule language.
- `grok()` returns `{}` when nothing matches, so `set_fields(grok(...))` is safe
  and there is no need to gate the `when` clause on the grok result. `build_rule`
  emits the canonical shape: a boolean `when` condition, then
  `set_fields(grok(pattern: "...", value: to_string($message.<field>), only_named_captures: true));`.
- `regex(...)` returns a `RegexMatchResult`, not a boolean, so a regex condition
  must be written `regex(pattern: "...", value: ...).matches == true`. Verified
  against a live Graylog: `POST /system/pipelines/rule/parse` and the simulator.
- Use `only_named_captures: true`; rules are validated via
  `POST /system/pipelines/rule/parse` before `POST /system/pipelines/rule`.
  `GraylogClient.simulate_rule` runs a rule against one message via
  `POST /system/pipelines/rule/simulate` (payload `{"message", "rule_source":{"source"}}`),
  which is the only way to catch undefined-grok-pattern and runtime errors.
  Note: Graylog answers 200 and extracts *nothing* when a rule fails at
  runtime - it does not return an `errors` field - so the usable check is which
  `field_names` came back (`app._simulation_missing`).
- Conditions (`build_rule` in `rule_builder.py`): `always` (`true`), `has_field`,
  `contains` (`has_field(x) && contains(to_string($message.x), "...")`), `regex`.
  Field references with dots/dashes/leading digits are backtick-quoted
  (`$message.`event.id``) or Graylog's parser reads them as arithmetic.
- The bundled catalog must stay a subset of the patterns the target Graylog
  defines. `HOST`, `VERSION`, `JAVACLASS`, `JAVAFILE`, `JAVAMETHOD` and
  `JAVASTACKTRACEPART` are absent from Graylog 7.x and are therefore excluded
  from `tools/gen_patterns.py`; an undefined pattern makes `grok()` silently
  match nothing (HTTP 200, no fields) rather than erroring.
- `POST /api/messages` returns each message's full `fields` dict plus
  `input_id`/`input_title` resolved from `gl2_source_input` via `/system/inputs`;
  the UI shows those existing fields and offers them (minus `message`) as
  condition choices, and seeds the context box with the input title as a hint.
- `rule_builder.anchor_fields` turns a fetched message's fields into captures:
  scalar fields whose value text appears in the sample become ranges (specific
  catalog pattern, else `GREEDYDATA`); `message`/`gl2_*`/non-scalars/overlaps
  are skipped. Captures are handed out left to right, one per field: a value
  that appears several times is anchored on the first occurrence no other field
  already covers, and the ambiguity is reported in `skipped`. Served by
  `POST /api/captures/from-fields`, called automatically when a message is
  loaded and when an existing-field row is clicked.

## Gotchas

- Keep escaping confined to `rule_builder.py`.
- Do not introduce `pkill -f app.py`; it matches the invoking shell. Use
  `fuser -k <port>/tcp` or a PID file.
- `.env` is gitignored; never put real tokens in `.env.example`.
