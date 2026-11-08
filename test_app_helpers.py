import app
import grok_catalog
import rule_builder

CAT = grok_catalog.load_catalog().by_name
SAMPLE = "Jan 14 09:22:31 host sshd[1234]: Failed password for root from 10.0.0.5 port 55512 ssh2"


def _ranges(*specs):
    return [{"key": k, "pattern": p, "start": s, "end": e} for k, p, s, e in specs]


def test_index_exposes_the_theme_toggle():
    client = app.app.test_client()
    html = client.get("/").get_data(as_text=True)
    assert 'id="btn-theme"' in html
    assert "prefers-color-scheme" in html


def test_pattern_status_full_for_matching_captures():
    ranges = _ranges(("ts", "SYSLOGTIMESTAMP", 0, 15), ("host", "HOSTNAME", 16, 20))
    assert app.pattern_status(SAMPLE, ranges, CAT) == "full"


def test_pattern_status_not_full_when_a_capture_pattern_is_wrong():
    ranges = _ranges(("ts", "TIMESTAMP_ISO8601", 0, 15), ("host", "HOSTNAME", 16, 20))
    assert app.pattern_status(SAMPLE, ranges, CAT) != "full"


def test_failing_captures_flags_only_the_bad_one():
    ranges = _ranges(("ts", "TIMESTAMP_ISO8601", 0, 15), ("host", "HOSTNAME", 16, 20))
    bad = rule_builder.failing_captures(SAMPLE, ranges, CAT)
    assert [b["key"] for b in bad] == ["ts"]
    assert bad[0]["value"] == "Jan 14 09:22:31"


def test_repair_feedback_names_key_and_verified_patterns():
    msg = app.repair_feedback("none", [{
        "key": "ts", "pattern": "TIMESTAMP_ISO8601",
        "value": "Jan 14 09:22:31", "status": "none",
    }], CAT)
    assert "ts" in msg
    assert "SYSLOGTIMESTAMP" in msg      # a pattern that really matches the value
    assert "TIMESTAMP_ISO8601" not in msg.split("DO match")[1]
    assert "segments" in msg


def test_repair_feedback_embeds_previous_segments():
    segs = [{"type": "capture", "key": "uid", "pattern": "POSINT", "value": "0"}]
    msg = app.repair_feedback("none", [], CAT, segs)
    assert '"uid"' in msg
    assert "do NOT drop" in msg


def test_autofix_replaces_failing_patterns_and_keeps_all_captures():
    sample = "vnStat daemon 2.13 (pid:44820 uid:0 gid:0, SQLite 3.53.1)"
    ranges = _ranges(
        ("version", "NOTSPACE", 14, 18),
        ("pid", "POSINT", 24, 29),
        ("uid", "POSINT", 34, 35),
        ("gid", "POSINT", 40, 41),
        ("sqlite_version", "NOTSPACE", 50, 56),
    )
    fixed, changes = rule_builder.autofix_patterns(sample, ranges, CAT)
    assert len(fixed) == 5
    assert {c["key"] for c in changes} == {"uid", "gid"}
    assert rule_builder.preview(sample, fixed, CAT)["status"] == "full"


def test_suggest_patterns_offers_verified_matches_only():
    sugg = rule_builder.suggest_patterns("10.0.0.5", CAT)
    assert "IP" in sugg
    assert "POSINT" not in sugg          # must not match "10.0.0.5"


def test_capture_score_ranks_full_match_above_partial():
    good = _ranges(("ts", "SYSLOGTIMESTAMP", 0, 15), ("host", "HOSTNAME", 16, 20))
    bad = _ranges(("ts", "TIMESTAMP_ISO8601", 0, 15), ("host", "HOSTNAME", 16, 20))
    assert app.capture_score(SAMPLE, good, CAT) > app.capture_score(SAMPLE, bad, CAT)


def test_pattern_status_empty_ranges_is_none():
    assert app.pattern_status(SAMPLE, [], CAT) == "none"


def test_field_names_for_prompt_filters_internal(monkeypatch):
    monkeypatch.setenv("GRAYLOG_FIELD_HINTS", "true")
    monkeypatch.setattr(app, "graylog_field_names", lambda force=False: [
        "source_ip", "gl2_remote_ip", "message", "streams", "http_method",
    ])
    names = app.field_names_for_prompt()
    assert "source_ip" in names and "http_method" in names
    assert "gl2_remote_ip" not in names
    assert "message" not in names
    assert "streams" not in names


def test_field_hints_can_be_disabled(monkeypatch):
    monkeypatch.setenv("GRAYLOG_FIELD_HINTS", "false")
    monkeypatch.setattr(app, "graylog_field_names", lambda force=False: ["source_ip"])
    assert app.field_names_for_prompt() == []


def test_graylog_field_names_keeps_last_known_when_unreachable(monkeypatch):
    class Unavailable:
        def list_fields(self, limit=0):
            raise app.GraylogError("cannot reach Graylog")

    monkeypatch.setattr(app, "graylog_client", lambda: (Unavailable(), None))
    monkeypatch.setattr(app, "_FIELDS_CACHE",
                        {"at": 0.0, "names": ["a_field"]})
    assert app.graylog_field_names(force=True) == ["a_field"]


def test_graylog_field_names_without_cache_is_empty(monkeypatch):
    monkeypatch.setattr(app, "graylog_client", lambda: (None, "not configured"))
    monkeypatch.setattr(app, "_FIELDS_CACHE", {"at": 0.0, "names": None})
    assert app.graylog_field_names(force=True) == []


def test_unique_rule_title_appends_a_counter():
    assert app.unique_rule_title(["One", "Two"], "Three") == "Three"
    assert app.unique_rule_title(["MyRule"], "MyRule") == "MyRule-2"
    assert app.unique_rule_title(["MyRule", "MyRule-2", "myrule"], "MyRule") == "MyRule-3"
    assert app.unique_rule_title(["MyRule"], "myrule") == "myrule-2"


def test_duplicate_detection_exact():
    src_a = ('rule "nginx access"\nwhen true\nthen\n'
             '  set_fields(grok(pattern: "%{IP:ip} %{WORD:method}"));\nend')
    src_b = ('rule "nginx access-2"\nwhen true\nthen\n'
             '  set_fields(grok(pattern: "%{IP:ip} %{WORD:method}"));\nend')
    out = app.find_rule_duplicates(src_a, [{"id": "r1", "title": "nginx access-2",
                                            "source": src_b}])
    assert out["exact"] == [{"id": "r1", "title": "nginx access-2"}]
    assert out["similar"] == []


def test_duplicate_detection_similar_pattern():
    src_a = ('rule "a"\nwhen true\nthen\n'
             '  set_fields(grok(pattern: "%{IP:ip} %{WORD:method} %{NUMBER:code}"));\nend')
    src_b = ('rule "b"\nwhen true\nthen\n'
             '  set_fields(grok(pattern: "%{IP:ip} %{WORD:method} %{INT:code}"));\nend')
    out = app.find_rule_duplicates(src_a, [{"id": "r1", "title": "b", "source": src_b}])
    assert out["exact"] == []
    assert out["similar"] and out["similar"][0]["title"] == "b"
    assert out["similar"][0]["score"] >= 0.85


def test_duplicate_detection_ignores_sources_without_grok():
    src_a = ('rule "a"\nwhen true\nthen\n'
             '  set_fields(grok(pattern: "%{IP:ip}"))\nend')
    out = app.find_rule_duplicates(src_a,
                                   [{"id": "r1", "title": "b", "source": "no grok here"}])
    assert out["checked"] == 1
    assert out["exact"] == [] and out["similar"] == []


def test_rule_grok_patterns_ignores_the_condition_regex():
    # A regex guard is also written `pattern: "..."`; only the grok in `then`
    # should be compared, or two unrelated guarded rules look identical.
    source = rule_builder.build_rule("%{IP:ip} %{WORD:verb}", {
        "name": "a",
        "condition": "regex",
        "condition_regex": r"^\d{1,3}(\.\d{1,3}){3}",
    })
    assert app.rule_grok_patterns(source) == ["%{IP:ip} %{WORD:verb}"]


def test_rule_push_attaches_rule_to_pipeline(monkeypatch):
    class FakeClient:
        def list_rules(self):
            return [{"title": "Something else"}]

        def parse_rule(self, source):
            return {"errors": None}

        def create_rule(self, title, description, source):
            assert title == "MyRule"
            return {"id": "rule-1", "title": title}

        def add_rule_to_pipeline(self, name, title):
            return {"id": "pipe-1", "title": name, "created": True,
                    "rule_added": title}

    monkeypatch.setattr(app, "graylog_client", lambda: (FakeClient(), None))
    monkeypatch.setattr(app.examples, "add_example", lambda *a, **k: None)
    client = app.app.test_client()
    resp = client.post("/api/rule/push", json={
        "sample": "hello world",
        "ranges": [{"key": "a", "pattern": "WORD", "start": 0, "end": 5}],
        "config": {"name": "MyRule", "description": "desc"},
        "pipeline_name": "pfSense",
    })
    assert resp.status_code == 200
    out = resp.get_json()
    assert out["pipeline"]["title"] == "pfSense"
    assert out["pipeline"]["rule_added"] == "MyRule"


def test_guard_for_sample_validates():
    sample = '172.16.0.1 - - [10/Oct/2026:13:55:36 -0700] "GET /a HTTP/1.1" 200 5'
    assert app.guard_for_sample(sample, "") == ("", "")
    assert app.guard_for_sample(sample, r"^\d+\.\d+\.\d+\.\d+ - - \[") == \
        (r"^\d+\.\d+\.\d+\.\d+ - - \[", "")
    g, warn = app.guard_for_sample(sample, "^POST")
    assert g == "" and "does not match" in warn
    g, warn = app.guard_for_sample(sample, ".*")
    assert g == "" and "matches every" in warn
    g, warn = app.guard_for_sample(sample, "([unclosed")
    assert g == "" and "not a valid regex" in warn
    # JSON-unescaped single-backslash regex escapes are recovered
    g, warn = app.guard_for_sample("nginx-prod", "\x08nginx\x08")
    assert g == r"\bnginx\b" and warn == ""


def test_generate_falls_back_to_structural_guard(monkeypatch):
    calls = {}

    def fake(base_url, model, sample, catalog_names, timeout=300.0,
             feedback=None, context="", examples=None, field_names=None):
        calls["feedback"] = feedback
        return ([{"key": "w", "pattern": "WORD", "type": "capture", "value": "hello"}],
                {"attempts": 1, "guard": "^nope"})

    monkeypatch.setattr(app.llm, "generate_segments", fake)
    client = app.app.test_client()
    resp = client.post("/api/generate", json={
        "sample": "hello world", "model": "m", "max_repairs": 0,
    })
    assert resp.status_code == 200
    out = resp.get_json()
    # The model guard did not match; a structural guard from the capture is
    # still useful and carries no per-message values.
    assert out["guard"] == r"\w+\ world"
    assert any("structural guard" in w for w in out["warnings"])


def _captures(sample, specs):
    """(key, pattern, value) specs -> ranges with real positions."""
    ranges = []
    pos = 0
    for key, pattern, value in specs:
        start = sample.index(value, pos)
        ranges.append({"key": key, "pattern": pattern,
                       "start": start, "end": start + len(value)})
        pos = start + len(value)
    return ranges


def test_generalize_guard_removes_per_message_values():
    sample = ("Jan 14 09:22:31 host sshd[1234]: Failed password for root "
              "from 10.0.0.5 port 55512 ssh2")
    ranges = _captures(sample, [
        ("ts", "SYSLOGTIMESTAMP", "Jan 14 09:22:31"),
        ("host", "HOSTNAME", "host"),
        ("pid", "POSINT", "1234"),
        ("user", "WORD", "root"),
        ("src_ip", "IP", "10.0.0.5"),
        ("src_port", "POSINT", "55512"),
    ])
    candidate = (r"^Jan 14 09:22:31 host sshd\[1234\]: Failed password for "
                 r"root from 10\.0\.0\.5 port 55512 ssh2")
    guard, notes = app.generalize_guard(sample, candidate, ranges)
    for value in ("Jan 14 09:22:31", "host", "1234", "root",
                  "10.0.0.5", "55512"):
        assert value not in guard
    assert r"\d+" in guard
    assert notes
    assert app.guard_for_sample(sample, guard) == (guard, "")


def test_generalize_guard_replaces_literal_paths():
    sample = "GET /index.html HTTP/1.1 200 5"
    guard, notes = app.generalize_guard(
        sample, r"^GET /index\.html HTTP/1\.1 200 5$")
    assert "index" not in guard
    assert r"\S+" in guard
    assert any("path" in note for note in notes)
    assert app.guard_for_sample(sample, guard) == (guard, "")


def test_generalize_guard_leaves_a_generic_guard_alone():
    sample = ("Jan 14 09:22:31 host sshd[1234]: Failed password for root "
              "from 10.0.0.5 port 55512 ssh2")
    guard = r"^sshd\[\d+\]:"
    assert app.generalize_guard(sample, guard) == (guard, [])


def test_structural_guard_uses_generic_capture_tokens():
    sample = "src=10.0.0.5 port=55512 action=allow"
    ranges = _captures(sample, [
        ("src_ip", "IP", "10.0.0.5"),
        ("src_port", "POSINT", "55512"),
        ("action", "WORD", "allow"),
    ])
    guard = app.structural_guard(sample, ranges)
    assert "10.0.0.5" not in guard
    assert "55512" not in guard
    assert "allow" not in guard
    assert app.guard_for_sample(sample, guard) == (guard, "")


def test_structural_guard_generalizes_uncaptured_digits():
    # The model missed the port, so it is in a literal gap - the structural
    # guard must still not hard-code it.
    sample = "accepted connection on port 55512"
    ranges = _captures(sample, [("word", "WORD", "accepted")])
    guard = app.structural_guard(sample, ranges)
    assert "55512" not in guard
    assert r"\d+" in guard
    assert app.guard_for_sample(sample, guard) == (guard, "")


def test_rule_duplicates_route_reports_exact_match(monkeypatch):
    ranges = [{"key": "a", "pattern": "WORD", "start": 0, "end": 5},
              {"key": "b", "pattern": "WORD", "start": 6, "end": 11}]
    catalog = grok_catalog.load_catalog().by_name
    built = rule_builder.build_all("hello world", ranges,
                                   {"name": "old name"}, catalog)
    existing_src = built["rule"]

    class FakeClient:
        def list_rules(self):
            return [{"id": "r1", "title": "old name", "source": existing_src}]

    monkeypatch.setattr(app, "graylog_client", lambda: (FakeClient(), None))
    client = app.app.test_client()
    resp = client.post("/api/rule/duplicates", json={
        "sample": "hello world",
        "ranges": ranges,
        "config": {"name": "new name"},
    })
    assert resp.status_code == 200
    out = resp.get_json()
    assert out["checked"] == 1
    assert out["exact"] == [{"id": "r1", "title": "old name"}]


def test_rule_push_renames_when_title_is_taken(monkeypatch):
    seen = {}

    class FakeClient:
        def list_rules(self):
            return [{"title": "MyRule"}]

        def parse_rule(self, source):
            seen["parsed"] = source
            return {"errors": None}

        def create_rule(self, title, description, source):
            seen["title"], seen["source"] = title, source
            return {"id": "rule-1", "title": title}

        def add_rule_to_pipeline(self, name, title):
            seen["pipe_rule"] = title
            return {"id": "pipe-1", "title": name, "created": False,
                    "rule_added": title}

    monkeypatch.setattr(app, "graylog_client", lambda: (FakeClient(), None))
    monkeypatch.setattr(app.examples, "add_example", lambda *a, **k: None)
    client = app.app.test_client()
    resp = client.post("/api/rule/push", json={
        "sample": "hello world",
        "ranges": [{"key": "a", "pattern": "WORD", "start": 0, "end": 5}],
        "config": {"name": "MyRule", "description": "desc"},
        "pipeline_name": "pfSense",
    })
    assert resp.status_code == 200
    assert seen["title"] == "MyRule-2"
    assert seen["parsed"].startswith('rule "MyRule-2"')
    assert seen["source"].startswith('rule "MyRule-2"')
    assert seen["pipe_rule"] == "MyRule-2"
    assert resp.get_json()["title"] == "MyRule-2"


def test_rule_push_reports_pipeline_failure_without_undoing_rule(monkeypatch):
    class FakeClient:
        def list_rules(self):
            return []

        def parse_rule(self, source):
            return {"errors": None}

        def create_rule(self, title, description, source):
            return {"id": "rule-1", "title": title}

        def add_rule_to_pipeline(self, name, title):
            raise app.GraylogError("forbidden")

    monkeypatch.setattr(app, "graylog_client", lambda: (FakeClient(), None))
    monkeypatch.setattr(app.examples, "add_example", lambda *a, **k: None)
    client = app.app.test_client()
    resp = client.post("/api/rule/push", json={
        "sample": "hello world",
        "ranges": [{"key": "a", "pattern": "WORD", "start": 0, "end": 5}],
        "config": {"name": "MyRule", "description": "desc"},
        "pipeline_name": "pfSense",
    })
    assert resp.status_code == 200
    out = resp.get_json()
    assert out["created"]["id"] == "rule-1"
    assert "forbidden" in out["pipeline"]["error"]
