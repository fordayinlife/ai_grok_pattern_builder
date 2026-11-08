import graylog_client


def make_client():
    return graylog_client.GraylogClient("http://graylog.local/api", "tok")


def test_get_input_titles_reads_id_and_config_title(monkeypatch):
    c = make_client()

    def fake(method, path, **kwargs):
        assert (method, path) == ("GET", "/system/inputs")
        return {"inputs": [
            {"id": "abc", "title": "pfSense"},
            {"id": "def", "configuration": {"title": "unraid"}},
            {"id": "ghi"},
        ]}

    monkeypatch.setattr(c, "_request", fake)
    assert c.get_input_titles() == {"abc": "pfSense", "def": "unraid"}


def test_search_messages_resolves_input_title(monkeypatch):
    c = make_client()

    def fake(method, path, **kwargs):
        if path == "/search/universal/relative":
            return {"messages": [
                {"index": "i1", "message": {"id": "1", "message": "hi",
                                            "gl2_source_input": "abc"}},
                {"index": "i2", "message": {"id": "2", "message": "yo",
                                            "gl2_source_input": "xyz"}},
            ]}
        if path == "/system/inputs":
            return {"inputs": [{"id": "abc", "title": "pfSense"}]}
        raise AssertionError(path)

    monkeypatch.setattr(c, "_request", fake)
    msgs = c.search_messages("*")
    assert msgs[0]["input_id"] == "abc"
    assert msgs[0]["input_title"] == "pfSense"
    assert msgs[1]["input_title"] is None
    assert msgs[0]["fields"]["message"] == "hi"


def test_search_messages_degrades_when_input_lookup_fails(monkeypatch):
    c = make_client()

    def fake(method, path, **kwargs):
        if path == "/search/universal/relative":
            return {"messages": [
                {"message": {"id": "1", "message": "hi", "gl2_source_input": "abc"}},
            ]}
        raise graylog_client.GraylogError("forbidden")

    monkeypatch.setattr(c, "_request", fake)
    msgs = c.search_messages("*")
    assert msgs[0]["input_title"] is None


def test_list_fields_sends_limit_and_sorts(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        seen["method"] = method
        seen["path"] = path
        seen["params"] = kwargs.get("params")
        return {"fields": ["zeta", "alpha", "beta"]}

    monkeypatch.setattr(c, "_request", fake)
    assert c.list_fields(limit=7) == ["alpha", "beta", "zeta"]
    assert (seen["method"], seen["path"]) == ("GET", "/system/fields")
    assert seen["params"] == {"limit": 7}


def test_list_rules_returns_list_and_wraps_dict(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        seen[path] = True
        return {"rules": [{"id": "r1", "title": "nginx - accesslog"}]}

    monkeypatch.setattr(c, "_request", fake)
    assert c.list_rules() == [{"id": "r1", "title": "nginx - accesslog"}]
    assert seen["/system/pipelines/rule"]


def test_simulate_rule_payload(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        seen["method"] = method
        seen["path"] = path
        seen["json"] = kwargs.get("json")
        return {"message": {}}

    monkeypatch.setattr(c, "_request", fake)
    c.simulate_rule('rule "r"\nwhen true\nthen\nend', "hello")
    assert seen["method"] == "POST"
    assert seen["path"] == "/system/pipelines/rule/simulate"
    assert seen["json"]["message"] == "hello"
    assert seen["json"]["rule_source"]["source"].startswith("rule")


def test_add_rule_to_pipeline_creates_when_missing(monkeypatch):
    c = make_client()
    calls = []

    def fake(method, path, **kwargs):
        calls.append((method, path, kwargs.get("json")))
        if method == "GET" and path == "/system/pipelines/pipeline":
            return []
        if method == "POST" and path == "/system/pipelines/pipeline":
            return {"id": "p1", "title": "pfSense", "source": "ignored"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out == {"id": "p1", "title": "pfSense", "created": True,
                   "rule_added": "MyRule"}
    post_json = [j for (m, p, j) in calls if m == "POST"][0]
    assert post_json["title"] == "pfSense"
    assert 'pipeline "pfSense"' in post_json["source"]
    assert "stage 0 match either" in post_json["source"]
    assert 'rule "MyRule"' in post_json["source"]


def test_add_rule_to_pipeline_updates_existing_stage0(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": 0, "match": "EITHER", "rules": ["OldRule"]}],
                    "source": 'pipeline "pfSense"\nstage 0 match either\nrule "OldRule"\nend'}
        if method == "PUT" and path == "/system/pipelines/pipeline/p1":
            seen["put"] = kwargs["json"]
            return {"id": "p1", "title": "pfSense"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out["rule_added"] == "MyRule"
    assert out["created"] is False
    src = seen["put"]["source"]
    assert 'rule "MyRule"' in src
    assert src.index('rule "MyRule"') < src.index('rule "OldRule"')


def test_add_rule_to_pipeline_is_case_insensitive(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": 0, "match": "EITHER",
                                "rules": ["OldRule", "MyRule"]}],
                    "source": 'pipeline "pfSense"\nstage 0 match either'
                              '\nrule "OldRule"\nrule "MyRule"\nend'}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "myrule")
    assert out["rule_added"] is None
    assert out["already_present"] is True


def test_add_rule_to_pipeline_adds_stage0_when_missing(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": 1, "match": "ALL", "rules": ["A"]}],
                    "source": 'pipeline "pfSense"\nstage 1 match all\nrule "A"\nend'}
        if method == "PUT" and path == "/system/pipelines/pipeline/p1":
            seen["put"] = kwargs["json"]
            return {"id": "p1", "title": "pfSense"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out["rule_added"] == "MyRule"
    src = seen["put"]["source"]
    assert "stage 0 match either" in src
    assert src.index("stage 0") < src.index("stage 1")


def test_add_rule_to_pipeline_still_inserts_when_stage_metadata_lies(monkeypatch):
    # The stage list claims the rule is present but the source never references
    # it - trusting only the metadata would leave a rule that never runs.
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": 0, "match": "EITHER", "rules": ["MyRule"]}],
                    "source": 'pipeline "pfSense"\nstage 0 match either\nend'}
        if method == "PUT" and path == "/system/pipelines/pipeline/p1":
            seen["put"] = kwargs["json"]
            return {"id": "p1", "title": "pfSense"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out.get("already_present") is None
    assert 'rule "MyRule"' in seen["put"]["source"]


def test_add_rule_to_pipeline_skips_rule_referenced_only_in_source(monkeypatch):
    # ...and the reverse: the source references it, the metadata does not.
    c = make_client()
    calls = []

    def fake(method, path, **kwargs):
        calls.append((method, path))
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [],
                    "source": 'pipeline "pfSense"\nstage 0 match either\n'
                              'rule "MyRule"\nrule "Other"\nend'}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "myrule")
    assert out["already_present"] is True
    assert ("PUT", "/system/pipelines/pipeline/p1") not in calls


def test_add_rule_to_pipeline_ignores_rules_from_other_stages(monkeypatch):
    # A rule referenced in stage 1 must not stop the stage-0 insert.
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": 1, "match": "ALL", "rules": ["MyRule"]}],
                    "source": 'pipeline "pfSense"\nstage 1 match all\n'
                              'rule "MyRule"\nend'}
        if method == "PUT" and path == "/system/pipelines/pipeline/p1":
            seen["put"] = kwargs["json"]
            return {"id": "p1", "title": "pfSense"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out.get("already_present") is None
    src = seen["put"]["source"]
    assert src.count('rule "MyRule"') == 2      # stage 0 reference added


def test_add_rule_to_pipeline_survives_a_non_numeric_stage(monkeypatch):
    c = make_client()
    seen = {}

    def fake(method, path, **kwargs):
        if method == "GET" and path == "/system/pipelines/pipeline":
            return [{"id": "p1", "title": "pfSense"}]
        if method == "GET" and path == "/system/pipelines/pipeline/p1":
            return {"id": "p1", "title": "pfSense", "description": "",
                    "stages": [{"stage": "zero", "match": "EITHER"}],
                    "source": 'pipeline "pfSense"\nstage 0 match either\nend'}
        if method == "PUT" and path == "/system/pipelines/pipeline/p1":
            seen["put"] = kwargs["json"]
            return {"id": "p1", "title": "pfSense"}
        raise AssertionError((method, path))

    monkeypatch.setattr(c, "_request", fake)
    out = c.add_rule_to_pipeline("pfSense", "MyRule")
    assert out["rule_added"] == "MyRule"
    assert 'rule "MyRule"' in seen["put"]["source"]


def test_stage0_rule_titles_reads_the_right_block():
    src = ('pipeline "p"\nstage 1 match all\nrule "Skip"\n'
           'stage 0 match either\nrule "Keep"\nend')
    assert graylog_client._stage0_rule_titles(src) == ["Keep"]
    assert graylog_client._stage0_rule_titles("") == []
