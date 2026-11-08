import pytest

import app
import examples
import rule_builder

SAMPLE = "Jan 14 09:22:31 host sshd[1234]: Failed password for root from 10.0.0.5 port 55512 ssh2"


@pytest.fixture(autouse=True)
def isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(examples, "EXAMPLES_FILE", tmp_path / "examples.json")
    return tmp_path / "examples.json"


def _segments():
    return [
        {"type": "capture", "key": "ts", "pattern": "SYSLOGTIMESTAMP",
         "value": "Jan 14 09:22:31"},
        {"type": "text", "value": " "},
        {"type": "capture", "key": "host", "pattern": "HOSTNAME", "value": "host"},
        {"type": "text", "value": " sshd["},
        {"type": "capture", "key": "pid", "pattern": "POSINT", "value": "1234"},
    ]


def test_add_and_load_round_trip():
    assert examples.load_examples() == []
    entry = examples.add_example(SAMPLE, _segments(), source="manual")
    assert entry["id"]
    loaded = examples.load_examples()
    assert len(loaded) == 1
    assert loaded[0]["sample"] == SAMPLE
    assert loaded[0]["segments"] == _segments()


def test_add_same_sample_updates_in_place():
    first = examples.add_example(SAMPLE, _segments(), source="manual")
    second = examples.add_example(SAMPLE, _segments()[:1], source="push")
    assert second["id"] == first["id"]
    assert second["source"] == "push"
    assert len(examples.load_examples()) == 1


def test_add_rejects_empty_sample_and_bad_segments():
    with pytest.raises(ValueError):
        examples.add_example("   ", _segments())
    with pytest.raises(ValueError):
        examples.add_example(SAMPLE, [])


def test_update_and_delete():
    entry = examples.add_example(SAMPLE, _segments())
    updated = examples.update_example(entry["id"], SAMPLE + "x", _segments()[:1])
    assert updated["sample"].endswith("x")
    assert examples.update_example("nope", SAMPLE, _segments()) is None
    assert examples.delete_example(entry["id"]) is True
    assert examples.delete_example(entry["id"]) is False


def test_clear_returns_count():
    examples.add_example(SAMPLE, _segments())
    examples.add_example(SAMPLE + "2", _segments())
    assert examples.clear_examples() == 2
    assert examples.load_examples() == []


def test_select_examples_prefers_similar():
    examples.add_example("completely different line about cats", _segments())
    examples.add_example(SAMPLE, _segments())
    picked = examples.select_examples(SAMPLE, 1)
    assert picked and picked[0]["sample"] == SAMPLE


def test_select_examples_ranks_a_small_store_too():
    # Fewer examples than slots: still ranked, closest first, not simply the
    # newest entries.
    examples.add_example("completely different line about cats", _segments())
    examples.add_example(SAMPLE, _segments())
    picked = examples.select_examples(SAMPLE, 5)
    assert [e["sample"] for e in picked] == [SAMPLE,
                                            "completely different line about cats"]


def test_select_examples_is_stable_for_equal_similarity():
    examples.add_example("aaa", _segments())
    examples.add_example("bbb", _segments())
    assert examples.select_examples("ccc", 2) == \
        examples.select_examples("ccc", 2)


def test_ranges_to_segments_round_trips_through_anchor():
    ranges = [
        {"key": "ts", "pattern": "SYSLOGTIMESTAMP", "start": 0, "end": 15},
        {"key": "host", "pattern": "HOSTNAME", "start": 16, "end": 20},
        {"key": "pid", "pattern": "POSINT", "start": 26, "end": 30},
    ]
    segments = rule_builder.ranges_to_segments(SAMPLE, ranges)
    back, warnings = rule_builder.anchor_segments(SAMPLE, segments)
    assert warnings == []
    assert back == ranges


def test_prompt_includes_examples():
    prompt = app.llm.build_system_prompt(["IP", "WORD"], examples_models())
    assert "Examples Learned From This Environment" in prompt
    assert "Example 1 line" in prompt


def examples_models():
    return [{"sample": SAMPLE, "segments": _segments()}]


# ---------------------------------------------------------------- HTTP routes

def _client(monkeypatch):
    monkeypatch.setattr(app.llm, "generate_segments",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no llm")))
    return app.app.test_client()


def test_examples_route_crud(monkeypatch):
    client = _client(monkeypatch)
    ranges = [
        {"key": "ts", "pattern": "SYSLOGTIMESTAMP", "start": 0, "end": 15},
        {"key": "host", "pattern": "HOSTNAME", "start": 16, "end": 20},
    ]
    r = client.post("/api/examples", json={"sample": SAMPLE, "ranges": ranges})
    assert r.status_code == 200
    created = r.get_json()
    assert created["ok"] is True
    assert created["stats"]["count"] == 1
    example_id = created["example"]["id"]
    assert created["example"]["segments"][0]["type"] == "capture"

    listed = client.get("/api/examples").get_json()
    assert listed["stats"]["count"] == 1
    assert "in_prompt" in listed

    upd = client.post(f"/api/examples/{example_id}",
                      json={"sample": SAMPLE + "!", "segments": _segments()})
    assert upd.status_code == 200
    assert upd.get_json()["example"]["sample"].endswith("!")

    dele = client.delete(f"/api/examples/{example_id}")
    assert dele.status_code == 200
    assert dele.get_json()["stats"]["count"] == 0


def test_examples_route_rejects_bad_payload(monkeypatch):
    client = _client(monkeypatch)
    assert client.post("/api/examples", json={"sample": ""}).status_code == 400
    assert client.post("/api/examples", json={"sample": SAMPLE}).status_code == 400
    assert client.post("/api/examples/unknown",
                       json={"sample": SAMPLE, "segments": _segments()}).status_code == 404
    assert client.delete("/api/examples/unknown").status_code == 404


def test_examples_clear_route(monkeypatch):
    client = _client(monkeypatch)
    client.post("/api/examples", json={"sample": SAMPLE, "segments": _segments()})
    out = client.post("/api/examples/clear", json={}).get_json()
    assert out["removed"] == 1
    assert out["stats"]["count"] == 0


def test_generate_uses_examples(monkeypatch):
    examples.add_example(SAMPLE, _segments())
    captured = {}

    def fake(base_url, model, sample, catalog_names, timeout=300.0,
             feedback=None, context="", examples=None, field_names=None):
        captured["examples"] = examples
        return _segments(), {"model": model, "raw": "", "attempts": 1}

    monkeypatch.setattr(app.llm, "generate_segments", fake)
    client = app.app.test_client()
    resp = client.post("/api/generate", json={"sample": SAMPLE})
    assert resp.status_code == 200
    assert resp.get_json()["examples_used"] == 1
    assert captured["examples"] and captured["examples"][0]["sample"] == SAMPLE


def test_generate_returns_suggested_name_and_description(monkeypatch):
    def fake(base_url, model, sample, catalog_names, timeout=300.0,
             feedback=None, context="", examples=None, field_names=None):
        return _segments(), {"model": model, "raw": "", "attempts": 1,
                             "name": "Firewall block event",
                             "description": "A pfSense block log line."}

    monkeypatch.setattr(app.llm, "generate_segments", fake)
    client = app.app.test_client()
    resp = client.post("/api/generate", json={"sample": SAMPLE, "enrich": False})
    assert resp.status_code == 200
    out = resp.get_json()
    assert out["suggested_name"] == "Firewall block event"
    assert out["suggested_description"] == "A pfSense block log line."
