"""Regression tests for /api/generate warning assembly and model round args."""

import app

# Two captures whose own pattern cannot match their value, so the deterministic
# autofix pass rewrites BOTH patterns and must report BOTH fixes.
SAMPLE = "vnStat daemon 2.13 (pid:44820 uid:0 gid:0, SQLite 3.53.1)"
SEGMENTS = [
    {"type": "text", "value": "vnStat daemon "},
    # value not present in the sample -> anchor_segments warns and skips it
    {"type": "capture", "key": "ghost", "pattern": "WORD", "value": "nope"},
    {"type": "capture", "key": "version", "pattern": "IP", "value": "2.13"},
    {"type": "text", "value": " (pid:"},
    {"type": "capture", "key": "uid", "pattern": "POSINT", "value": "0"},
    {"type": "text", "value": ", SQLite "},
    {"type": "capture", "key": "sqlite", "pattern": "IP", "value": "3.53.1"},
    {"type": "text", "value": ")"},
]


def _client(monkeypatch, answers, **kwargs):
    """POST /api/generate with generate_segments stubbed to consume `answers`."""
    calls = []

    def fake_generate_segments(base_url, model, sample, catalog_names,
                               timeout=300.0, feedback=None, context="",
                               examples=None, field_names=None):
        calls.append({"feedback": feedback, "examples": examples,
                      "field_names": field_names})
        return answers[min(len(calls) - 1, len(answers) - 1)], {
            "attempts": 1, "raw": "", "name": "", "description": "", "guard": "",
        }

    monkeypatch.setattr(app.llm, "generate_segments", fake_generate_segments)
    client = app.app.test_client()
    payload = {"sample": SAMPLE, "max_repairs": 0, "model": "m"}
    payload.update(kwargs)
    resp = client.post("/api/generate", json=payload)
    return resp, calls


def test_every_autofix_change_is_reported(monkeypatch):
    resp, _calls = _client(monkeypatch, [SEGMENTS])
    assert resp.status_code == 200
    data = resp.get_json()
    assert len(data["autofixed"]) >= 2
    notes = [w for w in data["warnings"] if w.startswith("auto-corrected ")]
    assert len(notes) == len(data["autofixed"])
    for change in data["autofixed"]:
        assert f"auto-corrected {change['key']}: {change['from']} -> " \
               f"{change['to']}" in data["warnings"]


def test_autofix_warnings_do_not_erase_the_others(monkeypatch):
    # Anything already warned about before the autofix block must survive it.
    resp, _calls = _client(monkeypatch, [SEGMENTS])
    data = resp.get_json()
    assert data["autofixed"]
    assert any("overlap" in w or "not found" in w for w in data["warnings"])


def test_json_response_keys_keep_their_order():
    assert app.app.json.sort_keys is False


def test_examples_are_offered_to_every_model_round(monkeypatch):
    monkeypatch.setattr(app.examples, "select_examples",
                        lambda sample, limit: [{"sample": "other line",
                                                "segments": []}])
    resp, calls = _client(monkeypatch, [SEGMENTS], max_repairs=3, enrich=True)
    assert resp.status_code == 200
    assert len(calls) >= 2                     # initial + at least one round
    for call in calls:
        assert call["examples"] == [{"sample": "other line", "segments": []}]
