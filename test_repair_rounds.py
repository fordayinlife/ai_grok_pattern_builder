import app
import grok_catalog

CAT = grok_catalog.load_catalog().by_name
SAMPLE = "Jan 14 09:22:31 host sshd[1234]: Failed password for root from 10.0.0.5 port 55512 ssh2"


def _segs(ts_pattern):
    return [
        {"type": "capture", "key": "ts", "pattern": ts_pattern,
         "value": "Jan 14 09:22:31"},
        {"type": "text", "value": " "},
        {"type": "capture", "key": "host", "pattern": "HOSTNAME", "value": "host"},
    ]


def _client(monkeypatch, answers, max_repairs, enrich=False):
    """POST /api/generate with generate_segments stubbed to consume `answers`."""
    calls = []

    def fake_generate_segments(base_url, model, sample, catalog_names,
                               timeout=300.0, feedback=None, context="",
                               examples=None, field_names=None):
        calls.append(feedback)
        segs = answers[min(len(calls) - 1, len(answers) - 1)]
        return segs, {"model": "test", "raw": "", "attempts": 1}

    monkeypatch.setattr(app.llm, "generate_segments", fake_generate_segments)
    client = app.app.test_client()
    resp = client.post("/api/generate", json={
        "sample": SAMPLE, "max_repairs": max_repairs, "enrich": enrich,
    })
    return resp, calls


def _enriched_segs():
    return _segs("SYSLOGTIMESTAMP") + [
        {"type": "text", "value": " sshd["},
        {"type": "capture", "key": "pid", "pattern": "POSINT", "value": "1234"},
    ]


def test_zero_repairs_is_a_single_model_call(monkeypatch):
    resp, calls = _client(monkeypatch, [_segs("TIMESTAMP_ISO8601")], 0)
    assert resp.status_code == 200
    assert len(calls) == 1
    assert resp.get_json()["repaired"] is False


def test_repair_rounds_stop_early_once_full(monkeypatch):
    # first answer has a broken ts pattern; second one is correct -> only
    # one repair round is spent even though three were allowed.
    resp, calls = _client(
        monkeypatch,
        [_segs("TIMESTAMP_ISO8601"), _segs("SYSLOGTIMESTAMP")],
        3,
    )
    data = resp.get_json()
    assert resp.status_code == 200
    assert len(calls) == 2          # initial + exactly one repair
    assert data["repaired"] is True
    assert data["status"] == "full"


def test_repair_rounds_keep_trying_while_not_full(monkeypatch):
    resp, calls = _client(
        monkeypatch,
        [_segs("TIMESTAMP_ISO8601"), _segs("NUMBER"),
         _segs("WORD"), _segs("SYSLOGTIMESTAMP")],
        3,
    )
    data = resp.get_json()
    assert len(calls) == 4          # initial + 3 repair rounds
    assert data["repaired"] is True
    assert data["status"] == "full"


def test_repair_rounds_never_drop_captures(monkeypatch):
    # a repair that loses the `host` capture must be rejected each round
    lost = [_segs("TIMESTAMP_ISO8601"),
            [{"type": "capture", "key": "ts", "pattern": "SYSLOGTIMESTAMP",
              "value": "Jan 14 09:22:31"}]]
    resp, calls = _client(monkeypatch, lost, 2)
    data = resp.get_json()
    assert data["repaired"] is False
    keys = {r["key"] for r in data["ranges"]}
    assert keys == {"ts", "host"}


def test_max_repairs_is_clamped_to_five(monkeypatch):
    resp, calls = _client(
        monkeypatch,
        [_segs("TIMESTAMP_ISO8601")] + [_segs("TIMESTAMP_ISO8601")] * 20,
        99,
    )
    resp.get_json()
    assert len(calls) <= 1 + 5      # initial + at most 5 rounds


def test_enrich_adds_missing_capture_on_a_full_match(monkeypatch):
    # base answer already fully matches, so the repair loop does nothing; the
    # enrich pass adds the `pid` field that was left as literal text.
    resp, calls = _client(
        monkeypatch,
        [_segs("SYSLOGTIMESTAMP"), _enriched_segs()],
        0,
        enrich=True,
    )
    data = resp.get_json()
    assert len(calls) == 2                  # initial + exactly one enrich pass
    assert data["enriched"] is True
    assert data["status"] == "full"
    assert {r["key"] for r in data["ranges"]} == {"ts", "host", "pid"}


def test_enrich_runs_at_most_once(monkeypatch):
    # even with a large repair budget, enrich is capped at a single pass
    resp, calls = _client(
        monkeypatch,
        [_segs("SYSLOGTIMESTAMP")] + [_enriched_segs()] * 10,
        5,
        enrich=True,
    )
    data = resp.get_json()
    assert len(calls) == 2
    assert data["enriched"] is True


def test_enrich_disabled_skips_the_extra_pass(monkeypatch):
    resp, calls = _client(
        monkeypatch,
        [_segs("SYSLOGTIMESTAMP"), _enriched_segs()],
        0,
        enrich=False,
    )
    data = resp.get_json()
    assert len(calls) == 1
    assert data["enriched"] is False
    assert {r["key"] for r in data["ranges"]} == {"ts", "host"}


def test_enrich_rejected_when_it_drops_a_capture(monkeypatch):
    dropped = [{"type": "capture", "key": "ts",
                "pattern": "SYSLOGTIMESTAMP", "value": "Jan 14 09:22:31"},
               {"type": "capture", "key": "pid", "pattern": "POSINT",
                "value": "1234"}]
    resp, calls = _client(
        monkeypatch,
        [_segs("SYSLOGTIMESTAMP"), dropped],
        0,
        enrich=True,
    )
    data = resp.get_json()
    assert data["enriched"] is False
    assert {r["key"] for r in data["ranges"]} == {"ts", "host"}
