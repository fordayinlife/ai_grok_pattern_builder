"""Tests for the push flow: simulate-before-create and verified-only learning."""

import app
import grok_catalog
import rule_builder

CAT = grok_catalog.load_catalog().by_name


def _payload(status="full"):
    """A generate-like payload whose grok either matches or does not."""
    sample = "Jan 14 09:22:31 host sshd[1234]: Failed password for root"
    if status == "full":
        ranges = [
            {"key": "ts", "pattern": "SYSLOGTIMESTAMP", "start": 0, "end": 15},
            {"key": "host", "pattern": "HOSTNAME", "start": 16, "end": 20},
            {"key": "pid", "pattern": "POSINT", "start": 26, "end": 30},
        ]
    else:
        ranges = [
            {"key": "ts", "pattern": "TIMESTAMP_ISO8601", "start": 0, "end": 15},
            {"key": "rest", "pattern": "WORD", "start": 16, "end": 20},
        ]
        assert app.pattern_status(sample, ranges, CAT) != "full"
    return sample, ranges


class FakeClient:
    """Records the Graylog calls a push makes."""

    def __init__(self, simulated=None):
        self.simulated = simulated
        self.simulate_calls = []
        self.created = []

    def list_rules(self):
        return []

    def parse_rule(self, source):
        return {"errors": None}

    def simulate_rule(self, source, message):
        self.simulate_calls.append((source, message))
        return self.simulated

    def create_rule(self, title, description, source):
        self.created.append((title, source))
        return {"id": "rule-1", "title": title}

    def add_rule_to_pipeline(self, name, title):
        return {"id": "pipe-1", "title": name, "created": True,
                "rule_added": title}


class NoSimulateClient(FakeClient):
    """A Graylog (or client) without the simulate endpoint."""

    simulate_rule = None


def _push(monkeypatch, client, sample, ranges):
    monkeypatch.setattr(app, "graylog_client", lambda: (client, None))
    learned = []
    monkeypatch.setattr(app.examples, "add_example",
                        lambda *a, **k: learned.append((a, k)))
    resp = app.app.test_client().post("/api/rule/push", json={
        "sample": sample,
        "ranges": ranges,
        "config": {"name": "MyRule", "description": "desc"},
    })
    return resp, learned


def test_push_simulates_the_rule_before_creating_it(monkeypatch):
    sample, ranges = _payload()
    client = FakeClient(simulated={"fields": {"ts": "Jan 14 09:22:31"},
                                   "field_names": ["ts", "host", "pid"]})
    resp, _ = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 200
    assert len(client.simulate_calls) == 1
    # simulated against the very sample the rule was built from
    assert client.simulate_calls[0][1] == sample
    assert len(client.created) == 1
    assert resp.get_json()["simulated"]["field_names"] == ["ts", "host", "pid"]
    assert resp.get_json()["simulation_warning"] == ""


def test_push_refuses_a_rule_graylog_cannot_run(monkeypatch):
    sample, ranges = _payload()
    client = FakeClient(simulated={"errors": ["undefined grok pattern {NOPE}"]})
    resp, _ = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 422
    assert "undefined grok pattern" in resp.get_json()["error"]
    assert client.created == []                     # nothing was created


def test_push_warns_when_the_simulation_extracts_nothing(monkeypatch):
    # Graylog answers 200 with no new fields when a rule cannot run, so the
    # push must say so even though it still creates the rule.
    sample, ranges = _payload()
    client = FakeClient(simulated={"fields": {"message": sample},
                                   "field_names": ["message"]})
    resp, _ = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 200
    assert len(client.created) == 1
    warning = resp.get_json()["simulation_warning"]
    assert "ts" in warning and "pid" in warning and "never match" in warning


def test_push_tolerates_a_client_without_simulate(monkeypatch):
    sample, ranges = _payload()
    client = NoSimulateClient()
    resp, learned = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 200
    assert client.simulate_calls == []              # never called
    assert resp.get_json()["simulated"] is None
    assert resp.get_json()["simulation_warning"] == ""
    assert len(client.created) == 1                 # push still happened


def test_push_teaches_only_a_fully_matching_pattern(monkeypatch):
    sample, ranges = _payload(status="full")
    client = FakeClient(simulated={})
    resp, learned = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 200
    assert resp.get_json()["learned"] is True
    assert len(learned) == 1
    assert learned[0][0][0] == sample                # the sample was stored


def test_push_does_not_teach_a_partial_pattern(monkeypatch):
    sample, ranges = _payload(status="partial")
    client = FakeClient(simulated={})
    resp, learned = _push(monkeypatch, client, sample, ranges)
    assert resp.status_code == 200
    assert resp.get_json()["learned"] is False
    assert learned == []


def test_learned_segments_round_trip_through_ranges():
    """What is stored must anchor back onto the sample unchanged."""
    sample, ranges = _payload()
    segments = rule_builder.ranges_to_segments(sample, ranges)
    reanchored, warnings = rule_builder.anchor_segments(sample, segments)
    assert warnings == []
    assert [(r["key"], r["pattern"], r["start"], r["end"]) for r in reanchored] \
        == [(r["key"], r["pattern"], r["start"], r["end"]) for r in ranges]


def test_simulate_route_reports_local_status(monkeypatch):
    sample, ranges = _payload()
    client = FakeClient(simulated={"fields": {"ts": "x"}, "field_names": ["ts"]})
    monkeypatch.setattr(app, "graylog_client", lambda: (client, None))
    resp = app.app.test_client().post("/api/rule/simulate", json={
        "sample": sample, "ranges": ranges,
        "config": {"name": "MyRule"},
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["local_status"] == "full"
    assert body["missing_fields"] == ["host", "pid"]   # only ts came back
    assert len(client.simulate_calls) == 1


def test_simulation_missing_compares_field_names():
    sim = {"fields": {"ts": "x"}, "field_names": ["ts", "message"]}
    assert app._simulation_missing(sim, ["ts", "host"]) == ["host"]
    assert app._simulation_missing(None, ["ts"]) == []
    assert app._simulation_missing(sim, []) == []
    assert app._simulation_missing("not a dict", ["ts"]) == []


def test_simulation_error_reads_errors_field():
    assert app._simulation_error({"errors": ["boom", "bam"]}) == "boom; bam"
    assert app._simulation_error({"errors": []}) == ""
    assert app._simulation_error({"fields": {}}) == ""
    assert app._simulation_error(None) == ""


def test_captures_from_fields_needs_a_sample():
    resp = app.app.test_client().post("/api/captures/from-fields",
                                      json={"fields": {"a": "b"}})
    assert resp.status_code == 400
