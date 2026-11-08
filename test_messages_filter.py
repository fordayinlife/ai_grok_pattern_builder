"""Tests for POST /api/messages and the uncovered-message scan."""

import app
import grok_catalog
import rule_builder
import rule_matcher

CAT = grok_catalog.load_catalog().by_name
ACCESS_GROK = (r'%{IP:src_ip} - - \[%{HTTPDATE:ts}\] '
               r'%{QS:request} %{NUMBER:code} %{NUMBER:bytes}')
ACCESS = '10.0.0.5 - - [10/Oct/2026:13:55:36 -0700] "GET /a HTTP/1.1" 200 2326'
SYSLOG = "Oct 09 09:22:31 gw sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2"


def _msg(text, extra=None):
    fields = {"message": text}
    fields.update(extra or {})
    return {"id": text[:8], "message": text, "timestamp": "t",
            "input_title": "in", "fields": fields}


class FakeClient:
    """Search results and rules, recorded so the paging can be asserted.

    `pages` maps a search offset to the messages Graylog would return from it,
    so a test can lay out exactly how many messages each page holds.
    """

    def __init__(self, pages, rules=None):
        self.pages = pages
        self.rules = rules if rules is not None else []
        self.search_calls = []

    def search_messages(self, query, range_seconds, limit, offset=0):
        self.search_calls.append((query, range_seconds, limit, offset))
        return list(self.pages.get(offset, []))

    def list_rules(self):
        return list(self.rules)


def _post(monkeypatch, client, **payload):
    monkeypatch.setattr(app, "graylog_client", lambda: (client, None))
    return app.app.test_client().post("/api/messages", json=payload)


def _rule(grok=ACCESS_GROK, **cfg):
    cfg.setdefault("name", "nginx access")
    source = rule_builder.build_rule(grok, cfg)
    return {"title": cfg["name"], "source": source}


def test_unfiltered_behaviour_is_unchanged(monkeypatch):
    client = FakeClient({0: [_msg(ACCESS), _msg(SYSLOG)]}, rules=[_rule()])
    resp = _post(monkeypatch, client, query="*", range=3600, limit=5,
                 require_unmatched=False)
    body = resp.get_json()
    assert resp.status_code == 200
    assert [m["message"] for m in body["messages"]] == [ACCESS, SYSLOG]
    assert body["scanned"] == 2 and body["covered"] == 0
    assert body["filtered"] is False
    assert body["rules_used"] == 0
    assert client.search_calls[0][3] == 0        # offset is sent
    assert client.search_calls[0][2] == 5        # one page, nothing paged


def test_filtering_is_the_default(monkeypatch):
    # No `require_unmatched` in the payload: the covered message is dropped,
    # which is the behaviour the UI checkbox relies on.
    client = FakeClient({0: [_msg(ACCESS), _msg(SYSLOG)]}, rules=[_rule()])
    body = _post(monkeypatch, client, limit=5).get_json()
    assert [m["message"] for m in body["messages"]] == [SYSLOG]
    assert body["filtered"] is True
    assert body["covered"] == 1


def test_covered_messages_are_filtered_out(monkeypatch):
    client = FakeClient({0: [_msg(ACCESS), _msg(SYSLOG)]},
                        rules=[_rule()])
    resp = _post(monkeypatch, client, limit=10, require_unmatched=True)
    body = resp.get_json()
    assert [m["message"] for m in body["messages"]] == [SYSLOG]
    assert body["covered"] == 1
    assert body["rules_used"] == 1
    assert body["unparsed_rules"] == 0
    assert body["filtered"] is True


def test_it_keeps_scanning_until_enough_are_found(monkeypatch):
    # Three pages, the first two are already covered.
    client = FakeClient({k: [_msg(ACCESS) for _ in range(50)]
                         for k in (0, 50, 100)}
                        | {150: [_msg(SYSLOG)]}, rules=[_rule()])
    resp = _post(monkeypatch, client, limit=1, max_scan=300)
    body = resp.get_json()
    assert len(body["messages"]) == 1
    assert body["messages"][0]["message"] == SYSLOG
    assert body["scanned"] == 151
    assert body["covered"] == 150
    assert [c[3] for c in client.search_calls] == [0, 50, 100, 150]


def test_it_stops_at_max_scan(monkeypatch):
    client = FakeClient({k: [_msg(ACCESS) for _ in range(50)] for k in range(0, 1000, 50)},
                        rules=[_rule()])
    resp = _post(monkeypatch, client, limit=10, max_scan=120)
    body = resp.get_json()
    assert body["scanned"] == 120                # 50 + 50 + 20, stopped there
    assert body["messages"] == []
    assert len(client.search_calls) == 3


def test_exhausted_is_reported_when_the_search_runs_dry(monkeypatch):
    client = FakeClient({0: [_msg(ACCESS)]}, rules=[_rule()])
    resp = _post(monkeypatch, client, limit=5, max_scan=300)
    body = resp.get_json()
    assert body["messages"] == []
    assert body["exhausted"] is True
    assert body["scanned"] == 1


def test_short_pages_end_the_scan(monkeypatch):
    # Graylog returning fewer than asked means there is nothing left.
    client = FakeClient({0: [_msg(SYSLOG)]}, rules=[_rule()])
    resp = _post(monkeypatch, client, limit=5)
    body = resp.get_json()
    assert len(body["messages"]) == 1
    assert body["exhausted"] is True
    assert len(client.search_calls) == 1


def test_unreadable_rules_hide_nothing(monkeypatch):
    rules = [_rule(), {"title": "hand",
                       "source": 'rule "hand"\nwhen\n  !is_null($message.x)\n'
                                 "then\n  set_field(\"a\", \"b\");\nend\n"}]
    client = FakeClient({0: [_msg(ACCESS)]}, rules=rules)
    body = _post(monkeypatch, client, limit=5).get_json()
    assert body["rules_used"] == 1
    assert body["unparsed_rules"] == 1
    assert body["messages"] == []                # the readable rule still filtered


def test_rules_that_cannot_be_read_fall_back_to_showing_everything(monkeypatch):
    class NoRules(FakeClient):
        def list_rules(self):
            raise app.GraylogError("forbidden")

    client = NoRules({0: [_msg(ACCESS)]}, rules=[])
    resp = _post(monkeypatch, client, limit=5)
    body = resp.get_json()
    assert resp.status_code == 200
    assert [m["message"] for m in body["messages"]] == [ACCESS]
    assert "could not read the existing rules" in body["notice"]
    assert client.search_calls[0][3] == 0


def test_covers_a_rule_guarded_by_its_own_regex(monkeypatch):
    guarded = _rule(condition="regex",
                    condition_regex=r"^\d{1,3}(\.\d{1,3}){3} - - \[")
    client = FakeClient({0: [_msg(ACCESS), _msg(SYSLOG)]}, rules=[guarded])
    body = _post(monkeypatch, client, limit=5).get_json()
    assert [m["message"] for m in body["messages"]] == [SYSLOG]
    assert body["covered"] == 1


def test_a_failing_search_after_a_page_still_returns_what_we_found(monkeypatch):
    class Flaky(FakeClient):
        def __init__(self):
            super().__init__({0: [_msg(ACCESS)]}, rules=[_rule()])
            self.calls = 0

        def search_messages(self, query, range_seconds, limit, offset=0):
            self.calls += 1
            if self.calls > 1:
                raise app.GraylogError("boom")
            return super().search_messages(query, range_seconds, limit, offset)

    client = Flaky()
    body = _post(monkeypatch, client, limit=5, max_scan=300).get_json()
    assert body["messages"] == []
    assert body["scanned"] == 1


def test_a_failing_first_search_is_an_error(monkeypatch):
    class Broken(FakeClient):
        def search_messages(self, query, range_seconds, limit, offset=0):
            raise app.GraylogError("cannot reach Graylog")

    resp = _post(monkeypatch, Broken({}), limit=5)
    assert resp.status_code == 502


def test_bad_numbers_are_rejected(monkeypatch):
    client = FakeClient({0: []}, rules=[])
    for payload in ({"range": "x"}, {"limit": "x"}, {"max_scan": "x"}):
        resp = _post(monkeypatch, client, **payload)
        assert resp.status_code == 400


def test_need_and_max_scan_are_clamped(monkeypatch):
    client = FakeClient({0: [_msg(SYSLOG)] * 30}, rules=[])
    body = _post(monkeypatch, client, limit=500, max_scan=9000,
                 require_unmatched=True).get_json()
    assert len(body["messages"]) == 30           # all 30 came through
    assert client.search_calls[0][2] == 50       # but only one page was asked for
    assert body["scanned"] == 30


def test_a_page_larger_than_asked_for_is_clipped(monkeypatch):
    # Graylog should never do this, but a page we did not ask for must not
    # push the scan past its budget.
    client = FakeClient({k: [_msg(ACCESS)] * 50 for k in range(0, 1000, 50)},
                        rules=[_rule()])
    body = _post(monkeypatch, client, limit=10, max_scan=120).get_json()
    assert body["scanned"] == 120
    assert [c[2] for c in client.search_calls] == [50, 50, 20]


def test_require_unmatched_accepts_a_string(monkeypatch):
    client = FakeClient({0: [_msg(ACCESS)]}, rules=[_rule()])
    body = _post(monkeypatch, client, limit=5,
                 require_unmatched="true").get_json()
    assert body["messages"] == []                # string "true" still filters
