"""Tests for judging whether an existing rule already handles a message."""

import pytest

import grok_catalog
import rule_builder
import rule_matcher
from rule_matcher import (ALL, CONTAINS, FIELD_EQ, FIELD_NE, HAS_FIELD, REGEX,
                          RuleParseError)


@pytest.fixture(scope="module")
def catalog():
    return grok_catalog.load_catalog().by_name


ACCESS_GROK = (r'%{IP:src_ip} - - \[%{HTTPDATE:ts}\] '
               r'%{QS:request} %{NUMBER:code} %{NUMBER:bytes}')
SAMPLE = ('10.0.0.5 - - [10/Oct/2026:13:55:36 -0700] '
          '"GET /a HTTP/1.1" 200 2326')
UNRELATED = "sshd[1234]: Failed password for root from 10.0.0.5 port 22 ssh2"

CONFIGS = {
    "always": {"condition": "always"},
    "regex": {"condition": "regex",
              "condition_regex": r"^\d{1,3}(\.\d{1,3}){3} - - \["},
    "has_field": {"condition": "has_field", "condition_field": "src_ip"},
    "contains": {"condition": "contains", "condition_field": "src_ip",
                 "condition_value": "10.0.0."},
}


def _matcher(label, catalog, **overrides):
    cfg = dict(CONFIGS[label])
    cfg.update(overrides)
    cfg.setdefault("name", label)
    return rule_matcher.parse_rule(
        rule_builder.build_rule(ACCESS_GROK, cfg), catalog, title=label)


def _condition_kinds(matcher):
    condition = matcher.condition
    if condition["kind"] == ALL:
        return [atom["kind"] for atom in condition["atoms"]]
    return [condition["kind"]]


# What each generated `when` block parses down to.
EXPECTED_KINDS = {
    "always": ["always"],
    "regex": ["regex"],
    "has_field": ["has_field"],
    "contains": ["has_field", "contains"],
}


class TestUnescapeRuleString:
    def test_round_trips_escape_rule_string(self):
        for text in [r"\[%{HTTPDATE:ts}\]", 'say "hi"', "a\\b",
                     "tab\there", "nl\nhere", "", "plain"]:
            assert rule_builder.unescape_rule_string(
                rule_builder.escape_rule_string(text)) == text

    def test_unknown_escape_is_kept(self):
        assert rule_builder.unescape_rule_string(r"a\qb") == r"a\qb"


class TestParseRule:
    def test_reads_grok_source_field_and_each_condition(self, catalog):
        for label in CONFIGS:
            m = _matcher(label, catalog)
            assert m.grok == ACCESS_GROK
            assert m.raw_grok != ACCESS_GROK      # stored escaped
            assert m.source_field == "message"
            assert _condition_kinds(m) == EXPECTED_KINDS[label]

    def test_reads_the_condition_arguments(self, catalog):
        assert _matcher("regex", catalog).condition["pattern"] \
            == r"^\d{1,3}(\.\d{1,3}){3} - - \["
        assert _matcher("has_field", catalog).condition == {
            "kind": HAS_FIELD, "field": "src_ip"}
        # build_rule emits has_field(...) && contains(...), so this is two atoms
        assert _matcher("contains", catalog).condition == {
            "kind": ALL, "atoms": [
                {"kind": HAS_FIELD, "field": "src_ip"},
                {"kind": CONTAINS, "field": "src_ip", "value": "10.0.0."}]}

    def test_reads_a_rule_matching_another_field(self, catalog):
        src = rule_builder.build_rule(r"%{DATA:raw}", {
            "name": "n", "source_field": "message"})
        # a rule that reads $message.event.id instead of the message itself
        src = src.replace("to_string($message.message)",
                          "to_string($message.`event.id`)")
        m = rule_matcher.parse_rule(src, catalog)
        assert m.source_field == "event.id"
        assert m.value_field == "event.id"

    def test_reads_a_positional_regex_condition(self, catalog):
        # Graylog's own rules write the positional form, sometimes without the
        # `.matches == true` suffix.
        for suffix in (".matches == true", "", ".matches"):
            src = rule_builder.build_rule(r"%{DATA:msg}", {"name": "n"})
            src = src.replace("true",
                              f'regex("^DHCP", to_string($message.message)){suffix}', 1)
            m = rule_matcher.parse_rule(src, catalog)
            assert m.condition == {"kind": REGEX, "pattern": "^DHCP",
                                   "field": "message"}
            assert m.covers("DHCPACK on 10.0.0.5", {}, catalog) is True
            assert m.covers("no match here", {}, catalog) is False

    def test_reads_an_uppercase_AND_and_a_field_comparison(self, catalog):
        src = rule_builder.build_rule(r"%{DATA:msg}", {"name": "n"})
        src = src.replace("true",
                          'has_field("gl2_source_input") AND '
                          'to_string($message.gl2_source_input)=="abc123"', 1)
        m = rule_matcher.parse_rule(src, catalog)
        assert _condition_kinds(m) == [HAS_FIELD, FIELD_EQ]
        assert m.condition["atoms"][1] == {"kind": FIELD_EQ,
                                           "field": "gl2_source_input",
                                           "value": "abc123"}
        assert m.covers("x", {"gl2_source_input": "abc123"}, catalog) is True
        assert m.covers("x", {"gl2_source_input": "other"}, catalog) is False

    def test_a_bare_field_comparison_of_the_wrong_field_is_not_covered(self,
                                                                       catalog):
        src = rule_builder.build_rule(r"%{DATA:msg}", {"name": "n"})
        src = src.replace("true",
                          'to_string($message.src_ip) != "10.0.0.5"', 1)
        m = rule_matcher.parse_rule(src, catalog)
        assert m.condition["kind"] == FIELD_NE
        assert m.covers("x", {"src_ip": "10.0.0.5"}, catalog) is False
        assert m.covers("x", {"src_ip": "others"}, catalog) is True
        assert m.covers("x", {}, catalog) is False   # absent field: no match

    def test_rejects_a_hand_written_condition(self, catalog):
        src = ('rule "hand"\nwhen\n  has_field("x") && !is_null($message.x)\n'
               "then\n"
               '  set_fields(grok(pattern: "%{IP:src}", '
               "value: to_string($message.message), only_named_captures: true));"
               "\nend\n")
        with pytest.raises(RuleParseError, match="unsupported when"):
            rule_matcher.parse_rule(src, catalog)

    def test_rejects_a_rule_using_unknown_patterns(self, catalog):
        src = rule_builder.build_rule("%{NOSUCH:a}", {"name": "n"})
        with pytest.raises(RuleParseError, match="does not define"):
            rule_matcher.parse_rule(src, catalog)

    def test_a_rule_that_sets_fields_without_a_grok_is_covered(self, catalog):
        # pfSense's filterlog rules split a CSV line and set dozens of fields.
        src = ('rule "filterlog"\nwhen\n  regex("^.*,(in|out),4,", '
               "to_string($message.message)).matches == true\nthen\n"
               '  let m = split(",", to_string($message.message));\n'
               '  set_field("SourceIP", m[18]);\n'
               '  set_field("DestIP", m[19]);\nend\n')
        m = rule_matcher.parse_rule(src, catalog)
        assert m.grok is None
        assert m.value_field == "message"
        assert m.covers("0,,,igb0,match,block,in,4,0x0,,60,1234,0,0,,tcp,"
                        "A,10.0.0.5,8.8.8.8,1234,53,40,,ACK,,", {}, catalog) is True
        assert m.covers("nothing to see here", {}, catalog) is False

    def test_a_routing_only_rule_never_covers(self, catalog):
        src = ('rule "route"\nwhen\n  has_field("gl2_source_input") AND '
               'to_string($message.gl2_source_input)=="abc"\nthen\n'
               '  route_to_stream(id: "abc", remove_from_default: true);\nend\n')
        with pytest.raises(RuleParseError, match="sets no fields"):
            rule_matcher.parse_rule(src, catalog)

    def test_rejects_a_rule_without_a_grok_or_a_set_field(self, catalog):
        src = 'rule "n"\nwhen\n  true\nthen\n  let x = "1";\nend\n'
        with pytest.raises(RuleParseError, match="sets no fields"):
            rule_matcher.parse_rule(src, catalog)

    def test_does_not_mistake_the_guard_regex_for_the_grok(self, catalog):
        # A regex condition also writes `pattern: "..."` - only the grok counts.
        m = _matcher("regex", catalog)
        assert m.grok == ACCESS_GROK
        assert "src_ip" not in m.condition["pattern"]


class TestCovers:
    def test_covers_never_raises_on_a_regex_it_cannot_compile(self, catalog):
        # pfSense's filterlog guard uses a mid-pattern (?i); even a pattern we
        # truly cannot run must degrade to "not covered", not blow up the scan.
        src = rule_builder.build_rule(r"%{DATA:msg}", {
            "name": "n",
            "condition": "regex",
            "condition_regex": r"^.*,(in|out),4,.*,(?i)tcp,.*$"})
        m = rule_matcher.parse_rule(src, catalog)
        assert m.covers("0,,,igb0,match,block,in,4,0x0,,tcp,A,10.0.0.5,8.8.8.8",
                        {}, catalog) is True
        assert m.covers("0,,,igb0,match,block,in,4,0x0,,udp,A,10.0.0.5,8.8.8.8",
                        {}, catalog) is False
        assert m.covers("nothing here", {}, catalog) is False

    def test_a_matching_line_is_covered(self, catalog):
        for label in CONFIGS:
            assert _matcher(label, catalog).covers(
                SAMPLE, {"src_ip": "10.0.0.5"}, catalog) is True

    def test_an_unrelated_line_is_not_covered(self, catalog):
        for label in CONFIGS:
            assert _matcher(label, catalog).covers(UNRELATED, {}, catalog) is False

    def test_a_partial_match_still_counts(self, catalog):
        # Graylog's grok() is unanchored: trailing junk keeps the fields from
        # being extracted, so the message counts as covered.
        m = _matcher("always", catalog)
        assert m.covers(SAMPLE + " trailing junk", {}, catalog) is True

    def test_a_matching_line_whose_grok_has_no_captures_is_not_covered(self,
                                                                       catalog):
        # A literal-only rule matches but sets no fields, so the message still
        # needs a real rule.
        src = rule_builder.build_rule(r"GET \d{3}", {"name": "n"})
        m = rule_matcher.parse_rule(src, catalog)
        assert m.covers("GET 200 1", {}, catalog) is False

    def test_conditions_gate_the_match(self, catalog):
        fields = {"src_ip": "10.0.0.5"}
        assert _matcher("contains", catalog,
                       condition_value="192.168.").covers(
                           SAMPLE, fields, catalog) is False
        assert _matcher("regex", catalog,
                       condition_regex="^POST ").covers(
                           SAMPLE, fields, catalog) is False
        assert _matcher("has_field", catalog,
                       condition_field="absent").covers(
                           SAMPLE, fields, catalog) is False

    def test_a_rule_on_another_field_matches_that_value(self, catalog):
        # covers() judges the value it is handed; whether that value exists at
        # all is covered()'s job (see TestCovered).
        src = rule_builder.build_rule(r"%{IP:src_ip}", {"name": "n",
                                                       "source_field": "message"})
        src = src.replace("to_string($message.message)",
                          "to_string($message.`event.id`)")
        m = rule_matcher.parse_rule(src, catalog)
        assert m.covers("10.0.0.5", {"event.id": "10.0.0.5"}, catalog) is True
        assert m.covers("not an ip", {"event.id": "10.0.0.5"}, catalog) is False


class TestParseMatchers:
    def test_unparsed_rules_are_reported_not_fatal(self, catalog):
        good = rule_builder.build_rule(ACCESS_GROK, dict(CONFIGS["always"]))
        bad = 'rule "hand"\nwhen\n  !is_null($message.x)\nthen\n  set_field("a", "b");\nend\n'
        matchers, unparsed = rule_matcher.parse_matchers(
            [{"title": "good", "source": good}, {"title": "bad", "source": bad}],
            catalog)
        assert [m.title for m in matchers] == ["good"]
        assert [u["title"] for u in unparsed] == ["bad"]
        assert "when condition" in unparsed[0]["reason"]

    def test_rules_without_source_are_skipped(self, catalog):
        matchers, unparsed = rule_matcher.parse_matchers(
            [{"title": "x"}, {"title": "y", "source": ""}, "not a dict"], catalog)
        assert matchers == [] and unparsed == []


class TestCovered:
    def test_covered_checks_every_matcher(self, catalog):
        matchers = [_matcher("always", catalog),
                    _matcher("has_field", catalog, condition_field="other")]
        assert rule_matcher.covered(
            {"message": SAMPLE, "fields": {"other": "x"}}, matchers, catalog) is True

    def test_covered_falls_back_to_the_message_field(self, catalog):
        matcher = _matcher("always", catalog)
        assert rule_matcher.covered({"message": SAMPLE, "fields": {}},
                                    [matcher], catalog) is True

    def test_covered_skips_matchers_whose_field_is_absent(self, catalog):
        src = rule_builder.build_rule(r"%{IP:src}", {"name": "n"})
        src = src.replace("to_string($message.message)",
                          "to_string($message.`event.id`)")
        matchers = [rule_matcher.parse_rule(src, catalog)]
        assert rule_matcher.covered({"message": SAMPLE, "fields": {}},
                                    matchers, catalog) is False
