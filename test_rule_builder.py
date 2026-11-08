import re

import pytest

import rule_builder
from grok_catalog import load_catalog
from rule_builder import (
    ValidationError,
    anchor_fields,
    anchor_segments,
    build_all,
    build_grok,
    build_rule,
    escape_literal,
    escape_rule_string,
    is_coarse,
    normalize_ranges,
    preview,
    rename_rule_source,
    suggest_patterns,
)


@pytest.fixture(scope="module")
def catalog():
    return load_catalog().by_name


APACHE = (
    '192.168.1.10 - - [10/Oct/2026:13:55:36 -0700] '
    '"GET /index.html HTTP/1.1" 200 2326'
)


def _ranges(sample, specs):
    out = []
    for key, pattern, value in specs:
        start = sample.index(value)
        out.append(
            {"key": key, "pattern": pattern, "start": start, "end": start + len(value)}
        )
    return out


class TestEscaping:
    def test_escape_literal(self):
        assert escape_literal("a[b].c") == r"a\[b\]\.c"
        assert escape_literal("1.2.3.4") == r"1\.2\.3\.4"
        assert escape_literal("cost $5 (odd)") == r"cost \$5 \(odd\)"
        assert escape_literal("plain text") == "plain text"

    def test_escape_rule_string(self):
        assert escape_rule_string('say "hi"') == 'say \\"hi\\"'
        assert escape_rule_string("back\\slash") == "back\\\\slash"
        assert escape_rule_string("line\nbreak") == "line\\nbreak"

    def test_rename_rule_source_replaces_first_line(self):
        src = 'rule "old name"\nwhen true\nthen\nend'
        assert rename_rule_source(src, "old name-2") == \
            'rule "old name-2"\nwhen true\nthen\nend'

    def test_rename_rule_source_escapes_new_name(self):
        assert rename_rule_source('rule "a"', 'we"ird') == 'rule "we\\"ird"'

    def test_rename_rule_source_single_line(self):
        assert rename_rule_source('rule "a"', "b") == 'rule "b"'

    def test_literal_brackets_do_not_break_regex(self, catalog):
        sample = "arr[0] = 42"
        grok = build_grok(sample, [])
        assert grok == r"arr\[0\] = 42"
        from grok_compiler import match

        status, _ = match(grok, sample, catalog)
        assert status == "full"


class TestNormalizeRanges:
    def test_sorts_and_validates(self):
        sample = "abcdef"
        ranges = normalize_ranges(
            sample,
            [
                {"key": "b", "pattern": "WORD", "start": 3, "end": 4},
                {"key": "a", "pattern": "WORD", "start": 0, "end": 1},
            ],
        )
        assert [r["key"] for r in ranges] == ["a", "b"]

    def test_overlap_raises(self):
        sample = "abcdef"
        with pytest.raises(ValidationError, match="overlaps"):
            normalize_ranges(
                sample,
                [
                    {"key": "a", "pattern": "WORD", "start": 0, "end": 3},
                    {"key": "b", "pattern": "WORD", "start": 2, "end": 5},
                ],
            )

    def test_out_of_bounds_raises(self):
        with pytest.raises(ValidationError, match="invalid text range"):
            normalize_ranges("abc", [{"key": "a", "pattern": "WORD", "start": 1, "end": 99}])

    def test_bad_key_raises(self):
        with pytest.raises(ValidationError, match="key"):
            normalize_ranges("abc", [{"key": "1bad", "pattern": "WORD", "start": 0, "end": 1}])

    def test_bad_pattern_raises(self):
        with pytest.raises(ValidationError, match="pattern"):
            normalize_ranges("abc", [{"key": "ok", "pattern": "has space", "start": 0, "end": 1}])


class TestBuildGrok:
    def test_interleaved(self):
        sample = "ip=10.0.0.1 port=8080"
        grok = build_grok(
            sample,
            [
                {"key": "ip", "pattern": "IPORHOST", "start": 3, "end": 11},
                {"key": "port", "pattern": "POSINT", "start": 17, "end": 21},
            ],
        )
        assert grok == r"ip=%{IPORHOST:ip} port=%{POSINT:port}"

    def test_empty_ranges_gives_escaped_sample(self):
        assert build_grok("a.b", []) == r"a\.b"


class TestBuildRule:
    def test_always_condition(self):
        rule = build_rule("%{WORD:w}", {"name": "My Rule"})
        assert rule.startswith('rule "My Rule"\nwhen\n  true\n')
        assert ".matches == true" not in rule
        assert 'pattern: "%{WORD:w}"' in rule
        assert "value: to_string($message.message)" in rule
        assert "only_named_captures: true" in rule
        assert rule.rstrip().endswith("end")

    def test_has_field_condition(self):
        rule = build_rule("%{WORD:w}", {"condition": "has_field", "condition_field": "syslog"})
        assert 'has_field("syslog")' in rule
        assert "set_fields(grok(" in rule

    def test_condition_field_with_dash_is_backtick_quoted(self):
        rule = build_rule(
            "%{WORD:w}",
            {"condition": "contains", "condition_field": "ip-c_geolocation",
             "condition_value": "1.2.3.4"},
        )
        assert r"to_string($message.`ip-c_geolocation`)" in rule

    def test_condition_field_with_dot_is_backtick_quoted(self):
        rule = build_rule(
            "%{WORD:w}",
            {"condition": "contains", "condition_field": "event.id",
             "condition_value": "42"},
        )
        assert 'has_field("event.id")' in rule
        assert r"to_string($message.`event.id`)" in rule

    def test_contains_condition(self):
        rule = build_rule(
            "%{WORD:w}",
            {"condition": "contains", "condition_field": "source", "condition_value": "web-01"},
        )
        assert 'has_field("source") && ' in rule
        assert 'contains(to_string($message.source), "web-01")' in rule

    def test_contains_condition_escapes_value(self):
        rule = build_rule(
            "%{WORD:w}",
            {"condition": "contains", "condition_field": "message", "condition_value": 'a"b'},
        )
        assert r'contains(to_string($message.message), "a\"b")' in rule

    def test_contains_condition_needs_value(self):
        with pytest.raises(ValidationError, match="value"):
            build_rule("%{WORD:w}", {"condition": "contains", "condition_field": "source"})

    def test_regex_condition_uses_source_field(self):
        rule = build_rule(
            "%{WORD:w}",
            {
                "condition": "regex",
                "condition_regex": "^POST",
                "source_field": "full_message",
            },
        )
        assert ('regex(pattern: "^POST", '
                "value: to_string($message.full_message)).matches == true") in rule

    def test_quotes_in_grok_are_escaped(self):
        rule = build_rule(r'path=\"x\"', {"name": "t"})
        assert r'pattern: "path=\\\"x\\\""' in rule

    def test_reserved_source_field_rejected(self):
        with pytest.raises(ValidationError, match="reserved"):
            build_rule("%{WORD:w}", {"source_field": "when"})

    def test_bad_condition_rejected(self):
        with pytest.raises(ValidationError):
            build_rule("%{WORD:w}", {"condition": "nope"})

    def test_invalid_regex_condition_rejected_locally(self):
        # Caught here instead of by Graylog on push, where it is far less clear.
        with pytest.raises(ValidationError, match="not a valid regex for Graylog"):
            build_rule("%{WORD:w}", {"condition": "regex",
                                     "condition_regex": "([unclosed"})

    def test_valid_regex_condition_is_accepted(self):
        rule = build_rule("%{WORD:w}", {"condition": "regex",
                                        "condition_regex": "^POST "})
        assert 'regex(pattern: "^POST", ' in rule
        assert ".matches == true" in rule

    def test_reserved_capture_key_rejected(self):
        with pytest.raises(ValidationError, match="rule-language word"):
            normalize_ranges("abc", [{"key": "when", "pattern": "WORD",
                                     "start": 0, "end": 3}])


class TestAnchorSegments:
    def test_happy_path(self):
        sample = "user=alice action=login"
        ranges, warnings = anchor_segments(
            sample,
            [
                {"type": "text", "value": "user="},
                {"type": "capture", "key": "user", "pattern": "USERNAME", "value": "alice"},
                {"type": "text", "value": " action="},
                {"type": "capture", "key": "action", "pattern": "WORD", "value": "login"},
            ],
        )
        assert warnings == []
        assert ranges == [
            {"key": "user", "pattern": "USERNAME", "start": 5, "end": 10},
            {"key": "action", "pattern": "WORD", "start": 18, "end": 23},
        ]

    def test_missing_value_warns_and_skips(self):
        ranges, warnings = anchor_segments(
            "hello world",
            [{"type": "capture", "key": "x", "pattern": "WORD", "value": "unicorn"}],
        )
        assert ranges == []
        assert any("not found" in w for w in warnings)

    def test_ignores_text_segments(self):
        ranges, _ = anchor_segments(
            "abc", [{"type": "text", "value": "abc"}]
        )
        assert ranges == []

    def test_text_segments_disambiguate_repeated_values(self):
        sample = "vnStat daemon 2.13 (pid:44820 uid:0 gid:0, SQLite 3.53.1)"
        ranges, warnings = anchor_segments(
            sample,
            [
                {"type": "text", "value": "vnStat daemon "},
                {"type": "capture", "key": "version", "pattern": "NOTSPACE", "value": "2.13"},
                {"type": "text", "value": " (pid:"},
                {"type": "capture", "key": "pid", "pattern": "POSINT", "value": "44820"},
                {"type": "text", "value": " uid:"},
                {"type": "capture", "key": "uid", "pattern": "NONNEGINT", "value": "0"},
                {"type": "text", "value": " gid:"},
                {"type": "capture", "key": "gid", "pattern": "NONNEGINT", "value": "0"},
                {"type": "text", "value": ", SQLite "},
                {"type": "capture", "key": "sqlite_version", "pattern": "NOTSPACE",
                 "value": "3.53.1"},
            ],
        )
        assert warnings == []
        by_key = {r["key"]: r for r in ranges}
        assert (by_key["pid"]["start"], by_key["pid"]["end"]) == (24, 29)
        assert (by_key["uid"]["start"], by_key["uid"]["end"]) == (34, 35)
        assert (by_key["gid"]["start"], by_key["gid"]["end"]) == (40, 41)

    def test_version_sample_reaches_full_match(self, catalog):
        sample = "vnStat daemon 2.13 (pid:44820 uid:0 gid:0, SQLite 3.53.1)"
        segments = [
            {"type": "text", "value": "vnStat daemon "},
            {"type": "capture", "key": "version", "pattern": "NOTSPACE", "value": "2.13"},
            {"type": "text", "value": " (pid:"},
            {"type": "capture", "key": "pid", "pattern": "POSINT", "value": "44820"},
            {"type": "text", "value": " uid:"},
            {"type": "capture", "key": "uid", "pattern": "NONNEGINT", "value": "0"},
            {"type": "text", "value": " gid:"},
            {"type": "capture", "key": "gid", "pattern": "NONNEGINT", "value": "0"},
            {"type": "text", "value": ", SQLite "},
            {"type": "capture", "key": "sqlite_version", "pattern": "NOTSPACE",
             "value": "3.53.1"},
        ]
        ranges, _ = anchor_segments(sample, segments)
        result = preview(sample, ranges, catalog)
        assert result["status"] == "full"
        assert result["fields"]["uid"] == "0"
        assert result["fields"]["gid"] == "0"
        assert result["fields"]["pid"] == "44820"


class TestPreview:
    def test_full_preview(self, catalog):
        ranges = _ranges(
            APACHE,
            [
                ("src_ip", "IPORHOST", "192.168.1.10"),
                ("ts", "HTTPDATE", "10/Oct/2026:13:55:36 -0700"),
                ("method", "WORD", "GET"),
                ("path", "NOTSPACE", "/index.html"),
                ("status", "INT", "200"),
                ("bytes", "INT", "2326"),
            ],
        )
        prev = preview(APACHE, ranges, catalog)
        assert prev["compile_error"] is None
        assert prev["status"] == "full"
        assert prev["fields"]["src_ip"] == "192.168.1.10"
        assert prev["fields"]["status"] == "200"
        assert "%{IPORHOST:src_ip}" in prev["grok"]

    def test_unknown_pattern_reported(self, catalog):
        ranges = [{"key": "x", "pattern": "NOTREAL", "start": 0, "end": 3}]
        prev = preview("abc", ranges, catalog)
        assert prev["status"] == "error"
        assert "NOTREAL" in prev["compile_error"]
        assert any("unknown pattern %{NOTREAL}" in w for w in prev["warnings"])

    def test_duplicate_key_warning(self, catalog):
        ranges = _ranges("one two", [("w", "WORD", "one"), ("w", "WORD", "two")])
        prev = preview("one two", ranges, catalog)
        assert any("duplicate key 'w'" in w for w in prev["warnings"])

    def test_build_all_returns_rule(self, catalog):
        ranges = _ranges("level=INFO", [("level", "WORD", "INFO")])
        out = build_all("level=INFO", ranges, {"name": "Lvl"}, catalog)
        assert out["rule"].startswith('rule "Lvl"')
        assert out["grok"] == r"level=%{WORD:level}"


class TestAnchorFields:
    def test_anchors_matching_fields_and_assigns_patterns(self, catalog):
        sample = APACHE
        ranges, skipped = anchor_fields(
            sample, {"src_ip": "192.168.1.10", "status": "200"}, catalog)
        by_key = {r["key"]: r for r in ranges}
        assert set(by_key) == {"src_ip", "status"}
        assert sample[by_key["src_ip"]["start"]:by_key["src_ip"]["end"]] == "192.168.1.10"
        for r in ranges:
            assert preview(sample, [r], catalog)["status"] == "full"

    def test_skips_message_internals_and_non_scalars(self, catalog):
        fields = {
            "message": APACHE,
            "gl2_remote_ip": "10.0.0.1",
            "streams": ["000000000000000000000001"],
            "missing": "not-in-the-text",
        }
        ranges, skipped = anchor_fields(APACHE, fields, catalog)
        assert ranges == []
        reasons = {s["key"]: s["reason"] for s in skipped}
        assert "streams" in reasons and reasons["streams"] == "not a scalar value"
        assert reasons["missing"] == "value not found in the sample"
        assert "message" not in reasons and "gl2_remote_ip" not in reasons

    def test_overlapping_values_keep_one(self, catalog):
        ranges, _ = anchor_fields("hello world", {"a": "hello world", "b": "world"}, catalog)
        assert len(ranges) == 1
        assert ranges[0]["key"] == "a"

    def test_repeated_value_is_anchored_once_per_field(self, catalog):
        # Two fields share the value: each claims its own occurrence instead of
        # both landing on the first one.
        ranges, skipped = anchor_fields("uid=0 gid=0 ok",
                                        {"uid": "0", "gid": "0"}, catalog)
        by_key = {r["key"]: r for r in ranges}
        assert set(by_key) == {"uid", "gid"}
        assert (by_key["uid"]["start"], by_key["uid"]["end"]) == (4, 5)
        assert (by_key["gid"]["start"], by_key["gid"]["end"]) == (10, 11)
        assert not any(s["reason"] == "overlaps another field" for s in skipped)

    def test_repeated_value_reports_which_occurrence_was_used(self, catalog):
        # A single field whose value appears twice cannot know which occurrence
        # was meant, so the ambiguity must be reported, not silently guessed.
        sample = 'host - "GET / HTTP/1.1" 200 200'
        ranges, skipped = anchor_fields(sample, {"bytes": "200"}, catalog)
        assert len(ranges) == 1
        assert sample[ranges[0]["start"]:ranges[0]["end"]] == "200"
        reasons = [s["reason"] for s in skipped if s["key"] == "bytes"]
        assert reasons == ["value appears 2 times - "
                           "anchored on the first free occurrence"]

    def test_two_fields_with_one_value_take_different_occurrences(self, catalog):
        # status and bytes share the text "200": each claims its own occurrence
        # instead of both collapsing onto the first one.
        sample = 'host - "GET / HTTP/1.1" 200 200'
        ranges, skipped = anchor_fields(
            sample, {"status": "200", "bytes": "200"}, catalog)
        starts = {r["key"]: r["start"] for r in ranges}
        assert set(starts) == {"status", "bytes"}
        assert starts["status"] != starts["bytes"]
        assert all(sample[s:s + 3] == "200" for s in starts.values())

    def test_unsatisfiable_field_reports_every_occurrence_taken(self, catalog):
        sample = "abab"
        ranges, skipped = anchor_fields(
            sample, {"a": "abab", "b": "ab"}, catalog)
        assert [r["key"] for r in ranges] == ["a"]
        reasons = [s["reason"] for s in skipped if s["key"] == "b"]
        assert reasons == ["every occurrence overlaps another field"]


class TestSuggestPatterns:
    def test_ip_beats_hostname_for_an_address(self, catalog):
        sugg = suggest_patterns("10.0.0.5", catalog)
        assert sugg[0] == "IP"
        assert "HOSTNAME" not in sugg[:2]

    def test_numbers_beat_hostnames_for_digit_strings(self, catalog):
        assert suggest_patterns("0", catalog)[0] == "NONNEGINT"
        assert suggest_patterns("55512", catalog)[0] == "POSINT"
        assert suggest_patterns("2.13", catalog)[0] == "NUMBER"

    def test_log_level_is_preferred(self, catalog):
        assert suggest_patterns("INFO", catalog)[0] == "LOGLEVEL"

    def test_generic_patterns_come_last(self, catalog):
        sugg = suggest_patterns("hello", catalog)
        assert sugg[-1] in rule_builder._GENERIC_PATTERNS
        assert sugg.index("WORD") > 0

    def test_limit_is_honoured(self, catalog):
        assert len(suggest_patterns("10.0.0.5", catalog, limit=3)) == 3


class TestIsCoarse:
    def test_whole_line_generic_capture_is_coarse(self):
        assert is_coarse("hello world", [{"key": "log", "pattern": "GREEDYDATA", "start": 0, "end": 11}])
        assert is_coarse("hello world", [{"key": "log", "pattern": "DATA", "start": 0, "end": 11}])

    def test_specific_or_partial_captures_are_not_coarse(self):
        assert not is_coarse("hello world", [{"key": "log", "pattern": "GREEDYDATA", "start": 1, "end": 11}])
        assert not is_coarse("hello world", [{"key": "w", "pattern": "WORD", "start": 0, "end": 5}])
        assert not is_coarse("hello world", [{"key": "a", "pattern": "GREEDYDATA", "start": 0, "end": 11},
                                              {"key": "b", "pattern": "GREEDYDATA", "start": 11, "end": 11}])

import re
class TestPortableRegex:
    def test_mid_pattern_flag_is_scoped_not_dropped(self):
        # Java (and so Graylog) reads `(?i)` anywhere; Python rejects it.
        assert rule_builder.portable_regex(r"a(?i)b") == r"a(?i:b)"
        assert re.compile(rule_builder.portable_regex(r"a(?i)b")).fullmatch("aB")
        assert not re.compile(rule_builder.portable_regex(r"a(?i)b")).fullmatch("Ab")

    def test_leading_flag_is_left_alone(self):
        assert rule_builder.portable_regex(r"(?i)abc") == r"(?i)abc"

    def test_several_flags_nest(self):
        assert rule_builder.portable_regex(r"a(?i)b(?s)c") == r"a(?i:b(?s:c))"
        compiled = re.compile(rule_builder.portable_regex(r"a(?i)b(?s)c"))
        assert compiled.fullmatch("aBc")

    def test_a_flag_inside_a_character_class_is_untouched(self):
        assert rule_builder.portable_regex(r"[(?i)x]") == r"[(?i)x]"

    def test_unbalanced_input_raises(self):
        with pytest.raises(ValueError):
            rule_builder.portable_regex(r"a(?i)b)")


