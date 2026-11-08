import pytest

from grok_catalog import load_catalog
from grok_compiler import (
    GrokError,
    UnknownPatternError,
    check_tokens,
    compile_grok,
    match,
    tokenize,
)


@pytest.fixture(scope="module")
def catalog():
    return load_catalog().by_name


def test_catalog_loads(catalog):
    assert len(catalog) >= 60
    for name in ("GREEDYDATA", "IP", "WORD", "TIMESTAMP_ISO8601", "COMMONAPACHELOG"):
        assert name in catalog


def test_every_catalog_pattern_compiles(catalog):
    for name in catalog:
        compiled, _ = compile_grok(f"%{{{name}}}", catalog)
        assert compiled is not None


def test_tokenize():
    parts = tokenize(r"abc %{IP:src} def %{WORD}")
    assert parts == [
        ("literal", "abc ", None),
        ("ref", "IP", "src"),
        ("literal", " def ", None),
        ("ref", "WORD", None),
    ]


def test_tokenize_plain_string():
    assert tokenize("no refs here") == [("literal", "no refs here", None)]


def test_tokenize_ignores_logstash_type_hint():
    parts = tokenize(r"%{HTTPDATE:timestamp;date;dd/MMM/yyyy:HH:mm:ss Z}")
    assert parts == [("ref", "HTTPDATE", "timestamp")]


def test_unknown_pattern_raises(catalog):
    with pytest.raises(UnknownPatternError):
        compile_grok("%{NOT_A_REAL_PATTERN:x}", catalog)


def test_check_tokens_is_non_raising(catalog):
    assert check_tokens("%{NOPE:a} ok %{WORD:b}", catalog) == ["unknown pattern %{NOPE}"]
    assert check_tokens("%{WORD:b}", catalog) == []


def test_full_match_with_fields(catalog):
    grok = r"accept %{IP:src} port %{POSINT:dport} by backend"
    status, fields = match(grok, "accept 10.0.0.5 port 443 by backend", catalog)
    assert status == "full"
    assert fields == {"src": "10.0.0.5", "dport": "443"}


def test_partial_match(catalog):
    status, fields = match("%{IP:src}", "client 10.0.0.5 disconnected", catalog)
    assert status == "partial"
    assert fields["src"] == "10.0.0.5"


def test_no_match(catalog):
    status, fields = match("%{IP:src}", "nothing here", catalog)
    assert status == "none"
    assert fields == {}


def test_nested_pattern_exposes_inner_keys(catalog):
    # SYSLOGPROG = %{PROG:program}(?:\[%{POSINT:pid}\])?
    status, fields = match(
        "%{SYSLOGPROG:prog}", "sshd[1234]", catalog
    )
    assert status == "full"
    assert fields["program"] == "sshd"
    assert fields["pid"] == "1234"
    assert fields["prog"] == "sshd[1234]"


def test_duplicate_capture_names_are_allowed(catalog):
    grok = "%{WORD:a} %{WORD:a}"
    status, fields = match(grok, "one two", catalog)
    assert status == "full"
    assert fields["a"] == "two"  # last wins, like Graylog's map


def test_invalid_regex_raises_grok_error(catalog):
    with pytest.raises(GrokError):
        compile_grok("%{WORD:a", catalog)  # unterminated
