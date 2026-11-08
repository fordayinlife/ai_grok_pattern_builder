"""Tests for the grok catalog: merging synced patterns and reading it back."""

import json

import grok_catalog
import rule_builder


def test_synced_patterns_override_bundled_ones(tmp_path, monkeypatch):
    monkeypatch.setattr(grok_catalog, "SYNCED_FILE",
                        tmp_path / "synced_patterns.json")
    count = grok_catalog.save_synced([
        {"name": "MYINT", "pattern": "(?:[0-9]+)"},
        {"name": "WORD", "pattern": "overridden"},
    ])
    assert count == 2

    cat = grok_catalog.load_catalog()
    assert cat.by_name["WORD"] == "overridden"     # synced wins
    assert cat.by_name["IP"]       == grok_catalog.load_catalog().by_name["IP"]
    assert set(cat.synced_names) == {"MYINT", "WORD"}
    assert len(cat.names) == len(cat.by_name)      # de-duplicated, not duplicated


def test_synced_names_are_cached_not_re_read(tmp_path, monkeypatch):
    synced = tmp_path / "synced_patterns.json"
    synced.write_text(json.dumps([{"name": "A", "pattern": "a"}]), encoding="utf-8")
    monkeypatch.setattr(grok_catalog, "SYNCED_FILE", synced)
    cat = grok_catalog.load_catalog()
    assert cat.synced_names == ["A"]
    synced.unlink()                                # changing the file must not
    assert cat.synced_names == ["A"]               # change an already loaded view


def test_save_synced_creates_a_missing_data_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(grok_catalog, "DATA_DIR", tmp_path / "sub" / "dir")
    monkeypatch.setattr(grok_catalog, "SYNCED_FILE",
                        grok_catalog.DATA_DIR / "synced.json")
    assert grok_catalog.save_synced([{"name": "X", "pattern": "x"}]) == 1
    assert grok_catalog.SYNCED_FILE.exists()


def test_duplicate_key_warning_is_reported_once():
    # A single-char pattern keeps the compiled regex unambiguous, so this only
    # checks the de-duplication of the warning itself.
    catalog = {"WORD": r"\w"}
    ranges = [{"key": "k", "pattern": "WORD", "start": i, "end": i + 1}
              for i in range(20)]
    prev = rule_builder.preview("x" * 20, ranges, catalog)
    assert sum(1 for w in prev["warnings"]
               if w.startswith("duplicate key")) == 1
    assert "duplicate key 'k'" in prev["warnings"][0]
