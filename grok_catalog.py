"""Grok pattern catalog: bundled StreamSets list + optional sync from Graylog."""

from __future__ import annotations

import json
import pathlib

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"
BUNDLED_FILE = DATA_DIR / "grok_patterns.json"
SYNCED_FILE = DATA_DIR / "synced_patterns.json"

CATEGORY_ORDER = ["general", "datetime", "java", "log", "network", "path"]


def _read_entries(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [e for e in data if e.get("name") and e.get("pattern")]


class Catalog:
    """Ordered, de-duplicated view over pattern entries. Later entries win."""

    def __init__(self, entries: list[dict], synced_names: list[str] | None = None):
        by_name: dict[str, dict] = {}
        for e in entries:
            by_name[e["name"]] = e
        self._by_name = by_name
        self._synced_names = synced_names or []

    @property
    def by_name(self) -> dict[str, str]:
        return {n: e["pattern"] for n, e in self._by_name.items()}

    @property
    def names(self) -> list[str]:
        return list(self._by_name)

    @property
    def synced_names(self) -> list[str]:
        return list(self._synced_names)

    def grouped(self) -> list[dict]:
        groups: dict[str, list[dict]] = {}
        for e in self._by_name.values():
            groups.setdefault(e.get("category") or "other", []).append(
                {"name": e["name"], "pattern": e["pattern"]}
            )
        ordered = []
        for cat in CATEGORY_ORDER + sorted(set(groups) - set(CATEGORY_ORDER)):
            if cat in groups:
                ordered.append({"name": cat, "patterns": groups[cat]})
        return ordered


def load_catalog() -> Catalog:
    """Bundled patterns with synced-from-Graylog patterns merged on top."""
    synced = _read_entries(SYNCED_FILE)
    return Catalog(_read_entries(BUNDLED_FILE) + synced,
                   synced_names=[e["name"] for e in synced])


def save_synced(entries: list[dict]) -> int:
    """Persist patterns fetched from Graylog; they override bundled names on load."""
    cleaned = []
    for e in entries:
        name = (e.get("name") or "").strip()
        pattern = (e.get("pattern") or "").strip()
        if name and pattern:
            cleaned.append(
                {"category": "graylog-synced", "name": name, "pattern": pattern}
            )
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    SYNCED_FILE.write_text(json.dumps(cleaned, indent=1) + "\n", encoding="utf-8")
    return len(cleaned)
