"""Learned examples: (raw log line -> correct segments) pairs taught by the user.

Every example is a few-shot demonstration for the model. Examples are appended
to the system prompt (a small, relevance-ranked subset) so the builder gets
better at the formats you actually use. Storage is a single JSON file next to
the bundled catalog; it is user data and is gitignored.
"""

from __future__ import annotations

import json
import pathlib
import time
import uuid
from difflib import SequenceMatcher

DATA_DIR = pathlib.Path(__file__).resolve().parent / "data"
EXAMPLES_FILE = DATA_DIR / "examples.json"
MAX_EXAMPLES = 1000  # hard cap so the file cannot grow without bound


def _clean_segments(segments: object) -> list[dict]:
    """Keep only well-formed {type,value[,key,pattern]} segment dicts."""
    if not isinstance(segments, list):
        raise ValueError("segments must be a list")
    cleaned: list[dict] = []
    for seg in segments:
        if not isinstance(seg, dict):
            continue
        stype = seg.get("type")
        if stype == "text":
            cleaned.append({"type": "text", "value": str(seg.get("value") or "")})
        elif stype == "capture":
            cleaned.append({
                "type": "capture",
                "key": str(seg.get("key") or "").strip(),
                "pattern": str(seg.get("pattern") or "").strip(),
                "value": str(seg.get("value") or ""),
            })
    if not cleaned:
        raise ValueError("example has no usable segments")
    return cleaned


def load_examples() -> list[dict]:
    """Return every stored example (oldest first). Missing file -> []."""
    try:
        raw = EXAMPLES_FILE.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    return [e for e in data if isinstance(e, dict) and e.get("sample")]


def _save(entries: list[dict]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = EXAMPLES_FILE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(entries, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(EXAMPLES_FILE)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def add_example(sample: str, segments: object, source: str = "manual") -> dict:
    """Add (or update, when the sample already exists) one example."""
    sample = str(sample or "")
    if not sample.strip():
        raise ValueError("sample is empty")
    cleaned = _clean_segments(segments)
    entries = load_examples()
    for e in entries:
        if e.get("sample") == sample:
            e["segments"] = cleaned
            e["source"] = source
            e["updated_at"] = _now()
            _save(entries)
            return e
    entry = {
        "id": uuid.uuid4().hex[:12],
        "sample": sample,
        "segments": cleaned,
        "source": source,
        "created_at": _now(),
    }
    entries.append(entry)
    if len(entries) > MAX_EXAMPLES:
        del entries[:-MAX_EXAMPLES]
    _save(entries)
    return entry


def update_example(example_id: str, sample: str, segments: object) -> dict | None:
    entries = load_examples()
    for e in entries:
        if e.get("id") == example_id:
            sample = str(sample or e.get("sample") or "")
            if not sample.strip():
                raise ValueError("sample is empty")
            e["sample"] = sample
            e["segments"] = _clean_segments(segments)
            e["source"] = "manual"
            e["updated_at"] = _now()
            _save(entries)
            return e
    return None


def delete_example(example_id: str) -> bool:
    entries = load_examples()
    kept = [e for e in entries if e.get("id") != example_id]
    if len(kept) == len(entries):
        return False
    _save(kept)
    return True


def clear_examples() -> int:
    count = len(load_examples())
    _save([])
    return count


def select_examples(sample: str, limit: int = 3) -> list[dict]:
    """Pick the `limit` stored examples most similar to `sample` for the prompt."""
    entries = load_examples()
    if limit <= 0 or not entries:
        return []
    if len(entries) > limit:
        def score(e: dict) -> float:
            return SequenceMatcher(None, sample, str(e.get("sample") or "")).ratio()

        return sorted(entries, key=score, reverse=True)[:limit]
    # Fewer examples than slots: rank them anyway so the closest ones are the
    # ones the model sees, and break ties deterministically.
    ranked = sorted(
        enumerate(entries),
        key=lambda pair: (
            -SequenceMatcher(None, sample, str(pair[1].get("sample") or "")).ratio(),
            pair[0],
        ),
    )
    return [e for _i, e in ranked[:limit]]


def stats() -> dict:
    entries = load_examples()
    try:
        size = EXAMPLES_FILE.stat().st_size
    except OSError:
        size = 0
    return {
        "count": len(entries),
        "file": str(EXAMPLES_FILE),
        "size": size,
        "exists": EXAMPLES_FILE.exists(),
    }
