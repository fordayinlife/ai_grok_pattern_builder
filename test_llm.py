import llm


def test_system_prompt_substitutes_catalog_without_brace_crash():
    prompt = llm.build_system_prompt(["WORD", "IP", "GREEDYDATA"])
    assert "GREEDYDATA, IP, WORD" in prompt
    assert "{catalog}" not in prompt
    assert '"segments"' in prompt            # JSON example survives .replace()
    assert "decompose" in prompt.lower()
    assert "message" in prompt.lower()       # the reserved-key rule is present
    assert '172.16.0.1 - - [10/Oct/2026:13:55:36 -0700]' in prompt


def test_extract_json_pulls_first_balanced_object():
    obj = llm._extract_json('noise {"segments": [{"type": "text"}]} trailing')
    assert obj == {"segments": [{"type": "text"}]}


def test_extract_json_handles_braces_inside_strings():
    obj = llm._extract_json('{"segments": [{"value": "a } b {"}]}')
    assert obj["segments"][0]["value"] == "a } b {"


def test_field_names_are_added_to_prompt():
    prompt = llm.build_system_prompt(["WORD"], field_names=["source_ip", "http_method"])
    assert "Existing Graylog Field Names" in prompt
    assert "http_method, source_ip" in prompt


def test_no_field_block_when_empty():
    prompt = llm.build_system_prompt(["WORD"], field_names=[])
    assert "Existing Graylog Field Names" not in prompt


def test_generate_segments_returns_name_and_description(monkeypatch):
    import json

    body = {
        "choices": [{"message": {"content": json.dumps({
            "name": "Firewall block event",
            "description": "A pfSense block log line with client and destination.",
            "guard": "^\\d+\\.\\d+\\.\\d+\\.\\d+",
            "segments": [{"type": "text", "value": "x"}],
        })}}]
    }

    class Resp:
        status_code = 200

        def raise_for_status(self):
            pass

        def json(self):
            return body

    monkeypatch.setattr(llm.requests, "post",
                        lambda url, json, timeout: Resp())
    segs, meta = llm.generate_segments("http://ollama.local", "m", "x", ["WORD"])
    assert meta["name"] == "Firewall block event"
    assert "pfSense block log" in meta["description"]
    assert meta["guard"] == r"^\d+\.\d+\.\d+\.\d+"
    assert segs == [{"type": "text", "value": "x"}]

    body["choices"][0]["message"]["content"] = json.dumps({
        "name": "x", "segments": [{"type": "text", "value": "y"}]})
    _, meta2 = llm.generate_segments("http://ollama.local", "m", "x", ["WORD"])
    assert meta2["guard"] == ""
