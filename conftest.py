import pytest


@pytest.fixture(autouse=True)
def _no_live_graylog_field_hints(monkeypatch):
    """Keep the suite offline: never fetch field names from a live Graylog."""
    monkeypatch.setenv("GRAYLOG_FIELD_HINTS", "false")
