import json
from datetime import datetime, timezone, timedelta
from io import BytesIO
from types import SimpleNamespace
from urllib import error

import pytest

from awxtop import awxtop


def test_classify_status_text_variants():
    assert awxtop.classify_status_text("good") == "good"
    assert awxtop.classify_status_text("running") == "good"
    assert awxtop.classify_status_text("warn") == "warn"
    assert awxtop.classify_status_text("failed") == "bad"
    assert awxtop.classify_status_text("unknownish") == "unknown"


def test_classify_instance_heuristics():
    assert awxtop.classify_instance({"enabled": False}) == "bad"
    assert awxtop.classify_instance({"errors": "Failed to connect to redis"}) == "bad"
    assert awxtop.classify_instance({"capacity": 0, "enabled": True}) == "warn"
    assert awxtop.classify_instance({"node_state": "running"}) == "good"
    assert awxtop.classify_instance({"enabled": True, "errors": ""}) == "good"


def test_time_helpers():
    # parse_iso8601 handles Z suffix
    dt = awxtop.parse_iso8601("2023-01-01T00:00:00Z")
    assert dt is not None and dt.year == 2023

    assert awxtop.format_elapsed(3661) == "1:01:01"
    assert awxtop.format_elapsed(None) == "--:--:--"

    # format_age_from_start with a recent timestamp
    started = datetime.now(timezone.utc) - timedelta(seconds=30)
    # Should be seconds string like "30s"
    assert awxtop.format_age_from_start(started).endswith("s")


def test_gateway_helpers():
    assert awxtop.gateway_status_char("good") == (".", "good")
    assert awxtop.gateway_status_char("bad") == ("x", "bad")
    assert awxtop.shorten_gateway_name("https://gw1.example.com") == "gw1"
    assert awxtop.shorten_gateway_name("https://gw1.example.com", show_full=True) == "gw1.example.com"
    assert awxtop.format_bad_percent({"good": 2, "bad": 1, "unknown": 1}) == "33.3%"


def test_request_token_with_password_tries_multiple(monkeypatch):
    """
    Ensure token acquisition falls back across token endpoints when one fails.
    """
    calls = []

    class DummyResponse:
        def __init__(self, payload: bytes):
            self.payload = payload

        def read(self):
            return self.payload

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=None, context=None):
        calls.append(req.full_url)
        # First endpoint returns HTTPError with JSON body
        if len(calls) == 1:
            fp = BytesIO(b'{"detail":"not found"}')
            raise error.HTTPError(req.full_url, 404, "Not Found", hdrs=None, fp=fp)
        # Second endpoint succeeds
        return DummyResponse(json.dumps({"token": "abc123"}).encode("utf-8"))

    monkeypatch.setattr(awxtop.request, "urlopen", fake_urlopen)

    token, err = awxtop.request_token_with_password(
        "https://example.com",
        "user",
        "pass",
        timeout=1.0,
        insecure=True,
    )
    assert token == "abc123"
    assert err is None
    assert len(calls) == 2


def test_resolve_token_prefers_explicit(monkeypatch):
    args = SimpleNamespace(
        token="TKN",
        username="user",
        password=None,
        base_url="https://example.com",
        timeout=1.0,
        insecure=False,
    )
    assert awxtop.resolve_token(args) == "TKN"


def test_resolve_token_with_username(monkeypatch):
    args = SimpleNamespace(
        token=None,
        username="user",
        password=None,
        base_url="https://example.com",
        timeout=1.0,
        insecure=False,
    )

    monkeypatch.setattr(awxtop.getpass, "getpass", lambda prompt: "pw")
    monkeypatch.setattr(
        awxtop,
        "request_token_with_password",
        lambda base, user, pwd, timeout, insecure: ("tok123", None),
    )

    assert awxtop.resolve_token(args) == "tok123"


def test_resolve_token_requires_credentials():
    args = SimpleNamespace(
        token=None,
        username=None,
        password=None,
        base_url="https://example.com",
        timeout=1.0,
        insecure=False,
    )
    with pytest.raises(SystemExit):
        awxtop.resolve_token(args)
