"""P3.1: OllamaSignalDrafter — self-hosted on-prem drafter backend.

Fakes the httpx layer (inject ``_client``) so the suite never hits a network.
"""
from __future__ import annotations

import httpx
import pytest

from ccguard.server.services.signal_drafter import DrafterError, OllamaSignalDrafter


class _Resp:
    def __init__(self, status_code: int, payload=None, bad_json: bool = False) -> None:
        self.status_code = status_code
        self._payload = payload
        self._bad_json = bad_json

    def json(self):
        if self._bad_json:
            raise ValueError("not json")
        return self._payload


class _Client:
    def __init__(self, resp: _Resp | None = None, exc: Exception | None = None) -> None:
        self._resp = resp
        self._exc = exc
        self.calls: list[dict] = []

    def post(self, url, json=None, timeout=None):  # noqa: A002
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self._exc is not None:
            raise self._exc
        return self._resp


def _drafter(client: _Client) -> OllamaSignalDrafter:
    d = OllamaSignalDrafter(endpoint="http://x:11434", model="qwen2.5:7b-instruct")
    d._client = client  # inject fake; draft() only lazy-inits when None
    return d


def test_draft_returns_response_text_and_posts_generate():
    raw_json = '{"id":"x.y","attack_technique":"T1","pattern":"a","description":"d"}'
    d = _drafter(_Client(_Resp(200, {"response": raw_json})))
    out = d.draft("some threat-intel text")
    assert out == raw_json
    call = d._client.calls[0]
    assert call["url"].endswith("/api/generate")
    assert call["json"]["model"] == "qwen2.5:7b-instruct"
    assert call["json"]["stream"] is False
    assert call["json"]["options"]["temperature"] == 0.0
    assert "system" in call["json"]  # shared _SYSTEM_PROMPT carried


def test_model_missing_404_raises():
    d = _drafter(_Client(_Resp(404)))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_model_missing_200_error_payload_raises():
    d = _drafter(_Client(_Resp(200, {"error": "model 'qwen2.5:7b-instruct' not found"})))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_network_error_raises():
    d = _drafter(_Client(exc=httpx.ConnectError("connection refused")))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_non_200_raises():
    d = _drafter(_Client(_Resp(500)))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_empty_response_raises():
    d = _drafter(_Client(_Resp(200, {"response": "   "})))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_preflight_true_on_reachable_model():
    d = _drafter(_Client(_Resp(200, {"response": "ok"})))
    assert d.preflight() is True


def test_preflight_false_on_model_missing():
    d = _drafter(_Client(_Resp(404)))
    assert d.preflight() is False
