"""P3.1/P3.2: OllamaSignalDrafter + build_signal_drafter factory.

Fakes the httpx layer (inject ``_client``) so the suite never hits a network.
"""
from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from ccguard.server.services.signal_drafter import (
    AnthropicSignalDrafter,
    DrafterError,
    OllamaSignalDrafter,
    build_signal_drafter,
)


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
    def __init__(self, resp=None, exc=None, get_resp=None, get_exc=None) -> None:
        self._resp = resp
        self._exc = exc
        self._get_resp = get_resp
        self._get_exc = get_exc
        self.calls: list[dict] = []

    def post(self, url, json=None, timeout=None):  # noqa: A002
        self.calls.append({"url": url, "json": json, "timeout": timeout})
        if self._exc is not None:
            raise self._exc
        return self._resp

    def get(self, url, timeout=None):
        if self._get_exc is not None:
            raise self._get_exc
        return self._get_resp


def _drafter(client: _Client) -> OllamaSignalDrafter:
    d = OllamaSignalDrafter(endpoint="http://x:11434", model="qwen2.5:7b-instruct")
    d._client = client  # inject fake; methods only lazy-init when None
    return d


# --- draft() --------------------------------------------------------------

def test_draft_returns_response_text_and_posts_generate():
    raw_json = '{"id":"x.y","attack_technique":"T1","pattern":"a","description":"d"}'
    d = _drafter(_Client(resp=_Resp(200, {"response": raw_json})))
    out = d.draft("some threat-intel text")
    assert out == raw_json
    call = d._client.calls[0]
    assert call["url"].endswith("/api/generate")
    assert call["json"]["model"] == "qwen2.5:7b-instruct"
    assert call["json"]["stream"] is False
    assert call["json"]["options"]["temperature"] == 0.0
    assert "system" in call["json"]


def test_model_missing_404_raises():
    with pytest.raises(DrafterError):
        _drafter(_Client(resp=_Resp(404))).draft("t")


def test_model_missing_200_error_payload_raises():
    d = _drafter(_Client(resp=_Resp(200, {"error": "model 'qwen2.5:7b-instruct' not found"})))
    with pytest.raises(DrafterError):
        d.draft("t")


def test_network_error_raises():
    with pytest.raises(DrafterError):
        _drafter(_Client(exc=httpx.ConnectError("connection refused"))).draft("t")


def test_non_200_raises():
    with pytest.raises(DrafterError):
        _drafter(_Client(resp=_Resp(500))).draft("t")


def test_empty_response_raises():
    with pytest.raises(DrafterError):
        _drafter(_Client(resp=_Resp(200, {"response": "   "}))).draft("t")


# --- preflight() (lightweight /api/tags) ----------------------------------

def test_preflight_true_when_model_present():
    body = {"models": [{"name": "qwen2.5:7b-instruct"}, {"name": "llama3.1:8b"}]}
    assert _drafter(_Client(get_resp=_Resp(200, body))).preflight() is True


def test_preflight_true_on_base_name_match():
    body = {"models": [{"name": "qwen2.5:7b-instruct-q4_K_M"}]}
    assert _drafter(_Client(get_resp=_Resp(200, body))).preflight() is True


def test_preflight_false_when_model_absent():
    body = {"models": [{"name": "llama3.1:8b"}]}
    assert _drafter(_Client(get_resp=_Resp(200, body))).preflight() is False


def test_preflight_false_on_unreachable():
    assert _drafter(_Client(get_exc=httpx.ConnectError("refused"))).preflight() is False


# --- build_signal_drafter factory (P3.2) ----------------------------------

def _cfg(**kw):
    base = dict(
        llm_provider="ollama",
        ollama_endpoint="http://x:11434",
        ollama_model="qwen2.5:7b-instruct",
        anthropic_api_key=None,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def test_factory_default_is_ollama_when_reachable(monkeypatch):
    monkeypatch.setattr(OllamaSignalDrafter, "preflight", lambda self: True)
    assert isinstance(build_signal_drafter(_cfg()), OllamaSignalDrafter)


def test_factory_none_when_ollama_down_and_no_key(monkeypatch):
    monkeypatch.setattr(OllamaSignalDrafter, "preflight", lambda self: False)
    assert build_signal_drafter(_cfg()) is None


def test_factory_anthropic_fallback_when_ollama_down_and_key(monkeypatch):
    monkeypatch.setattr(OllamaSignalDrafter, "preflight", lambda self: False)
    assert isinstance(
        build_signal_drafter(_cfg(anthropic_api_key="sk-x")), AnthropicSignalDrafter
    )


def test_factory_explicit_anthropic_provider():
    assert isinstance(
        build_signal_drafter(_cfg(llm_provider="anthropic", anthropic_api_key="sk-x")),
        AnthropicSignalDrafter,
    )


def test_factory_anthropic_provider_no_key_is_none():
    assert build_signal_drafter(_cfg(llm_provider="anthropic")) is None


def test_factory_auto_with_key_uses_anthropic_and_never_touches_ollama(monkeypatch):
    # the current hosted/testing path: a key means Anthropic, and Ollama's
    # preflight must NOT be called at all.
    def _boom(self):
        raise AssertionError("Ollama preflight must not run when auto+key")

    monkeypatch.setattr(OllamaSignalDrafter, "preflight", _boom)
    d = build_signal_drafter(_cfg(llm_provider="auto", anthropic_api_key="sk-x"))
    assert isinstance(d, AnthropicSignalDrafter)


def test_factory_auto_no_key_uses_ollama(monkeypatch):
    monkeypatch.setattr(OllamaSignalDrafter, "preflight", lambda self: True)
    assert isinstance(build_signal_drafter(_cfg(llm_provider="auto")), OllamaSignalDrafter)


def test_factory_auto_no_key_no_ollama_is_none(monkeypatch):
    monkeypatch.setattr(OllamaSignalDrafter, "preflight", lambda self: False)
    assert build_signal_drafter(_cfg(llm_provider="auto")) is None
