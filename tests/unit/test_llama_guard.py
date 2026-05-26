"""Transport-level tests for _llama_guard_scan() — Phase 5 / 05-02.

Uses ``httpx.MockTransport`` to fake the Ollama ``/api/generate`` endpoint
without adding new test dependencies. All seven failure modes specified
in 05-02-PLAN must produce well-defined outcomes:

- safe -> None
- unsafe + category -> ScanResult(source=llama_guard)
- TimeoutException -> None (fail-open, D-2)
- ConnectError -> None
- HTTP 500 -> None
- model missing (404 OR 200+error) -> marker ScanResult (D-3)
- malformed JSON body -> None

Plus one integration test confirming D-2: LlamaGuard runs uniformly for
severity=info/warn/block when regex did not match.
"""

from __future__ import annotations

from typing import Callable

import httpx
import pytest

from ccguard.agent import prompt_injection_engine as engine
from ccguard.agent.prompt_injection_engine import _llama_guard_scan, scan
from ccguard.schemas.policy import LlamaGuardConfig, PromptInjectionConfig


Handler = Callable[[httpx.Request], httpx.Response]


def _patch_httpx_client(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    """Replace ``httpx.Client`` inside the engine module with one that uses
    a MockTransport while preserving the original timeout argument."""

    real_client = httpx.Client

    def fake_client(**kwargs: object) -> httpx.Client:
        # The engine passes timeout=...; preserve it for assertions if needed.
        timeout = kwargs.get("timeout")
        return real_client(transport=httpx.MockTransport(handler), timeout=timeout)

    monkeypatch.setattr(engine.httpx, "Client", fake_client)


@pytest.fixture
def lg_cfg() -> LlamaGuardConfig:
    return LlamaGuardConfig(
        enabled=True,
        endpoint="http://localhost:11434",
        model="llama-guard3:8b",
        timeout_ms=500,
    )


# --- Test 1: safe verdict -> None -----------------------------------------


def test_safe_verdict_returns_none(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "safe"})

    _patch_httpx_client(monkeypatch, handler)
    assert _llama_guard_scan("hello world", lg_cfg) is None


# --- Test 2: unsafe with category -----------------------------------------


def test_unsafe_verdict_returns_scan_result(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"response": "unsafe\nS14"})

    _patch_httpx_client(monkeypatch, handler)
    result = _llama_guard_scan("malicious prompt", lg_cfg)
    assert result is not None
    assert result.category == "prompt-injection-template"
    assert result.source == "llama_guard"
    assert result.rule_id == "prompt_injection.llama_guard"
    assert "s14" in result.matched_pattern.lower()
    assert len(result.matched_pattern) <= len("llama-guard:") + 50


# --- Test 3: TimeoutException -> None -------------------------------------


def test_timeout_returns_none_fail_open(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("simulated timeout")

    _patch_httpx_client(monkeypatch, handler)
    assert _llama_guard_scan("anything", lg_cfg) is None


# --- Test 4: ConnectError -> None -----------------------------------------


def test_connect_error_returns_none(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("ollama is down")

    _patch_httpx_client(monkeypatch, handler)
    assert _llama_guard_scan("anything", lg_cfg) is None


# --- Test 5: HTTP 500 -> None ---------------------------------------------


def test_http_500_returns_none(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="internal error")

    _patch_httpx_client(monkeypatch, handler)
    assert _llama_guard_scan("anything", lg_cfg) is None


# --- Test 6a: model 404 -> marker ScanResult ------------------------------


def test_model_404_returns_marker_scan_result(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "model not found"})

    _patch_httpx_client(monkeypatch, handler)
    result = _llama_guard_scan("anything", lg_cfg)
    assert result is not None
    assert result.category == "llama_guard.model_missing"
    assert result.source == "llama_guard"
    assert result.rule_id == "prompt_injection.llama_guard.model_missing"
    assert "llama-guard3:8b" in result.matched_pattern


# --- Test 6b: 200 with body {"error": "...not found"} -> marker ------------


def test_model_missing_via_200_error_body_returns_marker(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"error": "model 'llama-guard3:8b' not found, try `ollama pull`"}
        )

    _patch_httpx_client(monkeypatch, handler)
    result = _llama_guard_scan("anything", lg_cfg)
    assert result is not None
    assert result.rule_id == "prompt_injection.llama_guard.model_missing"


# --- Test 7: malformed JSON body -> None ----------------------------------


def test_malformed_body_returns_none(
    monkeypatch: pytest.MonkeyPatch, lg_cfg: LlamaGuardConfig
) -> None:
    def handler(_req: httpx.Request) -> httpx.Response:
        return httpx.Response(200, text="<html>not json</html>")

    _patch_httpx_client(monkeypatch, handler)
    assert _llama_guard_scan("anything", lg_cfg) is None


# --- Test 8: LG called uniformly across severity=info (D-2) ---------------


@pytest.mark.parametrize("sev", ["info", "warn", "block"])
def test_llama_guard_invoked_for_every_severity_when_regex_did_not_match(
    monkeypatch: pytest.MonkeyPatch, sev: str
) -> None:
    """D-2: severity controls finding emission downstream — it does NOT
    short-circuit the LlamaGuard call. The engine must invoke LG regardless
    of severity when regex produced nothing."""

    calls: list[str] = []

    def fake_lg(text: str, lg_cfg: LlamaGuardConfig) -> None:
        calls.append(text)
        return None

    monkeypatch.setattr(engine, "_llama_guard_scan", fake_lg)
    cfg = PromptInjectionConfig(
        enabled=True,
        severity=sev,  # type: ignore[arg-type]
        llama_guard=LlamaGuardConfig(enabled=True),
    )
    # Text that does NOT match any default or admin pattern.
    result = scan("perfectly normal weather chitchat", cfg)
    assert result is None
    assert len(calls) == 1, (
        f"_llama_guard_scan must be called exactly once for severity={sev!r}"
    )


# --- Bonus: LG disabled -> not called -------------------------------------


def test_llama_guard_not_called_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        pytest.fail("_llama_guard_scan must not be called when llama_guard.enabled=False")

    monkeypatch.setattr(engine, "_llama_guard_scan", boom)
    cfg = PromptInjectionConfig(
        enabled=True, llama_guard=LlamaGuardConfig(enabled=False)
    )
    assert scan("plain text", cfg) is None
