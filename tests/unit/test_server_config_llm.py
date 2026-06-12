"""P3.2: ServerConfig LLM-backend fields. Default provider is 'auto' (Anthropic
when a key is present, Ollama otherwise)."""
from __future__ import annotations

from ccguard.server.config import ServerConfig


def test_llm_provider_defaults_to_auto():
    cfg = ServerConfig()
    assert cfg.llm_provider == "auto"
    assert cfg.ollama_endpoint == "http://localhost:11434"
    assert cfg.ollama_model == "qwen2.5:7b-instruct"


def test_load_reads_llm_env(monkeypatch, tmp_path):
    # force the env-defaults path (no config file present)
    monkeypatch.setenv("CCGUARD_SERVER_CONFIG", str(tmp_path / "absent.yaml"))
    monkeypatch.setenv("CCGUARD_LLM_PROVIDER", "anthropic")
    monkeypatch.setenv("CCGUARD_LLM_MODEL", "llama3.1:8b-instruct")
    monkeypatch.setenv("CCGUARD_LLM_ENDPOINT", "http://ollama-host:11434")
    cfg = ServerConfig.load()
    assert cfg.llm_provider == "anthropic"
    assert cfg.ollama_model == "llama3.1:8b-instruct"
    assert cfg.ollama_endpoint == "http://ollama-host:11434"
