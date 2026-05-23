"""Конфиг агента: load_or_create, генерация salt, идемпотентность."""

from __future__ import annotations

from pathlib import Path

from ccguard.agent.config import AgentConfig, load_or_create, save


def test_create_on_missing(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg, p = load_or_create(cfg_path)
    assert p == cfg_path
    assert cfg_path.exists()
    assert len(cfg.install_salt) == 64  # 32 bytes hex


def test_load_existing_keeps_salt(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg1, _ = load_or_create(cfg_path)
    salt1 = cfg1.install_salt

    cfg2, _ = load_or_create(cfg_path)
    assert cfg2.install_salt == salt1


def test_save_round_trip(tmp_path: Path) -> None:
    cfg_path = tmp_path / "config.yaml"
    cfg = AgentConfig(install_salt="abc")
    cfg.machine_label = "my-laptop"
    cfg.server.url = "https://srv.example.com"
    cfg.server.token = "tok"

    save(cfg, cfg_path)
    cfg2, _ = load_or_create(cfg_path)
    assert cfg2.machine_label == "my-laptop"
    assert cfg2.server.url == "https://srv.example.com"
    assert cfg2.server.token == "tok"
    assert cfg2.install_salt == "abc"
