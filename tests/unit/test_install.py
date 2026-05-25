"""install/uninstall: идемпотентность, не затирание чужих хуков, tamper-detection."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from ccguard.agent import install


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Изолировать ~/.claude и ~/.ccguard для каждого теста."""
    home = tmp_path / "home"
    claude_home = home / ".claude"
    cc_home = home / ".ccguard"
    claude_home.mkdir(parents=True)
    cc_home.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("CLAUDE_HOME", str(claude_home))
    monkeypatch.setenv("CCGUARD_AGENT_HOME", str(cc_home))
    return home


def test_install_creates_shim_and_writes_hooks(_isolated_home: Path) -> None:
    result = install.install_hook(scope="user")
    settings_file = Path(result["settings_file"])
    assert settings_file.exists()

    data = json.loads(settings_file.read_text())
    pre = data["hooks"]["PreToolUse"]
    matchers = {entry["matcher"] for entry in pre}
    assert matchers == set(install.HOOK_MATCHERS)

    shim = Path(result["shim_path"])
    assert shim.exists()
    assert os.access(shim, os.X_OK)
    assert install.SHIM_MARKER in shim.read_text()
    assert result["hooks_added"] == len(install.HOOK_MATCHERS)


def test_install_is_idempotent(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    first = Path(install.settings_path_for_scope("user")).read_text()

    second_result = install.install_hook(scope="user")
    second = Path(install.settings_path_for_scope("user")).read_text()

    assert second_result["hooks_added"] == 0
    assert json.loads(first) == json.loads(second)


def test_install_preserves_foreign_hooks(_isolated_home: Path) -> None:
    settings_file = install.settings_path_for_scope("user")
    settings_file.write_text(
        json.dumps(
            {
                "permissions": {"allow": ["Bash"]},
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/usr/bin/lint", "timeout": 3}
                            ],
                        }
                    ]
                },
            }
        )
    )

    install.install_hook(scope="user")
    data = json.loads(settings_file.read_text())
    bash_entry = next(e for e in data["hooks"]["PreToolUse"] if e["matcher"] == "Bash")
    commands = [h["command"] for h in bash_entry["hooks"]]
    assert "/usr/bin/lint" in commands
    assert any("ccguard" in c for c in commands)
    # permissions сохранились
    assert data["permissions"]["allow"] == ["Bash"]


def test_uninstall_removes_only_ours(_isolated_home: Path) -> None:
    settings_file = install.settings_path_for_scope("user")
    # Чужой хук уже там.
    settings_file.write_text(
        json.dumps(
            {
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "/usr/bin/lint"}],
                        }
                    ]
                }
            }
        )
    )

    install.install_hook(scope="user")
    install.uninstall_hook(scope="user")

    data = json.loads(settings_file.read_text())
    bash_entry = next(e for e in data["hooks"]["PreToolUse"] if e["matcher"] == "Bash")
    commands = [h["command"] for h in bash_entry["hooks"]]
    assert commands == ["/usr/bin/lint"]


def test_uninstall_idempotent(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    install.uninstall_hook(scope="user")
    # Повторный uninstall не падает и не находит ничего.
    result = install.uninstall_hook(scope="user")
    assert result["hooks_removed"] == 0


def test_verify_installation_ok(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    result = install.verify_installation(scope="user")
    assert result["ok"] is True
    assert result["issues"] == []


def test_verify_detects_disable_all_hooks(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    settings_file = install.settings_path_for_scope("user")
    data = json.loads(settings_file.read_text())
    data["disableAllHooks"] = True
    settings_file.write_text(json.dumps(data))

    result = install.verify_installation(scope="user")
    assert result["ok"] is False
    assert any("disableAllHooks" in i for i in result["issues"])


def test_verify_detects_missing_shim(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    install.shim_path().unlink()
    result = install.verify_installation(scope="user")
    assert result["ok"] is False
    assert any("shim missing" in i for i in result["issues"])


def test_install_creates_backup(_isolated_home: Path) -> None:
    settings_file = install.settings_path_for_scope("user")
    settings_file.write_text(json.dumps({"foo": "bar"}))
    result = install.install_hook(scope="user")
    assert result["backup"] is not None
    assert Path(result["backup"]).exists()


# --- PostToolUse audit hook (TUA-01/TUA-02) ---------------------------------


def test_install_writes_post_tool_use_audit_hook(_isolated_home: Path) -> None:
    result = install.install_hook(scope="user")
    settings_file = Path(result["settings_file"])
    data = json.loads(settings_file.read_text())

    post = data["hooks"]["PostToolUse"]
    assert len(post) == 1
    entry = post[0]
    assert entry["matcher"] == "*"
    assert len(entry["hooks"]) == 1
    hook = entry["hooks"][0]
    assert hook["type"] == "command"
    assert hook["command"] == str(install.audit_shim_path())
    assert hook["timeout"] == 3

    audit_shim = Path(result["audit_shim_path"])
    assert audit_shim.exists()
    assert os.access(audit_shim, os.X_OK)
    assert install.AUDIT_SHIM_MARKER in audit_shim.read_text()
    assert result["audit_hooks_added"] == 1


def test_install_is_idempotent_for_audit_hook(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    second = install.install_hook(scope="user")
    assert second["audit_hooks_added"] == 0

    settings_file = install.settings_path_for_scope("user")
    data = json.loads(settings_file.read_text())
    post = data["hooks"]["PostToolUse"]
    # No duplicates.
    assert len(post) == 1
    assert len(post[0]["hooks"]) == 1


def test_install_pre_and_post_coexist(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    settings_file = install.settings_path_for_scope("user")
    data = json.loads(settings_file.read_text())

    pre = data["hooks"]["PreToolUse"]
    pre_matchers = {entry["matcher"] for entry in pre}
    assert pre_matchers == set(install.HOOK_MATCHERS)

    post = data["hooks"]["PostToolUse"]
    post_matchers = {entry["matcher"] for entry in post}
    assert post_matchers == {"*"}


def test_install_preserves_foreign_post_hooks(_isolated_home: Path) -> None:
    settings_file = install.settings_path_for_scope("user")
    settings_file.write_text(
        json.dumps(
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/usr/bin/audit-foreign"}
                            ],
                        }
                    ]
                }
            }
        )
    )
    install.install_hook(scope="user")
    data = json.loads(settings_file.read_text())

    # Foreign PostToolUse entry still present.
    matchers = {e["matcher"] for e in data["hooks"]["PostToolUse"]}
    assert "Bash" in matchers
    assert "*" in matchers
    bash_entry = next(e for e in data["hooks"]["PostToolUse"] if e["matcher"] == "Bash")
    assert any(h["command"] == "/usr/bin/audit-foreign" for h in bash_entry["hooks"])


def test_install_creates_hooks_section_from_scratch(_isolated_home: Path) -> None:
    """settings.json missing `hooks` entirely → install creates both Pre and Post."""
    settings_file = install.settings_path_for_scope("user")
    settings_file.write_text(json.dumps({"permissions": {"allow": ["Read"]}}))
    install.install_hook(scope="user")
    data = json.loads(settings_file.read_text())
    assert "PreToolUse" in data["hooks"]
    assert "PostToolUse" in data["hooks"]
    assert data["permissions"]["allow"] == ["Read"]  # unrelated keys preserved


def test_verify_reports_audit_hook_registered(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    result = install.verify_installation(scope="user")
    assert result["ok"] is True
    assert result["audit_hook_registered"] is True


def test_verify_reports_audit_hook_missing(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    # Strip PostToolUse manually.
    settings_file = install.settings_path_for_scope("user")
    data = json.loads(settings_file.read_text())
    data["hooks"].pop("PostToolUse", None)
    settings_file.write_text(json.dumps(data))

    result = install.verify_installation(scope="user")
    assert result["ok"] is False
    assert result["audit_hook_registered"] is False
    assert any("audit hook missing" in i for i in result["issues"])


def test_verify_detects_missing_audit_shim(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    install.audit_shim_path().unlink()
    result = install.verify_installation(scope="user")
    assert result["ok"] is False
    assert any("audit shim missing" in i for i in result["issues"])


def test_uninstall_removes_audit_hook_and_shim(_isolated_home: Path) -> None:
    install.install_hook(scope="user")
    result = install.uninstall_hook(scope="user")

    settings_file = install.settings_path_for_scope("user")
    data = json.loads(settings_file.read_text())
    # PostToolUse fully gone (we only added our own).
    assert "PostToolUse" not in data.get("hooks", {})
    assert not install.audit_shim_path().exists()
    assert result["audit_hooks_removed"] == 1


def test_uninstall_keeps_foreign_post_hook(_isolated_home: Path) -> None:
    settings_file = install.settings_path_for_scope("user")
    settings_file.write_text(
        json.dumps(
            {
                "hooks": {
                    "PostToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [
                                {"type": "command", "command": "/usr/bin/audit-foreign"}
                            ],
                        }
                    ]
                }
            }
        )
    )
    install.install_hook(scope="user")
    install.uninstall_hook(scope="user")
    data = json.loads(settings_file.read_text())
    post = data["hooks"]["PostToolUse"]
    # Foreign hook preserved; our `*` entry gone.
    matchers = {e["matcher"] for e in post}
    assert matchers == {"Bash"}
    bash_entry = next(e for e in post if e["matcher"] == "Bash")
    assert bash_entry["hooks"][0]["command"] == "/usr/bin/audit-foreign"
