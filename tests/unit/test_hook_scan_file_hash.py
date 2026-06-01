"""Verify HookEntry carries file_path/file_content_hash/file_unreadable_reason
(under the existing repo-name attributes: command_file_path, command_file_hash,
plus the new file_unreadable_reason).
"""

from ccguard.schemas.inventory import HookEntry


def test_hook_entry_accepts_new_file_fields():
    entry = HookEntry(
        event="PreToolUse",
        matcher="Bash",
        type="command",
        command="/usr/local/bin/python /opt/script.py",
        source="/root/.claude/settings.json",
        is_ccguard_owned=False,
        command_file_path="/opt/script.py",
        command_file_hash="abc123def456",
        file_unreadable_reason=None,
    )
    assert entry.command_file_path == "/opt/script.py"
    assert entry.command_file_hash == "abc123def456"
    assert entry.file_unreadable_reason is None


def test_hook_entry_defaults_new_fields_to_none():
    entry = HookEntry(event="PreToolUse", type="command", source="/root/.claude/settings.json")
    assert entry.command_file_path is None
    assert entry.command_file_hash is None
    assert entry.file_unreadable_reason is None
