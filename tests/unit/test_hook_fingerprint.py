"""compute_fingerprint: deterministic four-field sha256 with None-as-empty."""

from ccguard.server.services.hook_baseline_service import compute_fingerprint


def test_fingerprint_is_deterministic():
    fp1 = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "abc")
    fp2 = compute_fingerprint("PreToolUse", "Bash", "python /opt/x.py", "abc")
    assert fp1 == fp2
    assert len(fp1) == 64  # full sha256 hex


def test_fingerprint_changes_when_event_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "abc")
    b = compute_fingerprint("PostToolUse", "Bash", "cmd", "abc")
    assert a != b


def test_fingerprint_changes_when_matcher_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "abc")
    b = compute_fingerprint("PreToolUse", "Write", "cmd", "abc")
    assert a != b


def test_fingerprint_changes_when_command_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd1", "abc")
    b = compute_fingerprint("PreToolUse", "Bash", "cmd2", "abc")
    assert a != b


def test_fingerprint_changes_when_file_content_hash_changes():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", "old")
    b = compute_fingerprint("PreToolUse", "Bash", "cmd", "new")
    assert a != b


def test_fingerprint_none_file_hash_is_stable():
    a = compute_fingerprint("PreToolUse", "Bash", "cmd", None)
    b = compute_fingerprint("PreToolUse", "Bash", "cmd", None)
    assert a == b
    # None must NOT equal empty file_hash "" — they're semantically distinct
    # (None = couldn't read, "" = inline cmd with no file). Spec § Граничные случаи.
    c = compute_fingerprint("PreToolUse", "Bash", "cmd", "")
    assert a != c
