"""ТЗ-IMPACT: detect_destructive — destruction by DANGEROUS target only.

AC1: destructive × sensitive target fires (delete/db/overwrite).
AC2 (FP-critical): destructive × safe/allowlisted target does NOT fire.
"""
from __future__ import annotations

import pytest

from ccguard.agent.signals.destructive import detect_destructive

# --- AC1: fires on dangerous targets ----------------------------------------
FIRES = [
    # delete
    ("rm -rf ~/.ssh", "delete"),
    ("rm -rf ~/.aws", "delete"),
    ("rm -rf /etc", "delete"),
    ("sudo rm -rf /usr/lib", "delete"),
    ("rm -rf /", "delete"),
    ("rm -rf ~", "delete"),
    ("rm -fr $HOME/.gnupg", "delete"),
    ("rm -f ~/.ssh/id_rsa", "delete"),
    ("shred ~/.ssh/id_ed25519", "delete"),
    # db
    ("psql -c 'DROP TABLE users'", "db"),
    ("DROP DATABASE production", "db"),
    ("mysql -e \"TRUNCATE TABLE orders\"", "db"),
    ("DELETE FROM customers", "db"),
    # overwrite
    ("echo x > ~/.aws/credentials", "overwrite"),
    ("cat evil > ~/.ssh/authorized_keys", "overwrite"),
    ("dd if=/dev/zero of=/dev/sda", "overwrite"),
    ("chmod -R 777 /etc", "overwrite"),
]


@pytest.mark.parametrize("command,expected", FIRES)
def test_destructive_fires_on_dangerous_target(command: str, expected: str) -> None:
    assert detect_destructive(command) == expected


# --- AC2: allowlist — normal dev work must NOT fire --------------------------
SAFE = [
    "rm -rf node_modules",
    "rm -rf dist",
    "rm -rf build",
    "rm -rf .next/cache",
    "rm -rf coverage",
    "rm -rf target/debug",
    "rm -rf ./out",
    "rm -rf /tmp/scratch",
    "rm -rf .venv",
    "rm -rf __pycache__",
    "DROP TABLE test_db",
    "DROP TABLE users_test",
    "DROP DATABASE test_fixtures",
    "TRUNCATE TABLE test_orders",
    "DELETE FROM users WHERE id = 1",      # has WHERE → not mass-delete
    "echo bundle > dist/bundle.js",         # overwrite of build output
    "chmod -R 755 node_modules",
    "ls -la ~/.ssh",                        # read, not destructive
    "cat ~/.aws/credentials",               # read, not destructive
    "git push --force",                     # git-destruction excluded by design
    "rm file.txt",                          # plain file, not sensitive
    "npm run build",
]


@pytest.mark.parametrize("command", SAFE)
def test_safe_targets_do_not_fire(command: str) -> None:
    assert detect_destructive(command) is None


def test_empty_and_garbage_safe() -> None:
    assert detect_destructive("") is None
    assert detect_destructive("   ") is None
    assert detect_destructive("echo hello world") is None
