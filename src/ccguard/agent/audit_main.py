"""Standalone entrypoint for the PostToolUse audit hook (TUA-01, TUA-02).

Mirrors :mod:`ccguard.agent.enforce_main`. Registered as ``ccguard-audit-bin``
in ``[project.scripts]`` so that, after ``pip install -e .``, the binary on
``$PATH`` can be referenced verbatim from Claude Code's ``settings.json``.
"""

from __future__ import annotations

import sys

from ccguard.agent.audit_hook.hook_main import main_cli


def main() -> int:
    return main_cli(sys.stdin.read())


if __name__ == "__main__":
    sys.exit(main())
