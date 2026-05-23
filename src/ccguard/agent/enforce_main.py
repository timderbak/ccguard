"""Standalone entrypoint для PyInstaller-сборки enforce-бинарника."""

from __future__ import annotations

import sys

from ccguard.agent.enforce import main_cli


def main() -> int:
    return main_cli()


if __name__ == "__main__":
    sys.exit(main())
