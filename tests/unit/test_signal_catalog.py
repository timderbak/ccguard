"""Catalog integrity: stable IDs, ATT&CK mapping, compiled patterns."""
from __future__ import annotations

import re

from ccguard.agent.signals.catalog import CATALOG, Signal


def test_catalog_nonempty_and_typed():
    # Floor bumped to 18 after Stage 6 catalog expansion (cloud creds, browser
    # creds, cloud-storage exfil, container escape, supply-chain publish,
    # cloud-metadata recon, systemd persistence).
    assert len(CATALOG) >= 18
    assert all(isinstance(s, Signal) for s in CATALOG)


def test_signal_ids_unique_and_kebab_namespaced():
    ids = [s.id for s in CATALOG]
    assert len(ids) == len(set(ids)), "duplicate signal id"
    for sid in ids:
        assert re.fullmatch(r"[a-z0-9]+(\.[a-z0-9_]+)+", sid), sid


def test_every_signal_has_attack_technique_and_pattern():
    for s in CATALOG:
        assert re.fullmatch(r"(T\d{4}(\.\d{3})?|ATLAS\..+)", s.attack_technique), s.id
        assert isinstance(s.pattern, re.Pattern)
