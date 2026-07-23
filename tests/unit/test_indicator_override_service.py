"""ThreatIndicator → agent signal-override serving.

Only active + enabled + platform-relevant ``dangerous_command`` indicators become
overrides; every other type/state is excluded, and an uncompilable pattern is
skipped (never breaks the served list).
"""
from __future__ import annotations

import re

from sqlmodel import Session

from ccguard.server.db.models import ThreatIndicator
from ccguard.server.db.session import init_db, make_engine
from ccguard.server.services.indicator_override_service import (
    load_indicator_overrides,
    load_sensitive_path_overrides,
    load_suspicious_host_rules,
)


def _engine(tmp_path, tag: str = ""):
    # Unique db name per call so two _load()s in one test don't share a DB.
    safe = re.sub(r"\W+", "_", tag)[:30] or "db"
    eng = make_engine(f"sqlite:///{tmp_path}/ov_{safe}.db")
    init_db(eng)
    return eng


def _ind(**kw) -> ThreatIndicator:
    base = dict(
        indicator_type="dangerous_command",
        value=r"curl\s+.*\|\s*(ba|z)?sh",
        value_kind="regex",
        source="manual",
        technique="T1059",
        tactic="execution",
        weight=1.0,
        platform_relevant=True,
        status="active",
        enabled=True,
        description="pipe-to-shell",
    )
    base.update(kw)
    return ThreatIndicator(**base)


def _load(tmp_path, *inds):
    tag = "_".join(str(i.value) for i in inds)
    eng = _engine(tmp_path, tag)
    with Session(eng) as s:
        for i in inds:
            s.add(i)
        s.commit()
    with Session(eng) as s:
        return load_indicator_overrides(s)


def test_active_dangerous_command_becomes_override(tmp_path) -> None:
    ovs = _load(tmp_path, _ind())
    assert len(ovs) == 1
    ov = ovs[0]
    assert str(ov["id"]).startswith("indicator.")
    assert ov["attack_technique"] == "T1059"
    assert ov["description"] == "pipe-to-shell"
    # pattern is a valid regex that matches the intended command
    assert re.search(str(ov["pattern"]), "curl http://x | sh")


def test_disabled_and_pending_excluded(tmp_path) -> None:
    ovs = _load(
        tmp_path,
        _ind(value="a", enabled=False),
        _ind(value="b", status="pending"),
        _ind(value="c", status="rejected"),
    )
    assert ovs == []


def test_non_dangerous_command_types_excluded(tmp_path) -> None:
    ovs = _load(
        tmp_path,
        _ind(indicator_type="sensitive_path", value="~/.ssh/id_rsa", value_kind="exact"),
        _ind(indicator_type="suspicious_host", value="pastebin.com", value_kind="exact"),
        _ind(indicator_type="safe_path", value="node_modules", value_kind="prefix"),
    )
    assert ovs == []  # only dangerous_command is served


def test_platform_irrelevant_excluded(tmp_path) -> None:
    assert _load(tmp_path, _ind(platform_relevant=False)) == []


def test_uncompilable_regex_skipped(tmp_path) -> None:
    ovs = _load(tmp_path, _ind(value="([unterminated", value_kind="regex"))
    assert ovs == []  # a bad regex is dropped, not served


def test_exact_kind_is_escaped(tmp_path) -> None:
    # an exact dangerous_command with regex metachars must be matched literally
    ovs = _load(tmp_path, _ind(value="rm -rf /$HOME", value_kind="exact"))
    assert len(ovs) == 1
    pat = str(ovs[0]["pattern"])
    assert re.search(pat, "run: rm -rf /$HOME now")   # literal match
    assert not re.search(pat, "rm -rf /XHOME")         # not treated as regex ($ anchor)


def test_technique_falls_back_to_tactic_then_na(tmp_path) -> None:
    a = _load(tmp_path, _ind(value="x", technique=None, tactic="impact"))
    assert a[0]["attack_technique"] == "impact"
    b = _load(tmp_path, _ind(value="y", technique=None, tactic=None))
    assert b[0]["attack_technique"] == "n/a"


def test_description_falls_back_to_value(tmp_path) -> None:
    ovs = _load(tmp_path, _ind(value="dangerous-thing", description=None))
    assert ovs[0]["description"] == "dangerous-thing"


# --- suspicious_host → SuspiciousHostRule ----------------------------------


def _host(**kw) -> ThreatIndicator:
    base = dict(
        indicator_type="suspicious_host", value="evil.example.com", value_kind="exact",
        source="manual", technique="T1567", tactic="exfiltration",
        status="active", enabled=True, description="known exfil host",
    )
    base.update(kw)
    return ThreatIndicator(**base)


def _load_hosts(tmp_path, *inds):
    tag = "h_" + "_".join(str(i.value) for i in inds)
    eng = _engine(tmp_path, tag)
    with Session(eng) as s:
        for i in inds:
            s.add(i)
        s.commit()
    with Session(eng) as s:
        return load_suspicious_host_rules(s)


def test_active_suspicious_host_becomes_warn_rule(tmp_path) -> None:
    rules = _load_hosts(tmp_path, _host())
    assert len(rules) == 1
    r = rules[0]
    assert r["id"] == r["id"]  # namespaced
    assert str(r["id"]).startswith("indicator/")
    assert r["pattern"] == "evil.example.com"
    assert r["type"] == "glob"
    assert r["severity"] == "warn"  # conservative: tag, don't block, by default
    assert r["title"] and r["reason"] and r["remediation"]  # all required fields present


def test_host_value_kind_conversions(tmp_path) -> None:
    reg = _load_hosts(tmp_path, _host(value=r"evil\d+\.com", value_kind="regex"))
    assert reg[0]["type"] == "regex" and reg[0]["pattern"] == r"evil\d+\.com"
    pre = _load_hosts(tmp_path, _host(value="cdn.evil", value_kind="prefix"))
    assert pre[0]["type"] == "glob" and pre[0]["pattern"] == "cdn.evil*"


def test_host_bad_regex_skipped(tmp_path) -> None:
    assert _load_hosts(tmp_path, _host(value="([bad", value_kind="regex")) == []


def test_non_host_types_not_in_host_rules(tmp_path) -> None:
    rules = _load_hosts(
        tmp_path,
        _host(indicator_type="dangerous_command", value="curl|sh", value_kind="regex"),
        _host(indicator_type="safe_path", value="node_modules"),
    )
    assert rules == []


def test_disabled_host_excluded(tmp_path) -> None:
    assert _load_hosts(tmp_path, _host(enabled=False)) == []


# --- sensitive_path → cred.read.store_* overrides --------------------------


def _path(**kw) -> ThreatIndicator:
    base = dict(
        indicator_type="sensitive_path", value="~/.config/newapp/token", value_kind="exact",
        source="manual", technique="T1552.001", tactic="credential-access",
        status="active", enabled=True, description="app token",
    )
    base.update(kw)
    return ThreatIndicator(**base)


def _load_paths(tmp_path, *inds):
    tag = "p_" + "_".join(str(i.value) for i in inds)
    eng = _engine(tmp_path, tag)
    with Session(eng) as s:
        for i in inds:
            s.add(i)
        s.commit()
    with Session(eng) as s:
        return load_sensitive_path_overrides(s)


def test_added_sensitive_path_is_served_with_cred_prefix(tmp_path) -> None:
    ovs = _load_paths(tmp_path, _path())
    assert len(ovs) == 1
    assert str(ovs[0]["id"]).startswith("cred.read.store_")
    assert ovs[0]["attack_technique"] == "T1552.001"


def test_served_path_signal_resolves_to_credential_access() -> None:
    # the prefix must actually feed the credential-access kill-chain stage
    from ccguard.server.services.chain_constants import stage_for_signal

    assert stage_for_signal("cred.read.store_42") == "credential-access"


def test_core_seed_os_standard_paths_excluded(tmp_path) -> None:
    # os-standard paths already have a baked cred.read.* signal → not served
    assert _load_paths(tmp_path, _path(value="~/.ssh/id_rsa", source="os-standard")) == []


def test_added_path_technique_defaults_to_t1552(tmp_path) -> None:
    ovs = _load_paths(tmp_path, _path(technique=None))
    assert ovs[0]["attack_technique"] == "T1552"


def test_disabled_and_non_path_excluded_from_path_serving(tmp_path) -> None:
    ovs = _load_paths(
        tmp_path,
        _path(value="a", enabled=False),
        _path(value="b", indicator_type="dangerous_command"),
    )
    assert ovs == []
