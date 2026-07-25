"""Pure MCP definition-change classifier — the anti-false-positive core.

The point: NOT every ``definition_hash`` change is a rug-pull. A pinned semver
bump is a routine update (info); a pin-drop / digest-swap / target-shift is real
(warn/critical). Pure function, offline-testable.
"""
from __future__ import annotations

from ccguard.server.services.mcp_change_classifier import classify_definition_change


def _c(old: str | None, new: str | None, **kw):
    return classify_definition_change(old, new, **kw)


# --- routine updates → info (the noise we must NOT emit as warn) ------------


def test_pure_version_bump_is_info():
    v = _c("npx -y notion-mcp@1.2.3 | ", "npx -y notion-mcp@1.3.0 | ")
    assert v.kind == "version_bump"
    assert v.severity == "info"


def test_scoped_package_version_bump_is_info():
    v = _c("npx -y @acme/mcp@2.0.1 | ", "npx -y @acme/mcp@2.1.0 | ")
    assert v.kind == "version_bump"
    assert v.severity == "info"


def test_docker_tag_bump_is_info():
    v = _c("docker run acme/mcp:1.4.0 | ", "docker run acme/mcp:1.5.0 | ")
    assert v.kind == "version_bump"
    assert v.severity == "info"


def test_pip_pinned_bump_is_info():
    v = _c("uvx mcp-server==0.3.1 | ", "uvx mcp-server==0.4.0 | ")
    assert v.kind == "version_bump"
    assert v.severity == "info"


# --- suspicious changes → warn/critical ------------------------------------


def test_pin_dropped_to_latest_is_warn():
    v = _c("npx -y notion-mcp@1.2.3 | ", "npx -y notion-mcp@latest | ")
    assert v.kind == "pin_dropped"
    assert v.severity == "warn"


def test_digest_change_is_critical():
    old = "docker run acme/mcp@sha256:" + "a" * 64 + " | "
    new = "docker run acme/mcp@sha256:" + "b" * 64 + " | "
    v = _c(old, new)
    assert v.kind == "digest_change"
    assert v.severity == "critical"


def test_target_shift_to_tmp_is_critical():
    v = _c("npx -y notion-mcp | ", "/tmp/evil-binary --steal | ")
    assert v.kind == "target_shift"
    assert v.severity == "critical"


def test_endpoint_host_shift_is_critical():
    v = _c(" | https://api.notion.com/mcp", " | https://evil.example.com/mcp")
    assert v.kind == "target_shift"
    assert v.severity == "critical"


def test_downgrade_to_non_tls_is_critical():
    v = _c(" | https://api.notion.com/mcp", " | http://api.notion.com/mcp")
    assert v.kind == "target_shift"
    assert v.severity == "critical"


# --- unclassifiable + no-baseline → cautious warn --------------------------


def test_opaque_change_is_warn():
    v = _c("server-alpha run | ", "server-beta run | ")
    assert v.kind == "opaque"
    assert v.severity == "warn"


def test_no_old_definition_is_opaque_warn():
    v = _c(None, "npx -y notion-mcp@1.2.3 | ")
    assert v.kind == "opaque"
    assert v.severity == "warn"


def test_identical_definition_is_noop():
    v = _c("npx -y notion-mcp@1.2.3 | ", "npx -y notion-mcp@1.2.3 | ")
    assert v.kind == "noop"


# --- corroborator seam (Tim's "check the changelog/release" idea) ----------


def test_corroborator_downgrades_opaque_change():
    v = _c("server-alpha run | ", "server-beta run | ", corroborator=lambda o, n: True)
    assert v.kind == "corroborated_update"
    assert v.severity == "info"


def test_corroborator_escalates_uncorroborated_change():
    v = _c("server-alpha run | ", "server-beta run | ", corroborator=lambda o, n: False)
    assert v.kind == "uncorroborated_change"
    assert v.severity == "critical"


def test_corroborator_unknown_leaves_opaque():
    v = _c("server-alpha run | ", "server-beta run | ", corroborator=lambda o, n: None)
    assert v.kind == "opaque"


def test_corroborator_error_is_swallowed():
    def boom(o, n):
        raise RuntimeError("registry down")

    v = _c("server-alpha run | ", "server-beta run | ", corroborator=boom)
    assert v.kind == "opaque"  # best-effort — a broken corroborator never breaks classification


def test_version_bump_never_consults_corroborator():
    calls = []
    _c("npx foo@1.0.0 | ", "npx foo@1.1.0 | ", corroborator=lambda o, n: calls.append(1))
    assert calls == []  # a clean bump is decided locally, no external call
