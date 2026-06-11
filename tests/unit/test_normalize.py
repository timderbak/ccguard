from ccguard.agent.signals.normalize import NormalizedCommand, normalize_command


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


def test_oversize_input_fails_open():
    big = "a" * 200_000
    n = normalize_command(big)
    assert isinstance(n, NormalizedCommand)
    assert n.text  # falls back to raw, never raises


def test_non_string_is_safe():
    n = normalize_command(None)  # type: ignore[arg-type]
    assert n.statements == [] and n.urls == []
