"""Browser + password-manager credential theft signals.

The scary vibe-coder case: a manipulated agent reaches into saved browser
passwords / cookies / a password-manager DB and reads or bulk-copies them. These
must fire, and benign dev activity must NOT.
"""
from __future__ import annotations

from ccguard.agent.signals.extractor import extract_signals


def _bash(cmd: str) -> set[str]:
    return set(extract_signals("Bash", {"command": cmd}))


def _read(path: str) -> set[str]:
    return set(extract_signals("Read", {"file_path": path}))


# --- browser credential / key stores ---------------------------------------


def test_firefox_key_db_is_caught():
    # key4.db is the Firefox NSS master key — unambiguous credential theft
    assert "cred.read.browser" in _read("~/.mozilla/firefox/ab12.default/key4.db")
    assert "cred.read.browser" in _bash("cat ~/.mozilla/firefox/ab12.default/key4.db")


def test_firefox_logins_json_is_caught():
    assert "cred.read.browser" in _read("~/.mozilla/firefox/ab12.default-release/logins.json")


def test_chrome_local_state_key_is_caught():
    # Local State holds the AES key that decrypts Chrome Login Data/Cookies
    assert "cred.read.browser" in _read("~/.config/google-chrome/Local State")


def test_chrome_login_data_still_caught():
    assert "cred.read.browser" in _read("~/.config/google-chrome/Default/Login Data")


def test_browser_profile_bulk_copy_is_caught():
    assert "cred.read.browser" in _bash("cp -r ~/.config/google-chrome /tmp/steal")
    assert "cred.read.browser" in _bash("tar czf out.tgz ~/.mozilla/firefox")


# --- password managers / OS credential vaults ------------------------------


def test_keepass_kdbx_is_caught():
    assert "cred.read.password_manager" in _read("~/Documents/vault.kdbx")
    assert "cred.read.password_manager" in _bash("cat secrets.kdb")  # legacy KeePass / DB2 keystore


def test_gnome_keyring_and_kwallet_caught():
    assert "cred.read.password_manager" in _read("~/.local/share/keyrings/login.keyring")


def test_macos_keychain_file_read_is_caught():
    assert "cred.read.password_manager" in _read("~/Library/Keychains/login.keychain-db")


def test_windows_credential_manager_caught():
    assert "cred.read.password_manager" in _bash("cmdkey /list")
    assert "cred.read.password_manager" in _bash("vaultcmd /listcreds:\"Windows Credentials\"")


# --- false-positive guards (must NOT fire) ---------------------------------


def test_prose_local_state_does_not_fire():
    # "local state" as ordinary words, not a Chrome path, must not misfire
    assert "cred.read.browser" not in _bash("echo restoring the local state machine")


def test_ordinary_copy_does_not_fire():
    assert "cred.read.browser" not in _bash("cp -r ./src ./build")


def test_ordinary_json_read_does_not_fire():
    assert "cred.read.browser" not in _read("~/project/config.json")
    assert "cred.read.password_manager" not in _read("~/project/package.json")
