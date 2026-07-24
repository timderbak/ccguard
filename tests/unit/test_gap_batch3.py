"""ATT&CK coverage-gap batch 3: ransomware encryption, dynamic-linker hijack,
shell-history credential harvest, timestamp forgery.

Each signal is behavior-gated; the FP guards assert ordinary dev work stays quiet.
"""
from __future__ import annotations

from ccguard.agent.signals.extractor import extract_signals


def _bash(cmd: str) -> set[str]:
    return set(extract_signals("Bash", {"command": cmd}))


def _read(path: str) -> set[str]:
    return set(extract_signals("Read", {"file_path": path}))


def _write(path: str) -> set[str]:
    return set(extract_signals("Write", {"file_path": path, "content": "x"}))


# --- impact.encrypt (T1486) — ransomware -------------------------------------


def test_7z_encrypt_delete_source_fires():
    assert "impact.encrypt" in _bash("7z a out.7z -pHunter2 -sdel ./docs")
    assert "impact.encrypt" in _bash("7za a -sdel -pS3cret vault.7z ~/Documents")


def test_find_exec_openssl_encrypt_fires():
    assert "impact.encrypt" in _bash(
        "find /home -type f -exec openssl enc -aes-256-cbc -k pw -in {} -out {}.enc \\;"
    )


def test_find_exec_gpg_encrypt_fires():
    assert "impact.encrypt" in _bash("find . -type f -exec gpg -c {} \\;")


def test_ransom_extension_output_fires():
    assert "impact.encrypt" in _bash("openssl enc -aes-256-cbc -in data.db -out data.db.locked")
    assert "impact.encrypt" in _bash("mv quarterly_report.pdf quarterly_report.pdf.encrypted")


def test_gpg_mass_encrypt_flag_fires():
    assert "impact.encrypt" in _bash("gpg --encrypt-files *.docx")


def test_encrypt_then_remove_loop_fires():
    assert "impact.encrypt" in _bash(
        'for f in *.txt; do openssl enc -aes-128-cbc -k p -in "$f" -out "$f.x"; rm "$f"; done'
    )


def test_benign_single_encrypt_does_not_fire():
    # A one-off encrypt of a single file to a non-ransom extension is normal.
    assert "impact.encrypt" not in _bash("openssl enc -aes-256-cbc -in secret.txt -out secret.enc")
    assert "impact.encrypt" not in _bash("gpg -c notes.txt")


def test_benign_archive_does_not_fire():
    assert "impact.encrypt" not in _bash("7z a backup.7z ./project")
    assert "impact.encrypt" not in _bash("tar czf backup.tgz ~/project")


# --- persist.preload (T1574.006) — dynamic-linker / PATH hijack --------------


def test_ld_so_preload_write_fires():
    assert "persist.preload" in _bash("echo /tmp/evil.so > /etc/ld.so.preload")
    assert "persist.preload" in _write("/etc/ld.so.preload")


def test_ld_preload_to_so_fires():
    assert "persist.preload" in _bash("LD_PRELOAD=/tmp/x.so ./app")
    assert "persist.preload" in _bash("export LD_PRELOAD=/dev/shm/lib.so")


def test_ld_preload_persisted_in_rc_fires():
    assert "persist.preload" in _bash("echo 'export LD_PRELOAD=/tmp/e.so' >> ~/.bashrc")


def test_path_prepend_worldwritable_fires():
    assert "persist.preload" in _bash("export PATH=/tmp/bin:$PATH")
    assert "persist.preload" in _bash("export PATH=.:$PATH")


def test_benign_path_prepend_does_not_fire():
    assert "persist.preload" not in _bash("export PATH=$HOME/bin:$PATH")
    assert "persist.preload" not in _bash("export PATH=/usr/local/bin:$PATH")
    assert "persist.preload" not in _bash("export PATH=~/go/bin:$PATH")


def test_benign_bashrc_edit_does_not_fire():
    assert "persist.preload" not in _bash("echo \"alias ll='ls -la'\" >> ~/.bashrc")


# --- cred.read.shell_history (T1552.003) -------------------------------------


def test_bash_history_read_fires():
    assert "cred.read.shell_history" in _read("~/.bash_history")
    assert "cred.read.shell_history" in _bash("cat ~/.zsh_history")
    assert "cred.read.shell_history" in _bash("grep -i password ~/.bash_history")


def test_client_history_files_fire():
    assert "cred.read.shell_history" in _read("~/.mysql_history")
    assert "cred.read.shell_history" in _read("~/.psql_history")
    assert "cred.read.shell_history" in _read("~/.python_history")
    assert "cred.read.shell_history" in _read("~/.local/share/fish/fish_history")


def test_rc_and_builtin_do_not_fire():
    # rc/config files and the bare `history` builtin (listing) are not a harvest.
    assert "cred.read.shell_history" not in _read("~/.bashrc")
    assert "cred.read.shell_history" not in _read("~/.zshrc")
    assert "cred.read.shell_history" not in _bash("history")
    assert "cred.read.shell_history" not in _read("~/project/config.history")


# --- defense.timestomp (T1070.006) -------------------------------------------


def test_touch_reference_clone_fires():
    assert "defense.timestomp" in _bash("touch -r /etc/passwd /tmp/evil")
    assert "defense.timestomp" in _bash("touch --reference=template.c generated.c")


def test_touch_explicit_time_fires():
    assert "defense.timestomp" in _bash("touch -t 202001010000 evidence.log")


def test_setfile_timestomp_fires():
    assert "defense.timestomp" in _bash("SetFile -d '01/01/2020 00:00:00' report.pdf")


def test_plain_touch_does_not_fire():
    assert "defense.timestomp" not in _bash("touch newfile.txt")
    assert "defense.timestomp" not in _bash("touch -a somefile")
    assert "defense.timestomp" not in _bash("touch -m build.stamp")
