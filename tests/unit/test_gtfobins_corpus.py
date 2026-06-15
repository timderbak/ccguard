"""CI guard for GTFOBins/LOLBAS enrichment: shell-spawn LOLBin breakouts and
sudo→shell privesc — the "100 ways to get a shell". Sourced from
gtfobins.github.io via a research workflow, mapped to FP-safe signals
(exec.shell_spawn / system.sudo_shell). Each abuse must fire its target; a
curated set of benign uses of the SAME binaries must stay quiet."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ccguard.agent.signals.extractor import extract_signals

_CASES = json.loads(
    (Path(__file__).resolve().parents[1] / "fixtures" / "gtfobins_corpus.json").read_text()
)["cases"]


@pytest.mark.parametrize("case", _CASES, ids=[c["command"][:45] for c in _CASES])
def test_gtfobins_breakout_caught(case: dict) -> None:
    fired = set(extract_signals("Bash", {"command": case["command"]}))
    assert case["target_signal"] in fired, (
        f"GTFOBins breakout MISSED: {case['command']!r}\n"
        f"  expected {case['target_signal']} — fired {sorted(fired) or '(none)'}"
    )


# benign use of the same LOLBins — must NOT fire shell_spawn / sudo_shell
_BENIGN = [
    "find . -name '*.py'",
    "find . -type f -exec grep -l TODO {} \\;",
    "find . -exec chmod 644 {} +",
    "sudo find /var/log -name '*.log' -mtime +30 -delete",
    "tar czf build.tgz dist/",
    "tar xf release.tar.gz -C /opt",
    "tar --checkpoint=1000 --checkpoint-action=dot -cf big.tar data/",
    "tar -I zstd -cf x.tar.zst d/",
    "vim file.py",
    "vim -c 'set ft=python' notes.txt",
    "vim -c 'wq' file",
    "sudo vim /etc/nginx/nginx.conf",
    "gdb -batch -ex 'bt' ./core",
    "gdb --args ./prog arg1",
    "sudo gdb --args ./server --config c.yaml",
    "env NODE_ENV=prod node app.js",
    "nice -n 19 npm run build",
    "nohup ./server &",
    "timeout 30 pytest",
    "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx",
    "cat urls.txt | xargs -n1 curl",
    "ls *.jpg | xargs -P4 convert",
    "awk '{print $1}' f",
    "ps aux | awk '/python/{print $2}'",
    "awk -F: '{print $1}' /etc/passwd",
    "ssh user@host",
    "ssh -o ProxyJump=bastion web01",
    "ssh -o ProxyCommand='cloudflared access ssh --hostname %h' host",
    "git -p log",
    "GIT_PAGER=less git show",
    "git -c core.pager='delta' log",
    "sed -n '1,10p' file",
    "sed -e 's/x/y/' -e 's/a/b/' f",
    "make -j8 all",
    "make --eval='CC=clang' build",
    "man tar",
    "LESSOPEN='| highlight %s' less code.c",
    "nmap -sV -p443 host",
    "sudo mount /dev/sdb1 /mnt",
    "sudo apt-get update",
    "sudo apt-get install -y nginx",
    # Windows LOLBins — benign admin/dev use
    "rundll32.exe shell32.dll,Control_RunDLL desk.cpl",
    "rundll32 printui.dll,PrintUIEntry",
    "msbuild MyApp.sln",
    "msbuild MyApp.csproj /p:Configuration=Release",
    "installutil MyWindowsService.exe",
    "wmic process list brief",
    "wmic logicaldisk get size,freespace",
    "powershell -File C:\\scripts\\backup.ps1",
    "Invoke-WebRequest -OutFile pkg.zip https://repo/x",
    "msiexec /i C:\\Installers\\VendorApp.msi",
    "msiexec /x {GUID} /qn",
    # reverse-shell benign lookalikes (client/download/listener — not a revshell)
    "telnet smtp.example.com 25",
    "telnet localhost 6379",
    "xterm -e 'vim file'",
    "New-Object System.Net.WebClient",
    "New-Object System.Net.Sockets.TcpListener",
    "powercat -c 127.0.0.1 -p 7002",
    'net.Dial("tcp","db:5432")',
    'TcpStream::connect("db:5432")',
    # file-read / exfil benign lookalikes
    "od -A x -t x1z build/output.o",
    "hexdump -C image.png | head",
    "cat /etc/hostname",
    "gpg --verify sha256sums.txt.asc",
    "gpg --decrypt backup.gpg > restored.tar",
    "python3 -m http.server 8080 --bind 127.0.0.1",
    "python3 -m http.server --bind localhost 9000",
    "php -S 127.0.0.1:8000",
]

_NEW_SIGS = (
    "exec.shell_spawn", "system.sudo_shell", "exec.windows_lolbin",
    "c2.reverse_shell", "cred.read.shadow", "egress.adhoc_server",
)


@pytest.mark.parametrize("cmd", _BENIGN)
def test_gtfobins_benign_stays_quiet(cmd: str) -> None:
    fired = set(extract_signals("Bash", {"command": cmd}))
    for sig in _NEW_SIGS:
        assert sig not in fired, f"FP {sig}: {cmd!r} → {sorted(fired)}"
