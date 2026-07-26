"""Declarative per-event signal catalog (Behavioral Detection, Stage 1).

Each :class:`Signal` is a single regex matched against a normalized text view
of one tool invocation (command + file path, lowercased). These are *per-event*
detections only; rate-based (burst) and stateful (sequence, config-drift)
detections live server-side in later stages.

ATT&CK / ATLAS mappings are part of the contract — the triage UI links each
fired signal to its technique. Keep IDs STABLE: they are persisted in
``ToolUseEvent.signals_json`` and referenced by the server-side risk engine.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache


@cache
def _compile(rx: str) -> re.Pattern[str]:
    """Скомпилировать и закэшировать regex. Кэш модульный, поэтому одинаковые
    паттерны компилируются один раз на весь процесс."""
    return re.compile(rx, re.IGNORECASE)


@dataclass(frozen=True)
class Signal:
    """One per-event behavioral signal.

    ``pattern`` is matched (``search``) against the normalized text of a tool
    invocation. ``attack_technique`` is a MITRE ATT&CK id (``T####`` /
    ``T####.###``) or an ATLAS reference (``ATLAS.<name>``).

    Хранится СЫРАЯ строка паттерна (``pattern_src``), а компиляция ленивая —
    через свойство ``pattern``. Причина: каталог из ~98 сигналов раньше
    компилировал ВСЕ regex на импорте модуля (~50мс), хотя на любой отдельный
    вызов инструмента срабатывает лишь часть проверок. Этот импорт лежит на
    горячем пути enforce (бюджет 100мс), поэтому компилируем по требованию, а
    не оптом при старте. API (``s.pattern.search(...)``) не меняется.
    """

    id: str
    attack_technique: str
    pattern_src: str
    description: str

    @property
    def pattern(self) -> re.Pattern[str]:
        return _compile(self.pattern_src)


def _p(rx: str) -> str:
    """Раньше компилировала regex; теперь возвращает сырую строку — компиляция
    отложена в ``Signal.pattern`` (см. докстринг). Оставлена как есть, чтобы не
    трогать ~98 записей CATALOG."""
    return rx


CATALOG: tuple[Signal, ...] = (
    Signal(
        "cred.read.aws",
        "T1552.001",
        _p(r"\.aws/(credentials|config)"),
        "Access to AWS credential files",
    ),
    Signal(
        "cred.read.ssh",
        "T1552.004",
        # red-team: + id_ecdsa and gpg secret-key export (private-key material).
        _p(r"(\.ssh/|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|gpg\b[^\n]*--export-secret-keys?)"),
        "Access to SSH/GPG private keys",
    ),
    Signal(
        "cred.read.dotenv",
        "T1552.001",
        _p(r"(\.env\b|\.npmrc\b|\.pypirc\b|\.pem\b|\.netrc\b)"),
        "Access to dotenv / package-manager / cert secrets",
    ),
    Signal(
        "egress.network_tool",
        "T1041",
        # Command-anchored: not preceded by a path/word char, so a tool name as a
        # path component (``/opt/curl``, ``func nc``) does not forge egress. Real
        # invocations (start, after space / ; | & ( newline) still fire. Red-team-
        # widened with alias/alt outbound tools (websocat/kcat/xh/socat/mail/...).
        _p(
            r"(?<![\w/.\-])(curl|curlie|wget|nc|ncat|netcat|socat|websocat"
            r"|kcat|kafkacat|xh|httpie|scp|sftp|mail|mailx|sendmail|ssmtp|msmtp)\b"
        ),
        "Outbound transfer tool invoked",
    ),
    # --- P1: egress as ACTION-category (host-agnostic) -----------------------
    # Exfil detection must not depend on a host allowlist. These fire on the
    # outbound PRIMITIVE regardless of destination; severity comes from the
    # cred->egress correlation, so a bare tag is informational, not a finding.
    # All resolve to the exfiltration stage via the existing ``egress.`` prefix
    # rule in chain_constants — correlation is untouched.
    Signal(
        "egress.http_client",
        "T1041",
        _p(
            # Anchored to CALL forms (not bare library names) so `npm i axios`,
            # `grep "fetch(" src/`, `git commit -m "http post"` do NOT fire.
            r"\b(requests\.(get|post|put|patch|delete|request)"
            r"|httpx\.(get|post|put|patch|delete)|urllib\.request|urllib2\."
            r"|http\.client|socket\.(socket|connect)"
            r"|invoke-webrequest|invoke-restmethod"
            r"|fetch\(\s*['\"]?https?://"
            r"|\bhttp\s+(?:get|post|put|patch|delete|head|options)\s+\S*[:/.]\S)"
        ),
        "Ad-hoc HTTP client egress (python requests/httpx/urllib/socket, node fetch(url), httpie, PowerShell) — host-agnostic",
    ),
    Signal(
        "egress.file_transfer",
        "T1048",
        _p(
            # Require a REMOTE destination so a purely-local `rsync a/ b/` (with
            # a stray `:` elsewhere on the line) does not fire.
            r"\b(rclone\s+(copy|sync|move)\s+\S+\s+\S+:"
            # rcat (upload-from-stdin) / cat (download-to-stdout) take a single
            # remote: arg — red-team found `rclone rcat remote:` evaded copy/sync/move.
            r"|rclone\s+(?:rcat|cat)\s+\S+:"
            r"|rsync\b[^\n]*\s(?:[\w.-]+@[\w.-]+:|[\w.-]+:[~/])"
            r"|\blftp\b|\btftp\b|\bftp\s+[\w.-]+\.[\w.-]+)"
        ),
        "Bulk file-transfer egress to a REMOTE host (rclone remote:, rsync host:path, ftp)",
    ),
    Signal(
        "egress.cloud_cli",
        "T1567.002",
        _p(r"\b(gh\s+gist\s+create|gh\s+release\s+upload|b2\s+upload-file|doctl\s+\S+\s+upload)\b"),
        "Cloud-CLI upload egress (gh gist/release, b2)",
    ),
    Signal(
        "exec.pipe_to_shell",
        "T1059.004",
        # | sh / | bash, base64 decode, eval, AND piping into a language
        # interpreter that reads CODE FROM STDIN (no script arg) — `curl … |
        # python3`, `… | perl`. A script arg (`… | python3 parse.py`) is data
        # processing and does NOT match (interpreter must end the pipe segment).
        _p(
            r"(\|\s*(ba|z)?sh\b"
            r"|\|\s*(python[0-9.]*|perl|ruby|node|deno|bun|php|rscript)\b\s*(?:/dev/stdin|-)?\s*(?=$|[|;&\n])"
            # red-team: pipe into awk system() / make -f - (stdin code) + sourcing
            # a process substitution `source <(curl …)` (dynamic code exec)
            r"|\|\s*g?awk\b[^\n]*system\("
            r"|\|\s*make\b[^\n]*-f\s*-"
            r"|\b(?:source|\.)\s+<\("
            r"|base64\s+(-d|--decode)|\beval\b)"
        ),
        "Piping/decoding into a shell or language interpreter (stdin code)",
    ),
    Signal(
        "exec.shell_spawn",
        "T1059",
        # GTFOBins "100 ways to get a shell" — a legit binary driven to spawn a
        # shell via its abuse-specific invocation (NOT the bare binary). Each
        # alternative is the FP-distinguishing token: -exec <shell>, tar exec
        # side-channels, editor/-debugger -c/-ex shell-out, exec-wrapper → bare
        # shell, awk system(), ssh ProxyCommand shell, sed e-command, make
        # $(shell), the `!sh` bang-escape (less/ed/ftp/vim), man -H<shell>, pager
        # → shell. Benign use of the same binaries (tar czf, find -name, awk
        # '{print}', vim -c 'wq', gdb -ex bt) stays quiet.
        _p(
            r"\bfind\b[^\n]*\s-(?:exec(?:dir)?|ok)\s+(?:/bin/|/usr/bin/)?(?:ba|z|da|k|a)?sh\b"
            r"|\btar\b[^\n]*(?:--checkpoint-action=exec|--to-command|--use-compress-program|\s-I\s)[^\n]*(?:/bin/|/usr/bin/)?(?:ba|z|da|k|a)?sh\b"
            r"|\b(?:vi|vim|view|nvim|rvim|ex)\b[^\n]*(?:\s-c\s|\s\+)[^\n]*(?::!|:\s*shell|:\s*ter|set\s+shell=|os\.system|os\.execute)"
            r"|\bgdb\b[^\n]*\s-(?:ex|iex|x|batch)\b[^\n]*(?:!\s*/?(?:bin/)?\w*sh|shell\s|os\.(?:system|execl|execv))"
            r"|\b(?:env|nice|nohup|stdbuf|setarch|ionice|taskset|setsid|rlwrap|aa-exec|chrt)\b[^\n]*\s(?:/bin/|/usr/bin/)?(?:ba|z|da|k|a)?sh\b(?:\s+-[ipl]+\b|\s*$|\s*[;|&])"
            r"|\bxargs\b[^\n]*-a\s*/dev/null[^\n]*(?:/bin/|/usr/bin/)?(?:ba|z|da|k|a)?sh\b"
            r"|\b(?:g|m|n)?awk\b[^\n]*(?:system\(|print\s*\|\s*['\"]?(?:/bin/)?(?:ba)?sh|\|\s*['\"]?(?:/bin/)?(?:ba)?sh)"
            r"|\bssh\b[^\n]*-o\s*(?:ProxyCommand|LocalCommand)=[^\n]*(?:;\s*(?:/bin/)?(?:ba)?sh|(?:/bin/)(?:ba|da)?sh)"
            r"|\bsed\b[^\n]*['\"][^'\"\n]*\b\d*\s*e\s+(?:exec\s+)?(?:/bin/)?(?:ba)?sh"
            r"|\bmake\b[^\n]*(?:--eval|-f\s*-|-f\s*/dev/stdin)[^\n]*\$\(\s*shell\s"
            r"|(?:^|\n)\s*!\s*(?:/bin/|/usr/bin/)?(?:ba|z|da)?sh\b"
            r"|\bman\b[^\n]*\s-H\s*(?:/bin/)?(?:ba)?sh"
            r"|(?:PAGER|GIT_PAGER)=['\"]?[^'\"\n]*sh\b[^'\"\n]*\bgit\b|\bgit\b[^\n]*\score\.pager=['\"]?[^'\"\n]*sh"
            r"|LESSOPEN=['\"]?\s*\|?\s*(?:/bin/)?(?:ba)?sh"
            r"|\bnmap\b[^\n]*--interactive"
            r"|\bmount\b[^\n]*-o\s+bind[^\n]*/bin/(?:ba)?sh"
            r"|\bapt(?:-get)?\b[^\n]*-o\s*\S*(?:Pre|Post)-Invoke\S*="
        ),
        "Shell spawn via LOLBin breakout (GTFOBins: find/tar/vim/gdb/awk/env/ssh/sed/make/pager)",
    ),
    Signal(
        "persist.shell_rc",
        "T1546.004",
        # red-team: + zshenv/zprofile/zlogin/bash_login (all sourced at shell start)
        _p(r"\.(bashrc|zshrc|zshenv|zprofile|zlogin|bash_profile|bash_login|profile)\b"),
        "Modification of shell startup files",
    ),
    Signal(
        "persist.cron",
        "T1053.003",
        _p(r"\bcrontab\b"),
        "Cron-based persistence",
    ),
    Signal(
        "discovery.recon",
        "T1033",
        _p(r"\b(whoami|uname|ifconfig|ip\s+addr|aws\s+sts\s+get-caller-identity)\b"),
        "Host/identity reconnaissance",
    ),
    # --- Behavioral Detection v2 Stage 6 (catalog expansion) ----------------
    Signal(
        "cred.read.gcp",
        "T1552.001",
        _p(r"(\.config/gcloud/|application_default_credentials\.json|\.boto\b)"),
        "Access to Google Cloud credential stores",
    ),
    Signal(
        "cred.read.azure",
        "T1552.001",
        _p(r"(\.azure/|azureprofile\.json|accesstokens\.json)"),
        "Access to Azure CLI credential stores",
    ),
    Signal(
        "cred.read.kube",
        "T1552.001",
        _p(r"(\.kube/config|\bkubeconfig\b)"),
        "Access to Kubernetes kubeconfig",
    ),
    Signal(
        "cred.read.browser",
        "T1555.003",
        _p(
            r"(login\s+data|cookies\.sqlite|cookies\.binarycookies|formhistory\.sqlite"
            # Firefox saved-password store: key4.db/key3.db is the NSS master key
            # (unambiguous — no dev tool reads it) + logins.json is the encrypted
            # blob; stealing Firefox creds needs the pair.
            r"|key[34]\.db\b"
            r"|(?:mozilla|firefox)[^\n]*/logins\.json"
            # Chromium-family cookie/login/webdata stores AND ``Local State`` — the
            # file holding the AES key that decrypts Chrome's Login Data/Cookies, so
            # attackers grab it alongside Login Data. Separator ``[/-]`` covers both
            # the Linux ``google-chrome`` dir and the macOS ``Google/Chrome`` path.
            r"|/(google[/-]chrome|chromium|microsoft\s*edge|bravesoftware|vivaldi|opera\s*software)/"
            r"(?:[^/\n]+/(cookies|login\s*data|web\s*data)|local\s*state)\b"
            # Bulk-copy / archive of a whole browser profile — steal creds+cookies
            # offline in one shot.
            r"|\b(?:cp|rsync|tar|zip|7z|scp)\b[^\n]*"
            r"(?:\.config/(?:google-chrome|chromium|bravesoftware)|\.mozilla/firefox"
            r"|library/application\s*support/(?:google/chrome|firefox)))"
        ),
        "Access to browser credential / cookie / key stores (incl. profile bulk-copy)",
    ),
    Signal(
        "cred.read.password_manager",
        "T1555.005",
        _p(
            # KeePass / KeePassXC database (.kdbx modern, .kdb legacy — also DB2
            # keystores, which are themselves a credential store worth flagging).
            r"(\.kdbx?\b"
            # GNOME keyring / KDE KWallet vault files.
            r"|\.local/share/keyrings/|login\.keyring\b|\bkdewallet\b|\.kwl\b"
            # macOS Keychain FILE read/copy (the `security` CLI path is os_keychain).
            r"|login\.keychain(?:-db)?\b"
            # Windows Credential Manager enumeration.
            r"|\bvaultcmd\b|\bcmdkey\s+/list\b|rundll32[^\n]*keymgr)"
        ),
        "Access to a password-manager / credential-vault store (KeePass / keyring / KWallet / Keychain file / Windows Credential Manager)",
    ),
    Signal(
        "cred.read.git",
        "T1552.001",
        _p(r"(\.git-credentials\b|gh\s+auth\s+token)"),
        "Access to git / GitHub CLI auth material",
    ),
    Signal(
        "cloud.exfil.storage",
        "T1567.002",
        _p(
            r"\b(aws\s+s3\s+(cp|sync)\s+\S+\s+s3://"
            r"|gsutil\s+cp\s+\S+\s+gs://"
            r"|az\s+storage\s+blob\s+upload)"
        ),
        "Cloud-storage write — exfiltration over web service",
    ),
    Signal(
        "container.escape_hint",
        "T1610",
        _p(r"(--privileged\b|/var/run/docker\.sock\b|\bnsenter\b|/proc/1/root)"),
        "Container-escape primitives",
    ),
    Signal(
        "pkg.publish",
        "T1195.002",
        _p(r"\b(npm\s+publish|twine\s+upload|cargo\s+publish|gem\s+push)\b"),
        "Package publish — supply-chain typosquatting / dependency injection",
    ),
    Signal(
        "recon.cloud_metadata",
        "T1552.005",
        _p(
            r"\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200"
            r"|metadata\.azure\.com|fd00:ec2::254)\b"
        ),
        "Cloud instance-metadata endpoint access (AWS/GCP/Azure/Alibaba)",
    ),
    Signal(
        "persist.systemd",
        "T1543.002",
        _p(r"(\.config/systemd/user/|systemctl\s+--user\s+(enable|start))"),
        "User-level systemd unit persistence",
    ),
    # --- Catalog Expansion C (Stage 7) — broader coverage --------------
    Signal(
        "cred.read.kube_secret",
        "T1552.001",
        _p(r"\bkubectl\s+(get|describe)\s+secret\b"),
        "Kubernetes secret enumeration",
    ),
    Signal(
        "cred.read.vault",
        "T1552.001",
        _p(r"\b(vault\s+(read|kv\s+get)|vault_token|\.vault-token\b)"),
        "HashiCorp Vault token / read",
    ),
    Signal(
        "cred.env.api_key",
        "T1552.001",
        # red-team: $AWS_SECRET_ACCESS_KEY evaded — `secret` was not at a word
        # boundary (followed by `_access_key`). Widened suffix set + more prefixes.
        _p(
            r"\$\{?(?:openai_|anthropic_|github_|gh_|aws_|gcp_|azure_)\w*"
            r"(?:api_key|token|secret|access_key|key|password|passwd)\b"
            r"|\$\{?(?:api_key|access_token|secret_key|secret_access_key)\b"
        ),
        "Reads sensitive env var (API key / token / secret)",
    ),
    Signal(
        "cred.read.git_credential_helper",
        "T1552.001",
        _p(r"\bgit\s+credential\s+(fill|approve|reject)\b"),
        "git credential helper invocation",
    ),
    # --- P2: credential-access breadth beyond the dotfile set ------------
    Signal(
        "cred.read.saas_token",
        "T1552.001",
        _p(
            # NOTE: .docker/config.json dropped — it FPs on the universal
            # kaniko/BuildKit `-v ~/.docker/config.json:...` volume-mount idiom.
            # End-anchored so .pgpass.bak / .s3cfg.lock etc. do not fire.
            r"(\.snowflake/|\.databricks|\.dbt/|\.netlify/|\.vercel/"
            r"|\.terraform\.d/credentials|\.terraformrc\b"
            r"|\.kaggle/|\.huggingface/token|\.continue/|\.s3cfg(?![\w])"
            r"|\.pgpass(?![\w.])|\.my\.cnf(?![\w]))"
        ),
        "Access to SaaS / cloud-CLI / DB credential files (Snowflake, Databricks, Terraform, pgpass…)",
    ),
    Signal(
        "cred.read.secret_manager",
        "T1555.005",
        _p(
            r"\b(op\s+(item\s+get|read)|bw\s+get\b|lpass\s+show"
            r"|gcloud\s+secrets\s+versions\s+access"
            r"|gcloud\s+auth\s+(application-default\s+)?print-access-token"
            r"|aws\s+secretsmanager\s+get-secret-value"
            r"|aws\s+configure\s+get\s+\S*secret\S*"
            r"|az\s+keyvault\s+secret\s+show|az\s+account\s+get-access-token"
            r"|doppler\s+secrets\s+(get|download)|sops\s+-d)\b"
        ),
        "Secret-manager / cloud-token CLI read (1Password / Bitwarden / LastPass / aws/gcloud/az)",
    ),
    Signal(
        "cred.read.os_keychain",
        "T1555.001",
        _p(
            r"\b(security\s+(find-(generic|internet)-password|dump-keychain)"
            r"|secret-tool\s+(lookup|search)|keyring\s+get"
            r"|pass\s+show|gopass\s+show)\b"
            # GTFOBins: gpg-decrypt the pass password-store (read the secret store)
            r"|\bgpg2?\b[^\n]*(?:-d\b|--decrypt\b)[^\n]*(?:\.)?password-store"
        ),
        "OS-native credential store read (macOS Keychain / Linux keyring / pass / gpg pass-store)",
    ),
    Signal(
        "cred.read.shadow",
        "T1003.008",
        # Reading /etc/shadow (or piping/redirecting it) — OS credential dumping.
        # od/xxd/strings forms reconstruct the hashes; gated on the /etc/shadow path.
        _p(
            r"(?<![\w.-])(?:cat|less|more|head|tail|od|xxd|hexdump|hd|strings|nl|tac|cp|base64|base32)"
            r"\b[^\n]*/etc/shadow\b|/etc/shadow\b[^\n]*(?:\||>)"
        ),
        "Read of /etc/shadow — OS credential (password hash) dumping",
    ),
    Signal(
        "persist.launchd",
        "T1543.001",
        _p(r"(LaunchAgents/|LaunchDaemons/|\blaunchctl\s+(load|bootstrap))"),
        "macOS launchd persistence",
    ),
    Signal(
        "persist.windows_run_key",
        "T1547.001",
        _p(r"(HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run|HKLM\\.*\\Run\b)"),
        "Windows registry Run-key persistence",
    ),
    Signal(
        "persist.autostart",
        "T1547",
        _p(r"\.config/autostart/|/etc/init\.d/"),
        "XDG autostart / init.d persistence",
    ),
    Signal(
        "persist.global_pkg_install",
        "T1546",
        _p(r"\b(npm\s+install\s+-g|pip\s+install\s+--user|cargo\s+install)\s+\S"),
        "Global package install — postinstall scripts persistence",
    ),
    Signal(
        "exec.code_eval_inline",
        "T1059",
        # red-team: version suffix (python3.12), php -r, Rscript -e, and remote
        # script exec `bun|deno run https://…` were all evading the old pattern.
        _p(
            r"\b(python[0-9.]*|node|perl|ruby|deno|bun|php|rscript)\s+-[ecr]\b"
            r"|\b(?:bun|deno)\s+run\s+https?://"
        ),
        "Inline code execution (python -c / node -e / php -r / Rscript -e / bun run url)",
    ),
    Signal(
        "exec.base64_decode",
        "T1027",
        _p(r"\bbase64\s+(-d|-D|--decode)\b"),
        "base64 decoding — common obfuscation step before exec",
    ),
    Signal(
        "exec.hex_decode",
        "T1027",
        _p(r"\b(xxd\s+-r|printf\s+['\"]?\\x[0-9a-f]{2})"),
        "Hex decoding of payload",
    ),
    Signal(
        "egress.dns_long_subdomain",
        "T1071.004",
        _p(r"[a-z0-9]{40,}\.(com|net|org|io|xyz|info)\b"),
        "DNS exfil — abnormally long subdomain",
    ),
    Signal(
        "egress.bot_api",
        "T1102",
        _p(r"\b(api\.telegram\.org|discord(?:app)?\.com/api/webhooks?|hooks\.slack\.com/services)"),
        "Outbound to bot/webhook endpoint",
    ),
    Signal(
        "egress.paste_site",
        "T1567",
        _p(r"\b(pastebin\.com|paste\.ee|gist\.github\.com|hastebin\.com|0x0\.st|transfer\.sh)\b"),
        "Outbound to paste/upload site",
    ),
    Signal(
        "system.permissive_chmod",
        "T1222.002",
        _p(r"\bchmod\s+(0?7[67]7|\+s\b|u\+s\b)"),
        "World-writable / setuid permission change",
    ),
    Signal(
        "system.sudo_nopasswd",
        "T1548.003",
        _p(r"NOPASSWD\s*:\s*ALL|sudo\s+-n\s+\w+"),
        "Sudo without password — privilege escalation primitive",
    ),
    Signal(
        "system.sudo_shell",
        "T1548.003",
        # GTFOBins-style privesc: sudo to a bare shell / su, or a sudo-specific
        # hook (apt Pre-Invoke, mount -o bind <shell>). The `sudo <gtfobin>
        # <shell-escape>` forms are caught by exec.shell_spawn on the escape; this
        # adds the privilege-escalation stage when sudo is the vehicle. The
        # shell/-s/-i must be a bare interactive shell — `sudo vim`/`sudo apt
        # install` stay quiet.
        _p(
            r"\bsudo\b[^\n]*(?:\s(?:/bin/|/usr/bin/)?(?:ba|z|da|k)?sh\b(?:\s|$|;)"
            r"|\bsu\b|\s-[is]\b|/bin/(?:ba)?sh)"
        ),
        "Sudo → interactive shell / su (privilege escalation)",
    ),
    Signal(
        "system.hosts_edit",
        "T1565.001",
        _p(r"/etc/hosts\b"),
        "Hosts file modification — DNS redirection",
    ),
    Signal(
        "discovery.network_scan",
        "T1046",
        _p(r"\b(nmap|masscan|rustscan|naabu)\b"),
        "Network port scan",
    ),
    Signal(
        "discovery.secret_grep",
        "T1552.001",
        _p(r"\b(grep|rg|ag)\b.*\b(api_key|api[_-]token|secret|password|BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE)\b"),
        "Filesystem-wide grep for secrets",
    ),
    Signal(
        "config.agent_settings_edit",
        "T1556",
        _p(r"\.claude/(settings\.json|claude\.json|\.mcp\.json)\b|claude_desktop_config\.json"),
        "AI-agent config tamper — Claude settings / MCP config edit",
    ),
    # --- P2: revive the 3 structurally-dead kill-chain stages -------------
    # defense-evasion / command-and-control / lateral-movement had no catalog
    # signal (so any chain step on them was dead). Content-regex signals; their
    # prefixes are mapped in chain_constants — the stage resolves with zero
    # engine change (the data-driven promise, same move as ТЗ-IMPACT).
    Signal(
        "defense.disable_security",
        "T1562.001",
        _p(
            # NOTE: --dangerously-skip-permissions is a normal Claude Code launch
            # flag (it skips Claude's permission prompts, NOT ccguard's hooks) —
            # tagging it as defense-evasion is a false positive, so it is excluded.
            r"(disableallhooks"
            # ccguard tamper — verb ADJACENT to the product name, EITHER order
            # (bounded, so prose like "ccguard helps disable nothing" does not fire).
            # Red-team: `systemctl --user stop ccguard.service` (verb-before),
            # `chattr +i ...ccguard-enforce` (lock the hook) now caught.
            r"|\bccguard\s+(uninstall|disable|stop|remove)\b|\b(uninstall|remove)\s+ccguard\b"
            r"|\b(?:stop|disable|mask|kill|unload|rm)\b[^\n]*ccguard"
            r"|\bchattr\s+[-+][ai]\b[^\n]*ccguard"
            r"|\bufw\s+disable\b|\biptables\s+-f\b|\bsetenforce\s+(0|permissive)\b"
            r"|spctl\s+--(?:master|global)-disable|csrutil\s+disable"
            # Kill / stop / restart / unload the EDR sensor itself.
            r"|(pkill|killall|kill)\b[^\n]*\b(falcon|crowdstrike|osquery|auditd|sentinelone)\b"
            r"|systemctl\s+(stop|disable|restart|mask)\s+\S*(falcon|crowdstrike|defender|auditd|osquery)"
            r"|launchctl\s+(unload|bootout)\b[^\n]*(crowdstrike|falcon))"
        ),
        "Disable / kill security tooling or the ccguard hook (impair defenses)",
    ),
    Signal(
        "defense.clear_history",
        "T1070.003",
        _p(
            r"(history\s+-c\b|history\s+-w\s+/dev/null|\bunset\s+histfile\b"
            r"|histsize\s*=\s*0|(export\s+)?histfile=/dev/null"
            r"|(rm|shred|truncate)\b[^\n]*\.(bash|zsh)_history(?![\w])"
            r"|>\s*~?/?\.(bash|zsh)_history(?![\w.])"
            r"|ln\s+-sf?\s+/dev/null\b[^\n]*_history)"
        ),
        "Shell-history clearing / tampering (indicator removal)",
    ),
    Signal(
        "defense.clear_logs",
        "T1070.002",
        _p(
            # High-precision WIPE forms only — a bare `cmd > /var/log/x.log`
            # redirect is dropped (it FPs on benign app/CI log writes). Retention
            # (`journalctl --vacuum-time=2d`) is excluded; only a 0-time/size or
            # --rotate wipe fires.
            r"(journalctl\s+(--rotate|--vacuum-time=0|--vacuum-size=0)"
            r"|(truncate\s+-s\s*0|\bshred)\b[^\n]*/var/log"
            r"|\brm\s+-\S*[rf][^\n]*/var/log"
            r"|(:|cat\s+/dev/null)\s*>\s*/var/log/)"
        ),
        "System-log wipe / truncation (indicator removal)",
    ),
    Signal(
        "c2.reverse_shell",
        "T1071.001",
        _p(
            # Mirror of the enforce hard-deny rule (kept in sync). Red-team-hardened:
            # /dev/tcp host/port shape, nc/ncat/netcat -e/--exec, socat EXEC:/SYSTEM:,
            # gawk /inet/, node/php/lua/perl/ruby socket→shell, python socket→shell
            # (inline or heredoc), pty.spawn shell upgrade.
            r"(/dev/(?:tcp|udp)/[^/\s]+/\d+"
            r"|\b(?:nc|ncat|netcat)\b[^\n]*\s(?:-e\b|--exec\b|--sh-exec\b|--lua-exec\b)"
            r"|mkfifo\b[^\n]*\|\s*(?:n?cat?|openssl\s+s_client|socat)\b"
            r"|socat\b[^\n]*\b(?:exec|system):|(?:ba)?sh\s+-i\b[^\n]*>&"
            r"|\bg?awk\b[^\n]*/inet/(?:tcp|udp)/"
            r"|\bnode\b[^\n]*(?:net\.(?:connect|createconnection)|require\(['\"]net['\"]\))"
            r"[^\n]*(?:child_process|spawn|exec)"
            r"|\bphp\b[^\n]*(?:fsockopen|pfsockopen|stream_socket_client)"
            r"[^\n]*(?:proc_open|shell_exec|`|/bin/|exec)"
            r"|\blua[0-9.]*\b[^\n]*socket[^\n]*(?:io\.popen|os\.execute)"
            r"|\b(?:perl|ruby)\b[^\n]*(?:socket|tcpsocket|fsockopen|io::socket)"
            r"[^\n]*(?:exec|/bin/(?:sh|bash)|io\.popen|->open|system)"
            r"|socket[^\n]*\.connect\([^\n]*(?:os\.dup2|pty\.spawn"
            r"|os\.system\(['\"]?(?:/bin/)?(?:sh|bash)"
            r"|subprocess\.\w+\(\s*\[?['\"](?:/bin/)?(?:sh|bash))"
            r"|pty\.spawn\(\s*\(?\s*['\"]?(?:/bin/)?(?:sh|bash)\b"
            # GTFOBins / cheat-sheet additions: telnet double-pipe, xterm remote
            # -display, PowerShell TCPClient, powercat -l -ep, Go/Rust socket+exec.
            r"|\btelnet\b[^\n]*\|[^\n]*(?:/bin/)?(?:ba)?sh[^\n]*\|[^\n]*\btelnet\b"
            r"|mkfifo\b[^\n]*\|\s*telnet"
            r"|\bxterm\b[^\n]*-display\s+\d{1,3}(?:\.\d{1,3}){3}:"
            r"|(?:new-object\s+)?(?:system\.)?net\.sockets\.tcpclient"
            r"|\bpowercat\b[^\n]*-l\b[^\n]*-ep\b|\bpowercat\b[^\n]*\s-e\s"
            r"|net\.Dial\(\s*['\"]tcp['\"][^\n]*exec\.Command\(\s*['\"]?(?:/bin/)?(?:ba)?sh"
            r"|exec\.Command\(\s*['\"](?:/bin/)?(?:ba)?sh[^\n]*net\.Dial"
            r"|TcpStream::connect[^\n]*(?:from_raw_fd|Command::new\(\s*['\"](?:/bin/)?(?:ba)?sh))"
        ),
        "Reverse shell — interactive C2 channel",
    ),
    Signal(
        "c2.tunnel",
        "T1572",
        _p(r"\b(ngrok|autossh|chisel|localtunnel)\b|cloudflared\s+tunnel|\bssh\b[^\n]*\s-R[\s\d:]"),
        "Outbound tunnel / remote-access relay (incl. ssh -R reverse tunnel)",
    ),
    Signal(
        "lateral.remote_exec",
        "T1021.004",
        _p(
            # Allow leading option flags (-i key / -p port / -o ...) and anchor
            # the remote-command token so `ssh -i k host ./x.sh` matches and
            # `ssh -T git@github.com` (auth probe, no command) does not.
            # Use [ \t] (same-line) not \s — the normalizer joins copies with
            # \n, and \s+\S+ would otherwise match a host on one line + the next
            # copy's first token, fabricating a "remote command".
            r"(ssh([ \t]+-\S+([ \t]+\S+)?)*[ \t]+([\w.-]+@)?[a-z0-9][\w.-]*[ \t]+\S"
            r"|\bpssh\b|\bpsexec\b|wmic\s+/node:|\bwinrs\s+-r)"
        ),
        "Remote command execution on another host (lateral movement; low-weight, correlation-gated)",
    ),
    # --- P2: catalog width pass — cred / discovery / persistence / exec ---
    Signal(
        "cred.read.cloud_session",
        "T1552.001",
        _p(
            r"(\.aws/sso/cache|\.config/gh/hosts|\.config/containers/auth\.json"
            r"|/var/run/secrets/kubernetes\.io/serviceaccount"
            r"|gcloud\s+auth\s+print-(access|identity)-token"
            r"|kubectl\s+config\s+view\s+--raw)"
        ),
        "Access to cloud/CI session tokens (AWS SSO cache, gh hosts, k8s SA token, gcloud token)",
    ),
    Signal(
        "discovery.cloud_enum",
        "T1526",
        _p(
            r"\b(aws\s+(iam|ec2|s3api)\s+(list|describe)"
            r"|gcloud\s+(projects|compute|iam)\s+list"
            r"|az\s+(account|vm|role)\s+list"
            r"|kubectl\s+get\s+(pods|secrets|nodes)\b[^\n]*(--all-namespaces|\s-A\b))"
        ),
        "Cloud resource / IAM enumeration (recon)",
    ),
    Signal(
        "discovery.account_enum",
        "T1087",
        _p(
            r"(\bgetent\s+passwd\b|/etc/passwd\b|\bdscl\s+\.\s+-?list\s+/users"
            r"|\bnet\s+user\b|\bnet\s+localgroup\b)"
        ),
        "Local account enumeration (/etc/passwd, getent, dscl, net user)",
    ),
    Signal(
        "persist.ssh_authorized_keys",
        "T1098.004",
        # WRITE-gated: a redirect/tee/ssh-copy-id into authorized_keys(2). A
        # plain `cat ~/.ssh/authorized_keys` READ must NOT be flagged as persistence.
        _p(r"(>>?\s*\S*authorized_keys2?\b|\btee\b[^\n]*authorized_keys2?\b|\bssh-copy-id\b)"),
        "Write to SSH authorized_keys — attacker-key persistence",
    ),
    Signal(
        "exec.powershell_encoded",
        "T1059.001",
        # Accept PowerShell -e/-en/-enc/-encodedcommand abbreviations + a quoted blob.
        _p(r"\b(powershell|pwsh)(\.exe)?\b[^\n]*\s-e[a-z]*\s+['\"]?[a-z0-9+/=]{16,}"),
        "PowerShell encoded command — obfuscated execution",
    ),
    # --- P2-width-3: collection stage (archive-staging / capture) ---------
    # The collection kill-chain stage was fed only by the ubiquitous
    # ``fs.write.*`` markers (every project write). These add HIGH-signal
    # collection IOAs — staging data BEFORE exfil — that resolve to the
    # ``collection`` stage via the new ``collection.`` prefix in chain_constants
    # (zero engine change). Precision over recall: a project-dir ``tar`` and
    # archive EXTRACTION stay silent; only a CREATE-archive over a credential
    # store / whole-home, or a real screen/clipboard capture, fires.
    Signal(
        "collection.archive_staging",
        "T1560.001",
        _p(
            # CREATE-archive (tar/gtar/bsdtar c… | zip -r | 7z[a] a | cpio -o |
            # gpg --symmetric) whose source is a credential store or the whole
            # home dir — the classic "stage before exfil" move. Hardened against
            # an adversarial FP/FN corpus:
            #  * (?<![\w./-]) command-anchors the verb so a FILENAME ``dump.tar``
            #    (note: ``-C`` lowercases to ``-c``) is not read as a tar verb;
            #  * (?![a-z]*[xt]) drops EXTRACT/LIST flag clusters (-x*/-t*), so a
            #    restore INTO a cred dir is not mislabeled as staging;
            #  * [^\n#]* stops at a trailing ``# comment`` (a bare ``~`` in a note
            #    must not fire);
            #  * dot-dirs close on (?:/|\s|$) so ``.ssh-config-backup`` stays quiet.
            # A reverse-order branch catches ``cd ~/.ssh && tar -cf - .`` where the
            # sensitive dir precedes the (create-only) archive verb.
            r"(?:"
            r"(?<![\w./-])(?:(?:g|bsd|gnu)?tar\s+(?:-\S+\s+)*(?:--create|-?(?![a-z]*[xt])[a-z]*c[a-z]*)"
            r"|zip\s+(?:-\S+\s+)*-[a-z]*r|7za?\s+a|cpio\s+-o"
            r"|gpg\b[^\n]*(?:--symmetric|--encrypt|\s-[ce]\b))"
            r"[^\n#]*"
            r"(?:~(?:\s|$)|\$home(?:\s|$|/)"
            r"|(?:[/~ ]|^)\.(?:ssh|aws|gnupg|password-store|kube|docker|mozilla)(?:/|\s|$)"
            r"|/etc/(?:passwd|shadow|ssh)\b)"
            r")"
            r"|(?:"
            r"(?<![\w./-])cd\s+\S*\.(?:ssh|aws|gnupg|password-store|kube|docker|mozilla)\b[^\n#]*"
            r"(?:&&|;)\s*[^\n#]*"
            r"(?:(?:g|bsd|gnu)?tar\s+(?:-\S+\s+)*(?:--create|-?(?![a-z]*[xt])[a-z]*c[a-z]*)"
            r"|7za?\s+a|cpio\s+-o|zip\s+(?:-\S+\s+)*-[a-z]*r)"
            r")"
        ),
        "Archive-staging of credentials / whole home (tar/zip/7z/cpio/gpg create over a sensitive source) — collection before exfil",
    ),
    Signal(
        "collection.screen_capture",
        "T1113",
        _p(
            # Dedicated screenshot binaries, command-anchored so a hyphenated
            # name (``screencapture-helper``) or a substring (``pilgrim``) does
            # not match. ImageMagick ``import`` REQUIRES the ``-window`` flag, so
            # the python ``import`` keyword and prose like "import config.png"
            # stay quiet.
            r"(?<![\w./-])(?:"
            r"screencapture|scrot|grimshot|grim|maim|gnome-screenshot|spectacle|flameshot|xwd"
            r")(?![\w-])"
            r"|(?<![\w./-])import\s+(?:-\S+\s+)*-window\b[^\n]*\.(?:png|jpe?g|webp|bmp|gif|tiff)\b"
            r"|(?<![\w./-])ffmpeg\b[^\n]*(?:x11grab|gdigrab)"
        ),
        "Screen capture (screencapture / scrot / grim / spectacle / ImageMagick import -window) — collection",
    ),
    Signal(
        "collection.clipboard",
        "T1115",
        _p(
            # Clipboard READ/scrape (command-anchored). Low weight — pbpaste has a
            # benign base rate; the value is correlation (clipboard → egress).
            # Writes stay quiet: pbcopy is excluded, xclip needs a trailing -o,
            # and xsel requires an ``o`` (output) flag — the ``b`` board flag
            # alone (e.g. ``xsel -ib``, a WRITE) must not fire. osascript reads
            # ``the clipboard`` / ``get the clipboard``; ``set the clipboard to``
            # (a WRITE) is excluded by the ``(?<!set\s)`` lookbehind.
            r"(?<![\w./-])(?:pbpaste|wl-paste|get-clipboard)(?![\w-])"
            r"|(?<![\w./-])xclip\b[^\n]*\s(?:-o|--output)(?![\w])"
            r"|(?<![\w./-])xsel\b[^\n]*(?:--output|\s-\S*o(?![\w]))"
            r"|(?<![\w./-])osascript\b[^\n]*(?<!set\s)\bthe\s+clipboard\b"
            r"|pyperclip\.paste"
        ),
        "Clipboard scrape (pbpaste / xclip -o / xsel -o / wl-paste / osascript / Get-Clipboard) — collection",
    ),
    # --- Coverage expansion (audit-driven, low-FP, data-driven auto-stage) --
    Signal(
        "collection.db_dump",
        "T1005",
        _p(
            r"\b(pg_dump(all)?|mysqldump|mariadb-dump|mongodump"
            r"|sqlite3\s+\S+\s+['\"]?\.dump|redis-cli\s+--rdb)\b"
        ),
        "Database dump (pg_dump/mysqldump/mongodump/sqlite3 .dump) — bulk collection",
    ),
    Signal(
        "cred.read.env_dump",
        "T1552.001",
        # Full environment dump: bare `env` / `printenv` (or piped/redirected) —
        # leaks every secret in env vars. `env VAR=x cmd` (setting a var) does NOT
        # match (a non-pipe/redirect token follows).
        _p(r"(?<![\w.-])(env|printenv)\s*($|\||>)"),
        "Full environment dump (env/printenv) — may leak secrets held in env vars",
    ),
    Signal(
        "pkg.install_untrusted",
        "T1195.002",
        # Install a package straight from a git/URL source (not a registry) —
        # supply-chain code-execution entry. A normal `pip install requests` has
        # no url and does not match.
        _p(
            r"\b(pip[0-9]?|pip3|uv|pipx|npm|pnpm|yarn)\s+(install|add)\b"
            r"[^\n]*(\bgit\+https?://|\bgit\+ssh|\bhttps?://|\bgit@)"
        ),
        "Package install from an untrusted git/URL source — supply-chain entry",
    ),
    Signal(
        "egress.adhoc_server",
        "T1071.001",
        # Pull-exfil: stand up an ad-hoc HTTP/upload server (python -m http.server /
        # uploadserver, php -S, ruby httpd, busybox httpd) on a NON-loopback bind —
        # an attacker then fetches files out. A localhost-bound preview server
        # (--bind 127.0.0.1 / php -S localhost:) is excluded.
        _p(
            r"(?:python[0-9.]*\s+-m\s+(?:http\.server|uploadserver)"
            r"|php\s+-S\s|ruby\s+-run\s+-e\s+httpd|busybox\s+httpd|\bhttp-server\b)"
            r"(?![^\n]*(?:127\.0\.0\.1|localhost|::1))"
        ),
        "Ad-hoc HTTP/upload server on a non-loopback bind — pull-exfil channel",
    ),
    Signal(
        "egress.dns_tool",
        "T1071.004",
        # DNS-resolver invocation with TUNNEL markers (TXT/NULL/ANY query, or an
        # encoded data label) — DNS exfil. A plain `dig example.com` is silent.
        _p(
            r"\b(dig|nslookup|host|drill|kdig)\b[^\n]*"
            r"(\b(txt|null|any)\b|[a-z2-7]{16,}\.[a-z0-9.-]+|\b[0-9a-f]{16,}\.)"
        ),
        "DNS-tool query with tunnel markers (TXT/NULL/ANY or encoded label) — DNS exfil",
    ),
    Signal(
        "persist.scheduled_task",
        "T1053",
        # Scheduler-based persistence variants not covered by persist.cron:
        # systemd timer, Windows schtasks/Register-ScheduledTask, one-shot `at`.
        # `at` is anchored to COMMAND position (start / after a separator) so
        # `echo "meet at 10:30"` and `cat backup.timer` stay quiet.
        _p(
            r"\bsystemctl\b[^\n]*\benable\b[^\n]*\.timer"
            r"|\bschtasks\b[^\n]*/create"
            r"|\bregister-scheduledtask\b"
            # red-team: transient timer via `systemd-run --on-calendar/--on-active`
            r"|systemd-run\b[^\n]*--on-(?:calendar|active|boot|unit-active|startup)"
            r"|(?:^|[;&|\n])\s*at\s+(now\b|[0-9]{1,2}:[0-9]{2}\b|noon\b|midnight\b)"
        ),
        "Scheduled-task persistence (systemd timer / schtasks / systemd-run / at)",
    ),
    Signal(
        "persist.git_hooks",
        "T1546",
        # red-team: git-hooks persistence — point core.hooksPath at an attacker
        # dir, or drop an executable straight into a .git/hooks/ path. The hook
        # runs on the next git operation (commit/checkout/...).
        _p(r"\bgit\s+config\b[^\n]*\bcore\.hookspath\b|/\.git/hooks/\S"),
        "Git-hooks persistence (core.hooksPath redirect / .git/hooks drop)",
    ),
    Signal(
        "impact.cryptomining",
        "T1496",
        # Resource hijacking: a stratum pool connection, a known miner binary
        # invoked as a command (anchored, not in a path/doc/package name), a
        # miner-specific flag, or a named cryptojacking implant (kdevtmpfsi/
        # kinsing/sysrv — never a legit filename, matched anywhere).
        _p(
            r"\bstratum\+(?:tcp|ssl|tcps)://|--donate-level\b|--coin\s+\w|--nicehash\b"
            r"|\b(?:kdevtmpfsi|kinsing|sysrv|dbused|diicot)\b"
            r"|(?<![\w/.\-])(?:xmrig|minerd|cpuminer(?:-multi)?|ethminer|xmr-stak|t-rex"
            r"|lolminer|phoenixminer|nbminer|teamredminer|gminer|cgminer|ccminer)\b(?![-\w.])"
        ),
        "Cryptomining / resource hijacking (stratum pool, miner binary, miner flag, known implant)",
    ),
    Signal(
        "impact.disk_wipe",
        "T1561.002",
        # Irreversible host destruction: mkfs with a force flag or onto a WHOLE
        # disk (not a fresh-USB partition), the always-wipe tools wipefs/
        # blkdiscard/sgdisk, zeroing a raw block device, or shred /dev. A USB
        # format (`mkfs /dev/sdb1`) and ISO-to-USB (`dd if=x.iso of=/dev/sdb`)
        # stay quiet.
        _p(
            r"\bmkfs(?:\.\w+)?\b[^\n]*\s-[fF]\b[^\n]*/dev/(?:sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mmcblk\d)\w*"
            r"|\bmkfs(?:\.\w+)?\b\s[^\n]*/dev/(?:sd[a-z]|vd[a-z]|xvd[a-z])(?![0-9])"
            r"|\b(?:wipefs|blkdiscard|sgdisk)\b\s[^\n]*/dev/(?:sd[a-z]|nvme\d|vd[a-z]|xvd[a-z]|mmcblk\d)\w*"
            r"|(?:cat\s+/dev/(?:zero|urandom)\s*>|dd\s+if=/dev/(?:zero|urandom)[^\n]*of=)\s*/dev/(?:sd[a-z]|nvme\d|vd[a-z]|mmcblk\d)\w*"
            r"|(?:^|[;&|]|\bsudo\s)\s*>\s*/dev/(?:sd[a-z]|nvme\d)\w*"
            r"|\bshred\b[^\n]*\s/dev/(?:sd[a-z]|nvme\d)\w*"
        ),
        "Disk wipe — mkfs/wipefs/blkdiscard/zero/shred against a raw block device",
    ),
    Signal(
        "impact.inhibit_recovery",
        "T1490",
        # Destroy backups / recovery points (ransomware-prep): delete VSS shadow
        # copies, disable Windows recovery, recursively destroy zfs/btrfs
        # snapshots, timeshift --delete-all, rm -rf the backup dirs. Listing /
        # single-snapshot rotation stays quiet (gated on delete-all / -r).
        _p(
            r"\bvssadmin\b[^\n]*\bdelete\b[^\n]*shadow|\bwmic\b[^\n]*shadowcopy\s+delete"
            r"|\bbcdedit\b[^\n]*recoveryenabled\s+no|\bwbadmin\b[^\n]*\bdelete\b"
            r"|\bzfs\s+destroy\b[^\n]*\s-r\b|\bbtrfs\s+subvolume\s+delete\b"
            r"|\btimeshift\b[^\n]*--delete-all"
            r"|\brm\s+-rf?\b[^\n]*(?:/var/backups|/\.snapshots|/snapshots)\b"
        ),
        "Inhibit recovery — delete shadow copies / snapshots / backups (ransomware-prep)",
    ),
    # --- ATT&CK coverage-gap batch 2: cloud/container, cred-memory, defense,
    # persistence, AI-frontier (sourced from a coverage-gap workflow) ----------
    Signal(
        "container.privileged",
        "T1611",
        # Container escape / host takeover: privileged container, host-root bind
        # mount (-v /:/host), SYS_ADMIN cap, host PID ns, host chroot, or a
        # privileged k8s manifest. A normal `docker run img` / `-v ./x:/app` quiet.
        _p(
            r"\bdocker\b[^\n]*\brun\b[^\n]*(?:--privileged|--cap-add[= ]\s*SYS_ADMIN|--pid[= ]host|-v\s+/:/|--volume[= ]/:/)"
            r"|\bchroot\s+/host\b|securityContext[^\n]*privileged:\s*true|\bhostPID:\s*true|\bhostPath:"
        ),
        "Privileged container / host-mount / k8s privileged pod — container escape",
    ),
    Signal(
        "collection.kubectl_cp",
        "T1530",
        # Copy data OUT of a pod (pod:/path as the SOURCE). `kubectl cp ./x pod:/`
        # (copy IN) does not match.
        _p(r"\bkubectl\s+cp\s+\S+:/"),
        "kubectl cp out of a pod — data collection from a container",
    ),
    Signal(
        "impact.cloud_destroy",
        "T1485",
        # Destructive cloud ops: remove a bucket, terminate instances, delete a
        # VM / resource group / DB, terraform auto-destroy. Read/list/plan quiet.
        _p(
            r"\baws\s+s3\s+rb\b[^\n]*--force|\baws\s+ec2\s+terminate-instances\b"
            r"|\bgcloud\s+compute\s+instances\s+delete\b|\bterraform\s+destroy\b[^\n]*-auto-approve"
            r"|\baz\s+group\s+delete\b|\baws\s+rds\s+delete-db-instance\b[^\n]*--skip-final"
        ),
        "Destructive cloud operation (bucket/instance/DB/resource-group delete)",
    ),
    Signal(
        "persist.cloud_iam",
        "T1098",
        # Cloud-account persistence: mint an access key / login profile, attach a
        # policy, add to a group. List/get (read) does not match.
        _p(
            r"\baws\s+iam\s+(?:create-access-key|create-login-profile|attach-user-policy|attach-role-policy|add-user-to-group)\b"
            r"|\bgcloud\s+iam\s+service-accounts\s+keys\s+create\b"
        ),
        "Cloud IAM persistence (create key / attach policy / add to group)",
    ),
    Signal(
        "defense.disable_firewall",
        "T1562.004",
        _p(
            r"\bufw\b[^\n]*\bdisable\b|\bnft\b[^\n]*flush\s+ruleset"
            r"|\bsystemctl\s+(?:stop|disable|mask)\s+\S*(?:firewalld|ufw)\b|\bpfctl\s+-d\b|\bsetenforce\s+0\b"
        ),
        "Disable host firewall (ufw/firewalld/nft/pf/SELinux) — impair defenses",
    ),
    Signal(
        "defense.masquerade",
        "T1036.005",
        # Place a binary at a system-daemon name/path (sshd/cron/systemd/...) —
        # hiding malware in plain sight. Normal install to a real name is quiet.
        _p(
            r"\b(?:cp|mv|ln\s+-s\w*|install)\b[^\n]*\s/(?:usr/(?:local/)?s?bin|s?bin)"
            r"/(?:sshd|crond?|systemd|init|agetty|kthreadd|kworker)\b"
        ),
        "Masquerade — binary placed at a system-daemon name (sshd/cron/systemd)",
    ),
    Signal(
        "discovery.privesc_enum",
        "T1083",
        # SUID/capabilities enumeration — classic privesc recon.
        _p(r"\bfind\b[^\n]*-perm\b[^\n]*(?:-0?4000|-u\s*[=+]\s*s|/4000)|\bgetcap\s+-r\s+/"),
        "SUID / capabilities enumeration (privilege-escalation recon)",
    ),
    Signal(
        "cred.dump.memory",
        "T1003.007",
        # Dump credentials from process memory: gdb/gcore memory dump, /proc/<pid>/
        # mem or environ, or a known harvester (lazagne/mimipenguin).
        _p(
            r"\bgdb\b[^\n]*dump\s+memory|\bgcore\b\s+\d|/proc/\d+/(?:mem|environ)\b"
            r"|/proc/self/environ|\b(?:lazagne|mimipenguin|mimipy)\b"
        ),
        "Credential dump from process memory (gdb/gcore/proc-mem/lazagne)",
    ),
    Signal(
        "cred.scan.secrets",
        "T1552.001",
        # Hunt private-key / AWS-secret material across the filesystem.
        _p(
            r"\b(?:grep|rg|egrep)\b[^\n]*(?:BEGIN[^\n]{0,25}?PRIVATE\s+KEY"
            r"|AKIA[0-9A-Z]{8,}|aws_secret_access_key)"
        ),
        "Filesystem scan for private-key / secret material",
    ),
    Signal(
        "persist.account",
        "T1136.001",
        # Create / elevate a local account: useradd into sudo/wheel/admin/docker,
        # uid 0, usermod -aG sudo, net user /add, passwd root. A service account
        # (`useradd -r -s /bin/false`) does not match.
        _p(
            r"\b(?:useradd|adduser)\b[^\n]*(?:-G\s*\S*(?:sudo|wheel|admin|docker)|-u\s*0\b)"
            r"|\busermod\b[^\n]*-a?G\s*\S*(?:sudo|wheel|admin|docker|root)"
            r"|\bnet\s+user\b[^\n]*/add|\bpasswd\s+root\b"
        ),
        "Local account creation / privilege grant (useradd sudo / usermod -aG / passwd root)",
    ),
    Signal(
        "ai.context_poison",
        "ATLAS.AML.T0051",
        # AI-AGENT-SPECIFIC (the moat): plant instructions into a file the agent
        # treats as AUTHORITY and re-reads (CLAUDE.md/AGENTS.md/.cursorrules/...),
        # or smuggle an injection into a PR/issue body a later agent will read.
        _p(
            r"(?:echo|printf|cat|tee)\b[^\n]*>>?\s*[^\n]*"
            r"(?:CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|copilot-instructions)"
            r"|\bgh\s+(?:pr|issue)\s+(?:create|comment|edit)\b[^\n]*--body[^\n]*"
            r"(?:ignore\s+(?:all\s+)?previous|disregard\s+(?:all\s+)?(?:above|previous)"
            r"|system\s*:|you\s+must\s|new\s+instructions)"
        ),
        "AI context poisoning — inject instructions into an agent-authority file / PR-issue body",
    ),
    Signal(
        "egress.icmp_tunnel",
        "T1095",
        # ICMP covert channel: ping with a hex payload, or hping/nping. A normal
        # `ping host` is silent.
        _p(r"(\bping\b[^\n]*\s-p\s+[0-9a-f]{4,}|\bhping3?\b|\bnping\b[^\n]*--icmp)"),
        "ICMP tunnel / exfil (ping -p payload, hping, nping --icmp) — covert channel",
    ),
    Signal(
        "exec.lolbin_download",
        "T1105",
        # Download-cradle via living-off-the-land binaries — almost always
        # malicious in download form. `certutil -hashfile` / local `regsvr32`
        # (no http) do NOT match.
        _p(
            r"\bcertutil\b[^\n]*(-urlcache|-f\s+https?://|-split\s+-f\s+https?://)"
            r"|\bbitsadmin\b[^\n]*/transfer"
            r"|\bmshta\b[^\n]*https?://"
            r"|\bregsvr32\b[^\n]*/i:\s*https?://"
        ),
        "Download-cradle via LOLBin (certutil/bitsadmin/mshta/regsvr32) — remote payload fetch+exec",
    ),
    Signal(
        "exec.windows_lolbin",
        "T1218",
        # LOLBAS proxy-execution / AWL-bypass — a signed Windows binary abused to
        # run attacker code. Each alternative is the abuse-specific marker (not the
        # bare binary): rundll32 script: URIs, installutil /U log-suppression,
        # wmic process call create, msiexec remote/DLL, cmstp /ni /s, conhost
        # --headless, scriptrunner -appvscript, pcalua -a, wuauclt DLL-provider,
        # powershell IEX download-cradle. Benign admin use (wmic process list,
        # msiexec /i local.msi, rundll32 shell32,Control_RunDLL) stays quiet.
        _p(
            r"\brundll32\b[^\n]*(?:javascript:|vbscript:|url\.dll\s*,\s*(?:OpenURL|FileProtocolHandler)"
            r"|,\s*RunHTMLApplication|GetObject\(\s*['\"]?script:|shell32\.dll\s*,\s*ShellExec_RunDLL)"
            r"|\binstallutil\b[^\n]*/LogToConsole=false[^\n]*/U\b"
            r"|\bwmic\b[^\n]*process\s+call\s+create"
            r"|\bmsiexec\b[^\n]*(?:/q\w*|/quiet)[^\n]*/i\s+https?://|\bmsiexec\b[^\n]*/y\s+\S+\.dll"
            r"|\bcmstp\b[^\n]*/ni\b[^\n]*/s\b"
            r"|\bconhost\b[^\n]*--headless\s+\S"
            r"|\bscriptrunner\b[^\n]*-appvscript"
            r"|\bpcalua\b[^\n]*\s-a\s"
            r"|\bwuauclt\b[^\n]*/UpdateDeploymentProvider"
            r"|\b(?:powershell|pwsh)\b[^\n]*(?:IEX|Invoke-Expression)[^\n]*"
            r"(?:New-Object\s+Net\.WebClient|DownloadString|\biwr\b|Invoke-WebRequest)"
            r"|\bmsbuild\b[^\n]*\.xml\b"
        ),
        "Windows LOLBAS proxy-execution / AWL-bypass (rundll32/installutil/wmic/msiexec/cmstp/...)",
    ),
    # --- Action signals (ТЗ-02 staging middle link) ----------------------
    # These are ACTION signals, not content-regex signals: emission is gated on
    # the tool being a write tool (Write/Edit/NotebookEdit) and decided by the
    # target path shape in ``extractor._write_signals`` — NOT by the generic
    # regex loop (a Read of ``.env`` must not look like a write). They live in
    # CATALOG only so their MITRE metadata flows to the UI / drafter the same
    # way cred/egress signals do; ``ACTION_SIGNAL_IDS`` excludes them from the
    # regex loop. The ``pattern`` below is documentary (the hidden-path rule)
    # and is never used for matching.
    Signal(
        "fs.write.hidden",
        "T1074",
        _p(r"(^|/)\.[^/]+|/(tmp|var/tmp)/"),
        "Write to a hidden/temp path — data staging",
    ),
    Signal(
        "fs.write.normal",
        "T1074",
        _p(r".+"),
        "Write to a normal project path (weak staging signal)",
    ),
    # ТЗ-03: ingestion of external/untrusted content — the delivery vector for
    # indirect prompt injection. Action signal (tool-gated on WebFetch/WebSearch
    # or a Read from an untrusted path) — emission lives in
    # ``extractor._external_content_signals``; the pattern below is documentary.
    # Mapped to ATLAS LLM Prompt Injection (the AI-specific technique this read
    # enables) rather than a generic ATT&CK id.
    Signal(
        "content.read.external",
        "ATLAS.AML.T0051",
        _p(r"/(tmp|var/tmp|downloads|node_modules|site-packages)/|/\.(cache|cargo|npm)/"),
        "Read of external/untrusted content (web fetch or untrusted path)",
    ),
    # ТЗ-04: category MARKERS emitted ALONGSIDE fs.write.{hidden,normal} when the
    # write target is a known build/package cache or a VCS dir. They carry only a
    # path CATEGORY (privacy — never the path) so the server-side staging
    # orchestrator can allowlist build noise without seeing the path. Documentary
    # patterns; emission is tool-gated in ``extractor._write_signals``.
    Signal(
        "fs.write.cache",
        "T1074",
        _p(r"/(node_modules|site-packages|__pycache__)/|/\.(cache|cargo|npm|pytest_cache|mypy_cache|tox)/"),
        "Write to a build/package cache (benign-staging allowlist marker)",
    ),
    Signal(
        "fs.write.vcs",
        "T1074",
        _p(r"/\.git/"),
        "Write to a VCS internal dir (benign-staging allowlist marker)",
    ),
    # --- ATT&CK coverage-gap batch 3: ransomware encryption, dynamic-linker
    # hijack, shell-history creds, timestamp forgery. Regular (regex-loop)
    # signals; each is behavior-gated so ordinary dev work stays quiet. ---------
    Signal(
        "impact.encrypt",
        "T1486",
        # Ransomware (data encrypted for impact). We already catch the PREP
        # (impact.inhibit_recovery deletes backups) but not the encrypt itself.
        # Gated on the mass / destroy-original shape so a single benign
        # `openssl enc`/`gpg -c` of one file stays quiet:
        #  * 7z archive with BOTH a password and -sdel (delete source after);
        #  * find … -exec <crypto> — encrypt every matched file;
        #  * a for/while loop that encrypts then rm/shred each file;
        #  * output written with a ransom extension (.locked/.encrypted/.crypted);
        #  * gpg --encrypt-files / --multifile (its native mass-encrypt flags);
        #  * rename to a ransom extension.
        _p(
            r"\b(?:7za?|7zr)\s+a\b(?=[^\n]*\s-p)(?=[^\n]*-sdel)"
            r"|\bfind\b[^\n]*-exec\s+(?:openssl\s+enc\b"
            r"|gpg\b(?=[^\n]*(?:--symmetric|--encrypt|\s-c\b))|ccrypt\b)"
            r"|\b(?:for|while)\b[^\n]*;\s*do\b"
            r"(?=[^\n]*(?:openssl\s+enc|gpg\b[^\n]*\s-c\b|ccrypt))"
            r"[^\n]*;\s*(?:rm|shred|unlink)\b"
            r"|\bopenssl\s+enc\b[^\n]*-out\s+\S+\.(?:locked|encrypted|crypted)\b"
            r"|\bgpg\b[^\n]*--(?:encrypt-files|multifile)\b"
            r"|\bmv\b[^\n]*\.(?:locked|encrypted|crypted)\b"
        ),
        "Ransomware — mass file encryption for impact (encrypt+destroy / ransom extension)",
    ),
    Signal(
        "persist.preload",
        "T1574.006",
        # Dynamic-linker hijack (LD_PRELOAD/ld.so.preload) + narrow PATH
        # interception. Any write to the global /etc/ld.so.preload; LD_PRELOAD /
        # LD_LIBRARY_PATH pointing at a .so / attacker dir; LD_PRELOAD persisted
        # into a shell rc; or PATH PREPENDED with a world-writable dir. A normal
        # `export PATH=$HOME/bin:$PATH` (not /tmp,/dev/shm,/var/tmp,.) stays quiet.
        _p(
            r"/etc/ld\.so\.preload\b"
            r"|\bld_preload\s*=\s*\S*\.(?:so|dylib)\b"
            r"|\bld_library_path\s*=\s*(?:/tmp|/dev/shm|/var/tmp|\.)[:/]"
            r"|\bld_preload\b[^\n]*>>?[^\n]*"
            r"(?:\.bashrc|\.bash_profile|\.profile|\.zshrc|/etc/environment)"
            r"|\bexport\s+path\s*=\s*(?:/tmp|/dev/shm|/var/tmp|\.)[:/]"
        ),
        "Dynamic-linker hijack (LD_PRELOAD / ld.so.preload) or PATH interception",
    ),
    Signal(
        "cred.read.shell_history",
        "T1552.003",
        # Harvest a shell / REPL / DB-client history file — commands (and pasted
        # secrets) live there. Distinct from defense.clear_history (which ERASES
        # it). The `history` builtin alone (listing) stays quiet — only the FILE.
        _p(
            r"\.(?:bash|zsh|sh|ash|ksh|python|node_repl|mysql|psql|rediscli"
            r"|irb|sqlite|mongo|php)_history\b"
            r"|\bfish_history\b|\.zhistory\b|\.lesshst\b"
            r"|(?:^|[\s/~])\.history\b"
        ),
        "Read of a shell / REPL / client history file (credential harvest)",
    ),
    Signal(
        "defense.timestomp",
        "T1070.006",
        # Timestamp forgery (anti-forensics): touch cloning another file's time
        # (-r/--reference) or setting an explicit time (-t/--time), or macOS
        # SetFile -d/-m. Plain `touch file` / `touch -a`/`-m` (to NOW) stays quiet.
        _p(
            r"\btouch\b[^\n]*\s(?:-r\b|--reference[=\s]|-t\s|--time[=\s])"
            r"|\bsetfile\b[^\n]*\s-[dm]\b"
        ),
        "Timestamp forgery — touch -r/-t clone/backdate (anti-forensics)",
    ),
    # ТЗ-IMPACT: data-destruction signals. ACTION signals — emission is gated on
    # a destructive Bash command hitting a SENSITIVE (non-allowlisted) target in
    # ``extractor._destructive_signals`` (via ``destructive.detect_destructive``),
    # NOT the regex loop. Documentary patterns. Mapped to T1485 Data Destruction;
    # these are the ``impact`` kill-chain stage that revives poison_to_destructive.
    Signal(
        "impact.delete",
        "T1485",
        _p(r"\brm\s+-\S*[rf]|\bshred\b|\bfind\b.*-delete"),
        "Destructive deletion of a sensitive target (rm -rf / shred / find -delete)",
    ),
    Signal(
        "impact.db",
        "T1485",
        _p(r"\b(drop\s+(table|database|schema)|truncate|delete\s+from)\b"),
        "Destructive DB operation on a non-test object (DROP / TRUNCATE / DELETE)",
    ),
    Signal(
        "impact.overwrite",
        "T1485",
        _p(r">\s*\S|\bdd\b.*\bof=|\bch(mod|own)\s+-\S*[rR]"),
        "Destructive overwrite of a sensitive file (redirect / dd / chmod -R)",
    ),
    # Уход из-под наблюдения через ВЛОЖЕННУЮ сессию агента. Наш хук встроен в
    # ТОТ экземпляр Claude Code, что на хосте; агент, запущенный внутри
    # контейнера/пода, работает в чистой среде без наших хуков — и оттуда может
    # делать что угодно. Ловим запуск известного CLI AI-агента внутри
    # docker/podman/kubectl. Локальный `claude ...` НЕ матчится (он-то как раз
    # под наблюдением) — только явно вложенный. Имена агентов подобраны
    # специфичными (без коротких/общих слов) ради нуля ложных срабатываний.
    Signal(
        "evade.nested_agent",
        "T1610",
        _p(
            r"\b(?:docker|podman)\s+(?:run|exec|compose\s+run)\b[^\n]*"
            r"\b(?:claude|cursor-agent|aider|codex|cline|opencode)\b"
            r"|\bkubectl\s+exec\b[^\n]*"
            r"\b(?:claude|cursor-agent|aider|codex|cline|opencode)\b"
        ),
        "Запуск сессии AI-агента внутри контейнера/пода — исполнение вне "
        "наблюдения ccguard (уход из-под хуков через вложенную среду)",
    ),
    # ASI07 (небезопасная межагентная коммуникация): агент открывает исходящий
    # канал к ДРУГОМУ агенту/модели/серверу. Два явных вектора: регистрация
    # удалённого MCP-канала (--transport sse/http или URL) и прямой вызов чужого
    # LLM/agent-API из shell. Гейт по сетевому клиенту (curl|wget|xh|httpie|nc) +
    # конкретный список хостов моделей держит ложные срабатывания у нуля: обычный
    # `curl https://docs...`, `pip install openai`, локальный `mcp add -- node ...`
    # (stdio, без url) не срабатывают.
    Signal(
        "intercomm.remote_agent",
        "T1071",
        _p(
            r"\bmcp\s+add\b[^\n]*(?:--transport\s+(?:sse|http)\b|https?://)"
            r"|\b(?:curl|wget|xh|httpie|nc)\b[^\n]*"
            r"\b(?:api\.openai\.com|api\.mistral\.ai|generativelanguage\.googleapis\.com"
            r"|api\.cohere\.(?:ai|com)|openrouter\.ai|api\.groq\.com"
            r"|api\.together\.(?:ai|xyz)|api\.perplexity\.ai|api\.deepseek\.com|api\.x\.ai)\b"
        ),
        "Агент открывает канал к другому агенту/модели: регистрация удалённого "
        "MCP (sse/http) или прямой вызов чужого LLM-API — межагентная "
        "коммуникация вне наблюдения (ASI07)",
    ),
)

# Action signals (see note above): excluded from the generic regex loop in
# ``extractor.extract_signals`` and emitted only by tool-gated paths
# (``_write_signals`` / ``_external_content_signals``).
ACTION_SIGNAL_IDS: frozenset[str] = frozenset(
    {
        "fs.write.hidden",
        "fs.write.normal",
        "content.read.external",
        "fs.write.cache",
        "fs.write.vcs",
        "impact.delete",
        "impact.db",
        "impact.overwrite",
    }
)
