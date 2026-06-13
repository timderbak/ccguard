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


@dataclass(frozen=True)
class Signal:
    """One per-event behavioral signal.

    ``pattern`` is matched (``search``) against the normalized text of a tool
    invocation. ``attack_technique`` is a MITRE ATT&CK id (``T####`` /
    ``T####.###``) or an ATLAS reference (``ATLAS.<name>``).
    """

    id: str
    attack_technique: str
    pattern: re.Pattern[str]
    description: str


def _p(rx: str) -> re.Pattern[str]:
    return re.compile(rx, re.IGNORECASE)


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
        _p(r"(\.ssh/|\bid_rsa\b|\bid_ed25519\b)"),
        "Access to SSH private keys",
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
        # invocations (start, after space / ; | & ( newline) still fire.
        _p(r"(?<![\w/.\-])(curl|wget|nc|ncat|scp|sftp)\b"),
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
            r"|\|\s*(python[0-9.]*|perl|ruby|node|deno|bun|php|rscript)\b\s*-?\s*(?=$|[|;&\n])"
            r"|base64\s+(-d|--decode)|\beval\b)"
        ),
        "Piping/decoding into a shell or language interpreter (stdin code)",
    ),
    Signal(
        "persist.shell_rc",
        "T1546.004",
        _p(r"\.(bashrc|zshrc|bash_profile|profile)\b"),
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
            # Chromium-family profile cookie / login stores (macOS/Linux paths).
            r"|/(google/chrome|chromium|microsoft\s*edge|bravesoftware|vivaldi|opera\s*software)/"
            r"[^/]+/(cookies|login\s*data|web\s*data)\b)"
        ),
        "Access to browser credential / cookie stores",
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
        _p(r"\$\{?(?:openai_|anthropic_|github_|aws_|gcp_)\w*(?:api_key|token|secret)\b|\$\{?(?:api_key|access_token|secret_key)\b"),
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
        ),
        "OS-native credential store read (macOS Keychain / Linux keyring / pass)",
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
        _p(r"\b(python3?|node|perl|ruby|deno|bun)\s+-[ec]\b"),
        "Inline code execution (python -c / node -e / etc)",
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
            # ccguard tamper — verb ADJACENT to the product name (bounded, so
            # prose like "ccguard helps disable nothing" does not fire).
            r"|\bccguard\s+(uninstall|disable|stop|remove)\b|\b(uninstall|remove)\s+ccguard\b"
            r"|\bufw\s+disable\b|\biptables\s+-f\b|\bsetenforce\s+(0|permissive)\b"
            r"|spctl\s+--master-disable|csrutil\s+disable"
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
            r"(/dev/tcp/|/dev/udp/|\bnc\b[^\n]*-e\s*/|\bncat\b[^\n]*-e\b"
            r"|mkfifo\b[^\n]*\|\s*n?cat?\b"
            r"|socat\b[^\n]*exec|bash\s+-i\b[^\n]*>&|sh\s+-i\b[^\n]*>&"
            # inline-interpreter reverse shells (python/perl/ruby socket→shell)
            r"|(python[0-9.]*|perl|ruby)\b[^\n]*socket[^\n]*(/bin/(sh|bash)|exec|subprocess))"
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
            # alone (e.g. ``xsel -ib``, a WRITE) must not fire.
            r"(?<![\w./-])(?:pbpaste|wl-paste|get-clipboard)(?![\w-])"
            r"|(?<![\w./-])xclip\b[^\n]*\s(?:-o|--output)(?![\w])"
            r"|(?<![\w./-])xsel\b[^\n]*(?:--output|\s-\S*o(?![\w]))"
            r"|pyperclip\.paste"
        ),
        "Clipboard scrape (pbpaste / xclip -o / xsel -o / wl-paste / Get-Clipboard) — collection",
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
        "egress.icmp_tunnel",
        "T1095",
        # ICMP covert channel: ping with a hex payload, or hping/nping. A normal
        # `ping host` is silent.
        _p(r"(\bping\b[^\n]*\s-p\s+[0-9a-f]{4,}|\bhping3?\b|\bnping\b[^\n]*--icmp)"),
        "ICMP tunnel / exfil (ping -p payload, hping, nping --icmp) — covert channel",
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
