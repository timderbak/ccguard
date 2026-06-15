"""Risk engine constants (Behavioral Detection, Stage 2).

Per-signal weights, tunable defaults, and the canonical ``rule_id`` for the
``risk.elevated`` finding. All numerics are admin-tunable via ``SettingsRecord``
(``risk.threshold``, ``risk.window_hours``, ``risk.half_life_hours``,
``risk.weight.<signal_id>``); the values here are first-boot defaults only.

Weights reflect ATT&CK tactic severity: credential access + egress weigh higher
than recon. Calibration is expected to evolve with pilot data; the catalog of
*which* signals exist is locked, the numbers are not.
"""
from __future__ import annotations

RISK_RULE_ID: str = "risk.elevated"

DEFAULT_THRESHOLD: float = 10.0
DEFAULT_WINDOW_HOURS: float = 24.0
DEFAULT_HALF_LIFE_HOURS: float = 6.0

DEFAULT_WEIGHTS: dict[str, float] = {
    "cred.read.aws": 5.0,
    "cred.read.shadow": 5.0,  # /etc/shadow = OS credential dumping
    "cred.read.ssh": 5.0,
    "cred.read.dotenv": 3.0,
    "egress.network_tool": 4.0,
    "egress.adhoc_server": 3.0,  # pull-exfil server (non-loopback)
    "exec.pipe_to_shell": 4.0,
    "exec.shell_spawn": 4.0,  # GTFOBins LOLBin shell breakout
    "persist.shell_rc": 3.0,
    "persist.cron": 3.0,
    "discovery.recon": 1.0,
    # Stage 6 catalog expansion — calibrated against the same ATT&CK-tactic
    # severity axis: cloud-cred reads weigh on par with AWS/SSH; container
    # escape and cloud-storage exfil are direct attack primitives; package
    # publish and systemd persistence rank with shell-rc.
    "cred.read.gcp": 5.0,
    "cred.read.azure": 5.0,
    "cred.read.kube": 5.0,
    "cred.read.browser": 5.0,
    "cred.read.git": 4.0,
    "cloud.exfil.storage": 5.0,
    "container.escape_hint": 4.0,
    "pkg.publish": 3.0,
    "recon.cloud_metadata": 3.0,
    "persist.systemd": 3.0,
    # Catalog Expansion C — same severity axis as the core set.
    "cred.read.kube_secret": 5.0,
    "cred.read.vault": 5.0,
    "cred.env.api_key": 4.0,
    "cred.read.git_credential_helper": 3.0,
    "cred.read.saas_token": 5.0,  # P2: SaaS/cloud-CLI/DB creds — top-tier
    "cred.read.secret_manager": 5.0,  # P2: password/secret-manager read
    "cred.read.os_keychain": 5.0,  # macOS Keychain / Linux keyring / pass
    "cred.read.cloud_session": 5.0,  # P2: cloud/CI session tokens
    "discovery.cloud_enum": 2.0,  # P2: recon, noisier
    "discovery.account_enum": 2.0,  # P2: recon, noisier
    "persist.ssh_authorized_keys": 4.0,  # P2: attacker-key persistence
    "exec.powershell_encoded": 4.0,  # P2: obfuscated exec, rarely benign
    "persist.launchd": 3.0,
    "persist.windows_run_key": 3.0,
    "persist.autostart": 3.0,
    "persist.scheduled_task": 3.0,  # systemd-timer / schtasks / at — same tier as cron
    "persist.git_hooks": 3.0,  # core.hooksPath / .git/hooks drop — runs on next git op
    "persist.global_pkg_install": 2.0,  # noisy on dev boxes, lower weight
    "exec.code_eval_inline": 2.0,
    "exec.base64_decode": 3.0,  # rarely benign in tool context
    "exec.hex_decode": 3.0,
    "egress.dns_long_subdomain": 3.0,
    "egress.bot_api": 4.0,
    "egress.paste_site": 4.0,
    # P1: host-agnostic egress action-category — same exfil severity band.
    "egress.http_client": 4.0,
    "egress.file_transfer": 4.0,
    "egress.cloud_cli": 4.0,
    "system.permissive_chmod": 3.0,
    "system.sudo_nopasswd": 4.0,  # privilege escalation primitive
    "system.sudo_shell": 4.0,  # sudo → shell = GTFOBins privesc
    "system.hosts_edit": 4.0,
    "discovery.network_scan": 2.0,
    "discovery.secret_grep": 4.0,
    "config.agent_settings_edit": 4.0,  # AI-specific high-value
    # ТЗ-02 staging-write action signals. normal is very noisy (every project
    # write) → low; hidden/temp writes are staging-suspicious → moderate.
    "fs.write.hidden": 2.0,
    "fs.write.normal": 1.0,
    # ТЗ-03 external-content read. Common on its own (every web fetch) → low;
    # the danger is the combination (external→stage), scored by the staging
    # detector, not by this per-event weight.
    "content.read.external": 1.0,
    # ТЗ-04 benign-category write markers (build/package caches, VCS). Almost
    # always legitimate build noise → minimal weight.
    "fs.write.cache": 0.5,
    "fs.write.vcs": 0.5,
    # ТЗ-IMPACT data-destruction signals — top-tier threat (Replit-style prod
    # wipe). Already target-gated (fire only on a sensitive, non-allowlisted
    # target via destructive.detect_destructive), so a high weight carries low
    # false-positive risk.
    "impact.delete": 5.0,
    "impact.db": 5.0,
    "impact.overwrite": 5.0,
    "impact.cryptomining": 5.0,  # resource hijacking
    "impact.disk_wipe": 5.0,  # irreversible host destruction
    "impact.inhibit_recovery": 5.0,  # ransomware-prep
    "impact.cloud_destroy": 5.0,  # destructive cloud op
    # ATT&CK coverage-gap batch 2
    "container.privileged": 4.0,  # container escape / host takeover
    "collection.kubectl_cp": 4.0,
    "persist.cloud_iam": 4.0,
    "defense.disable_firewall": 4.0,
    "defense.masquerade": 4.0,
    "discovery.privesc_enum": 2.0,  # recon, noisier
    "cred.dump.memory": 5.0,
    "cred.scan.secrets": 4.0,
    "persist.account": 4.0,
    "ai.context_poison": 4.0,  # AI-origin trigger (moat)

    # P2: revived kill-chain stages. Blinding the EDR and reverse shells are
    # top-tier and almost never benign; remote-exec (ssh) is noisier on dev
    # boxes so it leans on correlation rather than a high per-event weight.
    "defense.disable_security": 5.0,
    "defense.clear_history": 3.0,
    "defense.clear_logs": 4.0,
    "c2.reverse_shell": 5.0,
    "c2.tunnel": 3.0,
    "lateral.remote_exec": 2.0,
    # P2-width-3: collection. archive-staging is sensitive-source-gated (cred
    # store / whole home) → rarely benign, weighs with persistence. Screen
    # capture is moderate; clipboard scrape is noisy → low (leans on
    # collection→egress correlation).
    "collection.archive_staging": 4.0,
    "collection.screen_capture": 2.0,
    "collection.clipboard": 1.0,
    # Coverage expansion (audit-driven).
    "collection.db_dump": 3.0,
    "cred.read.env_dump": 4.0,
    "pkg.install_untrusted": 3.0,  # supply-chain entry
    "egress.dns_tool": 3.0,
    "egress.icmp_tunnel": 3.0,
    "exec.lolbin_download": 4.0,  # download-cradle LOLBin, rarely benign
    "exec.windows_lolbin": 4.0,  # LOLBAS proxy-exec / AWL-bypass
}
