# Future Improvements — the consolidated backlog

Every technique that has a walkthrough today but whose detection is a **filed gap**, plus
the proposed-but-not-yet-built detections from the 2026 research rounds. Sorted by
priority (value ÷ effort). Implementation guidance for the newest items lives in
[`../development-research/future-detections-research.md`](../development-research/future-detections-research.md).

## Tier 1 — cheap, closes whole categories

| # | Improvement | Closes | Walkthrough that tests it |
|---|---|---|---|
| 1 | **Sysmon install + EID 8/10/25 rules** | the entire injection family (APC/thread/section/hollowing), module telemetry for sideloading | `evasion-amsi-bypass-chain/` refs; runbook §6.5 |
| 2 | **`PROC-RMM-TOOL` + `PROC-EGRESS-TOOL` name watchlist** (rclone/ngrok/anydesk/rustdesk/…) | the 2026 RMM-abuse category | `c2-egress-tools/` |
| 3 | **`NET-DEADDROP` rule** (non-browser process → gist/telegram/discord/graph APIs) | dead-drop C2 over trusted services | `c2-deaddrop-github/` |
| 4 | **SSH-key auditor category** (`administrators_authorized_keys` + user authorized_keys diff) + **`PROC-NETSH-FIREWALL` rule** | the Akira SSH-backdoor chain | `persistence-ssh-backdoor/` |
| 5 | **Auditor extensions (one batch):** mscfile/exefile UAC proxy keys; IFEO GlobalFlag + SilentProcessExit; unquoted service paths; AlwaysInstallElevated; local-account baseline diff | the "arming" gaps from the persistence round | `privesc-uac-family/`, `persistence-silentprocessexit/`, `privesc-service-misconfig/`, `persistence-hidden-user/` |
| 6 | **Named-pipe enumeration sensor** (`\\.\pipe\` diff + msagent_/postex_/msse_ patterns) | CS SMB-beacon channel | `c2-named-pipes/` |
| 7 | **`PROC-DEAD-PARENT` check** (resolve PPID; dead/recycled = anomaly) | PPID spoofing | runbook §6.6 |

## Tier 2 — medium effort, needs new channels or care

| # | Improvement | Closes | Walkthrough |
|---|---|---|---|
| 8 | **Lateral channels: 4648, 4769 (RC4-filtered), 5145 (ADMIN$/IPC$), 4624 (NTLM+type 3/9, non-machine)** + `PROC-PSEXESVC` + `PROC-WINRM-SESSION` (wsmprovhost) | lateral movement visibility | `lateral-psexec-chain/`, `lateral-winrm/`, `privesc-kerberoast-pth/` |
| 9 | **AD persistence channels: 5136 (KeyCredentialLink/AllowedToActOnBehalf), 4662 (replication GUIDs, non-DC)** | Shadow Credentials / RBCD / DCSync | `ad-domain-persistence/` |
| 10 | **CodeIntegrity channel (3033/3077) + drivers-dir inventory** | BYOVD / vulnerable-driver abuse | (proposed — build with #12) |
| 11 | **`PROC-SUDDEN-SYSTEM`** (WMI poll + GetOwner; SYSTEM child of user parent) | usermode-visible output of the kernel-CVE wave | (proposed) |
| 12 | **Patch-level exposure audit** (build+QFE vs KEV list) | unpatched actively-exploited privesc | (proposed — cheap, high CCDC value) |
| 13 | **4104 content rules** (amsiInitFailed/AmsiScanBuffer/cradle patterns inside script blocks) | in-script AMSI bypasses | `evasion-amsi-bypass-chain/` |
| 14 | **tcp_bind listener sweep + DNS/ICMP transport detection** | inverted-channel and tunnel C2 | runbook §4.5 |
| 15 | **`PROC-LOLBIN-DOTNET` expansion** (msbuild inline-task project in user dir; msiexec from \Users\; msdt) | trusted-dev-tool execution | runbook §6.9 refs |

## Tier 3 — big builds / partially out of scope

| # | Improvement | Closes | Notes |
|---|---|---|---|
| 16 | **Memory scanner at sleep/wake transitions** with (a) module re-hash vs disk, (b) default-RWX entropy flag, (c) thread-pool work-item enumeration | sleep obfuscation, module stomping, Mockingjay, TpAllocWork | design requirements in future-detections-research.md §5 — this is THE major sensor investment; stomping must be a design input, not an afterthought |
| 17 | **Sysmon EID 1 creation-time hashing** | process ghosting / herpaderping | `evasion-process-ghosting/` documents partial mitigation today |
| 18 | **EFI System Partition walk + BCD store watch + Secure Boot revocation status** | bootkit *staging* (firmware itself out of scope) | BlackLotus lineage — see runbook sources |
| 19 | **Linux sensor** (auditd + persistence-path inotify) | cron/systemd/authorized_keys attacks on Linux hosts | research guide §4 item 11 |
| 20 | **File-metadata anomaly detection** (CreationTime≠LastWriteTime in scanned roots, metadata-only changes) | timestomping | `evasion-timestomp-deeppath/` |
| 21 | **ADS (alternate data stream) telemetry** | NTFS-hidden payloads | `implant-max-persistence/` mechanism #18 |
| 22 | **EDR self-protection** (watchdog pair + heartbeat-gap SIEM alarm) | red team killing the sensor | deferred by decision — the sensor is currently a killable python.exe |

## Explicitly out of scope (documented, not planned)

Kernel exploit detection itself (CLFS/DWM/Defender-engine CVEs — no usermode sensor can
see them; compensating: #11/#12), hypervisor/VBS attacks, UEFI firmware persistence
beyond staging detection (#18), cloud/identity ("living-off-the-cloud") — the host EDR's
blind spots, each with its compensating control noted.
