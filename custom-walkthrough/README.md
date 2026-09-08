# Custom Walkthroughs — one directory per technique

Each directory is a self-contained test: guide (`WALKTHROUGH.md`), a runnable victim-side
`test.ps1`, expected alerts for every step, and cleanup. Shared Kali implant-build steps
live in [`_common/implant-build.md`](_common/implant-build.md) — build once, use everywhere.
EDR console: http://127.0.0.1:8420. Global cleanup (removes artifacts from every test):
[`../poc-scripts/victim/05-full-cleanup.ps1`](../poc-scripts/victim/05-full-cleanup.ps1).

**The consolidated backlog of every filed gap:** [`FUTURE-IMPROVEMENTS.md`](FUTURE-IMPROVEMENTS.md).
**Research + implementation notes for the newest detections:**
[`../development-research/future-detections-research.md`](../development-research/future-detections-research.md).

## Delivery (how the implant arrives)

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`delivery-encoded-ps-cradle/`](delivery-encoded-ps-cradle/WALKTHROUGH.md) | base64-encoded PowerShell download cradle | PROC-ENC-PS, EVT-4688-SUSP, SIG-*, launch chain |
| [`delivery-lolbin-download/`](delivery-lolbin-download/WALKTHROUGH.md) | certutil / bitsadmin fetch | PROC-LOLBIN-DOWNLOAD, PERS-BITS |
| [`delivery-direct-copy/`](delivery-direct-copy/WALKTHROUGH.md) | silent file copy — no invocation telemetry | SIG-* (on-write scan only tripwire) |

## Execution (how it runs)

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`dll-sideload/`](dll-sideload/WALKTHROUGH.md) | full chain: Kali-built proxy version.dll loaded by a signed host | SIG-*, EVT-4688-TEMP, PROG-IMPLANT-LAUNCH |
| [`execution-rundll32-dll/`](execution-rundll32-dll/WALKTHROUGH.md) | imix.dll via rundll32 (CS spawn posture) | PROC-RUNDLL-NOARG, SIG-* |

## Privilege escalation

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`privesc-uac-family/`](privesc-uac-family/WALKTHROUGH.md) | fodhelper siblings: computerdefaults / eventvwr / sdclt | PERS-UAC-KEY (partial — 2 keys are gaps) |
| [`privesc-service-misconfig/`](privesc-service-misconfig/WALKTHROUGH.md) | unquoted service paths + AlwaysInstallElevated | EVT-7045/PERS-SERVICE; conditions = gaps |
| [`privesc-kerberoast-pth/`](privesc-kerberoast-pth/WALKTHROUGH.md) | Kerberoasting (4769 RC4) + Pass-the-Hash (4624 NTLM) — domain required | channels = gaps (filed with fix notes) |

## Persistence (how it survives)

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`implant-max-persistence/`](implant-max-persistence/WALKTHROUGH.md) | **HYDRA**: 19 mechanisms at once + evasion layers + resurrection pair — the capstone stress test | all 17 PERS-* rule types |
| [`persistence-service/`](persistence-service/WALKTHROUGH.md) | win_service build as auto-start service (SYSTEM beaconing) | EVT-7045, PERS-SERVICE |
| [`persistence-scheduled-task/`](persistence-scheduled-task/WALKTHROUGH.md) | SYSTEM task re-executing the implant every 5 min | EVT-4698, PERS-TASK + launch chain each firing |
| [`persistence-runkey-startup/`](persistence-runkey-startup/WALKTHROUGH.md) | Run key + Startup folder | PERS-RUNKEY, PERS-STARTUP |
| [`persistence-wmi-subscription/`](persistence-wmi-subscription/WALKTHROUGH.md) | fileless WMI EventFilter/Consumer binding | PERS-WMI-SUB |
| [`persistence-com-hijack/`](persistence-com-hijack/WALKTHROUGH.md) | HKCU CLSID shadow (T1546.015) | PERS-COM |
| [`persistence-bits-job/`](persistence-bits-job/WALKTHROUGH.md) | queued BITS job (T1197) | PERS-BITS |
| [`persistence-powershell-profile/`](persistence-powershell-profile/WALKTHROUGH.md) | profile.ps1 backdoor | PERS-PSPROFILE |
| [`persistence-silentprocessexit/`](persistence-silentprocessexit/WALKTHROUGH.md) | IFEO GlobalFlag + SilentProcessExit (payload on process *exit*) | launch chain; arming = gap |
| [`persistence-hidden-user/`](persistence-hidden-user/WALKTHROUGH.md) | `$`-suffixed hidden local account | EVT-4720/4732; SAM-insertion = gap |

## Evasion (what attackers do about you)

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`evasion-defender-sideload/`](evasion-defender-sideload/WALKTHROUGH.md) | sideload into Defender's own signed binaries (LockBit/REvil) | EVT/PROC-DEFENDER-SIDELOAD |
| [`evasion-masquerade-rename/`](evasion-masquerade-rename/WALKTHROUGH.md) | implant renamed svchost.exe | EVT-4688-TEMP, PROC-MASQ (path/byte-based) |
| [`evasion-timestomp-deeppath/`](evasion-timestomp-deeppath/WALKTHROUGH.md) | deep path + backdated timestamps | EVT-4688-TEMP; timestomping = filed gap |
| [`evasion-amsi-bypass-chain/`](evasion-amsi-bypass-chain/WALKTHROUGH.md) | AMSI blinded, then cradle | 4104 events; proves EDR is AMSI-independent |
| [`evasion-script-host-launchers/`](evasion-script-host-launchers/WALKTHROUGH.md) | mshta/wscript/wmic launchers | EVT/PROC-SCRIPTHOST |
| [`evasion-uac-fodhelper/`](evasion-uac-fodhelper/WALKTHROUGH.md) | fodhelper UAC bypass → elevated implant | PERS-UAC-KEY, launch chain |
| [`evasion-process-ghosting/`](evasion-process-ghosting/WALKTHROUGH.md) | VERY ADV: process ghosting / herpaderping (file↔process mismatch) | launch chain survives; static verify defeated (Sysmon fix) |
| [`evasion-sleep-obfuscation/`](evasion-sleep-obfuscation/WALKTHROUGH.md) | VERY ADV: in-memory sleep encryption (Ekko PoC) | SIG + launch chain; memory scanning = gap |

## Lateral movement & C2 channels

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`lateral-psexec-chain/`](lateral-psexec-chain/WALKTHROUGH.md) | PsExec destination chain (ADMIN$ → PSEXESVC → payload) | EVT-7045/PERS-SERVICE; 5145 = gap |
| [`lateral-winrm/`](lateral-winrm/WALKTHROUGH.md) | WinRM/PSRemoting session host | in-session cradle rules; 4648/wsmprovhost = gaps |
| [`c2-named-pipes/`](c2-named-pipes/WALKTHROUGH.md) | CS-style SMB named-pipe beacon (msagent_*) | static SIG-CS-BEACON; live pipes = gap |
| [`c2-deaddrop-github/`](c2-deaddrop-github/WALKTHROUGH.md) | dead-drop resolver C2 over GitHub Gists (T1102.001) | beacon chain survives; NET-DEADDROP = gap |
| [`c2-egress-tools/`](c2-egress-tools/WALKTHROUGH.md) | rclone / Ngrok / AnyDesk / RustDesk attacker utilities | service install generic; tool watchlist = gap |
| [`persistence-ssh-backdoor/`](persistence-ssh-backdoor/WALKTHROUGH.md) | the Akira chain: OpenSSH + administrators_authorized_keys + firewall rule | EVT-7045 fires; key file + netsh = gaps |
| [`ad-domain-persistence/`](ad-domain-persistence/WALKTHROUGH.md) | Shadow Credentials / RBCD / DCSync / ADCS (domain lab) | 5136/4662/4769 channels = gaps |
| [`evasion-advanced-injection/`](evasion-advanced-injection/WALKTHROUGH.md) | VERY ADV: Mockingjay / module stomping / thread-pool injection | edges survive; injection acts = Sysmon+scanner-gated |

## Network

| Directory | Technique | Key rules exercised |
|---|---|---|
| [`network-beacon-jitter/`](network-beacon-jitter/WALKTHROUGH.md) | jittered loopback beacon (no Kali needed) | NET-BEACON (jitter tolerance) |

The full multi-phase runbook with all reasoning lives in
[`../development-research/realm-c2-killchain-emulation-runbook.md`](../development-research/realm-c2-killchain-emulation-runbook.md);
the shared script battery (implant build, check-alerts scoreboard) in [`../poc-scripts/`](../poc-scripts/).
