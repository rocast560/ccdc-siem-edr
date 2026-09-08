# Future Detections — Research & Implementation Notes

Research-backed implementation guidance for every technique in the 2026 tradecraft
rounds (dead-drop C2, SSH backdoors, egress/RMM tools, AD domain persistence, advanced
injection). Each section: what it is, who does it, and *how to implement the detection in
this EDR later*. Companion walkthroughs live in `../custom-walkthrough/` per technique.
The consolidated backlog of ALL filed gaps is `../custom-walkthrough/FUTURE-IMPROVEMENTS.md`.

---

## 1. Dead-drop resolver C2 (`NET-DEADDROP`) — walkthrouth: `c2-deaddrop-github/`

**What:** the implant resolves its real C2 from a legitimate public service (GitHub Gist,
git commit messages, Telegram Bot API, Discord webhooks, Microsoft Graph, blockchain
contracts) — no attacker infrastructure in the binary or on the wire ([MITRE
T1102.001](https://attack.mitre.org/techniques/T1102/001/); real cases: [Drokbk](https://www.sophos.com/en-us/blog/drokbk-malware-uses-github-as-dead-drop-resolver),
[C2Looper 2026](https://www.zscaler.com/blogs/security-research/c2looper-new-backdoor-likely-tied-ransomware-github-c2),
[Telegram C2 rules](https://socprime.com/active-threats/detection-response-chronicles-exploring-telegram-abuse/)).

**Implement:** in `network.py`, maintain an endpoint list —
`api.github.com`, `gist.github.com`, `gist.githubusercontent.com`, `raw.githubusercontent.com`,
`discord.com/api`, `api.telegram.org`, `graph.microsoft.com`, `api.notion.so`, `paste.ee`,
`pastebin.com`. When a flow's remote host matches (resolve via DNS cache or maintain an
IP->host map from periodic resolution) AND the owning process is not a signed browser
(msedge/chrome/firefox/iexplore), raise `NET-DEADDROP` (critical). Secondary signal:
periodic polling of a *static-content* URL is beacon-shaped — feed those flows into the
existing cadence analyzer. Cost: low — the per-process flow data already exists.

## 2. SSH backdoor chain — walkthrough: `persistence-ssh-backdoor/`

**What:** install OpenSSH Server + operator key in
`C:\ProgramData\ssh\administrators_authorized_keys` + firewall rule, per
[CISA Akira AA24-109A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-109a)
and [Intrinsec](https://www.intrinsec.com/akira_ransomware/).

**Implement (three pieces):**
- Auditor category `sshkeys`: existence + content hash of
  `C:\ProgramData\ssh\administrators_authorized_keys` and every
  `<profile>\.ssh\authorized_keys` — diff vs baseline (any change = critical).
- `PROC-NETSH-FIREWALL` rule: cmdline regex
  `(?i)netsh(\.exe)?\s+advfirewall(\s+firewall)?\s+(add|delete|set)\s+rule` (high) and
  `(?i)set-netfirewallprofile.*-enabled\s+\$?false` (critical).
- sshd install: `Add-WindowsCapability OpenSSH.Server` produces a 7045-style service +
  `Microsoft-Windows-Setup` events; the service rule already covers the install; add a
  `PROC-SSHD-INSTALL` cmdline rule for the capability install command.

## 3. Egress / RMM tool watchlist — walkthrough: `c2-egress-tools/`

**What:** rclone (exfil), Ngrok (reverse tunnels), AnyDesk/RustDesk/ScreenConnect/
Splashtop/NetSupport/Level/Atera/Syncro (persistent RMM access) — the Akira/CISA tool
trio and the [rogue-RMM trend](https://www.huntress.com/blog/daisy-chaining-rogue-rmm-tools);
canonical list: [LOLRMM](https://lolrmm.io), [Intel471 hunting guide](https://www.intel471.com/blog/understanding-and-threat-hunting-for-rmm-software-misuse).

**Implement:** `PROC-RMM-TOOL` (critical) — process name in the curated list
(case-insensitive match on `name` + `.exe`), with cmdline secondaries:
`rclone.*(:\w+:|--config|\bcopy\b.*-q)`, `ngrok(\.exe)?\s+(tcp|http)`. Service-name
variant for installed RMM (auditor already diffs services; add name-list check to the
service diff for a named alert instead of generic `PERS-SERVICE`).

## 4. AD domain persistence channels — walkthrough: `ad-domain-persistence/`

**What:** Shadow Credentials (5136 on `msDS-KeyCredentialLink`), RBCD (5136 +
4769-S4U), DCSync (4662 replication GUIDs from non-DC accounts), ADCS ESC1/golden certs.

**Implement:** three new entries in `eventlog.py CHANNELS` with tight XPATH pre-filters
(essential — these channels are high-volume on a DC):
- Security 5136 filtered server-side: `...and (EventData/Data[@Name='AttributeLDAPDisplayName']="msDS-KeyCredentialLink" or ...="msDS-AllowedToActOnBehalfOfOtherIdentity")`
- Security 4662 filtered to the replication GUIDs `1131f6aa|1131f6ad|89e95b76` — alert
  only when the subject account is NOT a DC (`$`-suffixed machine accounts) and not the
  DC's own replication partners ([detection detail](https://blog.blacklanternsecurity.com/p/detecting-dcsync))
- Security 4769 with RC4 (`0x17`) — the Kerberoast half from the earlier round; same
  channel add
All are log-source-only: no host sensor changes needed, but they only work where the
DC's Security log is reachable (centralized forwarding at CCDC).

## 5. Advanced injection (Mockingjay / module stomping / TpAllocWork) — walkthrough: `evasion-advanced-injection/`

**What:** RWX-section abuse in signed DLLs (no Virtual* APIs), overwriting a loaded
signed DLL's `.text` (module looks legitimate in memory), thread-pool callback execution
(no thread creation). References in the walkthrough.

**Implement (staged):**
- Now: nothing — document as Sysmon-gated.
- With Sysmon: EID 8/10 rules cover some variants; TpAllocWork needs ETW
  `Microsoft-Windows-ThreadPool-*`-style providers or hook telemetry.
- Memory-scanner design requirements (build these in from day one):
  1. **Never trust module identity** — for every loaded module, re-hash the on-disk file
     and compare (stomping-proof). Mismatch = critical.
  2. **Flag default-RWX sections with non-zero entropy** in any module (Mockingjay-proof).
  3. **Enumerate thread-pool work items** alongside thread start addresses
     (TpAllocWork-proof).
  4. Scan at sleep/wake transitions as already designed (sleep-obfuscation-proof).

## 6. Carried from the earlier 2026 round (CVE wave / BYOVD / patch audit) — proposed, not yet built

- **CodeIntegrity channel** (`Microsoft-Windows-CodeIntegrity/Operational`, events
  3033/3077 = blocked driver loads) — BYOVD visibility ([Ransomware ISAC](https://ransom-isac.org/blog/analysing-and-detecting-byovd/)).
- **`PROC-SUDDEN-SYSTEM`** — WMI poll gains owner info (GetOwner); flag SYSTEM processes
  whose parent is a user-session process = the usermode-visible output of the kernel-CVE
  wave (CLFS/DWM/Defender-engine privesc — see `advanced-evasion-test-catalog.md` sources).
- **Patch-level exposure audit** — record OS build + QFE list; alert against a KEV-derived
  list of actively-exploited privesc CVEs ([CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)).
- **EFI/BCD staging watch** — auditor walk of the EFI System Partition + BCD store mtime
  (bootkit staging is visible from Windows; firmware itself is out of scope).

## Sources (2026 tradecraft rounds)

Dead drop: T1102.001 + Drokbk/C2Looper/Socket/SOC-Prime-Telegram/Cycraft links above.
SSH: CISA AA24-109A, Intrinsec, Maxwell CTI, Splunk netsh.
RMM/egress: Huntress, CISA, LOLRMM, Intel471.
AD: Elad Shamir, SwolfSec, Black Lantern, Elastic, Unit42, Certipy.
Injection: SecurityJoes, ired.team, naksyn, Tartarus, r-tec.
Kernel/BYOVD/patch: SOC Prime (CVE-2025-62221), ZeroPath (CLFS), Kudelski (RoguePlanet),
Ransomware ISAC, CISA KEV.
