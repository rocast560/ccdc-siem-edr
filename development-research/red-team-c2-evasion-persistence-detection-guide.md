# Red Team C2, Evasion & Persistence — A Defender's Research Guide for CCDC EDR Development

> **Purpose:** You are building an EDR to defend against CCDC-style red teams. This document maps what the red team actually runs — Havoc, Cobalt Strike, Mythic, and Realm C2, plus the persistence and userland/kernel evasion tricks common to all of them — to concrete things your EDR should hook, inspect, alert on, and be tested against.
>
> **Scope note:** Everything here is detection-oriented. Where techniques are described, they're described at the fidelity a detector author needs (what memory looks like, what API sequence fires, what artifact lands on disk) — not as an operating manual.

---

## 1. How CCDC Red Teams Actually Operate (Design Your EDR Around This)

Before per-framework detail, understand the engagement model — it dictates what you'll see:

- **Initial access is rarely exotic.** CCDC red teams typically enter through exposed services (unchanged default creds, unpatched web apps, SSH keys left in home directories, reused passwords), phishing drops, orVPN/jump hosts. The Cobalt Strike blog's own [National CCDC Red Team retrospective](https://www.cobaltstrike.com/blog/national-ccdc-red-team-fair-and-balanced) describes initial exploitation and **persistence as their primary job** — they expect to be evicted and re-establish footholds repeatedly.
- **They are loud on purpose early, quiet later.** Expect credential dumps, service creation, and scheduled tasks in the first hours. [Participant writeups (Jake Ginesin, 2024)](https://jakegines.in/blog/2024/ccdc/) and the [Uber red team retrospective](https://medium.com/uber-security-privacy/adventures-in-red-teaming-collegiate-cyber-defense-competition-cc415bac6ad) both describe red teams iterating on persistence faster than blue teams audit for it.
- **Speed matters more than fidelity.** Your EDR must catch the *second* implant minutes after the team wipes the first. Prioritize fast telemetry + clear incident payload (process, PID, parent, command line, target resource) over perfect classification.
- **Egress is often HTTPS to a single VPS.** DNS and ICMP tunnels appear at some regionals, but HTTP(S) C2 with jittered sleep dominates.
- **KnownCCDC red teamer folklore (Reddit, r/ccdc and the [David Cowen AMA](https://www.reddit.com/r/IAmA/comments/17hyds/i_am_david_cowen_the_red_team_captain_for_the/)):** persistence in cron, systemd units, SSH `authorized_keys`, new users added to sudoers, webshells dropped into existing web roots, and repeated re-exploitation of the same unpatched service after cleanup. Linux boxes are primary targets; assume Windows is in scope at nationals-level events.

**Design consequence:** the highest-value detections are (1) persistence-artifact monitoring, (2) process/API telemetry for injection and credential access, (3) beacon-like network behavior detection. That's the spine of this guide.

---

## 2. Cross-Cutting Technique Matrix (Test These Regardless of Framework)

Map everything to MITRE ATT&CK; build one test per cell using Atomic Red Team + the framework's own agent as the "live fire" test.

### 2.1 Execution / Injection (userland)

| Technique | What fires (your telemetry) | Where to hook/inspect |
|---|---|---|
| Classic `CreateRemoteThread` injection | `OpenProcess` w/ `PROCESS_VM_WRITE\|PROCESS_VM_OPERATION\|PROCESS_CREATE_THREAD` from a non-debugger process, remote `WriteProcessMemory`, thread start outside image | ETW `Thread` provider (StartAddr), kernel callbacks impossible in userland — use ETW + API interception |
| Process hollowing | SUSPENDED process creation followed by `NtUnmapViewOfSection`/`WriteProcessMemory` on its primary image region, then resume; final memory has no backing image on disk | Image-load ETW events vs. executable sections (RWX private memory with no file mapping) |
| `sRDI` / reflective DLL injection | `LoadLibrary` never fires; allocation of RWX via `VirtualAllocExNuma`/`NtAllocateVirtualMemory`, section objects w/o file backing | `Image` events absent where executable code runs — memory scanning (below) |
| **Unhooking / direct & indirect syscalls** (HellsGate, HalosGate, SysWhispers2/3) | Absence of `ntdll.dll` API calls in your hook layer while syscalls still happen (`ETW` still sees the syscall via kernel if you have a driver; userland-only EDR sees *nothing* on hooked APIs) | ETW syscall-style providers, `NtTraceControl` tamper detection, ntdll re-mapping from disk (watch for section created on `\Device\HarddiskVolume*\Windows\System32\ntdll.dll` by a non-loader process) |
| **EarlyBird injection** (common with Mythic/Apollo) | Process created suspended with `EXTENDED_STARTUPINFO_PRESENT` + `PROC_THREAD_ATTRIBUTE_PARENTSPOOFING`, `QueueUserAPC` into the not-yet-started main thread before resume | ETW `Process` + `Thread` correlation; flag APC-into-fresh-process |
| APC injection (queue to alertable thread) | `QueueUserAPC(2/3)` targeting threads in other processes; alertable waits | ETW Thread/APC; stack scanning for `ntdll!KiUserApcDispatcher` |
| **Callback-based execution** (popular in 2024–26 loaders) | Enum* / *Notify* APIs (e.g., `EnumFonts`, `CertEnumSystemStore`) executing shellcode via callback pointer | Hook the callback-registering APIs and validate callback target is a legitimate image |
| **Thread & stack spoofing** (DInvoke, ThreadStackSpoof, return-address spoofing in Havoc Demon) | `RIP`/return addresses pointing into RWX private memory or into `RtlExitUserThread` instead of the real caller chain | Periodic thread stack walks (see §3.4) |
| **Inline .NET execution** (`installutil.exe`, `regsvcs`, dotnet gadget chains) | LOLBIN executing with no matching on-disk assembly loaded from user-writable path | Process command line + image path allow-listing |

### 2.2 Credential access

- **LSASS access patterns:** `OpenProcess` on `lsass.exe` from non-protected processes; `MiniDumpWriteDump` targeting LSASS handle; `comsvcs.dll!MiniDump`; `Out-Minidump`; `Handle` duplication of LSASS. CCDC red teams *will* run this — detect via handle-inspection (NtQuerySystemInformation `SystemHandleInformation` sweeps looking for processes holding LSASS handles with `PROCESS_VM_READ`).
- **Registry SAM/SYSTEM/SECURITY reads:** `reg save HKLM\SAM`, `reg save HKLM\SYSTEM`, `hive` shadow-copy style reads, `SaveRegistryHive`. Alert on `RegSaveKey`/`NtSaveKey` on HKLM hives from any non-system process.
- **DPAPI & browser vaults:** `CryptUnprotectData` volume from unusual parents (credential harvesting via Chromium `Local State`).
- **Kerberos ticket ops** (Rubeus-style): `LsaCallAuthenticationPackage` with `KerbRetrieveTicketMessage` (Kerberoasting) — request encryption type `RC4 (0x17)` from 468-style Windows event `4769` is your SIEM-side catch; EDR-side, flag any process requesting service tickets in RC4.

### 2.3 Persistence — the full CCDC sweep

Build a **persistence auditor** that enumerates all of these on a schedule and diffs against a baseline snapshot taken at competition start:

**Windows:**
- Registry run keys / `RunOnce` (`HKCU\...\Run`, `HKLM\...\Run`, `Wow6432Node`), `Image File Execution Options` debuggers, `AppInit_DLLs`, `Winlogon` shell/Userinit, `PrintMonitors`, `ShellExecuteHooks`
- Scheduled tasks (`schtasks` / `Register-ScheduledTask` / Task Scheduler XML in `C:\Windows\System32\Tasks`); watch **task creation events 4698/4702** and any task whose action runs from a user-writable path or with odd args
- Services (`sc create`, `New-Service`, services with `binPath` pointing to user directories or `cmd.exe /c`); events **7045/7040**
- WMI event subscriptions (`__EventFilter` / `__CommandLineEventConsumer` / `__FilterToConsumerBinding`) — extremely common at CCDC; enumerate and diff
- Startup folder `.lnk`/`.bat`; COM object hijacks (`HKCU\Software\Classes\CLSID` shadowing HKLM); `.NET` CLR profilers / AppDomainManager hijacks (`COR_ENABLE_PROFILING` env)
- DLL search-order hijacks of ubiquitous services (Point-and-Print, `RTUtils`, printer spooler); new DLLs in `System32` are a high-signal diff
- New local users / added to Administrators (events **4720/4722/4732**), Golden Sudo (modified `Administrators` group), sticky keys replacement (`sethc.exe` hash swap)
- BitLocker/WDAC tampering, Defender exclusions added (`Add-MpPreference -ExclusionPath`), AMSI provider tampering

**Linux (most CCDC hosts — prioritize this):**
- cron (`/etc/cron.d`, per-user `crontab -l`, `at` jobs)
- systemd units/timers in `/etc/systemd/system`, user units in `~/.config/systemd/user`
- `~/.ssh/authorized_keys` changes (any new key after T0 baseline = red alert)
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/` diffs; UID-0 duplicates; new sudoers entries
- shell rc files (`~/.bashrc`, `/etc/profile.d`), `/etc/rc.local`, udev rules, `LD_PRELOAD` in `/etc/ld.so.preload` (rootkit-style hooking — a CCDC favorite)
- systemd unit `Exec` paths pointing into `/tmp`, `/dev/shm`, or `/home`
- webshells in web roots: detect via **new files with PHP/JSP `eval`/`system`/`Runtime.exec`/`assert` patterns** + file-write events from the web-server process
- SUID binaries created, capabilities (`setcap cap_setuid+ep`) granted
- SSH `authorized_keys` with attacker-controlled `command=`/`from=` forced-command fields
- systemd "generator" dirs, `~/.config/autostart` on desktop environments

**Test procedure for every item:** take baseline → plant artifact with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) / [Prefetch](Empire-style) → verify your EDR surfaces it within one audit cycle → verify the alert names the exact artifact and path.

### 2.4 Defense evasion specific to EDRs (what they'll do to *you*)

Assume a competent CCDC red team will try to kill or blind your sensors. Build tamper detection for:

- **Process kill / service stop of your agent** — watchdog process pair, driver-protected process if possible
- **ETW patching** — patching `EtwEventWrite` in-memory; detect by ntdll code-integrity checks on your own telemetry path
- **AMSI bypass** — the classic `AmsiScanBuffer` patch (`\x72` byte flip) or forcing `amsiInitFailed`; detect memory writes to `amsi.dll` text section
- **Callback removal / driver unloads** — unhooking kernel notify callbacks (requires admin + driver); userland EDR can only detect the *effects* (sudden telemetry gaps) — build **heartbeat + telemetry-gap detection into your SIEM**, not just the agent
- **Uninstallation with cached credentials** — protect your uninstall path with a random per-install token
- **Blocklist tampering** — config file edits; sign or checksum your config
- **Living in signed, allow-listed processes** — browsers, Teams, notepad++ updater abuse (DLL side-loading); enumerate side-loadable signed binaries on your gold image and pre-populate protections

---

## 3. Framework-by-Framework Playbook

### 3.1 Havoc C2 (Demon agent) — expect this at every CCDC

Havoc is free, modern, and the most common framework in student/pro red team arsenals. Its Demon agent is *designed* against EDR:

**What the red team configures:**
- **Indirect syscalls + sleep obfuscation + return-address spoofing** as the default evasion stack — see the [Red Secure Tech guide](https://www.redsecuretech.co.uk/blog/post/havoc-c2-sleep-obfuscation-return-address-spoofing-guide/1164) and [SonicWall's tracking of Havoc campaigns](https://www.sonicwall.com/blog/tracking-havoc-malware-activity-and-evasion-techniques). Demon encrypts its memory on every sleep (`Ekko`/`Zilean`-style sleep mask via `NtSetTimerResolution`/`RtlCreateTimer` tricks or `SetWaitableTimer` APC callbacks), so a scan at the wrong moment sees only ciphertext.
- **Injection options:** shellcode injection into `explorer.exe`/`spoolsv.exe`, DLL injection, spinlock thread hijacking; Demon can also run **module-less** (no reflective DLL on disk) with `.dll`/`.exe`/shellcode output wrapped in custom loaders (see [this AV/EDR bypass walkthrough](https://medium.com/@sam.rothlisberger/havoc-c2-with-av-edr-bypass-methods-in-2024-part-1-733d423fc67b)).
- **C2 profiles:** HTTPS with malleable-looking headers, SMB pipes for lateral pivoting.

**Your detection program for Havoc:**
1. **Memory scanning timing:** scan on *transitions*, not intervals — hook the sleep-enabling APIs (`WaitForSingleObjectEx`, `SleepEx`, `NtDelayExecution`) from your injection into the process, and scan immediately at wake. This defeats sleep encryption because the beacon must decrypt *before* executing. This is the single most important capability; read [Binary Defense's sleep obfuscation analysis](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation) for how each variant (Ekko, Foliage, Nighthawk-style) leaves different timer/APC signatures — those signatures themselves (e.g., `CreateTimerQueueTimer` with `EXECUTEINTIMERTHREAD` from unexpected contexts) are detections.
2. **Sleep-crypto artifacts:** Demon's sleep encryption leaves characteristic XOR/RC4-keyed regions adjacent to a plaintext sleep mask stub; hunt for private RWX regions whose entropy flips between scans.
3. **Indirect syscall artifact:** syscall instruction executed from a stub *outside* ntdll — detectable in userland via stack walk at `Nt`-API-enter hooks: if the return address doesn't fall inside `ntdll.dll`'s mapped range, it's an indirect/direct syscall stub. High-signal, low-FP.
4. **Config extraction for incident response:** Demon's embedded config (kill date, sleep, jitter, C2 hosts) sits encrypted near the implant's `.data`/PE-less blob — build a config scanner so once you find the implant you can extract its C2 list and block egress. The [Immersive Labs defensive operator's guide](https://www.immersivelabs.com/resources/c7-blog/havoc-c2-framework-a-defensive-operators-guide) is a good starting checklist.
5. **Network side:** jittered HTTPS beacons to a fresh VPS — detect via JA3/JA4 TLS fingerprinting (Demon's default TLS stack fingerprints are known and unlike browsers) and by beacon periodicity analysis in your SIEM (fixed + jitter interval = autocorrelation peak).

### 3.2 Cobalt Strike (Beacon) — the classic; still common at CCDC

**What the red team uses:** malleable C2 profiles, **Sleep Mask** (since 4.4; the 4.11 "evasive sleepmask" obfuscates Beacon, its heap allocations, and the mask itself — read the [official 4.11 post](https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping) and [4.10's BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-4-10-through-the-beacongate), which lets Beacon intercept its own API calls through a custom Sleep Mask), BOFs (beacon object files) for file-less post-ex, and spawn-and-syscall injection (`spawn` + `inject` into `rundll32`/`dllhost`).

**Detection program:**
1. **Named pipes:** Beacon's SMB mode uses default pipe names (`msagent_*`, postex pipe prefixes). Enumerate pipes per process; flag any process hosting a pipe whose name matches known Beacon defaults or who's *not* a legit pipe server. This is cheap and catches lazy operators.
2. **Sleep behavior:** Beacon sleep-masked memory still shows the classic pattern — a thread waiting on `SleepEx`/timer with its stack pointing into private memory. Thread-stack-walk at wake, same as Havoc.
3. **Beacon config extraction:** mature tooling exists (beacon-config parsers); pipe recovered memory through it to get C2s, sleep, watermark. Watermark is often used by CCDC red teams to tag teams — useful attribution.
4. **Malleable profile anomalies:** profiles staging via HTTP `GET` with odd URI grammar; detect stager requests by URI entropy and by `Mozilla/4.0`-style legacy UAs on modern OS builds.
5. **BOF execution:** BOFs run shellcode-mode, no `LoadLibrary` of their dependencies — syscall-density anomaly detection; short bursts of VirtualAlloc/VirtualProtect/VirtualFree triads in a row.
6. **Spawn hierarchy:** `rundll32.exe` spawned by your monitoring agent's target processes with no DLL arg; parent-child anomaly detection (`spoolsv.exe → rundll32.exe`, `explorer.exe → rundll32.exe` with no args) remains highly effective at CCDC skill levels.
7. **Public detection corpus:** the [Soteria "Evading Windows Defender with Cobalt Strike and Detecting the Undetected" post](https://blog.soteria.io/evading-windows-defender-with-cobalt-strike-and-detecting-the-undetected-5d41b566b347) walks the same attack/detect loop from the defender's side — use it as a lab syllabus.

### 3.3 Mythic — modular, multi-agent, web-tech agents

Mythic is a Dockerized platform with swappable agents; at CCDC expect **Apollo** (.NET/Windows), **Poseidon** (Go/cross-platform — *very* common against Linux CCDC hosts), and **Medusa** (Python). See [Team Cymru's defender-focused Mythic case study](https://www.team-cymru.com/post/mythic-case-study-assessing-common-offensive-security-tools) for a full assessment.

**Detection program:**
1. **.NET tradecraft (Apollo):** assemblies loaded via `Assembly.Load` from byte arrays — no file on disk. Hook/reflector over `System.Reflection.Assembly` loads (via .NET ETW provider `Microsoft-Windows-DotNETRuntime` — keyword `Loader` + `Jit` events give assembly names even when file-less). This is your strongest anti-.NET tool and catches PowerShell-less .NET execution everywhere. Also: `Assembly.Load` from a process that's not `dotnet.exe`/IIS/SQL = high signal.
2. **PowerShell-less PowerShell (System.Management.Automation) loading** — detect via the .NET assembly name appearing in Loader events.
3. **Go tradecraft (Poseidon on your Linux hosts):** large static Go binaries; detect via file entropy, Go-buildinfo strings (often present even in "obfuscated" builds — `Go buildinf:` magic), and network beaconing periodicity. For Linux EDR coverage: auditd/inotify-based telemetry on `/tmp`, `~/.config`, cron paths, systemd paths.
4. **Mythic task features:** Apollo supports **EarlyBird APC injection** — see §2.1 telemetry row; Mythic agents also do token manipulation (`run` as another user via stolen token) — flag `DuplicateTokenEx`/`CreateProcessWithTokenW` from non-Lsass parents.
5. **Jitter profiles & egress:** Mythic's HTTP profiles use random or configured jitter — SIEM-side periodicity detection with jitter tolerance (±30%) around common sleep values (30s, 60s, 300s).
6. **Mythic's web panel itself:** if the red team fat-fingers and exposes their Mythic UI, [hunt.io's C2 panel hunting guide](https://hunt.io/blog/hunting-c2-panels-beginners-guide) documents default paths/fingerprints (e.g., Mythic's `/new` login page) — scan your competition egress/host inventory for these.
7. **Egress webshell pivot pattern:** the [Netwitness webshell→Mythic walkthrough](https://community.netwitness.com/s/article/From-Webshell-to-C2-The-Evolution-of-Post-Exploitation-and-Covert-Operations) shows the typical chain: webshell in web root → stager → Poseidon/Apollo. Your webroot file-integrity monitoring (§2.3) is the tripwire.

### 3.4 Realm C2 (spellshift/realm) — the Rust-based cross-platform up-and-comer

[Realm (GitHub)](https://github.com/spellshift/realm) is Meta-maintained-ish (originally Facebook/Meta red team tooling), Rust-based, with an **Ether**-style Windows agent supporting userland syscall-only execution. Docs/wiki detail: [Realm wiki](https://github.com/spellshift/realm/wiki).

**Detection program (less public detection corpus — derive your own):**
1. **Rust binary fingerprinting:** Rust implants have recognizable standard-library patterns; build YARA over common Rust runtime strings/imports (e.g., `rust_begin_unwind`, panic message formatting strings) combined with no legitimate signer. Low volume of Rust unsigned binaries on CCDC hosts = high-signal.
2. **Userland syscall evasion (Ether-style):** same indirect-syscall stack-walk detection as Havoc — return address outside ntdll at syscall-enter.
3. **Cross-platform agent:** Realm runs on Linux/macOS too — same Go-style binary anomaly heuristics (entropy, build strings, stripped vs. dynamic linking ratio) apply.
4. **File-based config & inject:** Realm's Implant exports/inject options use conventional VirtualAllocEx/WriteProcessMemory — classic hook detection works; test it.
5. **No public "defender's guide" exists** — build your own lab: compile Realm from source (it's open), generate a payload, exercise each agent command, and record your EDR telemetry into a regression suite. This doubles as your golden test corpus.

---

## 4. EDR Capability Checklist (What To Build, In Priority Order)

| # | Capability | Catches | Build notes |
|---|---|---|---|
| 1 | **ETW telemetry pipeline** (Process, Thread, Image, Net, DotNETRuntime) | spawn/inject/assembly/file-less .NET | `StartTrace` w/ `EVENT_ENABLE_PROPERTY_ENABLE_KEYWORD_...`; watch for `NtTraceControl` patch attempts against your session |
| 2 | **API hook DLL injected into processes** (userland hooks on `VirtualAlloc*`, `WriteProcessMemory`, `CreateRemoteThread(Ex)`, `QueueUserAPC*`, `OpenProcess`, `Nt*` variants) | injection, LSASS access, unhooking attempts | inline hooks are detectable/tamperable — use them for *telemetry*, verify with ETW, don't trust for enforcement |
| 3 | **Memory scanning at sleep/wake transitions** (§3.1.1) | all sleep-masked implants (Havoc, CS 4.x, Realm) | inject a small watcher thread or hook sleep APIs; scan only on wake to control CPU |
| 4 | **Thread stack walking** (return-address validation against module maps) | indirect syscalls, stack/return-address spoofing | `RtlCaptureStackBackTrace` at hook-enter, verify frames map to signed images |
| 5 | **Persistence auditor (baseline + diff)** for §2.3 artifact inventory | every CCDC persistence trick | This is your highest CCDC ROI — simple, reliable, framework-agnostic |
| 6 | **Handle table scanning** for LSASS-holding processes | mimikatz-class credential theft | `NtQuerySystemInformation(SystemHandleInformation)` sweep every N seconds |
| 7 | **YARA-scannable on-write file inspection** | dropped loaders, webshells, Rust/Go implants | scan on create/write via minifilter or ETW File IO |
| 8 | **Beacon network periodicity detection** (SIEM-side) | all C2 egress | autocorrelation of outbound per (src,dst,dstport) with jitter tolerance |
| 9 | **JA3/JA4 + HTTP fingerprinting on egress** | non-browser TLS stacks (Go/Rust/C++ C2) | needs SPAN/proxy integration — SIEM design question, not agent |
| 10 | **Tamper detection & watchdog** (§2.4) | kills/blinds of your own agent | heartbeat gaps visible in SIEM even if agent dies |
| 11 | **Linux sensor** (auditd + inotify on persistence paths) | cron/systemd/authorized_keys attacks | most CCDC hosts are Linux — don't build a Windows-only EDR |

---

## 5. Testing Methodology (Per Framework)

For each of Havoc / CS / Mythic / Realm, run the same lab loop:

1. **Stand up the framework** in an isolated VM lab against throwaway Windows 10/11 and Ubuntu targets running your EDR build.
2. **Execute its full command set** — generate every payload format, run every injection option, every persistence command.
3. **Record telemetry coverage:** for each agent action, does your EDR produce ≥1 event? Build a coverage matrix (rows = ATT&CK technique, cols = framework action, cells = detection ID).
4. **Evade yourself:** apply each framework's evasion options (sleep obfuscation on/off, syscalls direct/indirect, spoofing on/off, module stalwart off/on) and confirm *which specific detection* fails and why. Evasion toggles are your ablation tests.
5. **Regression corpus:** save malicious memory dumps, dropped files, and PCAPs; wire into CI so new EDR builds re-run detection on frozen artifacts.
6. **Time-to-detect:** CCDC is timed — measure seconds from artifact creation to console visibility and tune the audit interval accordingly.

Useful test accelerators: [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (technique-level), [Evolving Window's "EDR-Testing" repo style loadern](https://github.com/MD-SEC/Malware-Analysis-Tools) style loaders, and the [0xdbgman EDR internals reference](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/) for understanding how your own hooks will be attacked (read the evasion half as a threat model for your sensor).

---

## 6. Source Reading List

**Havoc / Demon:**
- [Redfox Sec — Havoc C2 Complete Guide](https://www.redfoxsec.com/blog/havoc-c2-complete-guide-for-red-teamers-installation-commands-and-operational-use)
- [Red Secure Tech — Sleep Obfuscation & Return Address Spoofing in Havoc](https://www.redsecuretech.co.uk/blog/post/havoc-c2-sleep-obfuscation-return-address-spoofing-guide/1164)
- [SonicWall — Tracking Havoc Malware Activity and Evasion Techniques](https://www.sonicwall.com/blog/tracking-havoc-malware-activity-and-evasion-techniques)
- [Binary Defense — Understanding Sleep Obfuscation](https://binarydefense.com/resources/blog/understanding-sleep-obfuscation)
- [Immersive Labs — Havoc: A Defensive Operator's Guide](https://www.immersivelabs.com/resources/c7-blog/havoc-c2-framework-a-defensive-operators-guide)
- [Huntress — Fake Tech Support Delivering Havoc C2](https://www.huntress.com/blog/fake-tech-support-havoc-command-control)
- [Havoc official docs — Demon agent](https://havocframework.com/docs/agent)

**Cobalt Strike:**
- [Cobalt Strike 4.11 — Sleepmask](https://www.cobaltstrike.com/blog/cobalt-strike-411-shh-beacon-is-sleeping) / [4.10 — BeaconGate](https://www.cobaltstrike.com/blog/cobalt-strike-4-10-through-the-beacongate)
- [Soteria — Evading Defender with CS and Detecting the Undetected](https://blog.soteria.io/evading-windows-defender-with-cobalt-strike-and-detecting-the-undetected-5d41b566b347)
- [White Knight Labs — CS Profiles for EDR Evasion](https://whiteknightlabs.com/2025/05/19/harnessing-the-power-of-cobalt-strike-profiles-for-edr-evasion-part-2/)
- [Cobalt Strike — National CCDC Red Team](https://www.cobaltstrike.com/blog/national-ccdc-red-team-fair-and-balanced)

**Mythic:**
- [Team Cymru — Mythic Case Study (defender-focused)](https://www.team-cymru.com/post/mythic-case-study-assessing-common-offensive-security-tools)
- [Netwitness — From Webshell to C2](https://community.netwitness.com/s/article/From-Webshell-to-C2-The-Evolution-of-Post-Exploitation-and-Covert-Operations)
- [hunt.io — Hunting C2 Panels](https://hunt.io/blog/hunting-c2-panels-beginners-guide)
- [xbz0n — Mythic with EarlyBird injection](https://xbz0n.sh/blog/mythic-c2-early-bird-defender-evasion)

**Realm:**
- [Realm on GitHub](https://github.com/spellshift/realm)

**CCDC / general:**
- [Jake Ginesin — CCDC participant writeup (2024)](https://jakegines.in/blog/2024/ccdc/)
- [Uber Security — Red Teaming CCDC](https://medium.com/uber-security-privacy/adventures-in-red-teaming-collegiate-cyber-defense-competition-cc415bac6ad)
- [David Cowen CCDC red team AMA (Reddit)](https://www.reddit.com/r/IAmA/comments/17hyds/i_am_david_cowen_the_red_team_captain_for_the/)
- [Red Canary Threat Detection Report — C2 Frameworks](https://redcanary.com/threat-detection-report/trends/c2-frameworks/)
- [Bishop Fox — Red Team Tools & C2 Frameworks 2025](https://bishopfox.com/blog/2025-red-team-tools-c2-frameworks-active-directory-network-exploitation)
- [0xdbgman — EDR Internals, Detection, Evasion](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)
- [r/redteamsec — C2 options discussion](https://www.reddit.com/r/redteamsec/comments/1lnntki/discussion_about_c2_options/)

**Reddit threads worth mining for search terms:** r/ccdc, r/redteamsec, r/cybersecurity blue-team threads on "CCDC red team persistence" — recurring techniques named there: `authorized_keys` implants, cron + systemd resurrection pairs, WMI subscriptions, scheduled task re-arming, webshell re-drops, SSH `ForceCommand` abuse, and red teams deliberately leaving decoy persistence to burn blue team time. Enumerate all of these in your auditor (§2.3).
