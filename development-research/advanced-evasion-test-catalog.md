# Advanced Evasion Technique Test Catalog — Manual Tests Against the CCDC EDR

> **Purpose:** Research-grounded catalog of current red-team evasion techniques, each with a
> manual test you can run on this machine to see what your EDR catches and — just as
> important — what it can't see yet. Companion to `realm-c2-killchain-emulation-runbook.md`
> (which covers delivery, sideloading, hollowing, persistence).
>
> **Know your sensor set before reading the results:** your EDR today = WMI process polling
> + kernel-fed Security 4688/System 7045/PowerShell 4104 event logs + on-write/interval file
> scanning + persistence auditor + netstat beacon cadence. It has **no userland API hooks,
> no module-load telemetry, no memory scanning, and no Sysmon** (the eventlog sensor will
> consume Sysmon events if you install it — that single install unlocks several detections
> marked GAP below).

Priority ordering: ⚡ quick win (minutes, native tooling) · 🔧 needs a build or Atomic Red
Team · 🌑 primarily exposes a gap to file as backlog.

---

## 1. Defense-evasion against the platform (test these first — highest CCDC likelihood)

### 1.1 AMSI bypass ⚡

**Technique:** patch `amsi.dll!AmsiScanBuffer` in-memory or force `amsiInitFailed` so
PowerShell script content is never scanned. The [Lumu Defender-evading case
study](https://lumu.io/resources/edr-evasion-in-action-evading-microsoft-defender/) walks
the classic flow.

**Manual test** (from an elevated PowerShell — this is the well-known public one-liner,
benign on its own):

```powershell
# amsiInitFailed variant (the string your PROC-NOPS-AMSI rule knows)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
  .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

Then run any suspicious-looking string (`'Invoke-CCDCTest'`) to confirm AMSI is blind.

**Expected:** `PROC-NOPS-AMSI` fires **only if** the bypass rides the command line. This
one-liner runs *inside* a script block, so the cmdline rule won't see it — your real
tripwire is **PowerShell 4104 script-block logging**, which your eventlog sensor consumes:
the block text itself should appear as an event. Verify a 4104 event containing
`amsiInitFailed` arrived. If script-block logging isn't producing events, enable it:

```powershell
Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell -Name ScriptBlockLogging -Value 1
```

**Improvement to file:** a content rule over 4104 blocks (`amsiInitFailed|AmsiScanBuffer|
Net.WebClient.*DownloadString` patterns) instead of relying on command lines only.

### 1.2 Security-log clearing ⚡

**Manual test:** `wevtutil cl Security` (elevated).
**Expected:** `TAMPER-AUDIT` (critical) via event 1102 — but note the irony: the clear
removes evidence, and your alert is generated *from the 1102 record* which survives in the
System channel's clear-notification. Verify the alert actually raised; if the bookmark
swallowed it, that's a consumer bug.

### 1.3 Defender exclusion tampering ⚡

**Manual test:** `Add-MpPreference -ExclusionPath C:\Users\Public` (elevated).
**Expected:** `TAMPER-DEFENDER` (high) from the command line. Then remove it:
`Remove-MpPreference -ExclusionPath C:\Users\Public`. Also try
`Set-MpPreference -DisableRealtimeMonitoring $true` — currently **GAP**: no rule keys on
that cmdlet; add it to the same regex.

### 1.4 Timestomping 🌑 — T1070.006

**Manual test:**

```powershell
(GetItem C:\Users\Public\sysupd.exe).LastWriteTime = (Get-Date "2020-01-01")
```

**Expected:** nothing — you have no file-metadata telemetry. **GAP to file:** the signature
scanner caches by (size, mtime); timestomping to a *previous* mtime can also desync
rescans. Worth adding CreationTime≠LastWriteTime anomalies in user dirs to the auditor.

---

## 2. Process-injection family (T1055) — mostly Sysmon-gated

All of these are one `Invoke-AtomicTest` away if you [install Atomic Red
Team](https://github.com/redcanaryco/atomic-red-team); each lists the atomics and the
canonical detection (see the [Picus T1055.004
writeup](https://www.picussecurity.com/resource/blog/t1055-004-asynchronous-procedure-call)
for the Sysmon event mapping: **EID 8 CreateRemoteThread, EID 10 ProcessAccess, EID 25
ProcessTampering**).

| Technique | ATT&CK | Atomic test | What your EDR sees today | Canonical detection |
|---|---|---|---|---|
| APC injection 🔧 | T1055.004 | `Invoke-AtomicTest T1055.004` | PowerShell host process + encoded command if the atomic uses one; the injected victim (usually `notepad`/`ProcessHollowing` demo target) appears in the process table | Sysmon EID 8/10 |
| Thread hijacking 🔧 | T1055.003 | `Invoke-AtomicTest T1055.003` | Same — process telemetry only | Sysmon EID 8 + thread start-address |
| PE injection 🔧 | T1055.002 | atomics available | same | Sysmon EID 8/10 |
| Section-view injection 🔧 | T1055.011 | atomics available | same | Sysmon EID 10 on section handles |
| Process hollowing 🔧 | T1055.012 | covered in runbook §4.7 | `PROC-SUSP-PARENT` if parent pair matches | Sysmon EID 25 |

**The pattern to internalize:** without Sysmon, injection is invisible to you at injection
time — your detections are the *edges* (suspicious spawner command lines, user-writable
image paths, follow-on beaconing). Installing Sysmon with a SwiftOnSecurity-style config
and adding three rules over EID 8/10/25 to your eventlog sensor is the single highest-value
hour of detection work available to you.

---

## 3. Execution-path evasion (script-interpreter avoidance)

### 3.1 PowerShell-less .NET (`InstallUtil` / `regsvcs`) 🔧 — T1218.003

**Technique:** run a .NET assembly through a signed LOLBIN interpreter — no PowerShell
logging (4104), no PS command line, AMSI not in the path. Favorite of real red teams.

**Manual test:** any small .NET tool works (e.g., compile a benign "writes a marker file"
exe with `csc` if the .NET SDK is present, or use Rubeus-style tooling you may already have
in the lab):

```powershell
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false `
  /U C:\Users\Public\markertest.exe
```

**Expected:** `EVT-4688-TEMP` fires (path under \Users\Public) — that's your only tripwire.
**Improvement to file:** add a `PROC-LOLBIN-DOTNET` rule: command line matching
`(installutil|regsvcs|regasm|msbuild|dotnet).*(\Users\|\Temp\)` with an assembly argument.

### 3.2 Callback-based execution 🌑

**Technique:** shellcode executed via `EnumWindows`/`CertEnumSystemStore`-style API callbacks
— no thread creation, no remote writes, defeats CreateRemoteThread-centric detection
(popularized in 2024–26 loaders; see the [RingSafe 2026 evasion
survey](https://ringsafe.in/edr-bypass-techniques-2026-endpoint-evasion/)).
**Manual test:** needs a compiled benign demo (Rust/C, same pattern as the runbook's proxy
DLL — `EnumWindows` with a callback that writes a marker). **Expected today:** the process
launch telemetry only. **GAP:** callback registration isn't visible to any current sensor;
ETW `Microsoft-Windows-Kernel-Callback` or a hooked callback API would be needed. File it.

### 3.3 Masquerading — fake system-binary name ⚡ — T1036.003

**Manual test:**

```powershell
Copy-Item C:\Windows\System32\cmd.exe C:\Users\Public\svchost.exe
& C:\Users\Public\svchost.exe /c ping -n 30 127.0.0.1
```

**Expected:** `EVT-4688-TEMP` (high) — a "svchost.exe" whose image path is not
`\System32\` is the textbook masquerade signal, and your rule catches it by *path*, which is
correct. **Improvement:** add a dedicated `PROC-MASQ` rule: process name ∈ {svchost,
lsass, csrss, winlogon, services} AND path not under `\Windows\` → critical, so it reads
clearly on the console instead of the generic temp-path rule.

---

## 4. Telemetry-blinding techniques (against hook-based EDRs — mostly N/A, verify why)

These are the headline techniques in the [Maveris red-team EDR
guide](https://medium.com/maverislabs/evading-the-watchful-eye-a-red-teamers-guide-to-edr-bypass-techniques-e989a6f6c4ac)
and [0xdbgman's EDR internals
reference](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/) — but they
attack *hook-based userland EDRs*. Your EDR hooks nothing in the classic sense:

| Technique | What it attacks | Effect on YOUR EDR |
|---|---|---|
| **Direct/indirect syscalls** (SysWhispers3) | userland ntdll hooks | None — you don't hook. Process/4688/network telemetry unaffected. Worth testing only after you add hooks; the future detection is stack-walk return-address validation (runbook §3.4 of the research guide) |
| **ntdll unhooking / re-mapping** | patched ntdll exports | None today. When you add hooks, this becomes your #1 threat — plan tamper checks on your own hook integrity from day one |
| **ETW patching** (`EtwEventWrite` patch) | user-mode ETW providers | Your detections ride the *kernel-fed* Security/System logs and the kernel ETW session, which userland code cannot patch. This is a genuine architectural strength of your current build — keep it as you evolve |
| **Hardware-breakpoint unhooking (Blindside-style, [Cymulate](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/)) | inline hooks | None today (no hooks). Note for the future hook design |

**Manual test that proves the point:** run any SysWhispers-based benign demo — your process
sensor and 4688 still see the process normally. The lesson for the roadmap: when you add
userland hooks, re-run this catalog; techniques in this section flip from N/A to critical.

### 4.1 BYOVD (bring-your-own-vulnerable-driver) 🌑 — T1553.002

Kernel-grounded attacks (kill EDR processes via an abused signed driver). **Do not test on
this box** — a successful BYOVD is a real kernel compromise, out of lab scope. Defender's
vulnerable-driver blocklist (`Microsoft-Windows-Windows Defender/Operational` events) is the
telemetry to consume; note it as coverage only.

---

## 5. Parent PID spoofing 🔧 — T1134 / T1055 adjacenct

**Technique:** create the implant process with `PROC_THREAD_ATTRIBUTE_PARENTSPOOFING` so it
lists e.g. `explorer.exe` or `svchost.exe` as parent, defeating parent-child anomaly rules.

**Manual test:** needs a tiny launcher (the attribute is one `UpdateProcThreadAttribute`
call; a 30-line C#/Rust PoC in the lab) that spawns your `sysupd.exe` with a spoofed PPID.
No dedicated atomic exists ([Red Canary notes](https://redcanary.com/blog/testing-and-validation/atomic-red-team/top-atomic-red-team-tests/) — typically custom tooling).

**Expected:** your process sensor trusts WMI's `ParentProcessId` — the spoofed parent is
what it records, so `PROC-SUSP-PARENT` can be evaded by choosing a benign fake parent.
**Detection that still holds:** the 4688 record's `Creator Process ID` is *also* spoofed
(the kernel reports the attribute), so the honest signal is **inconsistency**: a parent that
(1) exited before the child started, or (2) whose image would never spawn this child.
**Improvement to file:** on each new process, resolve the PPID — if dead or recycled, raise
`PROC-DEAD-PARENT` (high). That single check defeats most PPID spoofing at your sensor
fidelity.

---

## 6. Quick-win test session plan (30 minutes, no builds)

1. §1.1 AMSI one-liner → check 4104 arrived; file the content-rule improvement
2. §1.2 `wevtutil cl Security` → `TAMPER-AUDIT` must fire
3. §1.3 `Add-MpPreference -ExclusionPath` → `TAMPER-DEFENDER` must fire
4. §3.3 fake `svchost.exe` in Public → `EVT-4688-TEMP` fires; add the named
   `PROC-MASQ` rule afterwards
5. Re-run the realm runbook's Phase 6 scoreboard to confirm no regressions

## 7. Backlog register (in priority order after the above)

1. **Sysmon install + EID 8/10/25 rules** — unlocks the entire injection family (§2)
2. **`PROC-DEAD-PARENT`** — PPID-spoofing consistency check (§5)
3. **4104 content rules** — AMSI/cradle patterns inside script blocks (§1.1)
4. **`PROC-LOLBIN-DOTNET` + `PROC-MASQ` named rules** (§3.1, §3.3)
5. **Module-load telemetry** — unsigned DLL in signed process (runbook §4.6's gap)
6. **tcp_bind listener sweep + DNS/ICMP transports** (runbook §4.5 / build guide §7)
7. **Memory scanning at sleep/wake** — only becomes relevant vs sleep-obfuscating implants
   (Havoc/CS), not imix

## Sources

- [RingSafe — EDR Bypass Techniques 2026](https://ringsafe.in/edr-bypass-techniques-2026-endpoint-evasion/)
- [Maveris Labs — A Red Teamer's Guide to EDR Bypass](https://medium.com/maverislabs/evading-the-watchful-eye-a-red-teamers-guide-to-edr-bypass-techniques-e989a6f6c4ac)
- [0xdbgman — EDR Tradecraft: Internals, Detection, Evasion](https://0xdbgman.github.io/posts/edr-internals-research-and-bypass/)
- [Lumu — EDR Evasion in Action: Evading Defender](https://lumu.io/resources/edr-evasion-in-action-evading-microsoft-defender/)
- [Cymulate — Blindside: hardware-breakpoint EDR evasion](https://cymulate.com/blog/blindside-a-new-technique-for-edr-evasion-with-hardware-breakpoints/)
- [Atomic Red Team T1055.004 (APC)](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1055.004/T1055.004.md) · [T1055 index](https://www.atomicredteam.io/docs/atomics/T1055)
- [Picus — T1055.004 detection mapping](https://www.picussecurity.com/resource/blog/t1055-004-asynchronous-procedure-call)
- [Red Canary — top atomic tests](https://redcanary.com/blog/testing-and-validation/atomic-red-team/top-atomic-red-team-tests/)
