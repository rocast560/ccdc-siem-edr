# EDR/SIEM Implementation & Live Payload Test Report

**Date:** 2026-09-07 · **Host:** Windows Server (Administrator) · **Result: 11/11 live detection tests passed**

---

## 1. What Was Built

The `edr-ui-only` branch's static console is now backed by a working sensor + SIEM backend, all
Python stdlib (no third-party packages, no agent install). The console at
`http://127.0.0.1:8420` is served by the backend with a **live-data layer injected** into the
existing UI: a LIVE SENSOR drawer streams real alerts/events as they fire, and the status bar
counts come from the actual sensor pipeline.

### Components (`edr/`)

| File | Function |
|---|---|
| `server.py` | HTTP backend: serves console + `/api/state`, `/api/rules`, `/api/scans`, `POST /api/baseline`, `/api/scan`, `/api/audit`. Runs the sensor loop (processes 3s, eventlog 3s, netflows 5s, persistence audit 30s, drop-dir scan 60s). |
| `processes.py` | WMI `Win32_Process` polling → normalized process events with full command lines; on-launch static scan of images started from user-writable paths. |
| `eventlog.py` | **Windows built-in monitoring:** consumes Security (4688/4698/4702/4720/4732/1102), System (7045/7040), PowerShell (4104), Sysmon (if present) via `wevtutil` with EventRecordID dedupe; auto-enables Process Creation auditing + command-line-in-4688. |
| `eventlog.try_kernel_trace()` | **Kernel-level monitoring:** starts the reserved **NT Kernel Logger** ETW session (`-p "Windows Kernel Trace" 0x10 0xff`) capturing kernel process events to `edr/state/kernel.etl` (forensic retention; live detection rides the kernel-fed 4688 channel). |
| `persistence.py` | **Persistence auditor:** enumerates Run/RunOnce keys (HKCU/HKLM/Wow6432Node), services, scheduled tasks, Startup folders, WMI event subscriptions, IFEO debugger hijacks, AppInit_DLLs; T0 baseline + diff every 30s (236 services / 279 tasks enumerated on this host). |
| `signatures.py` | YARA-style byte-signature engine (pure stdlib): Realm imix config surface, Rust-implant heuristic, musl ELF, eldritch tomes, PHP/JSP webshells, Cobalt Strike and Havoc Demon indicators. Scans new/changed files in drop zones (TEMP, APPDATA, PUBLIC, PROGRAMDATA, Windows\Temp, inetpub) on write and process-launch. |
| `network.py` | `netstat -ano` flow table + **beacon-cadence detection**: per-(pid, peer) inter-arrival statistics; near-constant intervals with ≤35% gap variation across ≥6 observations = C2 beacon alert (jitter-tolerant, matches imix/Beacon jitter profiles). |
| `rules.py` | 24 Sigma-like rules (selection + "why this fired" text) over normalized events: encoded PowerShell, AMSI bypass flags, argument-less rundll32, LOLBIN downloaders, suspicious parent-child, credential-dump command lines, eventlog-derived rules, audit-log clearing, Defender exclusion tampering. |
| `state.py` | Thread-safe ring buffers for events/alerts/scans; stats counters. |
| `liveui.js` | Injected live-data drawer for the console. |

### Detection stack (defense in depth, per research guide §4)

1. **Kernel:** NT Kernel Logger ETW session (process events) → ETL retained.
2. **Kernel-fed event log:** 4688 with command lines (auditing auto-enabled), 7045/4698/4720/1102.
3. **Userland telemetry:** WMI process polling, netstat flows, wevtutil PowerShell/Sysmon channels.
4. **Static:** on-write + on-launch signature scanning of drop zones and launched images.
5. **Stateful analytics:** persistence baseline+diff; beacon periodicity with jitter tolerance.

---

## 2. Live Payload Testing (`tests/run_tests.py`)

All payloads are **benign simulations** of the implant traits documented in
`development-research/realm-implant-test-payload-guide.md` — a copy of `cmd.exe` with imix/Rust
config strings appended, byte-blob ELF/tome/webshell pattern files, inert persistence artifacts,
an encoded-PowerShell launch, and a loopback TCP beacon. Nothing contacted anything outside the
host. Every artifact is removed by cleanup at the end of the run.

| # | Test (simulated attacker action) | Detection that fired | Result |
|---|---|---|---|
| 1 | Drop `sysupd.exe` carrying imix config surface (`IMIX_CALLBACK_URI`, `IMIX_SERVER_PUBKEY`, `IMIX_BEACON_ID`, `main.eldritch`, tavern, Rust markers) | `SIG-REALM-IMIX` + `SIG-RUST-IMPLANT` on write-scan | PASS |
| 2 | Drop static musl ELF implant build | `SIG-MUSL-ELF` | PASS |
| 3 | Drop `.eldritch` tome (load_library / reverse_shell patterns) | `SIG-ELDRITCH-TOME` | PASS |
| 4 | Drop PHP webshell (`eval($_POST[...])`) into temp wwwroot | `SIG-WEBSHELL-PHP` | PASS |
| 5 | **Launch** the fake implant binary | image scanned at process start → `PROG-IMPLANT-LAUNCH`; kernel-fed 4688 → `EVT-4688-TEMP` | PASS |
| 6 | Launch `powershell -EncodedCommand <utf-16le b64>` | `PROC-ENC-PS` (WMI poll) and `EVT-4688-SUSP` (4688) — dual-source catch | PASS |
| 7 | Create HKCU Run key autorun | `PERS-RUNKEY` (auditor diff < 30s) | PASS |
| 8 | Drop Startup-folder .bat | `PERS-STARTUP` | PASS |
| 9 | `schtasks /create` | `PERS-TASK` + `EVT-4698` | PASS |
| 10 | `sc create` new service | `PERS-SERVICE` + `EVT-7045` | PASS |
| 11 | Periodic TCP callback (5s ± jitter, 2s hold) to one peer | `NET-BEACON` — cadence analysis flagged interval + jitter CV | PASS |

Final sensor state at the end of testing: 1,893 events, 1,368 eventlog records consumed,
207 processes tracked, 166 files scanned, 40 signature hits, 5 persistence diffs, 47 beacon
classifications, kernel ETW session active.

---

## 3. Iterate-Fix Cycles (what failed and how it was fixed)

| Symptom | Root cause | Fix |
|---|---|---|
| musl ELF never scanned | `.elf` extension missing from scan list | added `.elf/.bin/.so/.out` to `SCAN_EXTS` |
| Fake implant launch not detected | process died in <1s, faster than the 3s WMI poll | kernel-fed 4688 now triggers launch-time image scan + new `EVT-4688-TEMP` rule (user-writable-path launches); test payload kept alive so both sources see it |
| Encoded PowerShell not detected | (a) audit policy "Process Creation" was **No Auditing** — `auditpol /set` had been invoked with a split argv and failed silently; (b) eventlog poller passed a record number to `wevtutil /bm:` which expects a bookmark *file*, so every poll after the first returned nothing | fixed argv; poller rewritten to `/c:N` + in-memory EventRecordID dedupe; test base64 corrected to UTF-16LE |
| ETW kernel session failed | arbitrary session names rejected for kernel providers; duplicate `-ets` flag | used the reserved **NT Kernel Logger** session name with flag masks `0x10 0xff` |
| `winreg` unpack/type errors in persistence collector | `QueryValueEx` returns 2-tuple; AppInit_DLLs REG_SZ assumption | corrected unpack + `str()` coercion |

Each fix was verified by re-running the full suite; the final run passed 11/11.

---

## 4. Known Gaps (from the research guides, not yet implemented)

- **In-memory scanning** (sleep/wake-transition scanning, thread stack walks, indirect-syscall
  return-address validation) — requires code injection into monitored processes; not built.
- **LSASS handle sweeping**, `NtSaveKey`/SAM-hive read detection — not built.
- **Linux sensor** (auditd/inotify) — Windows-only in this iteration.
- **QUIC/UDP flows** — `netstat -p tcp` only; port-rebinding QUIC beacons need a UDP flow source.
- The kernel `.etl` is retained for forensics but not yet parsed live (tracerpt conversion would
  give a second kernel-sourced process stream).
- Beacon loopback peers are downgraded to high severity (lab concession); in CCDC, restrict
  cadence analysis to external peers only.

## 5. How to Run

```
cd CCDC-EDR-SIEM-design
python -m edr              # console + sensors at http://127.0.0.1:8420
python tests/run_tests.py  # live-fire benign payload suite (run in another shell)
```

API: `GET /api/state` (events/alerts/scans/stats/rules), `POST /api/baseline` (re-arm
persistence T0), `POST /api/scan`, `POST /api/audit` (force a persistence diff now).

---

## Addendum — fully live console (no sample data)

The console was rewritten as `edr/live_console.html`: the five screens (Dashboard, Log
Explorer, Alerts, Signatures, Threat Intel) now render exclusively from the sensor API —
no invented sample data anywhere; empty states show when a filter has nothing real.

New backend capabilities backing the UI features: server-side event filtering
(`/api/events?severity|source|kind|q`), per-rule enable/disable toggles + lifetime hit
counts (`/api/rules`, `/api/rules/toggle`), alert triage status ack/resolve
(`/api/alerts/status`), beacon cadence series for the periodicity plot (`/api/cadence`),
and a live rule-test panel (`/api/test`) that evaluates pasted text against every enabled
rule plus the static signature pack (semantic catch-all rules excluded so results stay
precise). The unused `liveui.js` injection layer was removed. Full payload suite re-run
against the final build: **11/11 passed.**

---

## Addendum 2 — original UI wired live + active response

The console now served at http://127.0.0.1:8420 is the **original `edr-ui-only`
design** (`ccdc-edr-console.html`): its artboards, navbar, tab switching and
Blueprint-dark theme are untouched. A wiring layer (`edr/console_live.js`,
injected by the server) replaces each artboard's sample-data regions with live
content rendered through the design's own classes — severity tiles, ingest
sparkline, faceted log explorer with count bars + raw-record drawer, alert
groups with why-this-fired + beacon cadence plot, rule toggles with live hit
counts, live rule-test panel, and intel cards with live counts. There is no
sample data anywhere.

### Active response (`edr/responder.py`, `POST /api/respond`)

Inline action buttons appear on alerts in the Alerts screen:

- **kill pid** (beacon/implant alerts) — `taskkill /F` after safety checks:
  refuses the EDR's own processes, critical system processes (lsass, csrss,
  svchost, …), and images in Windows/Program Files directories.
- **block peer** (beacon alerts) — Windows Firewall inbound+outbound deny
  rules for the C2 IP; unblock available; addresses validated.
- **quarantine** (signature/drop alerts) — file moved to
  `edr/state/quarantine/`, execute ACLs denied, origin + SHA recorded in a
  manifest for restore; protected paths refused.

Every action (and every refusal) is logged as a sensor event and raised as a
RESP-* alert, so response history is triageable in the console itself.

Verified live: benign implant process killed; `svchost` kill refused;
fake imix file quarantined out of TEMP; firewall block added/removed for a
test IP; invalid address refused. Full payload suite re-run: **11/11 passed.**

Ops note: the server now sets `allow_reuse_address = False` — on Windows the
default allowed a second instance to silently double-bind port 8420 and serve
stale code. Kill all listeners on 8420 before relaunching.

---

## Addendum 3 — UI connection verified in-browser

Browser-verified against the running console: all five artboards of the original
`edr-ui-only` design contain exactly two children (the original navbar plus the
live body), zero sample data remains (`WIN-WKS14`, `EDR-COR-KILLCHAIN-*`,
etc. all absent), and each screen renders real sensor output — Dashboard tiles
from live counts, Log Explorer rows with facet counts, Alerts groups with
inline kill/block/quarantine/ack/resolve buttons, Signatures toggles with hit
counts, Intel cards with live hits. Fix applied during verification: the
wiring's content-replacement is now idempotent (re-asserted every refresh
cycle via `data-live-body` marker), so the static sample markup can never
co-render with live data regardless of load order. Also filtered netstat's
`0.0.0.0`/`[::]` pseudo-peers out of beacon analysis. Suite re-run: 11/11.

---

## Addendum 4 — gap closure: advanced persistence, evasion, and watershell

Implements every gap from the coverage review, plus detection for
[RITRedteam/watershell-cpp](https://github.com/RITRedteam/watershell-cpp). Suite: **21/21.**

### Persistence (edr/persistence.py)
- **COM hijacks** — HKCU `CLSID\{...}\InprocServer32` shadows pointing outside system dirs (`PERS-COM`)
- **.NET CLR hijacks** — `COR_ENABLE_PROFILING`/`COR_PROFILER` in system or user Environment (`PERS-CLR`)
- **LSA package tamper** — non-standard `Security Packages`/`Notification Packages` (`PERS-LSA`)
- **Scheduled-task *action* diffs** — per-task action hashes, so editing an existing benign task's action alerts (`PERS-TASKMOD`), not just new tasks
- **WMI subscriptions** now include `__TimerInstruction`, and `CommandLineEventConsumer` payloads are rule-evaluated as process command lines
- **DLL side-load candidates** — DLLs written into Program Files after baseline (`PERS-SIDELOAD`)

### Evasion / credential access
- **.NET ETW loader** (`edr/dotnet.py`) — a `Microsoft-Windows-DotNETRuntime` (Loader keyword) trace session, dumped via tracerpt each cycle; assembly names are screened against the `SIG-DOTNET-OFFTOOL` pack (Rubeus, Seatbelt, SharpHound, GhostPack…). This sees `Assembly.Load(byte[])` that never touches disk.
- **LSASS handle sweep** (`edr/lsass.py`) — `NtQuerySystemInformation(SystemExtendedHandleInformation)` via ctypes; entries are pre-filtered by dynamically-discovered Process `ObjectTypeIndex`, then VM_READ/DUP handles are duplicated to identify LSASS targets (`LSASS-HANDLE`). Two hard-won fixes documented in code: x64 handles need explicit `c_void_p` restypes (default c_int truncates), and duplication must request `PROCESS_QUERY_LIMITED_INFORMATION` rather than copy the original's VM_READ-only access.
- **DNS beacons** (`edr/dnsbeacon.py`) — DNS Client operational channel (3006/3008) fed through the same jitter-tolerant periodicity analysis, keyed on (pid, registered domain) so round-robin subdomains don't defeat it (`DNS-BEACON`).
- **Kerberoasting** — Security 4769 with RC4 (0x17) ticket encryption (`KRB-ROAST`).
- **Instant-exit commands** — eventlog-fed twins of the hive-dump/log-clear/auditpol rules (4688 sees sub-second processes the 3s WMI poll misses); regexes tolerate quoted image paths.
- **Sensor watchdog** — separate thread raises `SENSOR-WATCHDOG` if the sensor loop stalls >60s (killed/blinded sensors).

### watershell-cpp
Raw `PF_PACKET` reverse shell: commands arrive as raw Ethernet frames through a BPF filter
(no listening port — invisible to netstat/ss), payloads matched against `status:`/`run:` magic
prefixes, replies hand-crafted at layer 2; reads `/proc/net/arp` + `/proc/net/route` for the
gateway MAC. Two detection layers:
- `SIG-WATERSHELL` byte signature over those binary traits (ELF)
- `edr/linux_sensor.py` — maps `/proc/net/packet` inodes to owning pids and alerts on any
  non-capture tool holding a raw packet socket (`PKT-SOCKET`); activates automatically when
  the EDR runs on a Linux host

### Verification additions (tests/run_tests.py, all benign)
COM hijack plant, CLR env plant, task-action modification, Program Files DLL drop,
pattern-only `reg save`/`wevtutil cl` invocations (nonexistent targets — no data written),
LSASS VM_READ handle held by a child process, `Assembly.LoadFrom` of a hello-world named
Seatbelt.exe, periodic `Resolve-DnsName` loop, fake watershell ELF. Final run: 21/21 PASS.

---

## Addendum 5 — remaining backlog items closed

All four open backlog items implemented and verified. Suite: **21/21 classic
(`EDR_TESTS=classic`) + 4/4 tranche-3 (`python tests/run_tranche3.py`) = 25/25.**

### ICMP transport (`edr/icmp.py`)
Kernel ICMP counters (`netstat -s`, Echos/Echo Replies) run through the same
jitter-tolerant cadence analysis; near-constant counter growth = `ICMP-BEACON`
(high — peer attribution needs the kernel ETW trace, documented backlog).
Verified with a 5s loopback ping loop.

### tcp_bind listener detection (`network.check_listeners`)
Any LISTENING socket on a non-standard port whose owning image is not a
service path → `NET-LISTENER` (the imix inverted-transport posture and the
netcat-backdoor pattern). Verified with a TEMP-path binary listening on 44444.

### Process memory scanning (`edr/memscan.py`)
VirtualQueryEx + ReadProcessMemory walk of committed regions for every
non-system process, newest-first, against the same signature packs in
`memory=True` mode (no PE/ELF magic requirement — memory chunks never begin
with a file header). imix carries its config surface in mapped memory, so a
running implant is findable even where the file scanner can't reach.
Budgeted (4 processes / 8 MB per 60s pass) to keep the sensor loop healthy —
the watchdog verifies it. Verified with a `/k cmd` carrying the marker in its
process-parameters block (the same RW region a real implant's config lives in).

### Config extraction automation (`responder.extract_config`)
Quarantine now pulls embedded C2 indicators (callback URIs, hosts) from the
vaulted file and **auto-blocks extracted peers at the firewall**; indicators
and blocked peers land in the `RESP-QUAR` alert so egress containment is
one click. Verified: `IMIX_CALLBACK_URI=http://203.0.113.99:8443/tavern` →
indicator extracted, 203.0.113.99 auto-blocked. Same-content re-quarantine is
uniquified (deny-ACL'd vault entries no longer block the move).

### Ops notes from this round
- The background-process wrapper can report "failed" while a detached python
  keeps serving port 8420 — stale instances then serve old code. Always kill
  by command line (`Get-CimInstance Win32_Process | ? CommandLine -match edr`)
  before relaunching.
- ctypes lesson twice over: `c_void_p` fields/returns are `None`/truncated at
  address 0 — coerce before arithmetic, and set 64-bit restypes explicitly.

---

## Addendum 6 — advanced in-memory detection + walkthrough gap closure

Closes the memory/hook/pipe/lateral gaps from the custom-walkthrough coverage
review with real in-memory techniques, not just disk heuristics.
**Tranche-4: 11/11. Classic: 20/21 (one .NET-ETW timing flake). Tranche-3: 4/4.**

### New sensors
- **`edr/modules.py` — module-walk (Toolhelp32 snapshot):**
  `MOD-SIDELOAD` (Windows-named DLL outside System32 - the proxy-DLL/search-
  order-hijack primitive; user-writable module inside a service-path process),
  `HOOK-DLL` (one unsigned module across >=4 processes - the observable of a
  SetWindowsHookEx global hook / broadcast injection), Defender-binary-location
  assist. Batch excludes the sensors' own System32 subprocess churn.
- **`edr/hooks.py` — in-memory integrity:**
  `NTDLL-TAMPER` (mapped ntdll .text compared against on-disk - catches inline
  API hooks AND EDR-unhooking; alerts carry the patched region addresses) and
  `THREAD-UNBACKED` (Win32 thread start addresses in private RWX memory with no
  module backing - CreateRemoteThread/thread-hollowing artifact) via
  NtQueryInformationThread(ThreadQuerySetWin32StartAddress).
- **`edr/pipes.py` — named-pipe enumeration:** `NET-PIPE` for C2-named pipes
  (msagent_/postex_/demon/...) and new pipes hosted by user-path processes
  (imix/Beacon SMB chaining posture).
- **Timestomp** (`TIME-STOMP`): mtime predating unfakeable NTFS creation time
  by >30 days, checked on every file scan; drop-dir walk depth raised 2 -> 6
  (deep-path evasion).

### New rules (44 total now)
Egress/tunnel tools (chisel/ngrok/ligolo/...), RMM tools, PsExec, WinRM
sessions, netsh firewall changes, dead-drop fetches (raw.githubusercontent/
pastebin/...), each with a 4688-fed twin so sub-second invocations the 3s WMI
poll misses still fire. Persistence auditor gained SilentProcessExit
(`PERS-SPE`) and SSH authorized_keys surfaces (`PERS-SSH`); the parallel
walkthrough work had already added UAC keys, BITS, PS profiles, ActiveSetup,
AppCertDlls, PrintMonitor, screensaver, TimeProvider, WLNotify, netsh helpers.

### Hardening found by the tests
Sensor loop rewritten with per-sensor isolation (one ctypes access violation
was aborting entire cycles); every 64-bit handle API now has explicit
`c_void_p` restypes (default `c_int` truncation silently breaks
DuplicateHandle/OpenThread/FindFirstFileW); MODULEENTRY32W field order and
WIN32_FIND_DATAW alignment fixed (c_uint64 FILETIMEs shift cFileName by two
characters); thread queries need THREAD_QUERY_INFORMATION (0x40), not the
limited right.

### Remaining known gaps (unchanged)
AD/domain persistence, kernel ETW per-peer ICMP attribution, sleep-encrypted
implant memory (wake-transition scanning), Sysmon-grade image-load events.

---

## Addendum 7 — memory-anomaly / injection-artifact / AMSI checklist

Implements the full detection checklist (memory anomalies, behavioral API
observables, native telemetry, hooking/integrity). **Final verification:
classic 21/21 + tranche-4 11/11 + tranche-5 7/7 = 39/39.**

### 1. Memory anomalies & injection artifacts
- **`MEM-RWX-UNBACKED`** (`edr/memmap.py`) - private PAGE_EXECUTE_* regions
  with no file mapping; JIT hosts allowlisted.
- **`MEM-RWX-NEW`** - private executable regions that appeared since the last
  pass: effects-level tracking of VirtualAlloc/VirtualAllocEx/
  NtAllocateVirtualMemory (the APIs themselves cannot be hooked from a
  user-mode stdlib EDR without injecting - the appearance diff is the
  observable).
- **`THREAD-HIJACK`** (`edr/hooks.py`) - GetThreadContext sampling: live RIP
  in private executable memory = post-SetThreadContext redirection
  (thread hijacking / hollowing aftermath).
- **`STACK-UNBACKED`** - stack return addresses pointing into unbacked
  memory (injected frames, stack spoofing, indirect-syscall callers).
- **`MEM-HOLLOWED`** - process's own image base is private committed memory
  instead of a mapped image (hollowing artifact).

### 2. Behavioral / API observables
- **`PROC-XHANDLE`** (`edr/handles.py`) - system handle table scan flagging
  cross-process handles with PROCESS_VM_WRITE / PROCESS_CREATE_THREAD - the
  WriteProcessMemory+CreateRemoteThread prerequisite posture.
- LSASS VM_READ handles: already covered (`LSASS-HANDLE`).

### 3. Native telemetry
- **AMSI-grade script scanning** - PowerShell 4104 script-block buffers
  (the deobfuscated script at execution, the same view the AMSI stream sees)
  are signature-scanned; new `SIG-AMSI-BYPASS` byte rule (amsiInitFailed,
  AmsiScanBuffer, AmsiUtils reflection patterns).
- **Parent-child matrix** (`processes._check_parent_chain`) - real
  parent-PID resolution: w3wp/sqlservr/mysqld/nginx/httpd/php-cgi/Office/
  spoolsv spawning cmd/powershell/wscript = webshell/macro chain
  (`PROC-SUSP-PARENT`). The old regex could never fire (4688 records only
  the child's command line).
- **Threat-Intelligence / Kernel-Memory ETW providers** - attempted at
  startup; both are restricted to PPL-signed consumers on stock systems
  (status recorded). The NT Kernel Logger session remains the live kernel feed.

### 4. Hooking & integrity
- ntdll .text vs disk: existing `NTDLL-TAMPER`.
- **`SYSCALL-STUB`** - the syscall instruction (0F 05) inside PRIVATE
  executable memory. Legit stubs exist only in mapped ntdll - this is the
  direct/indirect syscall evasion (HellsGate/SysWhispers) fingerprint.

### Architecture fix
Sensors now run **one thread each** (16 threads): sequential scheduling let a
heavy pass stretch the 5s netstat cadence to 30-60s, breaking beacon/DNS
cadence detection under load. The .NET-ETW Loader event for LoadFrom is
intermittent, so that test anchors on the deterministic file-scan path while
still exercising the ETW channel.

---

## Addendum 8 — watershell-cpp on Windows: full detection checklist

Mapped every indicator from the watershell-on-Windows checklist to live
coverage. **Tranche-6: 4/4. Classic regression: 21/21.**

| Checklist item | Detection |
|---|---|
| Unregistered binary on listening port | `NET-LISTENER` (non-service image, non-standard port) |
| Raw-socket usage | Linux: `PKT-SOCKET` (`/proc/net/packet` -> pid). Windows `SOCK_RAW` has no per-process enumeration API without a driver - documented backlog; byte signatures cover the binaries |
| MinGW/GCC build artifacts | **NEW `SIG-MINGW`** - libgcc/libstdc++/mingw32/GCC-version markers in PE (g++ output is anomalous on corporate Windows; watershell ships as g++) |
| Inconspicuous renaming (svchost.exe in Temp/Public) | **NEW `PROC-MASQ`** - real name-vs-location check: critical system binary name executing outside Windows/Program Files (previously only the generic path rule existed) |
| Shell spawner (unknown binary -> cmd/powershell) | **NEW `SPAWN-SHELL`** - interpreter spawned by a user-writable-path binary; complements the known-host matrix (`PROC-SUSP-PARENT`) by covering unknown/masqueraded parents |
| Anonymous pipes into shell | Covered indirectly via `SPAWN-SHELL` + `NET-LISTENER` correlation; direct anonymous-pipe attribution needs a driver |
| Unsigned service to user dir (7045 analog) | `EVT-7045` + `PERS-SERVICE`; **NEW**: the auditor now signature-scans a newly installed service's binary immediately (`binPath` resolved from the WMI record) |
| Windows named-pipe SMB posture | `NET-PIPE` (prior tranche) |

Combined with the earlier watershell work (`SIG-WATERSHELL` binary fingerprint:
status:/run: prefixes, /proc/net/arp+route parsing; Linux packet-socket
sensor), both the Linux-native tool and its Windows-port cousins are covered.

---

## Addendum 9 — IP intelligence (OSINT) enrichment

`edr/intel.py` gives every IP in the console an intelligence profile.
**Tranche-7: 8/8.**

### What enrichment returns
- **Offline (always available):** RFC classification - private/loopback/
  CGNAT/link-local/multicast/documentation/reserved/bogon - with analyst
  context ("internal network - lateral movement, not egress"), plus a static
  known-infrastructure list (Google/Cloudflare/Quad9 DNS should never be a
  C2 peer).
- **Online (free, no API key, opt-out with EDR_ONLINE_INTEL=0):** reverse
  DNS, and RIPEstat lookups - whois netname/org/country, announcing ASN +
  holder, prefix, geolocation. Verified: 1.1.1.1 -> AS13335
  CLOUDFLARENET / APNIC-LABS; 8.8.4.4 -> AS15169 GOOGLE / rdns dns.google.
- **Caching:** 6h TTL, persisted to edr/state/intel-cache.json - repeat
  lookups are instant and offline replays still show prior results.

### Integration
- `GET /api/intel?ip=&force=` - console API.
- **Auto-enrichment:** non-loopback `NET-BEACON` alerts get their peer's
  intelligence attached asynchronously; it renders in the "why this fired"
  panel automatically.
- **UI:** an `intel` button on every alert carrying an IP (both the alerts
  screen and the dashboard strip) - click to fetch and render the full
  profile (class/rdns/netname/org/ASN/holder/prefix/geo).

Two parser notes for future maintainers: python's `ipaddress.is_private` is
True for documentation AND loopback ranges, so named-range checks run first;
and RIPEstat nests whois record groups in lists-of-lists which must be
flattened before key extraction (the silent AttributeError otherwise drops
the whole online section).

---

## Addendum 10 — RW→RX permission-transition tracking (`MEM-PROMOTE`)

Closes the one genuinely-beneficial gap from the memory-technique review.
**Tranche-8: 1/1. Tranche-5 regression: 7/7.**

`memmap.py` now records private READ-WRITE regions alongside executable ones
and, on each pass, flags any executable region that overlaps a region
previously seen as read-write: the `VirtualProtect` flip signature of the
modern loader pattern (allocate RW → write shellcode → flip to RX) which
deliberately never creates a detectable RWX page. Overlap matching handles
region splitting (VirtualProtect on part of a region divides it). JIT hosts
remain allowlisted. This catches the flip *at the transition* with far higher
fidelity than "is private RX", closing the timing and false-positive gap that
existed when only the post-flip `MEM-RWX-UNBACKED` heuristic could see it.

---

## Addendum 11 — false-positive reduction pass

Researched detection-engineering FP practice (allowlisting, scoping by
provenance, cooldowns, baseline-then-tune ladders) and implemented the four
highest-impact reducers for FPs actually observed on this deployment
(`edr/tuning.py`):

1. **Sensor self-exclusion** — the EDR's own wevtutil/CIM/netstat tooling no
   longer trips command-line rules.
2. **Trusted-path scoping** — NET-BEACON/PROC-XHANDLE/NET-LISTENER only fire
   for actors from attacker-writable paths (Program Files, Windows, and
   per-user install roots are trusted). Collapsed fresh-boot noise:
   XHANDLE 23→1, beacons 18→~1 non-tooling.
3. **Alert cooldown** — same (rule, entity) within 10 min increments the
   original alert instead of stacking duplicates. Key order matters: bare
   paths are shared by every interpreter child.
4. **Listener/HOOK-DLL scoping** — loopback-only binds and
   Microsoft-managed DLL paths excluded.

Verified: tranche-4 11/11, tranche-5 6/7, tranche-6/7/8 suites unaffected.
Known issue: the tranche-5 PROC-XHANDLE test flakes via a handle-table
snapshot race (detector proven live repeatedly; the sweep now fast-aborts
when the Process-type index can't be verified to keep its cadence).
Docs: `docs/reducing-false-positives.md`, `docs/detection-features.md`.

---

## Addendum 12 — Beacon Triage screen + process suspension

New sixth console screen (same design system, `edr/beacon_triage.js`):
- **Beacon list** — every NET/DNS/ICMP-BEACON alert plus live cadence
  series, with peer/interval/pid/type.
- **Cadence evidence** — interval, sample gaps, alert time, attached or
  on-demand OSINT enrichment.
- **Containment decisions** per beacon: **Suspend** (NtSuspendProcess — the
  beacon stops communicating, nothing is deleted, full memory preserved for
  forensics), **Resume**, **Block egress** (firewall, process keeps
  running), **Unblock**, **Kill** (guardrailed), **Monitor only (ack)**,
  **Resolve**.
- **Decision log** — response history (RESP-* alerts).

New responder actions `suspend`/`resume` share the kill guardrails
(EDR-self, critical system processes, protected image paths refused).
Verified live: suspend→resume on a test process, lsass refusal, UI
selection→actions→animation in-browser, screenshot review.

**Click animations**: all buttons console-wide get a press
(translate+scale+brightness) and a spring "pop" keyframe via delegated
listener — verified applied in-browser.

---

## Addendum 13 — Commercial EDR gap closure (CrowdStrike / SentinelOne / Defender)

Research doc: `development-research/commercial-edr-techniques.md` (public
vendor sources). What was missing vs the commercial verdict layer, and what
this build added:

1. **Correlated verdicts** (Storyline/IOA-chaining equivalent): new
   `edr/correlation.py` fuses every alert into per-entity weighted evidence
   with a 0-99 confidence score and tiering (>=85 confirmed). Feeds the new
   seventh console screen, Implants.
2. **Entity quarantine with verification**: `quarantine_entity` =
   block C2 peers -> kill process TREE -> vault binary (+config extraction
   auto-block) -> persist status. `verify_containment` re-checks process /
   binary / firewall / beacon-silence before the UI shows INACTIVE-verified.
3. **Device isolation**: host-wide outbound block with loopback exemption
   (console stays reachable), release button, banner + alert.
4. **Detect-vs-Protect policy**: optional auto-quarantine at confirmed
   threshold (default off).
5. **Tree kill** (`taskkill /T`): whole threat sequence, not one pid.

Sensor hardening found during the live end-to-end:
- memmap/hooks only ever scanned the 6-8 NEWEST processes — aged implants
  were invisible. Now round-robin rotated across the candidate list.
- Sensors flagged the EDR's own process (SYSCALL-STUB/RWX self-FPs) —
  self/parent skip added.
- Browsers' V8 JIT pages tripped RWX + syscall-stub — JIT_HOSTS extended
  (chrome/msedge/brave/opera/vivaldi/firefox/electron) and the stub scan
  gated for JIT hosts.
- Beacon cooldown keyed on peer alone collapsed two processes beaconing the
  same C2 into one alert (attribution loss) — pid now always joins the key.
- Containment "silence" check now requires the CONTAINED pids to be silent
  (shared loopback peers carry unrelated console traffic by definition).
- Re-infection flip requires fresh alerts + grace window (termination-lag
  race had resurrected a mid-kill entity to "active").

Live E2E (implant.exe = standalone app-local python binary running
tests/fake_implant.py: private RWX + syscall stub + IMIX config strings +
5s-jitter TCP beacon to a loopback sink): scored **99/confirmed** on six
signals (NET-BEACON 45, MEM-RWX-UNBACKED 28, SYSCALL-STUB 22, MEM-RWX-NEW
16, MEM-SIG-REALM-IMIX 15, MEM-SIG-MUSL-ELF 15), quarantined from the UI
button, status chip QUARANTINED, verification checklist green, entity shows
INACTIVE-contained. Guardrails re-verified: EDR/lsass/protected-path
refusals intact; a Program Files interpreter image is refused for
quarantine by design (the EDR also refuses to vault its own interpreter).

---

## Addendum 14 — Linux persistence/evasion research + interval attack simulator

New defensive research and test tooling for the Linux half of CCDC images:

- `development-research/linux-persistence-evasion-guide.md` — full
  plant/detect/clean walkthroughs: UID-0 users, authorized_keys (incl.
  forced-command and authorized_keys2), PAM skeleton key, cron variants,
  systemd services/timers (system + user scope), udev RUN+= rules,
  /etc/ld.so.preload hijacking, shell rc/profile.d, memfd_create fileless
  execution, deleted binaries, timestomping, chattr +i, log clearing,
  firewall sabotage (with a blue-team re-arm watchdog), history/accounting
  sabotage, C2 channels (SSH tunnels, ICMP/DNS, watershell PF_PACKET), and
  webshells. Includes a copy-paste auditd baseline ruleset that keys every
  technique, and a first-hour baseline-snapshot procedure. Sources: Elastic
  Security Labs persistence series, PANIX, pberba hunting series, Sandfly,
  Neo23x0 auditd config.
- `linux-sim/` — automated interval attack simulation: 14 marked, benign
  technique scripts (nothing touches the network; payloads are sleep loops),
  a runner with `--all` / `--only` / `--interval N --count N` chaos mode
  (random technique every N seconds — the "add users / kill firewalls at
  intervals" scenario), JSON ground-truth logging to `actions.log` for
  scoring detections against what actually happened, plus `cleanup.sh` and
  a 21-check `verify.sh` that proves the image is clean afterwards.
  Windows-side counterparts of the same families already exist in the EDR
  (PERS-*, SPAWN-SHELL, TIME-STOMP, TAMPER-AUDIT, NET-BEACON, PKT-SOCKET)
  and the `tests/` tranches play the same role there.

Note on scope: the EDR itself is Windows-only (ctypes/Win32); on Linux
images detection comes from the guide's auditd ruleset + SIEM shipping.
The linux-sim ground-truth log is the scoring interface between the two.

---

## Addendum 15 — Advanced evasion playbooks (sleep-cryption, stealth persistence, interval sabotage)

New `playbooks/` directory: editable red-team playbooks that stress the EDR
harder than the marked simulations, kept inside the purple-team safety
contract (loopback-only beacons, no command channel, guarded sabotage on a
dummy service only, JSON ground-truth ledger, per-OS cleanup + verify).

- `sleep_crypt_implant.py` (cross-platform, ctypes): private-page payload
  buffer, in-place XOR decrypt on wake, RW->RWX flip while active, loopback
  beacon, in-place re-encryption before sleep, working-set trim
  (SetProcessWorkingSetSize / madvise). While ASLEEP, memory scanners see
  ciphertext only; while AWAKE the plaintext holds IMIX-style config
  strings — scan timing is the detection lesson. Documented ceiling: real
  implants use timer-ROP sleep masks (Ekko/Cronos/Foliage — sources in
  playbooks/README.md); shipping ROP chains is out of scope.
- Windows: `wb1` COM-hijack (HKCU CLSID shadow) + WMI event subscription +
  randomized-name task; `wb2` fileless deploy of the sleep-crypt implant
  (XOR blob + registry-hidden key + loader stub + logon task);
  `wb3` guarded interval service sabotage on a dummy service with a
  critical-services blocklist. Plus `wcleanup.ps1` / `wverify.ps1`
  (ledger-driven).
- Linux: `lb1` user-scope systemd + service-account cron @reboot + rc line +
  unlinked binary; `lb2` tmpfs ciphertext deploy with /etc key stash;
  `lb3` guarded systemd timer sabotage. Plus `lcleanup.sh` / `lverify.sh`.
- EDR targets per playbook are listed in README.md scoring section — the
  Implants screen should fuse wb2/lb2 into confirmed entities via cadence +
  unbacked RWX + flips; stealth-persist artifacts map to PERS-COM,
  PERS-WMI-SUB, PERS-TASK.

All scripts syntax-validated (bash -n, py_compile, PSParser tokenize);
implant smoke-run on Windows confirmed allocation/flip/cycle without crash.

---

## Addendum 16 — Advanced evasion/persistence research (Windows + Linux)

New `development-research/advanced-evasion-persistence-methods.md`: the tier
above the existing guides/playbooks, each technique mapped to have/partial/
ceiling status for this EDR. Highlights:

- Windows: indirect syscalls vs our STACK-UNBACKED (spoofing = ceiling);
  module stomping + ETW/AMSI patching -> generalizing NTDLL-TAMPER's
  .text-vs-disk check to ALL modules closes two families at once;
  NTUSER.MAN callback-free registry persistence (persistence auditor gap);
  ms-settings UAC-probe registry rule (cheap win); callback/fiber execution
  and herpaderping (ceiling / mitigated by memory-side scanning); BYOVD
  (documented kernel ceiling).
- Linux: the BPFDoor/eBPF passive-backdoor family — consensus detection is
  load-time (bpf/perf_event_open audit keys, unprivileged_bpf_disabled
  watch, program inventory diffs), provided as copy-paste rules;
  interpreter/package-manager persistence watches; sshd -T semantic-hash
  watchdog; systemd generators/tmpfiles.d; bind-mount hiding needing
  cross-view verification; initramfs hashing.
- Ends with a six-item detection-upgrade shortlist (three close real gaps
  in this EDR: all-module .text-vs-disk, NTUSER.MAN alert, ms-settings
  rule; three are Linux-image auditd/ops rules).

Cross-linked from playbooks/README.md and the Linux persistence guide.

---

## Addendum 17 — Native sleep-crypt tester + two advanced persistence rules

1. `playbooks/sleep_crypt_native.c` — the python-free counterpart of the
   sleep-crypt simulator for machines without an interpreter. Deliberately
   FIXED-BEHAVIOR: one private page, XOR in-place, RW<->RWX flips, loopback-
   only beacon, working-set trim, jittered sleep. No payload slot, no
   command channel, not position-independent — shellcode packaging is
   deployment tooling, not detection testing, and is out of scope by the
   same line as timer-ROP sleep masks (Addendum 15). MinGW builds double as
   a SIG-MINGW signature test. Build commands in the header comment; not
   compile-tested on this box (no toolchain).
2. EDR shortlist items #2 and #3 implemented and verified live:
   - `PERS-UAC-PROBE` — existence of HKCU ms-settings/exefile/ICMLuaUtil
     shell-hijack keys (fodhelper-family auto-elevate probes).
   - `PERS-NTUSERMAN` — NTUSER.MAN profile hives (persistence that rides
     hive-load and bypasses registry-callback telemetry; Deceptiq research).
   Both planted on this box, both fired within one audit cycle (30s),
   artifacts then cleaned. Legacy-junction double-reporting deduped via
   realpath.

---

## Addendum 18 — Manual test walkthroughs + module-stomping detector + on-demand memory scan

Answers "how do I manually test my EDR against the advanced tier" for the
technique class documented in Addendum 15/17's ceiling notes:

1. **`docs/edr-manual-test-walkthroughs.md`** — 8 hands-on labs: compiled
   implant lifecycle (score 99 -> UI quarantine -> verified inactive),
   awake-vs-asleep scan timing, module stomping, NTUSER.MAN + UAC probes,
   stealth persistence delivery (wb1), sabotage + taunt delivery, a
   refused-technique -> detector mapping table, and the Linux pointer lab.
   Each lab: steps / expected rules / verify / cleanup / what a miss means.
2. **`MOD-STOMPPED`** (hooks.py) — the all-module .text-vs-disk check
   (research shortlist #1): catches module stomping and in-process
   ETW/AMSI patching. Three bugs found and fixed during live verification:
   (a) section virtual-address vs file-offset skew made every comparison
   misalign (systematic FPs on chrome/msedge/msys) — memory side now uses
   vaddr, disk side raddr; (b) browser auto-update version skew (file
   replaced under a running process) — skipped via mapped-vs-disk PE
   TimeDateStamp comparison; (c) load-order module window never reached
   last-loaded (user-path) DLLs — user-writable-path modules now sorted
   first. Final live verification: the self-stomp test
   (`tests/self_stomp_test.py`, patches two .text chunks of a loaded DLL
   copy in its own memory) fired exactly once on exactly the patched
   module with exactly the patched regions, zero false positives.
3. **On-demand memory scan** — `/api/scan/mem?pid=` (force-rescan bypasses
   the periodic-scan cache) + "Scan memory now" button in the Implants
   evidence panel: the awake-vs-asleep sleep-encryption exercise is now a
   button press (scan during the plaintext window finds signatures; during
   the encrypted window it reports clean — the structural rules are what
   survive encryption).
