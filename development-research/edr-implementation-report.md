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
