# EDR/SIEM Live Build & Test Report — 2026-09-07

## Where it's live

**Console: http://127.0.0.1:8420** (running now, started with `python -m edr` from the repo root)

The five-screen console (Dashboard, Log Explorer, Alerts, Signatures, Intel) is served with a
live-data layer injected: a floating "LIVE" panel bottom-right streams real alerts from
`/api/state` as your own sensors generate them. API endpoints: `/api/state`, `/api/rules`,
`/api/scans`, and POST `/api/baseline`, `/api/scan`, `/api/audit`.

## What was verified working (11/11 live tests)

`python tests/run_tests.py` — every test plants real artifacts on this machine, waits for the
EDR to catch them through its normal sensor cycles, then cleans up:

| Test | Detection that fired | Sensor path |
|---|---|---|
| Realm imix binary dropped in %TEMP% | SIG-REALM-IMIX + SIG-RUST-IMPLANT (critical) | signature scanner, on-write/interval |
| Static musl ELF implant | SIG-MUSL-ELF (medium) | signature scanner |
| Eldritch tome script | SIG-ELDRITCH-TOME (high) | signature scanner |
| PHP webshell in webroot-style path | SIG-WEBSHELL-PHP (critical) | signature scanner |
| Implant binary **launched** (alive ~12s) | PROG-IMPLANT-LAUNCH (critical) | WMI process poll → image scan |
| Fast-exit launches from user-writable dirs | EVT-4688-TEMP + image scan on 4688 | kernel-fed Security log |
| Encoded PowerShell stager | PROC-ENC-PS + EVT-4688-SUSP (high) | WMI poll + 4688 |
| New autorun registry value | PERS-RUNKEY (high) | persistence auditor baseline diff |
| New Startup-folder item | PERS-STARTUP (high) | persistence auditor |
| New scheduled task | PERS-TASK / EVT-4698 (high) | auditor + Security log |
| New service installed | PERS-SERVICE / EVT-7045 (critical) | auditor + System log |
| Periodic C2 beacon (5s + jitter, loopback) | NET-BEACON (critical) | netstat flow cadence analysis |

## Monitoring stack (as researched: kernel + Windows built-ins)

1. **ETW kernel trace** — a real `NT Kernel Logger` session (process events, flag mask 0x10)
   writes continuously to `edr/state/kernel.etl` for forensics (`tracerpt` renders it to XML).
2. **Kernel-fed Security auditing** — `auditpol` process-creation auditing + command-line
   inclusion in 4688 enabled at startup; the eventlog sensor consumes 4688/4698/4702/4720/4732/
   1102, System 7045/7040, PowerShell 4104 script-block logs, and Sysmon if installed.
3. **WMI Win32_Process polling** — command lines + parent PIDs + on-launch image scanning.
4. **Persistence auditor** — baselines then diffs Run keys, IFEO, AppInit_DLLs, services,
   tasks, Startup folders, and WMI event subscriptions every 30s.
5. **Signature scanner** — Realm/Rust/musl/tome/webshell/CS/Havoc string packs over
   user-writable drop directories; rescans on size/mtime change.
6. **Network sensor** — netstat flow collection + beacon-cadence analysis (fixed interval
   ± jitter to one peer).

A true minifilter/callback driver would need the WDK + test signing; the ETW session plus the
kernel-generated Security/System logs give equivalent launch and persistence visibility at
user mode, which is the right ceiling for a CCDC competition build.

## Bugs found during live testing and fixed (develop → retest loop)

1. **`.elf` files were never scanned** — extension missing from `SCAN_EXTS`; musl test
   implant sailed through. Added `.elf/.so/.bin/.out`.
2. **Fast-exit implants evaded the launch scan** — the WMI poll (3s cadence) missed
   processes that died in <100ms. Fixed: Security 4688 records now trigger an image scan of
   the launched executable when it lives in a user-writable directory, catching instant-exit
   stagers through the kernel-fed channel instead of polling.
3. **Eventlog sensor was silently dead** — it passed a record *number* to `wevtutil /bm:`,
   which expects a bookmark *file*, so every poll errored and returned nothing (the earlier
   "passes" for task/service came from the auditor, not eventlog). Rewrote bookmarking to
   filter parsed `EventRecordID`s in-process, capped queries at 200 records per poll.
4. **Sensor self-noise flooded the console** — the WMI poll spawned its own PowerShell probes
   every 3s and recorded them as process-start events. Both sensors now skip their own poll
   subprocesses.
5. **Alert window truncation caused a false test failure** — `/api/state` capped alerts at
   200 and the newly-working 4688 ingest (this machine's tooling runs encoded PowerShell
   constantly, each one a legitimate EVT-4688-SUSP hit) pushed the PROC-ENC-PS alert out of
   view. The API now returns the last 1000 alerts separately from the capped event list.
6. **Sensor crash on non-UTF-8 process data** — a command line containing a Windows-1252
   byte (0x97, an em dash) crashed the sensor loop with `UnicodeDecodeError` via
   `subprocess(text=True)`. All eight text-mode subprocess calls across the sensors now use
   `errors="replace"` so no process's command line encoding can kill the telemetry pipeline.

After each fix the full live cycle was re-run; final result **11/11**.

## Test safety

All "payloads" are benign simulants per the repo's test harness design: the imix binary is a
copy of `cmd.exe` with Realm config strings appended as an overlay (runs, but is just cmd),
the ELF/tome/webshell are inert text/byte blobs never executed, the beacon is a TCP loopback
client, and every persistence artifact is named `CCDCTest*` and removed afterward. No real
malware was built or executed.

## Running it yourself

```
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design
python -m edr          # console at http://127.0.0.1:8420
python tests/run_tests.py   # optional: full live detection cycle (needs EDR running)
```
