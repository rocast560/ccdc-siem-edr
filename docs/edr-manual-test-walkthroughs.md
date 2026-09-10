# EDR Manual Test Walkthroughs — the advanced tier, hands-on

Labs for manually testing this EDR against the advanced evasion/persistence
class (sleep-encryption, compiled/fileless execution, module stomping,
callback-free persistence, stealth delivery). Every lab uses the repo's
fixed-behavior tooling only — no payload slots, loopback-only beacons, all
artifacts cleanup-able. Each lab ends with **what should fire**, how to
verify it, and what a miss means.

Setup for all labs:

```powershell
cd C:\Users\Administrator\Desktop\CCDC-EDR-SIEM-design
python -m edr                          # console at http://127.0.0.1:8420
# keep a second terminal for planting; use the workspace interpreter copy
# for implant-ish processes so the trusted-image allowlist stays honest:
cp "C:\Program Files\Python313\python.exe" tests\bin\implant.exe
```

---

## Lab 1 — compiled, fileless-style implant lifecycle (the flagship run)

**Goal**: a python-free implant scores confirmed, gets quarantined from the
UI, and shows verified-inactive. Exercises: unbacked RWX, permission flips,
sleep-encrypted memory, cadence, quarantine + verification.

**Steps**
1. Build the native tester (needs any C toolchain; a MinGW build doubles as
   a SIG-MINGW test):
   `gcc -O2 -o tests/bin/sleep_crypt_native.exe playbooks/sleep_crypt_native.c -lws2_32`
   (no compiler? use `tests/bin/implant.exe tests/fake_implant.py` — same
   detection surfaces.)
2. Start the loopback sink: `tests/bin/implant.exe tests/beacon_listener.py`
3. Start the implant: `tests/bin/sleep_crypt_native.exe` (or the fake_implant).
4. Watch the **Implants screen** (`#implants`). Expect the entity within
   ~2–6 minutes (beacon needs ≥6 samples; memmap rotation needs to reach it).

**What should fire**
`NET-BEACON` (45) · `MEM-RWX-UNBACKED` (28) · `SYSCALL-STUB` (22) ·
`MEM-RWX-NEW` (16) · `MEM-SIG-*` (15 each) → **99 / CONFIRMED**.

**Verify**: `/api/implants` shows score ≥ 85 and the evidence bundle lists
the rules above. Click the row → evidence panel.

**Respond**: click **Quarantine implant** — peers firewalled, tree killed,
binary vaulted. Then **Verify containment** — four green checks → the chip
flips to `INACTIVE ✓ contained`.

**If it didn't fire**: NET-BEACON missing → check the cadence tracker sees
ESTABLISHED flows (`netstat -ano | findstr 9101`); RWX missing → the memmap
rotation hasn't reached the pid yet (75s × position-in-queue).

## Lab 2 — awake vs asleep: scan timing vs sleep-encryption

**Goal**: prove to yourself what encryption-in-memory does and doesn't hide.

**Steps**
1. Implant running (Lab 1). Note its cycle: ~6s awake, ~45s asleep (jittered).
2. On the Implants screen select the entity → click **Scan memory now**
   repeatedly. (API equivalent: `curl http://127.0.0.1:8420/api/scan/mem?pid=<pid>`)

**What you'll see**: scans landing inside the awake window report
`SIGNATURES IN PLAINTEXT` (`MEM-SIG-REALM-IMIX` etc.); scans during the
sleep window report clean — ciphertext only.

**The lesson**: signature scans are timing-dependent against sleep-encrypted
implants, which is exactly why the EDR leans on the *structural* signals
instead (unbacked RWX, flips, cadence) — those survive encryption. If you
want scans to catch it regardless, that's the argument for the
wake-transition scanning documented as a ceiling in the implementation
report.

## Lab 3 — module stomping / in-memory patching (NEW detector)

**Goal**: trigger `MOD-STOMPPED` — the all-module .text-vs-disk check that
catches module stomping and in-process ETW/AMSI patching.

**Steps**
1. `tests\bin\implant.exe tests\self_stomp_test.py 300`
   (loads a copy of winmm.dll into itself, rewrites two .text chunks
   in memory only, holds 5 minutes, self-restores)
2. Wait for the next hooks pass (90s interval, newest processes first).

**What should fire**: `MOD-STOMPPED` (critical) naming the module + the
patched regions.

**Verify**: Alerts screen or
`curl http://127.0.0.1:8420/api/state | findstr MOD-STOMPPED`.

**Clean**: automatic — the tester restores bytes and exits.

**If it didn't fire**: the ≥2-chunk threshold — confirm the log line says
"2 chunks patched"; if the process was already in `_checked` from a previous
run, use a fresh process.

## Lab 4 — callback-free persistence: NTUSER.MAN + UAC probes

**Steps**
```powershell
# UAC probe shape (fodhelper family)
New-Item -Path 'HKCU:\Software\Classes\ms-settings\Shell\Open\command' -Force
# registry-callback-free persistence shape
New-Item -ItemType File "$env:USERPROFILE\NTUSER.MAN"
```

**What should fire** (next 30s audit cycle): `PERS-UAC-PROBE` then
`PERS-NTUSERMAN`.

**Clean**:
`Remove-Item -Recurse 'HKCU:\Software\Classes\ms-settings'; Remove-Item "$env:USERPROFILE\NTUSER.MAN"`

**If it didn't fire**: check the auditor is cycling
(`/api/audit` returns findings) — these are presence checks, not
baseline diffs, so they re-verify every cycle.

## Lab 5 — stealth persistence delivery (wb1)

**Steps**: `playbooks\windows\wb1-stealth-persist.ps1` (admin) — plants a
COM CLSID hijack, a WMI event subscription, and a randomized-name task.

**What should fire**: `PERS-COM` · `PERS-WMI-SUB` · `PERS-TASK` (baseline
diff). The task's action-hash change also fires the task-action rule.

**Manual hunts** (the blue-team workflow if alerts were muted):
`Get-WmiObject __EventFilter -Namespace root\subscription` ·
`reg query HKCU\Software\Classes\CLSID /s /f InprocServer32` ·
`schtasks /query /fo LIST | findstr EdgeUpdate`

**Clean**: `playbooks\windows\wcleanup.ps1` then `wverify.ps1`.

## Lab 6 — interval sabotage + taunt delivery

**Steps**: `playbooks\windows\wb3-service-sabotage.ps1` (dummy service
stop/restore storm) and `taunts\windows\wt1-wallpaper.ps1 -IntervalMin 2`
(interval task delivery).

**What should fire**: task creation (`PERS-TASK`) for both; the service
storm shows in the event stream as service-control telemetry; the sabotage
loop script itself gets signature-scanned on creation.

**Clean**: `wcleanup.ps1` (both) — it removes CCDCTauntWP and CCDCSimWatch.

## Lab 7 — where the refused techniques live (concept → detector mapping)

The techniques documented but deliberately not built as deployable tooling,
and what catches their observable half today:

| technique (researched) | observable our EDR targets | rule |
|---|---|---|
| direct syscalls | syscall stub in private memory | `SYSCALL-STUB` |
| indirect syscalls | return address into private exec | `STACK-UNBACKED` |
| thread hijack to shellcode | RIP in private exec | `THREAD-HIJACK` |
| PI/shellcode execution | thread start address unbacked | `THREAD-UNBACKED` |
| module stomping / ETW-AMSI patch | module .text ≠ disk | `MOD-STOMPPED` (Lab 3) |
| sleep encryption | RW↔RWX flips + cadence | `MEM-RWX-NEW`/`MEM-PROMOTE`/`NET-BEACON` |
| NTUSER.MAN persistence | hive file presence | `PERS-NTUSERMAN` (Lab 4) |
| stack-spoofed indirect calls | (defeats stack checks) | documented ceiling |

## Lab 8 — Linux images

`linux-sim/simulate.sh --all --no-cleanup` with the guide's auditd ruleset
loaded, then hunt per `development-research/linux-persistence-evasion-guide.md`
and score against `linux-sim/actions.log`. The advanced additions
(eBPF load-time keys, interpreter-path watches) are in
`advanced-evasion-persistence-methods.md`.

---

**Scoring every lab**: `/api/implants` (fused verdicts) ·
`/api/state` (raw alerts) · the Implants/Alerts/Threat Intel screens. A
miss = a rule to write; re-run the lab after adding it and watch it close.
