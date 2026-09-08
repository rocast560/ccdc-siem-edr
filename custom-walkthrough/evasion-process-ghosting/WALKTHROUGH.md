# Test: Evasion (very advanced) — Process Ghosting / Herpaderping

**Chain:** file-based execution races that defeat on-disk scanning. **Process ghosting**
writes the payload in a delete-pending state and executes it *while the file is already
unlinked* — the image never exists in a scannable steady state. **Herpaderping**
(jthuraisamy's PoC) swaps the on-disk content *after* the image is mapped but *before*
execution — the kernel runs one binary while the disk shows another (e.g., Task Manager
shows notepad.exe, the disk file is the implant).

These are the honest hard cases for your architecture: both corrupt exactly the
file-scan→launch-scan chain your EDR depends on.

**Tooling:** the canonical public PoC is
[Herpadering.exe (jthuraisamy/Herpadering)](https://github.com/jthuraisamy/Herpadering) —
it replaces the target with a copy of itself; the ghosting equivalent lives in various
public `ProcessGhosting` repos (byonor/ghosting PoCs). Build on Kali/Windows with the
WDK-free branch or use the prebuilt release. **Lab-only, your binaries only.**

**Manual steps (build box → victim):**

```bash
# build the PoC (attacker box with VS/rust):
git clone https://github.com/jthuraisamy/Herpadering && cd Herpadering
# build per repo instructions -> herpadering.exe
# serve it alongside a benign target binary (e.g., a copy of notepad.exe)
```

```powershell
# victim: run the PoC against a benign target
C:\Users\Public\herpadering.exe C:\Users\Public\sysupd.exe   # PoC syntax per repo README
# observation points:
Get-Process <ghosted-name> | Select Path           # path points at the ORIGINAL file
Get-FileHash C:\Users\Public\<target>.exe          # hash matches the REPLACEMENT content
```

**Expected vs gap — all gaps, stated plainly:**

| Signal | Today |
|---|---|
| File written | ✅ `SIG-*` on-write scan fires — **when the file survives long enough**; ghosting's delete-pending write can beat the scan interval |
| Mismatch: running image ≠ on-disk content | ❌ GAP — detecting this needs kernel file↔process correlation (create-time image hash vs current file hash); Sysmon EID 1 (hashes at creation) + EID 7 correlation is the usermode approximation |
| Process runs | ✅ process telemetry still sees it (ghosting hides the *file*, not the *process*) — so launch-path rules (`EVT-4688-TEMP`) still fire if the path is user-writable |

**The honest verdict:** ghosting/herpaderping defeat *static on-disk* verification, not
process visibility. Your compensating controls: launch-path rules (still fire), behavioral
chain (beacon cadence still fires), and — when you install Sysmon — EID 1's
creation-time hashing, which is specifically immune to post-mapping content swaps.
File it as "partially mitigated, fully closed only with Sysmon."

**Cleanup:** delete PoC + target binaries.
